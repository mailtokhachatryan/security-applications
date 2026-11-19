package com.example.security.secrets;

import com.example.security.secrets.secret.SecretService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "secrets.encryption-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
@AutoConfigureMockMvc
@Testcontainers
class SecretProvidersTest {

	@Container
	@ServiceConnection
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");

	@Autowired
	private MockMvc mvc;
	@Autowired
	private SecretService service;
	@Autowired
	private JdbcClient jdbc;

	@BeforeEach
	void resetSecrets() {
		jdbc.sql("DELETE FROM secret").update();
	}

	@Test
	void onlyStandardUsersCanCreateOrRevealSecretsAndCsrfIsRequired() throws Exception {
		mvc.perform(get("/secrets")).andExpect(status().is3xxRedirection());
		mvc.perform(get("/secrets").with(user("visitor"))).andExpect(status().isForbidden());
		mvc.perform(post("/secrets").with(user("sender").authorities(() -> "STANDARD")).param("content", "secret"))
				.andExpect(status().isForbidden());
		mvc.perform(post("/secrets").with(user("visitor")).with(csrf()).param("content", "secret"))
				.andExpect(status().isForbidden());
		String token = service.create("must-survive-rejected-requests");
		mvc.perform(post("/secrets/{token}/reveal", token).with(user("visitor")).with(csrf()))
				.andExpect(status().isForbidden());
		assertThat(rows()).isEqualTo(1);
	}

	@Test
	void linkPreviewPreservesTheSecretAndRevealDeletesItWithEscapedNoStoreOutput() throws Exception {
		String secret = "<script>alert('private')</script>";
		String page = mvc.perform(post("/secrets").with(user("sender").authorities(() -> "STANDARD"))
				.with(csrf()).param("content", secret)).andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();
		String token = page.substring(page.indexOf("http://localhost:8081/secrets/") + "http://localhost:8081/secrets/".length());
		token = token.substring(0, 43);
		assertThat(token).matches("[A-Za-z0-9_-]{43}");
		assertThat(page).doesNotContain(secret);
		mvc.perform(get("/secrets/{token}", token).with(user("recipient").authorities(() -> "STANDARD")))
				.andExpect(status().isOk());
		assertThat(rows()).isEqualTo(1);
		mvc.perform(post("/secrets/{token}/reveal", token).with(user("recipient").authorities(() -> "STANDARD")).with(csrf()))
				.andExpect(status().isOk()).andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
				.andExpect(header().string("Referrer-Policy", "no-referrer"))
				.andExpect(content().string(org.hamcrest.Matchers.containsString("&lt;script&gt;")))
				.andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(secret))));
		assertThat(rows()).isZero();
		mvc.perform(post("/secrets/{token}/reveal", token).with(user("recipient").authorities(() -> "STANDARD")).with(csrf()))
				.andExpect(status().isNotFound());
	}

	@Test
	void storesEncryptedContentAndOnlyTheDigestOfTheLinkToken() {
		String token = service.create("private message");
		String storedToken = jdbc.sql("SELECT token_hash FROM secret").query(String.class).single();
		byte[] payload = jdbc.sql("SELECT encrypted_payload FROM secret").query((row, index) -> row.getBytes(1)).single();
		assertThat(storedToken).hasSize(64).doesNotContain(token);
		assertThat(new String(payload, StandardCharsets.UTF_8)).doesNotContain("private message");
	}

	@Test
	void simultaneousReadersObtainExactlyOneCopy() throws Exception {
		String token = service.create("only-once");
		CompletableFuture<String> first = CompletableFuture.supplyAsync(() -> consumeOrMissing(token));
		CompletableFuture<String> second = CompletableFuture.supplyAsync(() -> consumeOrMissing(token));
		assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
				.containsExactlyInAnyOrder("only-once", "missing");
		assertThat(rows()).isZero();
	}

	@Test
	void decryptionFailureRollsBackConsumptionAndInvalidContentIsRejected() throws Exception {
		String token = service.create("preserve-on-failure");
		jdbc.sql("UPDATE secret SET encrypted_payload = :payload").param("payload", new byte[]{1, 2, 3}).update();
		assertThatThrownBy(() -> service.consume(token)).isInstanceOf(IllegalStateException.class);
		assertThat(rows()).isEqualTo(1);
		mvc.perform(post("/secrets").with(user("sender").authorities(() -> "STANDARD")).with(csrf()).param("content", " "))
				.andExpect(status().isBadRequest());
	}

	private String consumeOrMissing(String token) {
		try {
			return service.consume(token);
		} catch (ResponseStatusException unavailable) {
			assertThat(unavailable.getStatusCode().value()).isEqualTo(404);
			return "missing";
		}
	}

	private long rows() {
		return jdbc.sql("SELECT count(*) FROM secret").query(Long.class).single();
	}
}
