package com.example.security.mvc;

import com.example.security.common.account.Account;
import com.example.security.common.account.AccountRepository;
import com.example.security.common.account.Permission;
import com.example.security.common.login.LoginAttemptRepository;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@Import(SecurityApplicationTest.TimeConfiguration.class)
class SecurityApplicationTest {

	private static final String PASSWORD = "testing-password-2026";
	private static final Instant START = Instant.parse("2026-11-19T10:00:00Z");
	private static List<String> hashes;

	@Container
	@ServiceConnection
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");

	@Autowired
	private MockMvc mvc;
	@Autowired
	private AccountRepository accounts;
	@Autowired
	private LoginAttemptRepository attempts;
	@Autowired
	private MutableClock clock;

	@BeforeAll
	static void createPasswordHashes() {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
		hashes = List.of(encoder.encode(PASSWORD), encoder.encode(PASSWORD), encoder.encode(PASSWORD));
	}

	@BeforeEach
	void reset() {
		attempts.deleteAll();
		accounts.deleteAll();
		clock.now.set(START);
		accounts.save(new Account("info@example.com", hashes.get(0), Set.of(Permission.VIEW_INFO, Permission.STANDARD)));
		accounts.save(new Account("admin@example.com", hashes.get(1), Set.of(Permission.VIEW_INFO, Permission.VIEW_ADMIN, Permission.STANDARD)));
		accounts.save(new Account("member@example.com", hashes.get(2), Set.of(Permission.STANDARD)));
	}

	@Test
	void publicAboutAndProtectedResourcesFollowThePermissionMatrix() throws Exception {
		mvc.perform(get("/about")).andExpect(status().isOk()).andExpect(jsonPath("$.application").value("Security application"));
		mvc.perform(get("/info")).andExpect(status().isUnauthorized());
		mvc.perform(get("/admin")).andExpect(status().isUnauthorized());
		mvc.perform(get("/info").with(user("viewer").authorities(new SimpleGrantedAuthority("VIEW_INFO"))))
				.andExpect(status().isOk()).andExpect(jsonPath("$.application").value("MVC application"))
				.andExpect(jsonPath("$.activeUsers").isNumber());
		mvc.perform(get("/admin").with(user("viewer").authorities(new SimpleGrantedAuthority("VIEW_INFO"))))
				.andExpect(status().isForbidden());
		mvc.perform(get("/admin").with(user("admin").authorities(new SimpleGrantedAuthority("VIEW_ADMIN"))))
				.andExpect(status().isOk());
		mvc.perform(get("/info").with(user("member").authorities(new SimpleGrantedAuthority("STANDARD"))))
				.andExpect(status().isForbidden());
		mvc.perform(get("/admin/blocked-users").with(user("member"))).andExpect(status().isForbidden());
	}

	@Test
	void emailLoginUsesDistinctSaltedHashesAndCustomPages() throws Exception {
		assertThat(hashes).doesNotHaveDuplicates().allSatisfy(hash -> {
			assertThat(hash).startsWith("$2a$12$").doesNotContain(PASSWORD);
			assertThat(new BCryptPasswordEncoder().matches(PASSWORD, hash)).isTrue();
		});
		mvc.perform(get("/login")).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("name=\"email\"")));
		MockHttpSession session = (MockHttpSession) mvc.perform(formLogin().user("email", "  INFO@EXAMPLE.COM ").password(PASSWORD))
				.andExpect(authenticated().withUsername("info@example.com"))
				.andReturn().getRequest().getSession(false);
		mvc.perform(get("/info").session(session)).andExpect(status().isOk());
		mvc.perform(get("/sign-out").session(session)).andExpect(status().isOk());
		mvc.perform(post("/sign-out").session(session)).andExpect(status().isForbidden());
		mvc.perform(post("/sign-out").session(session).with(csrf())).andExpect(redirectedUrl("/login?logout"));
		assertThat(session.isInvalid()).isTrue();
	}

	@Test
	void thirdFailureBlocksForExactlyFiveMinutesAndBlockedAttemptsPreserveExpiry() throws Exception {
		for (int i = 0; i < 3; i++) {
			failedLogin("info@example.com");
		}
		Instant expiry = START.plus(Duration.ofMinutes(5));
		assertThat(attempts.findById("info@example.com").orElseThrow().getBlockedUntil()).isEqualTo(expiry);
		mvc.perform(formLogin().user("email", "info@example.com").password(PASSWORD)).andExpect(unauthenticated());
		assertThat(attempts.findById("info@example.com").orElseThrow().getBlockedUntil()).isEqualTo(expiry);
		mvc.perform(get("/admin/blocked-users").with(user("admin").authorities(new SimpleGrantedAuthority("VIEW_ADMIN"))))
				.andExpect(status().isOk()).andExpect(jsonPath("$[0].email").value("info@example.com"))
				.andExpect(jsonPath("$[0].blockedUntil").value(expiry.toString()));
		clock.now.set(expiry);
		mvc.perform(formLogin().user("email", "info@example.com").password(PASSWORD)).andExpect(authenticated());
		assertThat(attempts.findById("info@example.com").orElseThrow().getBlockedUntil()).isNull();
		mvc.perform(get("/admin/blocked-users").with(user("admin").authorities(new SimpleGrantedAuthority("VIEW_ADMIN"))))
				.andExpect(status().isOk()).andExpect(content().json("[]"));
	}

	@Test
	void successResetsConsecutiveFailuresAndUnknownEmailsFollowTheSamePolicy() throws Exception {
		failedLogin("info@example.com");
		failedLogin("info@example.com");
		assertThat(attempts.findById("info@example.com").orElseThrow().getBlockedUntil()).isNull();
		mvc.perform(formLogin().user("email", "info@example.com").password(PASSWORD)).andExpect(authenticated());
		failedLogin("info@example.com");
		assertThat(attempts.findById("info@example.com").orElseThrow().getBlockedUntil()).isNull();
		for (int i = 0; i < 3; i++) {
			failedLogin("unknown@example.com");
		}
		assertThat(attempts.findById("unknown@example.com").orElseThrow().getBlockedUntil()).isEqualTo(START.plusSeconds(300));
	}

	@Test
	void concurrentFailuresCannotLoseTheThirdAttempt() throws Exception {
		CompletableFuture<?>[] calls = new CompletableFuture<?>[3];
		for (int i = 0; i < calls.length; i++) {
			calls[i] = CompletableFuture.runAsync(() -> {
				try {
					failedLogin("member@example.com");
				} catch (Exception error) {
					throw new IllegalStateException(error);
				}
			});
		}
		CompletableFuture.allOf(calls).get(15, TimeUnit.SECONDS);
		assertThat(attempts.findById("member@example.com").orElseThrow().getBlockedUntil()).isEqualTo(START.plusSeconds(300));
	}

	private void failedLogin(String email) throws Exception {
		mvc.perform(formLogin().user("email", email).password("wrong-password"))
				.andExpect(unauthenticated()).andExpect(redirectedUrl("/login?error"));
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class TimeConfiguration {
		@Bean
		@Primary
		MutableClock testClock() {
			return new MutableClock();
		}
	}

	static class MutableClock extends Clock {
		private final AtomicReference<Instant> now = new AtomicReference<>(START);

		@Override
		public ZoneId getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(ZoneId zone) {
			return Clock.fixed(instant(), zone);
		}

		@Override
		public Instant instant() {
			return now.get();
		}
	}
}
