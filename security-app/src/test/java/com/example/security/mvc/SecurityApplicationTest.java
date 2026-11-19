package com.example.security.mvc;

import com.example.security.common.account.Account;
import com.example.security.common.account.AccountRepository;
import com.example.security.common.account.Permission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class SecurityApplicationTest {

	@Container
	@ServiceConnection
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");

	@Autowired
	private MockMvc mvc;
	@Autowired
	private AccountRepository accounts;
	@Autowired
	private PasswordEncoder encoder;

	@BeforeEach
	void resetAccounts() {
		accounts.deleteAll();
	}

	@Test
	void databaseAccountsUseSaltedHashesAndAboutIsPublic() throws Exception {
		String password = "testing-password-2026";
		String first = encoder.encode(password);
		String second = encoder.encode(password);
		assertThat(first).isNotEqualTo(second).doesNotContain(password);
		assertThat(encoder.matches(password, first)).isTrue();
		accounts.save(new Account("viewer@example.com", first, Set.of(Permission.STANDARD)));
		mvc.perform(get("/about")).andExpect(status().isOk());
		mvc.perform(get("/info")).andExpect(status().isUnauthorized());
		mvc.perform(get("/info").with(httpBasic("VIEWER@example.com", password))).andExpect(status().isOk());
	}
}
