package com.example.security.common.account;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
@Profile("demo")
@EnableConfigurationProperties(DemoAccounts.Settings.class)
class DemoAccounts implements ApplicationRunner {

	private final AccountRepository repository;
	private final PasswordEncoder encoder;
	private final Settings settings;

	DemoAccounts(AccountRepository repository, PasswordEncoder encoder, Settings settings) {
		this.repository = repository;
		this.encoder = encoder;
		this.settings = settings;
	}

	@Override
	@Transactional
	public void run(ApplicationArguments args) {
		for (DemoUser user : settings.users()) {
			String email = user.email().strip().toLowerCase(Locale.ROOT);
			if (repository.findByEmail(email).isEmpty()) {
				repository.save(new Account(email, encoder.encode(user.password()), user.permissions()));
			}
		}
	}

	@ConfigurationProperties("demo")
	record Settings(List<DemoUser> users) {
		Settings {
			if (users == null || users.size() != 3) {
				throw new IllegalArgumentException("Configure three demo users.");
			}
			users = List.copyOf(users);
		}
	}

	record DemoUser(String email, String password, Set<Permission> permissions) {
		DemoUser {
			if (email == null || !email.contains("@") || email.length() > 254 || permissions == null || permissions.isEmpty()) {
				throw new IllegalArgumentException("A demo user requires an email and permissions.");
			}
			if (password == null || password.length() < 12 || password.getBytes(StandardCharsets.UTF_8).length > 72) {
				throw new IllegalArgumentException("Demo passwords require at least 12 characters and at most 72 UTF-8 bytes.");
			}
			permissions = Set.copyOf(permissions);
		}

		@Override
		public String toString() {
			return "DemoUser[email=" + email + ", permissions=" + permissions + "]";
		}
	}
}
