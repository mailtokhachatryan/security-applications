package com.example.security.common.login;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.time.Clock;
import java.util.Locale;

@Configuration(proxyBeanMethods = false)
class BasicAuthenticationConfiguration {

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

	@Bean
	UserDetailsService users(@Value("${app.email}") String email, @Value("${app.password}") String password,
			PasswordEncoder encoder) {
		return new InMemoryUserDetailsManager(User.withUsername(email.strip().toLowerCase(Locale.ROOT))
				.password(encoder.encode(password)).authorities("AUTHENTICATED").build());
	}

	@Bean
	Clock clock() {
		return Clock.systemUTC();
	}
}
