package com.example.security.common.login;

import com.example.security.common.account.AccountRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.util.Locale;

@Configuration(proxyBeanMethods = false)
class DatabaseAuthenticationConfiguration {

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

	@Bean
	UserDetailsService users(AccountRepository accounts) {
		return email -> accounts.findByEmail(email.strip().toLowerCase(Locale.ROOT))
				.map(account -> User.withUsername(account.getEmail()).password(account.getPasswordHash())
						.authorities("AUTHENTICATED").build())
				.orElseThrow(() -> new UsernameNotFoundException("Account is unavailable."));
	}

	@Bean
	Clock clock() {
		return Clock.systemUTC();
	}
}
