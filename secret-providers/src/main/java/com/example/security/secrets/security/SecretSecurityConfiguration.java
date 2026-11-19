package com.example.security.secrets.security;

import com.example.security.common.login.EmailAuthenticationProvider;
import com.example.security.common.login.SecuritySupport;
import com.example.security.secrets.secret.SecretSettings;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecretSettings.class)
class SecretSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, EmailAuthenticationProvider provider) throws Exception {
		return SecuritySupport.configure(http, provider)
				.authorizeHttpRequests(requests -> requests
						.requestMatchers("/login", "/assets/**", "/error").permitAll()
						.anyRequest().hasAuthority("STANDARD"))
				.build();
	}
}
