package com.example.security.mvc.security;

import com.example.security.common.login.EmailAuthenticationProvider;
import com.example.security.common.login.SecuritySupport;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
class WebSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, EmailAuthenticationProvider provider) throws Exception {
		return SecuritySupport.configure(http, provider)
				.authorizeHttpRequests(requests -> requests
						.requestMatchers("/about", "/login", "/assets/**", "/error").permitAll()
						.requestMatchers("/info").hasAuthority("VIEW_INFO")
						.requestMatchers("/admin", "/admin/**").hasAuthority("VIEW_ADMIN")
						.anyRequest().authenticated())
				.build();
	}
}
