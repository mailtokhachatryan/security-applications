package com.example.security.mvc.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
class WebSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests(requests -> requests
				.requestMatchers("/about").permitAll()
				.anyRequest().authenticated())
				.formLogin(form -> form.usernameParameter("email").defaultSuccessUrl("/info", true))
				.httpBasic(Customizer.withDefaults())
				.build();
	}
}
