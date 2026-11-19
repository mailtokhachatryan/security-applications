package com.example.security.common.login;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

public final class SecuritySupport {

	private SecuritySupport() {
	}

	public static HttpSecurity configure(HttpSecurity http, EmailAuthenticationProvider provider) throws Exception {
		return http.authenticationManager(new ProviderManager(provider))
				.formLogin(form -> form.loginPage("/login").usernameParameter("email")
						.defaultSuccessUrl("/", false).failureUrl("/login?error").permitAll())
				.logout(logout -> logout.logoutUrl("/sign-out").logoutSuccessUrl("/login?logout").permitAll())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
				.headers(headers -> headers.referrerPolicy(policy -> policy.policy(ReferrerPolicy.NO_REFERRER)))
				.exceptionHandling(exceptions -> exceptions
						.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
								new OrRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher("/info"),
										PathPatternRequestMatcher.withDefaults().matcher("/admin/**")))
						.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"), request -> true));
	}
}
