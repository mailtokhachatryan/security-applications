package com.example.security.common.login;

import com.example.security.common.account.Account;
import com.example.security.common.account.AccountRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

@Component
public class EmailAuthenticationProvider implements AuthenticationProvider {

	private final AccountRepository accounts;
	private final LoginAttemptRepository attempts;
	private final PasswordEncoder encoder;
	private final Clock clock;
	private final String dummyPasswordHash;

	public EmailAuthenticationProvider(AccountRepository accounts, LoginAttemptRepository attempts,
			PasswordEncoder encoder, Clock clock) {
		this.accounts = accounts;
		this.attempts = attempts;
		this.encoder = encoder;
		this.clock = clock;
		this.dummyPasswordHash = encoder.encode(UUID.randomUUID().toString());
	}

	@Override
	@Transactional(noRollbackFor = AuthenticationException.class)
	public Authentication authenticate(Authentication authentication) {
		String email = authentication.getName().strip().toLowerCase(Locale.ROOT);
		if (email.isBlank() || email.length() > 254 || !email.contains("@")) {
			throw rejected();
		}
		attempts.ensureEmail(email);
		LoginAttempt attempt = attempts.lockEmail(email);
		Instant now = clock.instant();
		if (attempt.isBlocked(now)) {
			throw rejected();
		}
		Account account = accounts.findByEmail(email).orElse(null);
		String password = String.valueOf(authentication.getCredentials());
		String hash = account == null ? dummyPasswordHash : account.getPasswordHash();
		boolean matches = password.getBytes(StandardCharsets.UTF_8).length <= 72 && encoder.matches(password, hash);
		if (!matches || account == null) {
			attempt.recordFailure(now);
			throw rejected();
		}
		attempt.reset();
		User principal = new User(email, "", account.getPermissions().stream()
				.map(permission -> new SimpleGrantedAuthority(permission.name())).toList());
		return UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static BadCredentialsException rejected() {
		return new BadCredentialsException("Email or password is incorrect, or sign-in is temporarily blocked.");
	}
}
