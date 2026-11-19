package com.example.security.common.login;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Duration;
import java.time.Instant;

@Entity
@Table(name = "login_attempt")
public class LoginAttempt {

	@Id
	private String email;
	private int failures;
	private Instant blockedUntil;

	protected LoginAttempt() {
	}

	boolean isBlocked(Instant now) {
		return blockedUntil != null && blockedUntil.isAfter(now);
	}

	void recordFailure(Instant now) {
		if (blockedUntil != null && !blockedUntil.isAfter(now)) {
			reset();
		}
		failures++;
		if (failures == 3) {
			blockedUntil = now.plus(Duration.ofMinutes(5));
		}
	}

	void reset() {
		failures = 0;
		blockedUntil = null;
	}

	public String getEmail() {
		return email;
	}

	public Instant getBlockedUntil() {
		return blockedUntil;
	}
}
