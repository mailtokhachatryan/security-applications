package com.example.security.mvc.admin;

import com.example.security.common.login.LoginAttemptRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@RestController
class BlockedUsersController {

	private final LoginAttemptRepository repository;
	private final Clock clock;

	BlockedUsersController(LoginAttemptRepository repository, Clock clock) {
		this.repository = repository;
		this.clock = clock;
	}

	@GetMapping("/admin/blocked-users")
	@Transactional(readOnly = true)
	List<BlockedUser> blockedUsers() {
		return repository.findByBlockedUntilAfterOrderByBlockedUntilAsc(clock.instant()).stream()
				.map(attempt -> new BlockedUser(attempt.getEmail(), attempt.getBlockedUntil())).toList();
	}

	record BlockedUser(String email, Instant blockedUntil) {
	}
}
