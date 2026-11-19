package com.example.security.mvc.stats;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;

@RestController
class StatsController {

	private final SecureRandom random = new SecureRandom();
	private final Clock clock;

	StatsController(Clock clock) {
		this.clock = clock;
	}

	@GetMapping("/info")
	Stats info() {
		return new Stats("MVC application", random.nextInt(1000), clock.instant());
	}

	record Stats(String application, int activeUsers, Instant generatedAt) {
	}

	record ApplicationInfo(String application) {
	}
}
