package com.example.security.common.login;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, String> {

	@Modifying
	@Query(value = "INSERT INTO login_attempt (email) VALUES (:email) ON CONFLICT (email) DO NOTHING", nativeQuery = true)
	void ensureEmail(@Param("email") String email);

	@Query(value = "SELECT * FROM login_attempt WHERE email = :email FOR UPDATE", nativeQuery = true)
	LoginAttempt lockEmail(@Param("email") String email);

	List<LoginAttempt> findByBlockedUntilAfterOrderByBlockedUntilAsc(Instant now);
}
