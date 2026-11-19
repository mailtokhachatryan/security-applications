package com.example.security.secrets.secret;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
class SecretRepository {

	private final JdbcClient jdbc;

	SecretRepository(JdbcClient jdbc) {
		this.jdbc = jdbc;
	}

	void insert(String tokenHash, byte[] payload) {
		jdbc.sql("INSERT INTO secret (token_hash, encrypted_payload) VALUES (:hash, :payload)")
				.param("hash", tokenHash).param("payload", payload).update();
	}

	Optional<byte[]> consume(String tokenHash) {
		// DELETE RETURNING allows exactly one reader to obtain the stored payload.
		return jdbc.sql("DELETE FROM secret WHERE token_hash = :hash RETURNING encrypted_payload")
				.param("hash", tokenHash).query((result, row) -> result.getBytes("encrypted_payload")).optional();
	}
}
