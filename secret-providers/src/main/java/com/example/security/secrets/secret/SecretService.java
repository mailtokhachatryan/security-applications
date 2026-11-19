package com.example.security.secrets.secret;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

@Service
@Transactional(readOnly = true)
public class SecretService {

	private static final int MAX_LENGTH = 8192;
	private static final Pattern TOKEN_PATTERN = Pattern.compile("[A-Za-z0-9_-]{43}");
	private final SecureRandom random = new SecureRandom();
	private final SecretRepository repository;
	private final SecretCipher cipher;

	SecretService(SecretRepository repository, SecretCipher cipher) {
		this.repository = repository;
		this.cipher = cipher;
	}

	@Transactional
	public String create(String content) {
		if (content == null || content.isBlank() || content.length() > MAX_LENGTH) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Enter a secret of 1 to 8192 characters.");
		}
		byte[] bytes = new byte[32];
		random.nextBytes(bytes);
		String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		String hash = hash(token);
		repository.insert(hash, cipher.encrypt(content, hash));
		return token;
	}

	/** Consumes and decrypts a secret in one transaction, including concurrent requests. */
	@Transactional
	public String consume(String token) {
		String hash = hash(token);
		return repository.consume(hash).map(payload -> cipher.decrypt(payload, hash))
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Secret is unavailable."));
	}

	public void validateToken(String token) {
		if (token == null || !TOKEN_PATTERN.matcher(token).matches()) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Secret is unavailable.");
		}
	}

	private String hash(String token) {
		validateToken(token);
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII)));
		} catch (NoSuchAlgorithmException unavailable) {
			throw new IllegalStateException("SHA-256 is unavailable.", unavailable);
		}
	}
}
