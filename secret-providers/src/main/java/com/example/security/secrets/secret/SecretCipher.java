package com.example.security.secrets.secret;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

@Component
class SecretCipher {

	private static final int IV_BYTES = 12;
	private final SecureRandom random = new SecureRandom();
	private final SecretKeySpec key;

	SecretCipher(SecretSettings settings) {
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(settings.encryptionKey());
		} catch (IllegalArgumentException | NullPointerException invalidKey) {
			throw new IllegalArgumentException("SECRET_ENCRYPTION_KEY must be a Base64-encoded 32-byte key.");
		}
		if (decoded.length != 32) {
			throw new IllegalArgumentException("SECRET_ENCRYPTION_KEY must decode to 32 bytes.");
		}
		this.key = new SecretKeySpec(decoded, "AES");
	}

	byte[] encrypt(String content, String tokenHash) {
		byte[] iv = new byte[IV_BYTES];
		random.nextBytes(iv);
		byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, iv, content.getBytes(StandardCharsets.UTF_8), tokenHash);
		return ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array();
	}

	String decrypt(byte[] payload, String tokenHash) {
		if (payload.length < IV_BYTES + 16) {
			throw new IllegalStateException("Stored secret is invalid.");
		}
		ByteBuffer buffer = ByteBuffer.wrap(payload);
		byte[] iv = new byte[IV_BYTES];
		buffer.get(iv);
		byte[] ciphertext = new byte[buffer.remaining()];
		buffer.get(ciphertext);
		return new String(crypt(Cipher.DECRYPT_MODE, iv, ciphertext, tokenHash), StandardCharsets.UTF_8);
	}

	private byte[] crypt(int mode, byte[] iv, byte[] content, String tokenHash) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(mode, key, new GCMParameterSpec(128, iv));
			cipher.updateAAD(tokenHash.getBytes(StandardCharsets.US_ASCII));
			return cipher.doFinal(content);
		} catch (GeneralSecurityException failure) {
			throw new IllegalStateException("Secret encryption operation failed.", failure);
		}
	}
}
