package com.example.security.secrets.secret;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;

@ConfigurationProperties("secrets")
public record SecretSettings(URI publicBaseUrl, String encryptionKey) {

	public SecretSettings {
		if (publicBaseUrl == null || publicBaseUrl.getHost() == null || publicBaseUrl.getUserInfo() != null
				|| publicBaseUrl.getQuery() != null || publicBaseUrl.getFragment() != null
				|| !("http".equals(publicBaseUrl.getScheme()) || "https".equals(publicBaseUrl.getScheme()))) {
			throw new IllegalArgumentException("Configure an absolute HTTP or HTTPS secret provider base URL.");
		}
	}

	@Override
	public String toString() {
		return "SecretSettings[publicBaseUrl=" + publicBaseUrl + "]";
	}
}
