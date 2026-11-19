package com.example.security.secrets;

import com.example.security.common.SharedSecurityConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import(SharedSecurityConfiguration.class)
public class SecretProvidersApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecretProvidersApplication.class, args);
	}
}
