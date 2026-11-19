package com.example.security.secrets.secret;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
class SecretController {

	private final SecretService service;
	private final SecretSettings settings;

	SecretController(SecretService service, SecretSettings settings) {
		this.service = service;
		this.settings = settings;
	}

	@GetMapping("/")
	String home() {
		return "redirect:/secrets";
	}

	@GetMapping("/secrets")
	String form() {
		return "secret-form";
	}

	@PostMapping("/secrets")
	String create(@RequestParam String content, Model model) {
		String token = service.create(content);
		model.addAttribute("link", UriComponentsBuilder.fromUri(settings.publicBaseUrl())
				.pathSegment("secrets", token).build().toUriString());
		return "secret-link";
	}

	@GetMapping("/secrets/{token}")
	String preview(@PathVariable String token, Model model) {
		service.validateToken(token);
		model.addAttribute("token", token);
		return "secret-confirm";
	}

	@PostMapping("/secrets/{token}/reveal")
	String reveal(@PathVariable String token, Model model) {
		model.addAttribute("secret", service.consume(token));
		return "secret-reveal";
	}
}
