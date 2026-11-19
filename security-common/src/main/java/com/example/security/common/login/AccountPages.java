package com.example.security.common.login;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
class AccountPages {

	@GetMapping("/login")
	String login() {
		return "login";
	}

	@GetMapping("/sign-out")
	String logout() {
		return "logout";
	}
}
