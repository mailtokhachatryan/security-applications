package com.example.security.mvc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"app.email=viewer@example.com", "app.password=testing-password-2026"})
@AutoConfigureMockMvc
class SecurityApplicationTest {

	@Autowired
	private MockMvc mvc;

	@Test
	void infoRequiresEmailAndPasswordAuthentication() throws Exception {
		mvc.perform(get("/info")).andExpect(status().isUnauthorized());
		mvc.perform(get("/info").with(httpBasic("viewer@example.com", "testing-password-2026")))
				.andExpect(status().isOk()).andExpect(jsonPath("$.application").value("MVC application"))
				.andExpect(jsonPath("$.activeUsers").isNumber());
	}
}
