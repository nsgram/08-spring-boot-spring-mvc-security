package com.capgemini.springboot.demosecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
	
	@GetMapping("/showMyLoginPage")
	public String getLoginPage() {
		//return "plain-login";
		return "fancy-login";
	}
	@GetMapping("/access-denied")
	public String getAccessDeniedPage() {
		return "access-denied";
	}

}
