package com.example.springsecuritybasicauthentication.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/welcome")
public class WelcomeController
{
    @GetMapping("/")
    public String greet(Authentication authentication)
    {
        String username = authentication.getName();
        return "Spring Security Basic Authentication - Welcome: " + username;
    }
}
