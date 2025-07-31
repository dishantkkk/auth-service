package com.saas.authservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class TestController {
    @GetMapping("/test")
    public String test() {
        return "Auth Service is working!";
    }
}
