package com.example.securevault.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;

@Controller
public class AuthController {

    @PostMapping("/login")
    public String login(
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session) {

        if ("admin".equals(username) && "admin123".equals(password)) {
            session.setAttribute("user", username);
            return "redirect:/upload.html";
        }

        return "redirect:/login.html";
    }
    @GetMapping("/")
    public String home() {
        return "redirect:/login.html";
    }


    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login.html";
    }
}
