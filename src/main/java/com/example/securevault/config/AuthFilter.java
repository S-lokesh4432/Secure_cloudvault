package com.example.securevault.config;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component
public class AuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        HttpSession session = request.getSession(false);

        // Allow login page, login action, css, root
        if (
            path.equals("/") ||
            path.equals("/login.html") ||
            path.equals("/login") ||
            path.startsWith("/css")
        ) {
            filterChain.doFilter(request, response);
            return;
        }

        // 🔒 Block everything else if not logged in
        if (session == null || session.getAttribute("user") == null) {
            response.sendRedirect("/login.html");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
