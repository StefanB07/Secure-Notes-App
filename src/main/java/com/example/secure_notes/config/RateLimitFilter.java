package com.example.secure_notes.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitFilter implements Filter {

    private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 100;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String clientIp = req.getRemoteAddr();

        requestCounts.putIfAbsent(clientIp, new AtomicInteger(0));
        int requests = requestCounts.get(clientIp).incrementAndGet();

        if (requests > MAX_REQUESTS_PER_MINUTE) {
            res.setStatus(429);
            res.getWriter().write("Rate limit exceeded");
            return;
        }

        chain.doFilter(request, response);
    }
}