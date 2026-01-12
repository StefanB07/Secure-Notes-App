package com.example.secure_notes.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class RateLimitFilter implements Filter {

    private static final Map<String, UserRequestState> requestCounts = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 100;
    private static final long TIME_WINDOW_MS = 60 * 1000;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String clientIp = req.getHeader("X-Forwarded-For");
        if (clientIp == null || clientIp.isEmpty()) {
            clientIp = req.getRemoteAddr();
        }

        // Initialize state if new user
        requestCounts.putIfAbsent(clientIp, new UserRequestState());
        UserRequestState state = requestCounts.get(clientIp);

        long currentTime = System.currentTimeMillis();

        if (currentTime - state.lastResetTime.get() > TIME_WINDOW_MS) {
            state.lastResetTime.set(currentTime);
            state.requestCount.set(0);
        }

        int requests = state.requestCount.incrementAndGet();

        if (requests > MAX_REQUESTS_PER_MINUTE) {
            res.setStatus(429);
            res.getWriter().write("Rate limit exceeded. Try again later.");
            return;
        }

        chain.doFilter(request, response);
    }

    private static class UserRequestState {
        final AtomicInteger requestCount = new AtomicInteger(0);
        final AtomicLong lastResetTime = new AtomicLong(System.currentTimeMillis());
    }
}