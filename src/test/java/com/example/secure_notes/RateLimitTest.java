package com.example.secure_notes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Threat K: Achieve [ServiceFlooded] (DoS)
 *
 * Tests that the RateLimitFilter blocks excessive requests from a single IP.
 * Current limit: 100 requests per minute per IP.
 */
@SpringBootTest
@AutoConfigureMockMvc
public class RateLimitTest {

    @Autowired
    private MockMvc mockMvc;

    // Must match RateLimitFilter.MAX_REQUESTS_PER_MINUTE
    private static final int RATE_LIMIT = 100;

    @Test
    @DisplayName("Threat K: Should block user after exceeding rate limit")
    public void testRateLimit_blocksAfterExceedingLimit() throws Exception {
        // Use a unique IP for this test to avoid interference from other tests
        String testIp = "10.99.99." + System.currentTimeMillis() % 255;

        int blockedCount = 0;
        int allowedCount = 0;

        // Send more requests than the limit
        int totalRequests = RATE_LIMIT + 20;

        for (int i = 0; i < totalRequests; i++) {
            MvcResult result = mockMvc.perform(post("/login")
                            .with(csrf())
                            .param("username", "testuser")
                            .param("password", "wrongpassword")
                            .header("X-Forwarded-For", testIp))
                    .andReturn();

            int status = result.getResponse().getStatus();

            if (status == 429) {
                blockedCount++;
            } else {
                allowedCount++;
            }
        }

        System.out.println("=== RATE LIMIT TEST REPORT ===");
        System.out.println("Total requests: " + totalRequests);
        System.out.println("Allowed: " + allowedCount);
        System.out.println("Blocked (429): " + blockedCount);
        System.out.println("Expected blocked: ~" + (totalRequests - RATE_LIMIT));

        // Verify that some requests were blocked
        assertTrue(blockedCount > 0,
                "Security Fail: Rate limiting did not block any requests! " +
                        "Expected at least " + (totalRequests - RATE_LIMIT) + " blocked.");

        // Verify that allowed requests are approximately equal to the limit
        assertTrue(allowedCount <= RATE_LIMIT + 1,
                "Security Fail: More requests allowed than the rate limit! " +
                        "Allowed: " + allowedCount + ", Limit: " + RATE_LIMIT);
    }

    @Test
    @DisplayName("Threat K: Different IPs should have separate rate limits")
    public void testRateLimit_separateLimitsPerIP() throws Exception {
        String ip1 = "10.88.1." + System.currentTimeMillis() % 255;
        String ip2 = "10.88.2." + System.currentTimeMillis() % 255;

        // Send 50 requests from IP1
        for (int i = 0; i < 50; i++) {
            mockMvc.perform(post("/login")
                    .with(csrf())
                    .param("username", "user1")
                    .param("password", "wrong")
                    .header("X-Forwarded-For", ip1));
        }

        // IP2 should still be allowed (not affected by IP1's requests)
        MvcResult result = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", "user2")
                        .param("password", "wrong")
                        .header("X-Forwarded-For", ip2))
                .andReturn();

        int status = result.getResponse().getStatus();
        assertTrue(status != 429,
                "Security Fail: IP2 was blocked due to IP1's requests! Rate limits should be per-IP.");
    }
}