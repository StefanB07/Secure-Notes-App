
package com.example.secure_notes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
public class RateLimitTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Should block user after too many login attempts")
    public void testRateLimit() throws Exception {

        int blockedCount = 0;
        int successCount = 0;

        for (int i = 0; i < 50; i++) {

            MvcResult result = mockMvc.perform(post("/login")
                            .with(csrf())
                            .param("username", "admin")
                            .param("password", "wrongpassword")
                            .header("X-Forwarded-For", "192.168.1.100"))
                    .andReturn();

            int status = result.getResponse().getStatus();

            if (status == 429) {
                blockedCount++;
            } else {
                successCount++;
            }
        }

        System.out.println("TEST REPORT: " + successCount + " Allowed, " + blockedCount + " Blocked.");

        if (blockedCount == 0) {
            throw new AssertionError("Security Fail: The application never blocked the brute force attack!");
        }
    }
}
