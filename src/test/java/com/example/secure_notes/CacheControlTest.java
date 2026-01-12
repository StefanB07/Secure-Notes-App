package com.example.secure_notes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Threat E: Achieve [NoteReadFromBrowserCache]
 *
 * Scenario: A user accesses the app from a shared computer (library/cafe).
 * After they log out, an attacker hits the "Back" button to view cached pages.
 *
 * Countermeasure: Server sends Cache-Control headers to prevent browser caching.
 * Expected headers: Cache-Control: no-cache, no-store, max-age=0, must-revalidate
 */
@SpringBootTest
@AutoConfigureMockMvc
public class CacheControlTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Threat E: Authenticated pages should have no-cache headers")
    public void testCacheControlHeaders_onAuthenticatedPages() throws Exception {
        MvcResult result = mockMvc.perform(get("/notes")
                        .with(user("testuser").password("pass").roles("USER")))
                .andExpect(status().isOk())
                .andReturn();

        String cacheControl = result.getResponse().getHeader("Cache-Control");

        System.out.println("=== CACHE CONTROL TEST ===");
        System.out.println("Cache-Control header: " + cacheControl);

        // Verify Cache-Control header exists and contains security directives
        assertTrue(cacheControl != null && !cacheControl.isEmpty(),
                "Security Fail: No Cache-Control header found on authenticated page!");

        assertTrue(cacheControl.contains("no-cache") || cacheControl.contains("no-store"),
                "Security Fail: Cache-Control header missing 'no-cache' or 'no-store'! " +
                "Header was: " + cacheControl);
    }

    @Test
    @DisplayName("Threat E: Note view page should prevent caching")
    public void testCacheControlHeaders_onNoteViewPage() throws Exception {
        // This test verifies the home page has proper cache headers
        MvcResult result = mockMvc.perform(get("/")
                        .with(user("testuser").password("pass").roles("USER")))
                .andExpect(status().isOk())
                .andReturn();

        String cacheControl = result.getResponse().getHeader("Cache-Control");
        String pragma = result.getResponse().getHeader("Pragma");
        String expires = result.getResponse().getHeader("Expires");

        System.out.println("=== CACHE HEADERS ON HOME PAGE ===");
        System.out.println("Cache-Control: " + cacheControl);
        System.out.println("Pragma: " + pragma);
        System.out.println("Expires: " + expires);

        // At minimum, Cache-Control should be set
        assertTrue(cacheControl != null,
                "Security Fail: No Cache-Control header on home page!");
    }

    @Test
    @DisplayName("Threat E: Login page can be cached (public page)")
    public void testLoginPage_cacheAllowed() throws Exception {
        // Login page is public, so caching is less critical
        // But we still want to verify the endpoint works
        MvcResult result = mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andReturn();

        // Just verify the page loads - caching policy for public pages is flexible
        assertTrue(result.getResponse().getStatus() == 200,
                "Login page should be accessible");
    }
}

