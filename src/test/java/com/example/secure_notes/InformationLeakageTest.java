package com.example.secure_notes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for Threat F: APIStructureKnown / InformationLeakage.
 * Verifies that internal details (e.g. exception messages, class names, SQL) are not leaked in error responses.
 */
@SpringBootTest
@AutoConfigureMockMvc
public class InformationLeakageTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Accessing non-existing note returns generic error without stack trace or internals")
    public void nonExistingNoteDoesNotLeakInternals() throws Exception {
        // Use a random UUID that should not exist
        String nonExistingId = "00000000-0000-0000-0000-000000000000";

        mockMvc.perform(get("/notes/" + nonExistingId)
                        .with(user("alice").password("password").roles("USER")))
                .andExpect(status().isForbidden())
                // Should show our generic error message, not a stack trace or internal exception
                .andExpect(content().string(containsString("You are not allowed to perform this action.")))
                .andExpect(content().string(not(containsString("java.lang"))))
                .andExpect(content().string(not(containsString("Stack trace"))))
                .andExpect(content().string(not(containsString("org.postgresql"))));
    }
}

