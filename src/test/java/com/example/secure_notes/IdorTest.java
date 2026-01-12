package com.example.secure_notes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
public class IdorTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("User Bob should NOT be able to see or edit Alice's note")
    public void testIdorProtection() throws Exception {

        // 1. Alice creates a note
        mockMvc.perform(post("/notes")
                        .with(user("Alice").roles("USER"))
                        .param("title", "Alice Secret")
                        .param("content", "My private data")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        // 2. Get the ID of that note
        MvcResult dashboardResult = mockMvc.perform(get("/notes")
                        .with(user("Alice").roles("USER")))
                .andExpect(status().isOk())
                .andReturn();

        String html = dashboardResult.getResponse().getContentAsString();
        Pattern pattern = Pattern.compile("href=\"/notes/([a-f0-9\\-]+)\"");
        Matcher matcher = pattern.matcher(html);

        if (!matcher.find()) {
            throw new RuntimeException("Could not find note ID. Is the table empty?");
        }

        String noteId = matcher.group(1); // <--- Defined here
        String targetUrl = "/notes/" + noteId;
        System.out.println("Target Note URL: " + targetUrl);

        // 3. Verify Bob cannot READ the note (Existing check)
        mockMvc.perform(get(targetUrl)
                        .with(user("Bob").roles("USER")))
                .andExpect(status().isForbidden());

        // --- NEW CHECK ADDED HERE ---
        // 4. Verify Bob cannot EDIT the note (New check for Threat H)
        mockMvc.perform(get(targetUrl + "/edit")
                        .with(user("Bob").roles("USER")))
                .andExpect(status().isOk())            // Expect 200 OK (page rendered)
                .andExpect(view().name("error/404"));  // Expect the specific error view
    }
}