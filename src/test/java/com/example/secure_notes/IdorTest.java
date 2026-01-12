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

@SpringBootTest
@AutoConfigureMockMvc
public class IdorTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("User Bob should NOT be able to see Alice's note")
    public void testIdorProtection() throws Exception {

        mockMvc.perform(post("/notes")
                        .with(user("Alice").roles("USER"))
                        .param("title", "Alice Secret")
                        .param("content", "My private data")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

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

        String noteId = matcher.group(1);
        String targetUrl = "/notes/" + noteId;
        System.out.println("Target Note URL: " + targetUrl);

        mockMvc.perform(get(targetUrl)
                        .with(user("Bob").roles("USER")))
                .andExpect(status().isForbidden());
    }
}