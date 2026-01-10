package com.example.secure_notes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureMockMvc
public class XssTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("XSS Payload should be escaped in HTML output")
    @WithMockUser(username = "tester", roles = "USER")
    public void testXssSanitization() throws Exception {


        String xssPayload = "<script>alert('XSS')</script>";

        mockMvc.perform(post("/notes")
                        .param("title", xssPayload)
                        .param("content", xssPayload)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        MvcResult result = mockMvc.perform(get("/notes"))
                .andExpect(status().isOk())
                .andReturn();

        String htmlResponse = result.getResponse().getContentAsString();

        assertThat(htmlResponse).doesNotContain(xssPayload);

        assertThat(htmlResponse).contains("&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;");
    }
}