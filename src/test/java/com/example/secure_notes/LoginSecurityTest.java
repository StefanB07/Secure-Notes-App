package com.example.secure_notes;

import com.example.secure_notes.model.User;
import com.example.secure_notes.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Security tests for login functionality.
 * Tests various attack vectors that could compromise the application.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        // Create a test user if not exists
        if (userRepository.findByUsername("testuser").isEmpty()) {
            User user = new User();
            user.setUsername("testuser");
            user.setPassword(passwordEncoder.encode("testpass123"));
            user.setRole("USER");
            userRepository.save(user);
        }
    }

    // ==================== LOGIN PAGE TESTS ====================

    @Test
    @DisplayName("Login page should be accessible without authentication")
    void loginPage_shouldBeAccessible() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    @DisplayName("Register page should be accessible without authentication")
    void registerPage_shouldBeAccessible() throws Exception {
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));
    }

    // ==================== SQL INJECTION ATTACKS ====================

    @Test
    @DisplayName("SQL Injection: OR 1=1 in username should fail")
    void sqlInjection_orAlwaysTrue_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "' OR '1'='1")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("SQL Injection: OR 1=1 with comment should fail")
    void sqlInjection_orWithComment_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "admin'--")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("SQL Injection: UNION SELECT attack should fail")
    void sqlInjection_unionSelect_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "' UNION SELECT * FROM users--")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("SQL Injection: DROP TABLE attempt should fail")
    void sqlInjection_dropTable_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "'; DROP TABLE users;--")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("SQL Injection: in password field should fail")
    void sqlInjection_inPassword_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser")
                        .password("password", "' OR '1'='1"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("SQL Injection: Stacked queries should fail")
    void sqlInjection_stackedQueries_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser'; INSERT INTO users VALUES (999,'hacker','hacked','ADMIN');--")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    // ==================== XSS ATTACKS ====================

    @Test
    @DisplayName("XSS: Script tag in username should fail login")
    void xss_scriptTagInUsername_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "<script>alert('xss')</script>")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("XSS: Event handler in username should fail login")
    void xss_eventHandlerInUsername_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "<img src=x onerror=alert('xss')>")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("XSS: JavaScript URI in username should fail login")
    void xss_javascriptUri_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "javascript:alert('xss')")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    // ==================== PATH TRAVERSAL / LDAP INJECTION ====================

    @Test
    @DisplayName("Path Traversal: Directory traversal in username should fail")
    void pathTraversal_inUsername_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "../../../etc/passwd")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("LDAP Injection: in username should fail")
    void ldapInjection_inUsername_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "*)(uid=*))(|(uid=*")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    // ==================== NULL BYTE / SPECIAL CHARACTERS ====================

    @Test
    @DisplayName("Null byte injection in username should fail")
    void nullByteInjection_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser\0admin")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Unicode/special characters in username should fail")
    void unicodeInjection_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "tëstüsér")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    // ==================== COMMAND INJECTION ====================

    @Test
    @DisplayName("Command injection: pipe command should fail")
    void commandInjection_pipe_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser | cat /etc/passwd")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Command injection: backticks should fail")
    void commandInjection_backticks_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "`cat /etc/passwd`")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    // ==================== AUTHENTICATION BYPASS ====================

    @Test
    @DisplayName("Empty username should fail")
    void emptyUsername_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "")
                        .password("password", "testpass123"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Empty password should fail")
    void emptyPassword_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser")
                        .password("password", ""))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Very long username should not crash application")
    void veryLongUsername_shouldNotCrash() throws Exception {
        String longUsername = "a".repeat(10000);
        mockMvc.perform(formLogin("/login")
                        .user("username", longUsername)
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Very long password should not crash application")
    void veryLongPassword_shouldNotCrash() throws Exception {
        String longPassword = "a".repeat(10000);
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser")
                        .password("password", longPassword))
                .andExpect(unauthenticated());
    }

    // ==================== VALID LOGIN (SANITY CHECK) ====================

    @Test
    @DisplayName("Valid credentials should succeed")
    void validCredentials_shouldSucceed() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser")
                        .password("password", "testpass123"))
                .andExpect(authenticated());
    }

    @Test
    @DisplayName("Wrong password should fail")
    void wrongPassword_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "testuser")
                        .password("password", "wrongpassword"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Non-existent user should fail")
    void nonExistentUser_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "nonexistentuser12345")
                        .password("password", "anything"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Case-sensitive username check")
    void caseSensitiveUsername_shouldFail() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "TESTUSER")
                        .password("password", "testpass123"))
                .andExpect(unauthenticated());
    }
}
