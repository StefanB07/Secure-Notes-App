package com.example.secure_notes.controller;

import com.example.secure_notes.model.User;
import com.example.secure_notes.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Set;
import java.util.regex.Pattern;

@Controller
public class RegistrationController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Username: 3-20 chars, alphanumeric + underscore only (prevents SQL injection, XSS)
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,20}$");

    // Password: min 6 chars, max 100
    private static final int MIN_PASSWORD_LENGTH = 6;
    private static final int MAX_PASSWORD_LENGTH = 100;

    // Reserved usernames that cannot be registered (security + prevent confusion)
    private static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "administrator", "root", "system", "null", "undefined",
            "api", "login", "logout", "register", "notes", "user", "users",
            "anonymous", "guest", "test", "support", "help", "info"
    );

    public RegistrationController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/register")
    public String showRegistrationForm() {
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam("username") String username,
                               @RequestParam("password") String password,
                               @RequestParam("confirmPassword") String confirmPassword,
                               Model model) {

        // Trim whitespace
        username = username.trim();
        String usernameLower = username.toLowerCase();

        // Check for null/empty inputs
        if (username.isEmpty() || password.isEmpty()) {
            model.addAttribute("error", "Username and password are required.");
            return "register";
        }

        // Validate username format (security: prevents injection attacks)
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            model.addAttribute("error", "Username must be 3-20 characters, letters, numbers, and underscores only.");
            return "register";
        }

        // Check for reserved usernames
        if (RESERVED_USERNAMES.contains(usernameLower)) {
            model.addAttribute("error", "This username is reserved. Please choose another.");
            return "register";
        }

        // Validate password length
        if (password.length() < MIN_PASSWORD_LENGTH) {
            model.addAttribute("error", "Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
            model.addAttribute("username", username);
            return "register";
        }

        if (password.length() > MAX_PASSWORD_LENGTH) {
            model.addAttribute("error", "Password must be at most " + MAX_PASSWORD_LENGTH + " characters.");
            model.addAttribute("username", username);
            return "register";
        }

        // Check passwords match
        if (!password.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match.");
            model.addAttribute("username", username);
            return "register";
        }

        // Check if username already exists (case-insensitive check)
        if (userRepository.findByUsername(username).isPresent() ||
            userRepository.findByUsername(usernameLower).isPresent()) {
            model.addAttribute("error", "Username already exists. Please choose another.");
            return "register";
        }

        // Create and save new user (password is hashed with BCrypt)
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPassword(passwordEncoder.encode(password));
        newUser.setRole("USER");

        userRepository.save(newUser);

        // Redirect to log  in with success message
        return "redirect:/login?registered";
    }
}
