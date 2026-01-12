package com.example.secure_notes.config;

import com.example.secure_notes.model.User;
import com.example.secure_notes.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataLoader {

    @Bean
    CommandLineRunner initDatabase(UserRepository repo, PasswordEncoder encoder) {
        return args -> {
            // Helper method to add user only if not exists
            createUserIfNotExists(repo, encoder, "alice", "password", "USER");
            createUserIfNotExists(repo, encoder, "bob", "password", "USER");

            // new users can be added here according to this template
            // createUserIfNotExists(repo, encoder, "charlie", "pass123", "USER");
        };
    }

    private void createUserIfNotExists(UserRepository repo, PasswordEncoder encoder,
                                        String username, String password, String role) {
        if (repo.findByUsername(username).isEmpty()) {
            repo.save(new User(username, encoder.encode(password), role));
            System.out.println("--- USER CREATED: " + username + " ---");
        }
    }
}