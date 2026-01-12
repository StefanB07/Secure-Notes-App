
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
            // Verificăm dacă baza e goală ca să nu duplicăm userii la fiecare restart
            if (repo.count() == 0) {
                // User 1: Alice (parola: password)
                repo.save(new User("alice", encoder.encode("password"), "USER"));

                // User 2: Bob (parola: password)
                repo.save(new User("bob", encoder.encode("password"), "USER"));

                System.out.println("--- USERS CREATED: alice/password AND bob/password ---");
            }
        };
    }
}
