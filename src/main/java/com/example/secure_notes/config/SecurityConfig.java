package com.example.secure_notes.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/css/**").permitAll() // Lăsăm liber la înregistrare și stiluri
                        .anyRequest().authenticated() // Orice altceva cere login
                )
                .formLogin(form -> form
                        .defaultSuccessUrl("/", true) // După login, du-ne pe Home
                        .permitAll()
                )
                .logout(logout -> logout.permitAll());

        return http.build();
    }

    // Algoritmul de criptare (Standardul industriei)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}