package com.example.secure_notes.model;

import jakarta.persistence.*;

@Entity
@Table(name = "users") // 'user' e cuvânt rezervat în PostgreSQL, deci folosim 'users'
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password; // Aici va fi hash-ul parolei, nu parola în clar!

    private String role; // Ex: "USER", "ADMIN"

    // Constructor gol
    public User() {}

    // Constructor util
    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    // Getters și Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}