package com.example.secure_notes.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity // Asta spune Spring că aceasta este o tabelă SQL
@Table(name = "notes")
public class Note {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false, length = 5000) // Text mai lung
    private String content;

    // CRITIC PENTRU GRUPA 16: Aici vom stoca cine a scris notița.
    // Vom verifica acest câmp la fiecare citire pentru a bloca Anti-Goal-ul "Unauthorized Access".
    @Column(nullable = false)
    private String ownerUsername;

    private boolean isLocked = false; // Pentru cerința de editare exclusivă

    private LocalDateTime createdAt;

    // Constructor gol (obligatoriu pentru JPA)
    public Note() {}

    // Constructor util
    public Note(String title, String content, String ownerUsername) {
        this.title = title;
        this.content = content;
        this.ownerUsername = ownerUsername;
        this.createdAt = LocalDateTime.now();
    }

    // --- GETTERS și SETTERS (Generați automat sau manual) ---
    // Poți da Alt+Insert în IntelliJ -> Getter and Setter -> Select All -> OK

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getOwnerUsername() { return ownerUsername; }
    public void setOwnerUsername(String ownerUsername) { this.ownerUsername = ownerUsername; }

    public boolean isLocked() { return isLocked; }
    public void setLocked(boolean locked) { isLocked = locked; }

    public LocalDateTime getCreatedAt() { return createdAt; }
}