package com.example.secure_notes.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity // JPA entity mapped to SQL table
@Table(name = "notes")
public class Note {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false, length = 5000)
    private String content;

    // Owner username used for access control
    @Column(nullable = false)
    private String ownerUsername;

    // Simple lock to enforce exclusive editing
    private boolean isLocked = false;

    private String lockedBy; // username of locker

    private LocalDateTime lockedAt;

    private LocalDateTime createdAt;

    // Comma-separated usernames with read-only access
    @Column(length = 1000)
    private String sharedReadOnly = "";

    // Comma-separated usernames with read-write access
    @Column(length = 1000)
    private String sharedReadWrite = "";

    // Default constructor required by JPA
    public Note() {}

    public Note(String title, String content, String ownerUsername) {
        this.title = title;
        this.content = content;
        this.ownerUsername = ownerUsername;
        this.createdAt = LocalDateTime.now();
    }

    // Getters and setters

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getOwnerUsername() { return ownerUsername; }
    public void setOwnerUsername(String ownerUsername) { this.ownerUsername = ownerUsername; }

    public boolean isLocked() { return isLocked; }
    public void setLocked(boolean locked) { isLocked = locked; }

    public String getLockedBy() { return lockedBy; }
    public void setLockedBy(String lockedBy) { this.lockedBy = lockedBy; }

    public LocalDateTime getLockedAt() { return lockedAt; }
    public void setLockedAt(LocalDateTime lockedAt) { this.lockedAt = lockedAt; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public String getSharedReadOnly() { return sharedReadOnly; }
    public void setSharedReadOnly(String sharedReadOnly) { this.sharedReadOnly = sharedReadOnly; }

    public String getSharedReadWrite() { return sharedReadWrite; }
    public void setSharedReadWrite(String sharedReadWrite) { this.sharedReadWrite = sharedReadWrite; }

    // --- Access control helpers ---

    public boolean canRead(String username) {
        if (username.equals(ownerUsername)) return true;
        if (sharedReadOnly != null && containsUser(sharedReadOnly, username)) return true;
        if (sharedReadWrite != null && containsUser(sharedReadWrite, username)) return true;
        return false;
    }

    public boolean canWrite(String username) {
        if (username.equals(ownerUsername)) return true;
        if (sharedReadWrite != null && containsUser(sharedReadWrite, username)) return true;
        return false;
    }

    public boolean isOwner(String username) {
        return username.equals(ownerUsername);
    }

    private boolean containsUser(String list, String username) {
        if (list == null || list.isBlank()) return false;
        String[] users = list.split(",");
        for (String u : users) {
            if (u.trim().equalsIgnoreCase(username)) return true;
        }
        return false;
    }

    public void addReadOnlyUser(String username) {
        if (!containsUser(sharedReadOnly, username) && !username.equals(ownerUsername)) {
            // Ensure user is not in read-write list
            removeReadWriteUser(username);
            if (sharedReadOnly == null || sharedReadOnly.isBlank()) {
                sharedReadOnly = username;
            } else {
                sharedReadOnly = sharedReadOnly + "," + username;
            }
        }
    }

    public void addReadWriteUser(String username) {
        if (!containsUser(sharedReadWrite, username) && !username.equals(ownerUsername)) {
            // Ensure user is not in read-only list
            removeReadOnlyUser(username);
            if (sharedReadWrite == null || sharedReadWrite.isBlank()) {
                sharedReadWrite = username;
            } else {
                sharedReadWrite = sharedReadWrite + "," + username;
            }
        }
    }

    public void removeReadOnlyUser(String username) {
        if (sharedReadOnly != null) {
            sharedReadOnly = removeFromList(sharedReadOnly, username);
        }
    }

    public void removeReadWriteUser(String username) {
        if (sharedReadWrite != null) {
            sharedReadWrite = removeFromList(sharedReadWrite, username);
        }
    }

    private String removeFromList(String list, String username) {
        if (list == null || list.isBlank()) return "";
        String[] users = list.split(",");
        StringBuilder sb = new StringBuilder();
        for (String u : users) {
            if (!u.trim().equalsIgnoreCase(username)) {
                if (sb.length() > 0) sb.append(",");
                sb.append(u.trim());
            }
        }
        return sb.toString();
    }
}