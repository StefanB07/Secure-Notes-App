package com.example.secure_notes.repository;

import com.example.secure_notes.model.Note;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface NoteRepository extends JpaRepository<Note, UUID> {
    List<Note> findByOwnerUsernameOrderByCreatedAtDesc(String ownerUsername);

    Optional<Note> findByIdAndOwnerUsername(UUID id, String ownerUsername);

    // Find notes shared with a user (read-only or read-write)
    @Query("SELECT n FROM Note n WHERE n.sharedReadOnly LIKE %:username% OR n.sharedReadWrite LIKE %:username%")
    List<Note> findSharedWithUser(@Param("username") String username);
}