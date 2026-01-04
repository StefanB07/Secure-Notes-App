package com.example.secure_notes.repository;

import com.example.secure_notes.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // Spring generează automat codul SQL pentru metoda asta doar din numele ei!
    Optional<User> findByUsername(String username);
}