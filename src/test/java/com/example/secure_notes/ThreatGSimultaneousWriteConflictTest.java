package com.example.secure_notes;

import com.example.secure_notes.model.Note;
import com.example.secure_notes.repository.NoteRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Threat G: Achieve [SimultaneousWriteConflict]
 *
 * Scenario:
 * User A and User B open the same note.
 * User A saves.
 * User B saves shortly after, attempting to overwrite User A.
 *
 * Expected countermeasure:
 * Locking + access control prevents overwrite.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ThreatGSimultaneousWriteConflictTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private NoteRepository noteRepository;

    private Note sharedNote;

    @BeforeEach
    void setUp() {
        sharedNote = new Note();
        sharedNote.setOwnerUsername("alice");
        sharedNote.setTitle("Initial");
        sharedNote.setContent("Initial content");
        sharedNote.setCreatedAt(LocalDateTime.now());

        sharedNote.setLocked(false);
        sharedNote.setLockedBy(null);
        sharedNote.setLockedAt(null);

        sharedNote.addReadWriteUser("bob");
        sharedNote = noteRepository.saveAndFlush(sharedNote);
    }

    @Test
    @DisplayName("Threat G: Lock prevents simultaneous write conflict")
    void threatG_preventSimultaneousWriteConflict_withLocking() throws Exception {
        UUID id = sharedNote.getId();

        // 1. Alice opens edit -> acquires lock
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("note_form"));

        Note afterAliceEditOpen = noteRepository.findById(id).orElseThrow();
        assertTrue(afterAliceEditOpen.isLocked(), "Lock must be set when Alice opens edit");
        assertEquals("alice", afterAliceEditOpen.getLockedBy(), "Lock owner must be Alice");

        // 2. Alice saves -> update + release lock
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("alice").roles("USER"))
                        .with(csrf())
                        .param("title", "Alice title")
                        .param("content", "Alice content"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/notes/" + id));

        Note afterAliceSave = noteRepository.findById(id).orElseThrow();
        assertEquals("Alice title", afterAliceSave.getTitle());
        assertEquals("Alice content", afterAliceSave.getContent());
        assertFalse(afterAliceSave.isLocked(), "Lock must be released after save");
        assertNull(afterAliceSave.getLockedBy(), "Lock owner must be cleared");

        // 3. Bob tries to overwrite WITHOUT lock
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("bob").roles("USER"))
                        .with(csrf())
                        .param("title", "Bob overwrite attempt")
                        .param("content", "Bob overwrite attempt"))
                .andExpect(status().is3xxRedirection());

        Note finalNote = noteRepository.findById(id).orElseThrow();
        assertEquals("Alice title", finalNote.getTitle(), "Bob must not overwrite Alice's title");
        assertEquals("Alice content", finalNote.getContent(), "Bob must not overwrite Alice's content");
    }

    @Test
    @DisplayName("Threat G: User B cannot open edit while User A holds lock")
    void threatG_userBCannotOpenEditWhileUserAHoldsLock() throws Exception {
        UUID id = sharedNote.getId();

        // Alice acquires lock
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("note_form"));

        Note lockedNote = noteRepository.findById(id).orElseThrow();
        assertTrue(lockedNote.isLocked());
        assertEquals("alice", lockedNote.getLockedBy());

        // Bob attempts to open edit while locked
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("bob").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("note_view"))
                .andExpect(model().attributeExists("error"));

        Note afterBobAttempt = noteRepository.findById(id).orElseThrow();
        assertTrue(afterBobAttempt.isLocked(), "Lock must still be active");
        assertEquals("alice", afterBobAttempt.getLockedBy(), "Lock must still belong to Alice");
    }

    @Test
    @DisplayName("Threat G: Lock owner can successfully save")
    void threatG_lockOwnerCanSave() throws Exception {
        UUID id = sharedNote.getId();

        // Alice opens edit
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice").roles("USER")))
                .andExpect(status().isOk());

        // Alice saves while holding lock
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("alice").roles("USER"))
                        .with(csrf())
                        .param("title", "Updated by Alice")
                        .param("content", "New content"))
                .andExpect(status().is3xxRedirection());

        Note updated = noteRepository.findById(id).orElseThrow();
        assertEquals("Updated by Alice", updated.getTitle());
        assertEquals("New content", updated.getContent());
        assertFalse(updated.isLocked(), "Lock must be released after save");
    }
}
