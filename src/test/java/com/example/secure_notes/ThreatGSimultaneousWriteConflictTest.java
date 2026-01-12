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
 * Scenario: User A and User B open the same note.
 * User A saves. User B saves shortly after, overwriting User A's work.
 *
 * Countermeasure expected: locking / concurrency control prevents B from overwriting while A holds lock.
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
        // Create a note owned by alice, shared read/write with bob
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

        // Step 1: Alice opens edit -> acquires lock
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice").password("pass").roles("USER"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("note_form"));

        // Verify lock is set
        Note afterAliceEditOpen = noteRepository.findById(id).orElseThrow();
        assertTrue(afterAliceEditOpen.isLocked(), "Lock must be set when Alice opens edit");
        assertEquals("alice", afterAliceEditOpen.getLockedBy(), "Lock owner must be Alice");

        // Step 2: Alice saves -> update + release lock
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("alice").password("pass").roles("USER"))
                        .with(csrf())
                        .param("title", "Alice title")
                        .param("content", "Alice content"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/notes/" + id));

        Note afterAliceSave = noteRepository.findById(id).orElseThrow();
        assertEquals("Alice title", afterAliceSave.getTitle(), "Alice save must persist");
        assertEquals("Alice content", afterAliceSave.getContent(), "Alice save must persist");
        assertFalse(afterAliceSave.isLocked(), "Lock should be released after Alice saves");
        assertNull(afterAliceSave.getLockedBy(), "Lock owner cleared after save");

        // Step 3: Bob tries to save WITHOUT holding lock (simulating race condition attack)
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("bob").password("pass").roles("USER"))
                        .with(csrf())
                        .param("title", "Bob overwrite attempt")
                        .param("content", "Bob overwrite attempt"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/notes/" + id));

        // Assert: Bob did NOT overwrite Alice, because controller requires holding lock for update
        Note finalNote = noteRepository.findById(id).orElseThrow();
        assertEquals("Alice title", finalNote.getTitle(), "Bob must not overwrite Alice's title");
        assertEquals("Alice content", finalNote.getContent(), "Bob must not overwrite Alice's content");
    }

    @Test
    @DisplayName("Threat G: User B cannot open edit while User A holds lock")
    void threatG_userBCannotOpenEditWhileUserAHoldsLock() throws Exception {
        UUID id = sharedNote.getId();

        // Alice acquires lock by opening edit
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice").password("pass").roles("USER"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("note_form"));

        // Verify lock is set by Alice
        Note lockedNote = noteRepository.findById(id).orElseThrow();
        assertTrue(lockedNote.isLocked());
        assertEquals("alice", lockedNote.getLockedBy());

        // Bob tries to open edit while locked -> should be blocked and shown note_view with error
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("bob").password("pass").roles("USER"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("note_view"))
                .andExpect(model().attributeExists("error"));

        // Verify lock still belongs to Alice (Bob didn't steal it)
        Note afterBobAttempt = noteRepository.findById(id).orElseThrow();
        assertTrue(afterBobAttempt.isLocked(), "Lock must still be active");
        assertEquals("alice", afterBobAttempt.getLockedBy(), "Lock must still belong to Alice");
    }

    @Test
    @DisplayName("Threat G: Lock owner can successfully save")
    void threatG_lockOwnerCanSave() throws Exception {
        UUID id = sharedNote.getId();

        // Alice opens edit (acquires lock)
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice").password("pass").roles("USER"))
                        .with(csrf()))
                .andExpect(status().isOk());

        // Alice saves while holding lock - should succeed
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("alice").password("pass").roles("USER"))
                        .with(csrf())
                        .param("title", "Updated by Alice")
                        .param("content", "New content"))
                .andExpect(status().is3xxRedirection());

        // Verify changes persisted
        Note updated = noteRepository.findById(id).orElseThrow();
        assertEquals("Updated by Alice", updated.getTitle());
        assertEquals("New content", updated.getContent());
        assertFalse(updated.isLocked(), "Lock released after save");
    }
}

