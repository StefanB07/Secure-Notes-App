package com.example.secure_notes;

import com.example.secure_notes.model.Note;
import com.example.secure_notes.repository.NoteRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

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
class ThreatGSimultaneousWriteConflictTest {

    @Autowired MockMvc mockMvc;
    @Autowired NoteRepository noteRepository;

    @Test
    void threatG_preventSimultaneousWriteConflict_withLocking() throws Exception {
        // Arrange: note owned by alice, shared read/write with bob
        Note note = new Note();
        note.setOwnerUsername("alice");
        note.setTitle("Initial");
        note.setContent("Initial content");
        note.setCreatedAt(LocalDateTime.now());
        note.addReadWriteUser("bob");
        note = noteRepository.save(note);

        UUID id = note.getId();

        // Step 1: User A opens edit -> acquires lock
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("note_form"));

        Note afterAliceEditOpen = noteRepository.findById(id).orElseThrow();
        assertTrue(afterAliceEditOpen.isLocked(), "Lock must be set when Alice opens edit");
        assertEquals("alice", afterAliceEditOpen.getLockedBy(), "Lock owner must be Alice");

        // Step 2: User A saves (POST /notes/{id}) -> update + release lock
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("alice"))
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

        // Step 3: User B tries to save "1 second later" WITHOUT holding lock
        // (Threat: overwrite Alice's work)
        mockMvc.perform(post("/notes/{id}", id)
                        .with(user("bob"))
                        .with(csrf())
                        .param("title", "Bob overwrite attempt")
                        .param("content", "Bob overwrite attempt"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/notes/" + id));

        // Assert: Bob did NOT overwrite Alice, because controller requires holding lock for update.
        Note finalNote = noteRepository.findById(id).orElseThrow();
        assertEquals("Alice title", finalNote.getTitle(), "Bob must not overwrite Alice's title");
        assertEquals("Alice content", finalNote.getContent(), "Bob must not overwrite Alice's content");
    }

    @Test
    void threatG_userBCannotEvenOpenEditWhileUserAHoldsLock() throws Exception {
        // Arrange
        Note note = new Note();
        note.setOwnerUsername("alice");
        note.setTitle("T");
        note.setContent("C");
        note.setCreatedAt(LocalDateTime.now());
        note.addReadWriteUser("bob");
        note = noteRepository.save(note);

        UUID id = note.getId();

        // Alice acquires lock by opening edit
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("note_form"));

        // Bob tries to open edit while locked -> should be blocked and shown note_view with an error
        mockMvc.perform(get("/notes/{id}/edit", id)
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("note_view"))
                .andExpect(model().attributeExists("error"));

        // Verify lock still belongs to Alice
        Note afterBobAttempt = noteRepository.findById(id).orElseThrow();
        assertTrue(afterBobAttempt.isLocked());
        assertEquals("alice", afterBobAttempt.getLockedBy());
    }
}
