
package com.example.secure_notes.security;

import com.example.secure_notes.model.Note;
import com.example.secure_notes.model.User;
import com.example.secure_notes.repository.NoteRepository;
import com.example.secure_notes.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional // Rolls back DB changes after each test
public class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private NoteRepository noteRepository;

    @Autowired
    private UserRepository userRepository;

    private Note aliceNote;

    @BeforeEach
    void setup() {
        // Ensure users exist (DataLoader might have run, but we ensure cleanliness)
        if(userRepository.findByUsername("alice").isEmpty()) {
            userRepository.save(new User("alice", "pass", "USER"));
        }
        if(userRepository.findByUsername("bob").isEmpty()) {
            userRepository.save(new User("bob", "pass", "USER"));
        }
        if(userRepository.findByUsername("mallory").isEmpty()) {
            userRepository.save(new User("mallory", "pass", "USER"));
        }

        // Alice creates a note
        aliceNote = new Note("Alice's Secrets", "Top Secret Content", "alice");
        noteRepository.save(aliceNote);
    }


    // Testează prevenirea IDOR (Insecure Direct Object Reference): Verifică faptul că utilizatorul "Bob"
    // primește o eroare (403/404) atunci când încearcă să citească o notă care aparține lui "Alice",
    // chiar dacă ghicește ID-ul corect.
    @Test
    @WithMockUser(username = "bob")
    void testIDOR_BobCannotReadAliceNote() throws Exception {
        // Bob tries to GET /notes/{aliceNoteId}
        mockMvc.perform(get("/notes/" + aliceNote.getId()))
                // Your controller returns "error/404" view to prevent leaking existence
                .andExpect(view().name("error/404"));
    }


    // Testează protecția la scriere/editare: Asigură că un utilizator neautorizat nu poate accesa
    // formularul de editare al unei note străine, garantând astfel izolarea datelor între utilizatori.
    @Test
    @WithMockUser(username = "bob")
    void testIDOR_BobCannotEditAliceNote() throws Exception {
        // Bob tries to GET /notes/{id}/edit
        mockMvc.perform(get("/notes/" + aliceNote.getId() + "/edit"))
                .andExpect(view().name("error/404"));
    }
}
