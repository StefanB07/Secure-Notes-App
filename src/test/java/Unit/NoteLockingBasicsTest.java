package Unit;

import com.example.secure_notes.model.Note;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

public class NoteLockingBasicsTest {

    private Note noteOwnedBy(String owner) {
        Note n = new Note();
        n.setOwnerUsername(owner);
        n.setTitle("t");
        n.setContent("c");
        return n;
    }

    @Test
    void defaultUnlockedState() {
        Note note = noteOwnedBy("alice");
        assertFalse(note.isLocked());
        assertNull(note.getLockedBy());
        assertNull(note.getLockedAt());
    }

    @Test
    void lockAndUnlockFlow() {
        Note note = noteOwnedBy("alice");

        note.setLocked(true);
        note.setLockedBy("alice");
        note.setLockedAt(LocalDateTime.now());

        assertTrue(note.isLocked());
        assertEquals("alice", note.getLockedBy());

        note.setLocked(false);
        note.setLockedBy(null);
        note.setLockedAt(null);

        assertFalse(note.isLocked());
        assertNull(note.getLockedBy());
    }
}
