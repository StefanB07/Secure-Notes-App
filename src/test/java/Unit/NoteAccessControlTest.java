package Unit;

import com.example.secure_notes.model.Note;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class NoteAccessControlTest {

    private Note newOwnedNote(String owner) {
        Note n = new Note();
        n.setOwnerUsername(owner);
        n.setTitle("t");
        n.setContent("c");
        return n;
    }

    @Test
    void ownerHasReadAndWrite() {
        Note note = newOwnedNote("alice");
        assertTrue(note.canRead("alice"));
        assertTrue(note.canWrite("alice"));
        assertTrue(note.isOwner("alice"));
    }

    @Test
    void unknownUserHasNoAccess() {
        Note note = newOwnedNote("alice");
        assertFalse(note.canRead("bob"));
        assertFalse(note.canWrite("bob"));
    }

    @Test
    void readOnlyUserCanReadButNotWrite() {
        Note note = newOwnedNote("alice");
        note.addReadOnlyUser("bob");

        assertTrue(note.canRead("bob"));
        assertFalse(note.canWrite("bob"));
    }

    @Test
    void readWriteUserCanReadAndWrite() {
        Note note = newOwnedNote("alice");
        note.addReadWriteUser("bob");

        assertTrue(note.canRead("bob"));
        assertTrue(note.canWrite("bob"));
    }

    @Test
    void addingReadOnlyRemovesFromReadWrite() {
        Note note = newOwnedNote("alice");
        note.addReadWriteUser("bob");
        note.addReadOnlyUser("bob");

        assertTrue(note.canRead("bob"));
        assertFalse(note.canWrite("bob"));
        assertEquals("bob", note.getSharedReadOnly());
        assertTrue(note.getSharedReadWrite() == null || note.getSharedReadWrite().isBlank());
    }

    @Test
    void addingReadWriteRemovesFromReadOnly() {
        Note note = newOwnedNote("alice");
        note.addReadOnlyUser("bob");
        note.addReadWriteUser("bob");

        assertTrue(note.canRead("bob"));
        assertTrue(note.canWrite("bob"));
        assertEquals("bob", note.getSharedReadWrite());
        assertTrue(note.getSharedReadOnly() == null || note.getSharedReadOnly().isBlank());
    }

    @Test
    void duplicateAddsAreIgnored() {
        Note note = newOwnedNote("alice");
        note.addReadOnlyUser("bob");
        note.addReadOnlyUser("bob"); // duplicate
        assertEquals("bob", note.getSharedReadOnly());

        note.addReadWriteUser("carol");
        note.addReadWriteUser("carol"); // duplicate
        assertEquals("carol", note.getSharedReadWrite());
    }

    @Test
    void removeUsersFromLists() {
        Note note = newOwnedNote("alice");
        note.addReadOnlyUser("bob");
        note.addReadOnlyUser("carol");
        note.addReadWriteUser("dave");
        note.addReadWriteUser("erin");

        note.removeReadOnlyUser("carol");
        note.removeReadWriteUser("dave");

        assertTrue(note.canRead("bob"));
        assertFalse(note.canRead("carol"));
        assertTrue(note.canWrite("erin"));
        assertFalse(note.canWrite("dave"));
    }

    @Test
    void caseInsensitiveUserMatch() {
        Note note = newOwnedNote("alice");
        note.addReadWriteUser("BoB");
        assertTrue(note.canWrite("bob"));
        assertTrue(note.canWrite("BOB"));
    }

    @Test
    void ownerCannotBeAddedToShareLists() {
        Note note = newOwnedNote("alice");
        note.addReadOnlyUser("alice");
        note.addReadWriteUser("alice");

        assertTrue(note.getSharedReadOnly() == null || note.getSharedReadOnly().isBlank());
        assertTrue(note.getSharedReadWrite() == null || note.getSharedReadWrite().isBlank());
    }
}
