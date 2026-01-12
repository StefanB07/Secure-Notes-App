package com.example.secure_notes.controller;

import com.example.secure_notes.model.Note;
import com.example.secure_notes.repository.NoteRepository;
import com.example.secure_notes.repository.UserRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.AccessDeniedException;

import java.security.Principal;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/notes")
public class NoteController {

    private final NoteRepository noteRepository;
    private final UserRepository userRepository;

    /**
     * Lock lease duration. If a note stays locked longer than this without activity,
     * the lock is considered expired and can be taken by another authorized user.
     */
    private static final Duration LOCK_TIMEOUT = Duration.ofMinutes(3);

    public NoteController(NoteRepository noteRepository, UserRepository userRepository) {
        this.noteRepository = noteRepository;
        this.userRepository = userRepository;
    }

    // List all notes for current user (owned + shared)
    @GetMapping
    public String listNotes(Model model, Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }
        String username = principal.getName();

        // Get user's own notes
        List<Note> ownNotes = noteRepository.findByOwnerUsernameOrderByCreatedAtDesc(username);

        // Get notes shared with user (filter to ensure accurate match)
        List<Note> sharedNotes = noteRepository.findSharedWithUser(username)
                .stream()
                .filter(n -> n.canRead(username) && !n.isOwner(username))
                .collect(Collectors.toList());

        model.addAttribute("notes", ownNotes);
        model.addAttribute("sharedNotes", sharedNotes);
        return "notes";
    }

    // Show form to create a new note
    @GetMapping("/new")
    public String newNoteForm(Model model) {
        model.addAttribute("note", new Note());
        return "note_form";
    }

    // Handle create
    @PostMapping
    public String createNote(@ModelAttribute("note") Note note, BindingResult result, Principal principal) {
        if (result.hasErrors()) {
            return "note_form";
        }
        // Enforce ownership server-side (SECURITY: ignore any client-sent ownerUsername)
        note.setOwnerUsername(principal.getName());
        note.setCreatedAt(LocalDateTime.now());
        noteRepository.save(note);
        return "redirect:/notes";
    }

    // View a single note (owner or shared user)
    @GetMapping("/{id}")
    public String viewNote(@PathVariable("id") UUID id, Model model, Principal principal) {
        String username = principal.getName();
        Optional<Note> noteOpt = noteRepository.findById(id);

        if (noteOpt.isEmpty()) {
            throw new AccessDeniedException("Note not found");
        }

        Note note = noteOpt.get();

        if (!note.canRead(username)) {
            throw new AccessDeniedException("You do not have permission to view this note.");
        }

        model.addAttribute("note", note);
        model.addAttribute("isOwner", note.isOwner(username));
        model.addAttribute("canWrite", note.canWrite(username));
        return "note_view";
    }

    // Show edit form (respect lock)
    @GetMapping("/{id}/edit")
    public String editNoteForm(@PathVariable("id") UUID id, Model model, Principal principal) {
        String username = principal.getName();
        Optional<Note> noteOpt = noteRepository.findById(id);

        if (noteOpt.isEmpty()) {
            return "error/404";
        }

        Note note = noteOpt.get();

        // Security check: can user write to this note?
        if (!note.canWrite(username)) {
            return "error/404";
        }

        // Expire stale locks (prevents indefinite locking if a user closes tab / navigates away)
        if (note.isLocked() && note.getLockedAt() != null) {
            Duration age = Duration.between(note.getLockedAt(), LocalDateTime.now());
            if (age.compareTo(LOCK_TIMEOUT) > 0) {
                note.setLocked(false);
                note.setLockedBy(null);
                note.setLockedAt(null);
                noteRepository.save(note);
            }
        }

        // Check lock (after expiry logic)
        if (note.isLocked() && !username.equals(note.getLockedBy())) {
            model.addAttribute("error", "Notița este blocată de " + note.getLockedBy() + ". Încercați mai târziu.");
            model.addAttribute("note", note);
            model.addAttribute("isOwner", note.isOwner(username));
            model.addAttribute("canWrite", note.canWrite(username));
            return "note_view";
        }

        // Acquire/refresh lock
        note.setLocked(true);
        note.setLockedBy(username);
        note.setLockedAt(LocalDateTime.now());
        noteRepository.save(note);

        model.addAttribute("note", note);
        return "note_form";
    }

    // Handle update + release lock
    @PostMapping("/{id}")
    public String updateNote(@PathVariable("id") UUID id,
                             @ModelAttribute("note") Note updated,
                             BindingResult result,
                             Principal principal) {
        String username = principal.getName();
        Optional<Note> noteOpt = noteRepository.findById(id);

        if (noteOpt.isEmpty()) {
            return "error/404";
        }

        Note existing = noteOpt.get();

        // Security check: can user write?
        if (!existing.canWrite(username)) {
            return "error/404";
        }

        // Must hold lock to edit
        if (!existing.isLocked() || !username.equals(existing.getLockedBy())) {
            return "redirect:/notes/" + id;
        }

        if (result.hasErrors()) {
            return "note_form";
        }

        existing.setTitle(updated.getTitle());
        existing.setContent(updated.getContent());
        existing.setLocked(false);
        existing.setLockedBy(null);
        existing.setLockedAt(null);
        noteRepository.save(existing);

        return "redirect:/notes/" + id;
    }

    // Delete (owner only)
    @PostMapping("/{id}/delete")
    public String deleteNote(@PathVariable("id") UUID id, Principal principal) {
        String username = principal.getName();
        noteRepository.findByIdAndOwnerUsername(id, username)
                .ifPresent(noteRepository::delete);
        return "redirect:/notes";
    }

    // Show share form (owner only)
    @GetMapping("/{id}/share")
    public String shareNoteForm(@PathVariable("id") UUID id, Model model, Principal principal) {
        String username = principal.getName();
        Optional<Note> noteOpt = noteRepository.findByIdAndOwnerUsername(id, username);

        if (noteOpt.isEmpty()) {
            return "error/404";
        }

        Note note = noteOpt.get();
        model.addAttribute("note", note);

        // Get all users except owner for sharing dropdown
        var allUsers = userRepository.findAll()
                .stream()
                .filter(u -> !u.getUsername().equals(username))
                .collect(Collectors.toList());
        model.addAttribute("allUsers", allUsers);

        return "note_share";
    }

    // Handle adding share permission
    @PostMapping("/{id}/share")
    public String addSharePermission(@PathVariable("id") UUID id,
                                     @RequestParam("username") String targetUsername,
                                     @RequestParam("permission") String permission,
                                     Principal principal) {
        String username = principal.getName();
        Optional<Note> noteOpt = noteRepository.findByIdAndOwnerUsername(id, username);

        if (noteOpt.isEmpty()) {
            return "error/404";
        }

        Note note = noteOpt.get();

        // Validate target user exists
        if (userRepository.findByUsername(targetUsername).isEmpty()) {
            return "redirect:/notes/" + id + "/share?error=usernotfound";
        }

        // Add permission based on type
        if ("readonly".equals(permission)) {
            note.addReadOnlyUser(targetUsername);
        } else if ("readwrite".equals(permission)) {
            note.addReadWriteUser(targetUsername);
        }

        noteRepository.save(note);
        return "redirect:/notes/" + id + "/share?success";
    }

    // Remove share permission
    @PostMapping("/{id}/unshare")
    public String removeSharePermission(@PathVariable("id") UUID id,
                                        @RequestParam("username") String targetUsername,
                                        Principal principal) {
        String username = principal.getName();
        Optional<Note> noteOpt = noteRepository.findByIdAndOwnerUsername(id, username);

        if (noteOpt.isEmpty()) {
            return "error/404";
        }

        Note note = noteOpt.get();
        note.removeReadOnlyUser(targetUsername);
        note.removeReadWriteUser(targetUsername);
        noteRepository.save(note);

        return "redirect:/notes/" + id + "/share";
    }

    // Cancel edit (release lock without saving)
    @PostMapping("/{id}/cancel-edit")
    public String cancelEdit(@PathVariable("id") UUID id, Principal principal) {
        String username = principal.getName();
        Optional<Note> noteOpt = noteRepository.findById(id);

        if (noteOpt.isPresent()) {
            Note note = noteOpt.get();
            // Only release lock if current user holds it
            if (note.isLocked() && username.equals(note.getLockedBy())) {
                note.setLocked(false);
                note.setLockedBy(null);
                note.setLockedAt(null);
                noteRepository.save(note);
            }
        }

        return "redirect:/notes";
    }
}
