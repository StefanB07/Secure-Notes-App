# KAOS Security Requirements – Continuation

This continuation document adds complementary KAOS goals, anti-goals, and countermeasures that are *implemented in the current code base* but are not (or only partially) captured in `KAOS.md`.

It is meant to be an **annex**: you can selectively copy useful fragments into your main KAOS report.

---

## 1. Ownership‑Enforced Access Control (Per‑User Isolation)

### 1.1 New System Goal
**Goal G6:** `Maintain [NoteAccessibleOnlyToOwnerOrAuthorizedUser]`  
**Pattern:** `Maintain [ObjectInfoAccessibleOnlyToAuthorizedAgents]`

**Informal definition:** For any Note `n` and User `u`, `u` may access `n` (read or write) only if one of the following holds:

- `u.username == n.ownerUsername`, or
- `u` has been granted explicit sharing rights to `n` (read-only or read-write).

### 1.2 Refined Threats / Anti-Goals

**Anti‑Goal AG6:** `Achieve [NoteAccessWithoutAuthorizationCheck]`  
Attacker: Logged‑in malicious user.

Threat refinements:

1. **Threat F:** `Achieve [DirectURLAccessToForeignNote]`
   - **Vulnerability:** Controller fetches notes *only by ID* (e.g. `findById(...)`) without verifying the owner or share permissions.
   - **Scenario:** Attacker is authenticated as user `uA` and tries `/notes/{idOfUserBNote}`.

2. **Threat G:** `Achieve [BypassOwnershipViaControllerBug]`
   - **Vulnerability:** The controller receives a `Note` object from a form and trusts its `ownerUsername` field.
   - **Scenario:** Attacker tampers HTML form / request body, sets `ownerUsername = 'victim'`, thereby stealing ownership.

### 1.3 Countermeasures / Requirements

**SR‑6:** `Maintain [RepositoryOwnershipFiltering]`  
**Resolves:** Threat F, partially Threat G.

- **Implementation:** All data access for individual notes must verify ownership or valid share permissions.
- **Code hooks:**
  - `NoteRepository.findByOwnerUsernameOrderByCreatedAtDesc(String ownerUsername)`
  - `NoteRepository.findByIdAndOwnerUsername(UUID id, String ownerUsername)`
  - `Note.canRead(username)` and `Note.canWrite(username)` helper methods
  - `NoteController` **always** calls these methods using `principal.getName()`.

**SR‑7:** `Avoid [ClientControlledOwnershipField]`  
**Resolves:** Threat G.

- **Implementation rule:** The server must **ignore** any `ownerUsername` received from the client and override it with the authenticated user.
- **Code hooks:**
  - In `NoteController.createNote(...)`:
    - `note.setOwnerUsername(principal.getName());` (ownership set on server side).
  - In `NoteController.updateNote(...)`:
    - Ownership is not taken from `updated`; only title and content are copied.

**Traceability:**  
`G6` ← resolved by { `SR‑6`, `SR‑7` } which are concretely realized by the `NoteRepository` and `NoteController` code paths.

---

## 2. Strengthened Locking Semantics

`KAOS.md` already defines Countermeasure 4 (`ApplicationLevelLocking`). The current codebase refines this with concrete semantics.

### 2.1 Refined Goal

**Goal G7:** `Maintain [NoteEditedOnlyWhileLockedByEditor]`  
**Pattern:** `Maintain [ObjectInfoChangeOnlyIfPreconditionHolds]`

**Definition:** A Note `n` can only be modified (write operation) by user `u` if `n.isLocked == true` and `n.lockedBy == u.username` at the time of saving.

### 2.2 New Threats

**Anti‑Goal AG7:** `Achieve [NoteModifiedWithoutLock]`  
Attacker: Legitimate user or automation script.

Threats:

1. **Threat H:** `Achieve [POSTUpdateWithoutLockAcquisition]`
   - **Scenario:** Attacker forges an HTTP POST directly to `/notes/{id}` without following the UI's edit flow.
   - **Vulnerability:** The server doesn't verify lock ownership before persisting updates.

2. **Threat I:** `Achieve [LockStolenDuringEdit]`
   - **Scenario:** User A acquires a lock. User B somehow obtains or forges a request that tricks the server into thinking B holds the lock.

### 2.3 Countermeasures / Requirements

**SR‑8:** `Maintain [ServerSideLockVerificationOnUpdate]`  
**Resolves:** Threat H.

- **Implementation:** Before any update, the server must load the existing note from the database and verify that:
  - `existing.isLocked == true` and
  - `existing.lockedBy.equals(currentUsername)`.
- **Code hooks:**
  - `NoteController.updateNote(...)`:
    ```java
    if (!existing.isLocked() || !username.equals(existing.getLockedBy())) {
        return "redirect:/notes/" + id;
    }
    ```

**SR‑9:** `Maintain [ExclusiveLockAcquisitionOnEditRequest]`  
**Resolves:** Threat I, supports G7.

- **Implementation:** When a user requests `/notes/{id}/edit`, the server:
  1. Fetches the note only if user has write permissions.
  2. If `note.isLocked` and `note.lockedBy != currentUser`, denies edit and returns a read‑only view with an error.
  3. If not locked, sets `isLocked = true`, `lockedBy = currentUser`, and `lockedAt = now`.
- **Code hooks:**
  - `NoteController.editNoteForm(...)`:
    - Lock conflict check and error message.
    - Lock acquisition and `noteRepository.save(note)`.

**SR‑10:** `Achieve [LockReleaseOnSuccessfulSave]`  
**Resolves:** Part of AG7, improves system availability for concurrent editors.

- **Implementation:** After a successful update, the lock must be released so others can edit later.
- **Code hooks:**
  - `NoteController.updateNote(...)`:
    ```java
    existing.setLocked(false);
    existing.setLockedBy(null);
    existing.setLockedAt(null);
    ```

---

## 3. Authentication & Password Handling Refinements

`KAOS.md` already defines SR‑3 around "Secure Session Management" at a high level. The current implementation adds more concrete measures.

### 3.1 New/Refined Goals

**Goal G8:** `Maintain [PasswordStoredOnlyAsIrreversibleHash]`  
**Pattern:** `Maintain [ConfidentialDataStoredOnlyInDerivedForm]`

### 3.2 Refined Threats

**Anti‑Goal AG8:** `Achieve [PlaintextPasswordDisclosureFromDB]`  
Attacker: DB admin or data breach adversary.

**Threat J:** `Achieve [PasswordStoredInClear]`  
- **Vulnerability:** Passwords stored as plain text or weakly encoded form.

### 3.3 Countermeasures / Requirements

**SR‑11:** `Maintain [PasswordHashingWithStrongAlgorithm]`  
**Resolves:** Threat J.

- **Implementation:** Use a strong, adaptive one‑way hash algorithm (BCrypt) for all stored passwords.
- **Code hooks:**
  - `SecurityConfig.passwordEncoder()` returns `new BCryptPasswordEncoder()`.
  - `DataLoader` uses `encoder.encode("password")` when creating `alice` and `bob`.
  - `CustomUserDetailsService` passes the hashed password to Spring Security which compares hashes only.

Trace:  
`G8` ← resolved by `SR‑11` realized via `SecurityConfig`, `DataLoader`, `CustomUserDetailsService`.

---

## 4. Sharing & Access Control (Read-Only vs Read-Write)

### 4.1 New System Goal

**Goal G9:** `Maintain [NoteSharedOnlyByOwnerWithExplicitPermissions]`  
**Pattern:** `Maintain [AccessControlDelegationOnlyByResourceOwner]`

**Definition:** Only the owner of a Note `n` can grant or revoke sharing permissions. Shared users receive either read-only or read-write access as explicitly specified.

### 4.2 Anti-Goals / Threats

**Anti‑Goal AG9:** `Achieve [UnauthorizedSharingModification]`  
Attacker: Non-owner user with shared access.

Threats:

1. **Threat K:** `Achieve [SharedUserModifiesShareList]`
   - **Scenario:** User B has read-write access to note owned by A. User B tries to POST to `/notes/{id}/share` to add User C.
   - **Vulnerability:** Share endpoints don't verify ownership.

2. **Threat L:** `Achieve [ReadOnlyUserEditsNote]`
   - **Scenario:** User B has read-only access. User B forges POST to `/notes/{id}` to update content.
   - **Vulnerability:** Update endpoint only checks if user can read, not write.

3. **Threat M:** `Achieve [SharedUserDeletesNote]`
   - **Scenario:** User B has read-write access. User B tries to delete the note.
   - **Vulnerability:** Delete endpoint doesn't enforce owner-only restriction.

### 4.3 Countermeasures / Requirements

**SR‑12:** `Maintain [ShareManagementRestrictedToOwner]`  
**Resolves:** Threat K.

- **Implementation:** All share/unshare endpoints must verify that `currentUser == note.ownerUsername`.
- **Code hooks:**
  - `NoteController.shareNoteForm(...)` uses `findByIdAndOwnerUsername(id, username)`
  - `NoteController.addSharePermission(...)` uses `findByIdAndOwnerUsername(id, username)`
  - `NoteController.removeSharePermission(...)` uses `findByIdAndOwnerUsername(id, username)`

**SR‑13:** `Maintain [WriteOperationsRequireWritePermission]`  
**Resolves:** Threat L.

- **Implementation:** Before any update operation, verify `note.canWrite(currentUsername)` returns true.
- **Code hooks:**
  - `NoteController.editNoteForm(...)`: checks `note.canWrite(username)`
  - `NoteController.updateNote(...)`: checks `existing.canWrite(username)`

**SR‑14:** `Maintain [DeleteRestrictedToOwner]`  
**Resolves:** Threat M.

- **Implementation:** Delete operations must verify ownership, not just write access.
- **Code hooks:**
  - `NoteController.deleteNote(...)` uses `findByIdAndOwnerUsername(id, username)`

**SR‑15:** `Maintain [ShareTargetUserValidation]`  
**Resolves:** Privilege escalation via non-existent user injection.

- **Implementation:** Before adding a share permission, verify the target user exists in the database.
- **Code hooks:**
  - `NoteController.addSharePermission(...)`:
    ```java
    if (userRepository.findByUsername(targetUsername).isEmpty()) {
        return "redirect:/notes/" + id + "/share?error=usernotfound";
    }
    ```

---

## 5. KAOS Summary – Additional Requirements

This table extends the one in `KAOS.md` with the new requirements introduced here.

| ID     | Requirement                                  | KAOS Link / Rationale                                  | Implementation Status |
|--------|----------------------------------------------|--------------------------------------------------------|-----------------------|
| SR‑6   | Repository‑level ownership filtering         | Resolves `AccessNoteWithoutOwnerCheck` (Threat F)      | **Implemented**       |
| SR‑7   | Ignore client‑controlled `ownerUsername`     | Resolves `OwnershipTampering` (Threat G)               | **Implemented**       |
| SR‑8   | Verify lock holder on every update          | Resolves `POSTUpdateWithoutLock` (Threat H)            | **Implemented**       |
| SR‑9   | Exclusive lock acquisition on edit request  | Resolves `LockStolenDuringEdit` (Threat I)             | **Implemented**       |
| SR‑10  | Release lock on successful save             | Supports integrity & availability after edits          | **Implemented**       |
| SR‑11  | BCrypt password hashing                      | Resolves `PasswordStoredInClear` (Threat J)            | **Implemented**       |
| SR‑12  | Share management restricted to owner         | Resolves `SharedUserModifiesShareList` (Threat K)      | **Implemented**       |
| SR‑13  | Write operations require write permission    | Resolves `ReadOnlyUserEditsNote` (Threat L)            | **Implemented**       |
| SR‑14  | Delete restricted to owner                   | Resolves `SharedUserDeletesNote` (Threat M)            | **Implemented**       |
| SR‑15  | Share target user validation                 | Prevents privilege escalation via invalid users        | **Implemented**       |

These entries can be merged into the main `KAOS.md` as an update, or kept here as evidence that the current implementation is aligned with KAOS‑style reasoning.
