# KAOS Security Requirements Engineering Report
**Group:** 16
**Methodology:** KAOS (Knowledge Acquisition in autOmated Specification)
**Application:** Secure Notes App

## 1. Introduction
This document defines the security requirements for the Secure Notes Application using the Anti-Model construction method described by van Lamsweerde. We proceed by defining legitimate System Goals, deriving malicious Anti-Goals (Attacker Intents), refining these into Threat Trees, and finally selecting Countermeasures (Security Requirements).

---

## 2. Confidentiality Goals (User Isolation)

### 2.1 The System Goal
**Goal:** `Avoid [NoteContentKnownByUnauthorizedUser]`
**Formal Pattern:** `Avoid [SensitiveInfoKnownByUnauthorizedAgent]`
**Definition:** For any Note `n` and User `u`, if `u` is not the owner of `n` (and `n` is not shared with `u`), then `u` shall not know `n.content`.

### 2.2 The Anti-Model (Attacker Intent)
**Anti-Goal:** `Achieve [NoteContentKnownByUnauthorizedUser]`
**Attacker:** Malicious User / External Hacker.

#### Threat Tree Refinement:
How can the attacker achieve this?
1.  **Threat A:** `Achieve [AccessNoteByGuessingID]`
    * **Vulnerability:** The system uses predictable, sequential IDs (e.g., `/notes/1`, `/notes/2`).
    * **Attacker Capability:** The attacker can iterate through integers to access resources they don't own.
2.  **Threat B:** `Achieve [AccessNoteBySQLInjection]`
    * **Vulnerability:** User input is concatenated directly into SQL queries.
    * **Attacker Capability:** Inject SQL fragments to bypass ownership checks (e.g., `' OR '1'='1`).
3.  **Threat C:** `Achieve [AccessNoteBySessionHijacking]`
    * **Vulnerability:** Session IDs are exposed or predictable.

### 2.3 Derived Countermeasures
To resolve these threats, we introduce the following Security Requirements:

* **Countermeasure 1 (Protects against Threat A):** `Avoid [PredictableResourceIDs]`
    * **Implementation:** Use **UUIDs** (Universally Unique Identifiers) for all Note primary keys instead of auto-incrementing integers.
    * *Spring Boot:* Use `@GeneratedValue(strategy = GenerationType.UUID)` in the Note entity.

* **Countermeasure 2 (Protects against Threat B):** `Avoid [UnsanitizedDatabaseInput]`
    * **Implementation:** Use Parameterized Queries or an ORM that handles escaping.
    * *Spring Boot:* Use **Spring Data JPA** (Repository pattern) which automatically sanitizes inputs.

* **Countermeasure 3 (Protects against Threat C):** `Maintain [SecureSessionManagement]`
    * **Implementation:** Enforce strict session handling.
    * *Spring Boot:* Use **Spring Security** with HTTP-Only cookies and default session protection.

---

## 3. Integrity Goals (Concurrency & Locking)

### 3.1 The System Goal
**Goal:** `Maintain [NoteContentChangeOnlyIfLockedAndAuthorized]`
**Formal Pattern:** `Maintain [ObjectInfoChangeOnlyIfCorrectAndAuthorized]`
**Definition:** A Note `n` can only be updated by User `u` if `u` has write permissions AND `n` is currently locked by `u`.

### 3.2 The Anti-Model
**Anti-Goal:** `Achieve [NoteOverwrittenByConcurrentEdit]`
**Attacker:** A second legitimate user (or race condition exploit).

#### Threat Tree Refinement:
1.  **Threat D:** `Achieve [SimultaneousWriteConflict]`
    * **Scenario:** User A and User B open the same note. User A saves. User B saves 1 second later, overwriting User A's work.
    * **Vulnerability:** Lack of concurrency control or locking mechanism.

### 3.3 Derived Countermeasures
* **Countermeasure 4 (Protects against Threat D):** `Achieve [ApplicationLevelLocking]`
    * **Implementation:** Implement a "Locked Mode" where a user must acquire a lock before editing.
    * *Logic:*
        1. User requests "Edit Mode" -> Server checks `isLocked`.
        2. If `false`, set `isLocked=true`, `lockedBy=User`, `lockedAt=Now`.
        3. If `true` (and different user), deny access.
        4. Unlock on save or timeout.

---

## 4. Availability Goals (Resilient Storage)

### 4.1 The System Goal
**Goal:** `Achieve [NoteAccessWhenNeeded]`
**Formal Pattern:** `Achieve [ObjectInfoUsableWhenNeededAndAuthorized]`
**Definition:** Authorized users must be able to retrieve their notes even if a primary storage node fails.

### 4.2 The Anti-Model
**Anti-Goal:** `Achieve [NoteServiceUnavailable]`
**Attacker:** DoS Attacker or Physical Infrastructure Failure.

#### Threat Tree Refinement:
1.  **Threat E:** `Achieve [StorageNodeFailure]`
    * **Vulnerability:** The system relies on a single database instance (`db-master`). If this container stops, data is inaccessible.

### 4.3 Derived Countermeasures
* **Countermeasure 5 (Protects against Threat E):** `Maintain [DataReplication]`
    * **Implementation:** Deploy a secondary database node (`db-replica`) that replicates data from the master.
    * *Docker Setup:* Update `docker-compose.yml` to include a generic PostgreSQL replication setup or a secondary mock node to demonstrate architecture compliance.

---

## 5. Summary of Security Requirements (To-Do List)

| ID | Requirement | KAOS Justification | Implementation Status |
|----|------------|--------------------|-----------------------|
| **SR-1** | Use UUIDs for Note IDs | Counteracts `AccessNoteByGuessingID` | Pending               |
| **SR-2** | Spring Data JPA | Counteracts `AccessNoteBySQLInjection` | Pending               |
| **SR-3** | Spring Security Config | Counteracts `NoteContentKnownByUnauthorizedUser` | Pending               |
| **SR-4** | Note Locking Mechanism | Counteracts `SimultaneousWriteConflict` | Pending               |
| **SR-5** | Database Replication | Counteracts `StorageNodeFailure` | Pending               |


```mermaid
graph TD
%% --- STYLING (Black & White KAOS Style) ---
%% White background, black lines, black text
    classDef default fill:#fff,stroke:#000,stroke-width:1px,color:#000;
    classDef boldBorder fill:#fff,stroke:#000,stroke-width:3px,color:#000;
    classDef dashed fill:#fff,stroke:#000,stroke-width:1px,stroke-dasharray: 5 5,color:#000;

%% --- ROOT ANTI-GOAL ---
%% Bold border to represent the initial anti-goal
    AG_Root[/Achieve NoteContentKnownByUnauthorizedUser/]:::boldBorder

%% --- THREATS (Refinements) ---
    AG_Guess[/Threat A: AccessNoteByGuessingID/]
    AG_SQL[/Threat B: AccessNoteBySQLInjection/]
    AG_Hijack[/Threat C: AccessNoteBySessionHijacking/]

%% Connect Root to Threats
    AG_Root --> AG_Guess
    AG_Root --> AG_SQL
    AG_Root --> AG_Hijack

%% --- VULNERABILITIES (Leaf Nodes) ---
%% Represented as Pentagons ("House" shape)
    Vuln_SeqID{{Vulnerability: Sequential IDs}}
    Vuln_Concat{{Vulnerability: Concatenated SQL Input}}
    Vuln_Sess{{Vulnerability: Exposed Session IDs}}

    AG_Guess --> Vuln_SeqID
    AG_SQL --> Vuln_Concat
    AG_Hijack --> Vuln_Sess

%% --- COUNTERMEASURES ---
%% Dashed lines indicating resolution
    CM_UUID[/Req: Avoid PredictableResourceIDs/]:::dashed
    CM_JPA[/Req: Avoid UnsanitizedDatabaseInput/]:::dashed
    CM_Sec[/Req: Maintain SecureSessionManagement/]:::dashed

    CM_UUID -. resolves .-> Vuln_SeqID
    CM_JPA -. resolves .-> Vuln_Concat
    CM_Sec -. resolves .-> Vuln_Sess
```


```mermaid
graph TD
%% --- STYLING (Black & White KAOS Style) ---
classDef default fill:#fff,stroke:#000,stroke-width:1px,color:#000;
classDef boldBorder fill:#fff,stroke:#000,stroke-width:3px,color:#000;
classDef dashed fill:#fff,stroke:#000,stroke-width:1px,stroke-dasharray: 5 5,color:#000;

    %% --- ROOT ANTI-GOAL ---
    AG_Root[/Achieve NoteOverwrittenByConcurrentEdit/]:::boldBorder

    %% --- THREATS ---
    AG_Conflict[/Threat D: Achieve SimultaneousWriteConflict/]

    %% Connect Root to Threat
    AG_Root --> AG_Conflict

    %% --- VULNERABILITIES ---
    Vuln_Lock{{Vulnerability: Lack of Concurrency Control}}

    AG_Conflict --> Vuln_Lock

    %% --- COUNTERMEASURES ---
    CM_Lock[/Req: Achieve ApplicationLevelLocking/]:::dashed

    CM_Lock -. resolves .-> Vuln_Lock
```

```mermaid
graph TD
    %% --- STYLING (Black & White KAOS Style) ---
    classDef default fill:#fff,stroke:#000,stroke-width:1px,color:#000;
    classDef boldBorder fill:#fff,stroke:#000,stroke-width:3px,color:#000;
    classDef dashed fill:#fff,stroke:#000,stroke-width:1px,stroke-dasharray: 5 5,color:#000;

    %% --- ROOT ANTI-GOAL ---
    AG_Root[/Achieve NoteServiceUnavailable/]:::boldBorder

    %% --- THREATS ---
    AG_Fail[/Threat E: Achieve StorageNodeFailure/]

    %% Connect Root to Threat
    AG_Root --> AG_Fail

    %% --- VULNERABILITIES ---
    Vuln_SPOF{{Vulnerability: Single Database Instance}}

    AG_Fail --> Vuln_SPOF

    %% --- COUNTERMEASURES ---
    CM_Repl[/Req: Maintain DataReplication/]:::dashed

    CM_Repl -. resolves .-> Vuln_SPOF
```