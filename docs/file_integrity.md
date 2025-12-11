# File Integrity Module (`file_integrity.py`)

A cryptographically secure anti-tamper subsystem within the ClearSight Anti-Cheat framework.  
This module enforces file integrity verification, self-integrity protection, baseline hashing, and tamper-aware termination logic.

---

# Overview  

The File Integrity Checker performs the following functions:

- Creates an encrypted and digitally signed baseline of known-good file hashes  
- Verifies baseline integrity using RSA-PSS  
- Derives its AES-GCM encryption key from RSA private key material (no hardcoded secrets)  
- Verifies the anti-cheat module’s own integrity using a persistent self-integrity baseline  
- Detects new, modified, or missing game files  
- Detects debugger attachment (optional DEV_MODE bypass)  
- Uses a honeyfile trap to detect broad sweeping tampering  
- Logs all events using `[INFO]`, `[WARNING]`, `[ERROR]`, and `[FATAL]` levels  

When a validated tamper event is detected, the module triggers a simulated forced game termination recorded under `[FATAL]`.

---

# Baseline Architecture

Two independent baselines are maintained:

1. **Self-Integrity Baseline**  
   Stored as:
   - `ClearSight/data/baseline/self_integrity.bin`
   - `ClearSight/data/baseline/self_integrity.sig`

   Contains a SHA-256 hash of the anti-cheat module itself (`game.py` or your designated module file).  
   Any mismatch indicates the anti-cheat was modified.

2. **File-Integrity Baseline**  
   Stored as:
   - `ClearSight/data/hashes.json.enc`  
   - `ClearSight/data/hashes.json.sig`

   Contains SHA-256 hashes of game files inside `GAME_DIRECTORY`, excluding folders and extensions specified in `EXCLUDED_FOLDERS` and `EXCLUDED_EXTENSIONS`.

Both baselines must be deleted if the folder structure or monitored files change during development.

---

# Directory and Path Design

By default:

- `GAME_DIRECTORY` points to the main game folder  
- Honeyfile is stored at `GAME_DIRECTORY/honeypot.dat`  
- Self-integrity baseline is stored inside `ClearSight/data/baseline`  
- File-integrity baseline is stored inside `ClearSight/data/`  

This organization ensures:

- Game assets remain separate from anti-cheat assets  
- Baseline files cannot be mistaken for regular game content  
- Paths remain predictable for encryption, signing, and verification

---

# Self-Integrity System

The module protects itself through:

1. SHA-256 hashing of the anti-cheat source file  
2. Storing that hash in `self_integrity.bin`  
3. Signing it with RSA-PSS  
4. Verifying the signature and current hash every run

If the file has changed:

- In production: `[FATAL] FI-SI-002 Anti-cheat module has been modified!`  
- In DEV_MODE: a warning is logged and the baseline is automatically rebuilt

---

# File-Integrity System

The module hashes all valid game files under `GAME_DIRECTORY`.  
Files are ignored if they appear in:

- `EXCLUDED_FOLDERS` (e.g., `ClearSight`, `__pycache__`, `.git`)  
- `EXCLUDED_EXTENSIONS` (e.g., `.tmp`, `.log`, `.cache`)  

The resulting mapping of `{ path: sha256 }` is:

- Serialized into JSON  
- Encrypted with AES-256-GCM  
- Signed with RSA-PSS  

On subsequent runs:

- Baseline signature is verified  
- Baseline is decrypted  
- Current file hashes are compared to stored values  
- Any changes trigger a termination event

---

# Honeyfile System

A special tripwire file named `honeypot.dat` is placed at the root of `GAME_DIRECTORY`.

Rules:

- The game never touches this file  
- The anti-cheat expects it to exist and remain unchanged  
- If deleted, modified, or replaced → integrity violation  

This quickly detects mass-editing cheats or cleanup scripts used by malicious tools.

---

# Debugger Detection

The system checks for both:

- Python-level debuggers (via `sys.gettrace()`)  
- Native Windows debuggers (via `IsDebuggerPresent`)  

In production, debugger presence triggers:

```py
[CRITICAL] [FI-DBG-001] Debugger detected.
```

In DEV_MODE, the debugger event becomes:

```py
[WARNING] Debugger detected, but ignoring because DEV_MODE is enabled.
```

This allows debugging without disabling security entirely.

---

# AES Key Derivation

To avoid storing plaintext secrets, the AES key is derived from RSA private key internals.

Process:

1. Load `private_key.pem`  
2. Extract integer components (`d`, `p`, `q`)  
3. Hash them together using SHA-256  
4. Run PBKDF2-HMAC-SHA256 to derive a 256-bit AES key  
5. Use AES-GCM with a random 96-bit nonce for encryption/decryption

This ensures that:

- Only the correct private key can decrypt the baseline  
- Tampering with the key invalidates the entire system  
- No passwords appear in source code or config files

---

# Logging System

The module uses four severity levels:

- `[INFO]` — Normal operations  
- `[WARNING]` — Suspicious or DEV_MODE-bypassed behavior  
- `[ERROR]` — Non-fatal integrity or configuration issues  
- `[CRITICAL]` — Guaranteed game termination events

Example `[CRITICAL]` entry:

```py
2025-12-11 12:41:22,118 [FILE_INTEGRITY] [CRITICAL] [FI-INT-001]
Terminating simulated game process (PID=4211) — Reason: Integrity violation detected.
```

All logs are written to:

```
ClearSight/logs/file_integrity.log
```

Folders are automatically created if missing.

---

# Integrity Violation Codes

The module uses standardized event codes:

| Code         | Meaning |
|--------------|---------|
| FI-KEY-001   | Missing RSA private key |
| FI-SI-001    | Self-integrity signature invalid |
| FI-SI-002    | Anti-cheat module modified |
| FI-BL-001    | Baseline signature invalid |
| FI-BL-002    | Baseline decryption failed |
| FI-HF-001    | Honeyfile missing/modified |
| FI-DBG-001   | Debugger detected |
| FI-INT-001   | Integrity violation detected |
| FI-INT-002   | Missing game files |
| FI-INT-003   | Unexpected new files |

These codes simplify debugging and external monitoring.

---

# Development Workflow

During development:

- Enable `DEV_MODE = True`  
- Modify code freely  
- Baselines auto-regenerate  
- Debuggers are ignored  
- Termination events become non-blocking

Before production:

- Disable `DEV_MODE`  
- Regenerate final baselines  
- Protect key files and folders from modification  

---

# Runtime Flow

<img width="1766" height="1084" alt="image" src="https://github.com/user-attachments/assets/df7e2a2a-5a32-4803-8875-37fba56b35bd" />

---

# Summary

The File Integrity Checker forms a critical part of the ClearSight Anti-Cheat system by providing:

- Cryptographically strong tamper detection  
- Self-protection against modification  
- Secure baseline storage  
- Honeyfile tripwire mechanisms  
- Debugger detection  
- Robust logging with `[FATAL]` severity  

It is designed to be educational, maintainable, and production-ready.

---

End of `docs/file_integrity.md`.

