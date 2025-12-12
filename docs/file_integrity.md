# File Integrity Module (`file_integrity.py`)

A cryptographically secure anti-tamper subsystem within the ClearSight Anti-Cheat framework.  
This module enforces file integrity verification, self-integrity protection, baseline hashing, and tamper-aware termination logic.

[View script](https://github.com/VenalityXT/Anti-Cheat-Project/blob/main/src/file_integrity.py)

> [!IMPORTANT]
> This module is designed for **controlled lab and research environments**.
> Advanced anti-cheat hardening techniques such as **code obfuscation, packing, virtualization, and anti-reversing countermeasures** are intentionally **not implemented**.
>
> This omission is deliberate to ensure the system remains **observable, testable, auditable, and debuggable** for learning, analysis, and detection logic validation.

---

## Overview  

The File Integrity Checker performs the following functions:

- Creates an encrypted and digitally signed baseline of known-good file hashes  
- Verifies baseline integrity using RSA-PSS  
- Derives its AES-GCM encryption key from RSA private key material (no hardcoded secrets)  
- Verifies the anti-cheat module’s own integrity using a persistent self-integrity baseline  
- Detects new, modified, or missing game files  
- Detects debugger attachment (optional DEV_MODE bypass)  
- Uses a honeyfile trap to detect broad sweeping tampering  
- Logs all events using `[INFO]`, `[WARNING]`, `[ERROR]`, and `[CRITICAL]` levels  

When a validated tamper event is detected, the module triggers a simulated forced game termination recorded under `[CRITICAL]`.

---

## Baseline Architecture

Two independent baselines are maintained:

### 1. Self-Integrity Baseline  

Stored as:
- `ClearSight/data/baseline/self_integrity.bin`
- `ClearSight/data/baseline/self_integrity.sig`

This baseline contains a SHA-256 hash of the anti-cheat module itself (`file_integrity.py`).  
Any mismatch indicates that the anti-cheat has been modified.

### 2. File-Integrity Baseline  

Stored as:
- `ClearSight/data/hashes.json.enc`  
- `ClearSight/data/hashes.json.sig`

This baseline contains SHA-256 hashes of game files located inside `GAME_DIRECTORY`, excluding folders and extensions specified in `EXCLUDED_FOLDERS` and `EXCLUDED_EXTENSIONS`.

> [!CAUTION]
> Both baselines must be deleted and regenerated if the monitored file set or directory structure changes.
> Failure to do so will result in guaranteed integrity violations.

---

## Directory and Path Design

By default:

- `GAME_DIRECTORY` points to the main game folder  
- The honeyfile is stored at `GAME_DIRECTORY/honeypot.dat`  
- The self-integrity baseline is stored inside `ClearSight/data/baseline`  
- The file-integrity baseline is stored inside `ClearSight/data/`  

This layout ensures:

- Game assets remain separate from anti-cheat assets  
- Baseline files cannot be mistaken for regular game content  
- Paths remain predictable for encryption, signing, and verification logic

---

## Self-Integrity System

The module protects itself through the following steps:

1. SHA-256 hashing of the anti-cheat source file  
2. Storing the hash in `self_integrity.bin`  
3. Digitally signing the hash using RSA-PSS  
4. Verifying the signature and current hash on every execution  

If the file has changed:

- In production: `[CRITICAL] FI-SI-002 Anti-cheat module has been modified!`  
- In DEV_MODE: a warning is logged and the baseline is automatically rebuilt  

---

## File-Integrity System

The module hashes all valid game files under `GAME_DIRECTORY`.  
Files are ignored if they appear in:

- `EXCLUDED_FOLDERS` (e.g., `ClearSight`, `__pycache__`, `.git`)  
- `EXCLUDED_EXTENSIONS` (e.g., `.tmp`, `.log`, `.cache`)  

The resulting `{ path: sha256 }` mapping is:

- Serialized into JSON  
- Encrypted using AES-256-GCM  
- Signed using RSA-PSS  

On subsequent runs:

- The baseline signature is verified  
- The baseline is decrypted  
- Current file hashes are compared against stored values  
- Any discrepancy triggers an integrity violation and termination event  

---

## Honeyfile System

A special tripwire file named `honeypot.dat` is placed at the root of `GAME_DIRECTORY`.

Rules:

- The game never touches this file  
- The anti-cheat expects the file to exist and remain unchanged  
- Deletion, modification, or replacement triggers an integrity violation  

This mechanism rapidly detects mass-editing cheats and automated cleanup tools.

---

## Debugger Detection

The module checks for both:

- Python-level debuggers using `sys.gettrace()`  
- Native Windows debuggers using `IsDebuggerPresent`  

In production:

`[CRITICAL] [FI-DBG-001] Debugger detected.`

In DEV_MODE:

`[WARNING] Debugger detected, but ignoring because DEV_MODE is enabled.`

> [!WARNING]
> Debugger detection is intentionally strict and may trigger false positives in advanced development, instrumentation, or monitoring environments.

---

## AES Key Derivation

To avoid storing plaintext secrets, the AES encryption key is derived directly from RSA private key internals.

Process:

1. Load `private_key.pem`  
2. Extract integer components (`d`, `p`, `q`)  
3. Hash the components together using SHA-256  
4. Run PBKDF2-HMAC-SHA256 to derive a 256-bit AES key  
5. Use AES-GCM with a random 96-bit nonce for encryption and decryption  

This design ensures:

- Only the correct private key can decrypt the baseline  
- Tampering with the key invalidates the entire system  
- No passwords or static secrets appear in source code or configuration files  

---

## Logging System

The module uses four severity levels:

- `[INFO]` — Normal operations  
- `[WARNING]` — Suspicious or DEV_MODE-bypassed behavior  
- `[ERROR]` — Non-fatal integrity or configuration issues  
- `[CRITICAL]` — Guaranteed termination events  

Example `[CRITICAL]` log entry:

`2025-12-11 12:41:22,118 [FILE_INTEGRITY] [CRITICAL] [FI-INT-001]  
Terminating simulated game process (PID=4211) — Reason: Integrity violation detected.`

All logs are written to:

`ClearSight/logs/file_integrity.log`

Directories are created automatically if missing.

---

## Integrity Violation Codes

| Code         | Meaning |
|--------------|---------|
| FI-KEY-001   | Missing RSA private key |
| FI-SI-001    | Self-integrity signature invalid |
| FI-SI-002    | Anti-cheat module modified |
| FI-BL-001    | Baseline signature invalid |
| FI-BL-002    | Baseline decryption failed |
| FI-HF-001    | Honeyfile missing or modified |
| FI-DBG-001   | Debugger detected |
| FI-INT-001   | Integrity violation detected |
| FI-INT-002   | Missing game files |
| FI-INT-003   | Unexpected new files |

---

## Development Workflow

During development:

- Set `DEV_MODE = True`  
- Modify code freely  
- Baselines regenerate automatically  
- Debuggers are ignored  
- Termination events become non-blocking  

Before production:

- Disable `DEV_MODE`  
- Regenerate final baselines  
- Protect key files and baseline directories from modification  

---

## Runtime Flow

<img width="1770" height="1089" alt="image" src="https://github.com/user-attachments/assets/c011eaff-1c41-41b7-8da2-2c0cd24c7730" />

---

## Summary

The File Integrity Module provides:

- Cryptographically strong tamper detection  
- Self-protection against modification  
- Secure baseline storage  
- Honeyfile tripwire mechanisms  
- Debugger awareness  
- Structured logging with standardized event codes  

It is designed to be **educational, auditable, and extensible**, with clarity prioritized over adversarial hardening.

---

End of `docs/file_integrity.md`.
