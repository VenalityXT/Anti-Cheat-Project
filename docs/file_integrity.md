# File Integrity Module (`file_integrity.py`)

## Purpose
This module ensures that key game files remain unmodified during runtime. It verifies file integrity using cryptographic hashes, AES encryption, and RSA signatures.

---

## How It Works

1. **Hashing Game Files**:  
   All files (except those in the `ClearSight` folder) are recursively hashed using SHA256.

2. **Baseline Creation**:  
   On first run, the script:
   - Hashes all files
   - Encrypts the hash dictionary using AES-CBC with a PBKDF2-derived key
   - Signs the encrypted file using RSA (PSS padding + SHA256)

3. **Verification Process**:
   - On each cycle, the script hashes the current state of all files
   - Compares them to the **decrypted** baseline
   - If a change is found, it logs the violation and simulates terminating the game

4. **Digital Signature Fix**
   > 🔧 **Issue Found:** Originally, the script was verifying the signature against the decrypted JSON instead of the original encrypted file.  
   > ✅ **Fix:** Adjusted `check_signature()` in `verify_hashes()` to check the signature against the `encrypted_hash_data` instead of `decrypted_json_bytes`.

---

## Key Files

Files & Purpose

| `file_integrity.py`, The main integrity monitor loop |
| `hashes.json.enc`, Encrypted file hashes (AES) |
| `hashes.json.sig`, Digital signature of the encrypted file |
| `public_key.pem`, Used to verify signature |
| `private_key.pem`, Used to sign baseline hashes |

---

## Logging

All activity is logged to:
logs/file_integrity.log

## Example Error Handling
![ErrorHandling](https://github.com/user-attachments/assets/2f619ffb-3073-4457-9c00-8fede39447c0)

Future Enhancements
Add hash exclusions by file extension (e.g. .log, .tmp)

Alert system (send a message or push notification)

GUI tool to regenerate baseline and keys
