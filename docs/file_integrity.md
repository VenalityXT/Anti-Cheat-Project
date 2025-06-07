# File Integrity Module (`file_integrity.py`)

## Purpose

The **File Integrity Module** safeguards critical game files against tampering, unauthorized modifications, or corruption during runtime. By continuously validating file integrity, it provides a robust defense layer against cheating techniques that rely on altering game assets or executables.

---

## Design Overview

The module employs a multi-layered cryptographic approach combining:

- SHA-256 hashing of game files to detect any content changes.
- AES-CBC encryption to securely store baseline hashes.
- RSA digital signatures (PSS padding + SHA-256) to guarantee the authenticity and integrity of the baseline data.

---

## Development and Iterations

### Initial Prototype

**Method:**  
The first version simply computed SHA-256 hashes of files and stored them in a plain JSON file.

**Limitations:**  
- Baseline file was stored in plaintext, making it vulnerable to tampering.  
- No digital signature or encryption, allowing attackers to modify baseline hashes and bypass integrity checks.

### Adding Encryption

**Enhancement:**  
Introduced AES-CBC encryption to protect baseline hashes.

**How:**  
- Hash dictionary serialized to JSON.  
- Encrypted with AES using a key derived via PBKDF2 from a strong passphrase.

**Impact:**  
- Baseline hashes were no longer visible or modifiable in plaintext.  
- Increased security against baseline forgery.

### Introducing Digital Signatures

**Enhancement:**  
Added RSA digital signatures to verify the authenticity of the encrypted baseline file.

**Details:**  
- Generated a 2048-bit RSA key pair: private key signs the encrypted baseline; public key verifies it.  
- Signature created using PSS padding and SHA-256 hashing.

**Benefits:**  
- Attackers cannot replace the baseline file without producing a valid signature.  
- Provides non-repudiation and strong tamper-evidence.

### Bug Fixes and Security Improvements

**Issue:**  
Signature verification was incorrectly done against the decrypted JSON instead of the original encrypted bytes.

**Correction:**  
Verified the signature against the encrypted baseline data.

**Result:**  
Prevented false negatives and ensured detection of any baseline tampering.

### Performance Optimization

**Improvements:**  
- Excluded files in the `ClearSight` folder and certain non-critical file types (e.g., logs, temporary files) to reduce hashing overhead.  
- Considered incremental hashing by tracking file metadata, but retained full recursive hashing for maximum assurance.

---

## How It Works: Step-by-Step

### 1. Baseline Creation (First Run)

- Recursively scan all monitored directories, excluding exceptions.  
- Compute SHA-256 hashes for each file.  
- Serialize the hash dictionary as JSON.  
- Encrypt the JSON data with AES-CBC using a PBKDF2-derived key.  
- Digitally sign the encrypted file with the RSA private key.  
- Save `hashes.json.enc` (encrypted hashes) and `hashes.json.sig` (signature) to disk.

### 2. Verification Loop (Runtime)

- Read the encrypted baseline file and its signature.  
- Verify the signature against the encrypted data using the RSA public key.  
- If signature verification fails, trigger a tampering alert immediately.  
- Decrypt the baseline hashes using AES.  
- Recompute current hashes of monitored files.  
- Compare current hashes with baseline; on mismatch, log the event and simulate termination of the game.

---

## Cryptographic Files

| File Name           | Purpose                                                        |
|---------------------|----------------------------------------------------------------|
| `file_integrity.py` | Main integrity verification script and monitoring loop        |
| `hashes.json.enc`   | AES-encrypted baseline hash data                               |
| `hashes.json.sig`   | RSA digital signature for verifying baseline authenticity     |
| `public_key.pem`    | RSA public key used for signature verification                 |
| `private_key.pem`   | RSA private key used to sign baseline (kept secret)           |

---

## Logging and Alerts

- All integrity checks and results are logged to:  
  `logs/file_integrity.log`  
- Detected violations trigger immediate logging with timestamps and affected file paths.  
- Future plans include real-time alerting (e.g., push notifications or game UI alerts).

---

## Challenges and Lessons Learned

- Proper cryptographic handling is critical—subtle errors in signature verification can invalidate security.  
- Balancing security with performance requires selective hashing and possibly incremental verification.  
- Secure private key management is vital to prevent signature forgery.

---

## Future Enhancements

- Add configurable file exclusions (extensions/directories) for performance.  
- Implement incremental baseline updates to avoid full rescans.  
- Develop a graphical baseline management tool for key and baseline operations.  
- Integrate real-time alerting systems.  
- Manage multiple baseline versions for different game patches or configurations.

---

## Screenshots

![Error Handling Example](https://github.com/user-attachments/assets/2f619ffb-3073-4457-9c00-8fede39447c0)

---

This module is a cornerstone for maintaining game integrity, drastically reducing the risk of cheating via file manipulation and increasing the overall trustworthiness of the gaming environment.
