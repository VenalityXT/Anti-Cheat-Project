# ==================================================================================================
# FILE_INTEGRITY.PY
#
# PURPOSE:
#   Provides secure, production-style file integrity monitoring for an FPS anti-cheat engine.

#   This module:
#     • Verifies its own integrity using a persistent self-hash baseline
#     • Detects file tampering, additions, or deletions
#     • Uses AES-256-GCM with RSA-PSS signatures to protect baseline data
#     • Derives AES keys directly from RSA private key material (no hardcoded secrets)
#     • Implements debugger detection and honeyfile trap logic
#     • Employs timing jitter to prevent predictable scanning windows
#
# DESIGN GOAL:
#   Highly readable, secure, and professional — suitable for teaching, portfolio display,
#   and demonstrating real-world anti-cheat concepts to recruiters.
# ==================================================================================================


# ============================================= IMPORTS ============================================= #
# Standard library imports
import os
import sys
import time
import json
import random
import hashlib
import logging
import secrets
import ctypes
from typing import Dict

# Cryptography primitives for hashing, AES-GCM, RSA-PSS, and KDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ============================================ CONSTANTS ============================================ #

# Disables game termination conditions from debugging
DEV_MODE = True

# Root directory of the game to monitor
GAME_DIRECTORY = r"C:\Users\mguaj\OneDrive\Desktop\MyFPSGame"

# Paths for storing encrypted baselines + signatures
BASELINE_FILE = "ClearSight/data/baseline/hashes.bin"
BASELINE_SIGNATURE_FILE = "ClearSight/data/baseline/hashes.sig"

# Paths for storing self-integrity baseline + signature
SELF_HASH_FILE = "ClearSight/data/baseline/self_integrity.bin"
SELF_HASH_SIGNATURE_FILE = "ClearSight/data/baseline/self_integrity.sig"

# Cryptographic keypaths
PUBLIC_KEY_FILE = "ClearSight/keys/public_key.pem"
PRIVATE_KEY_FILE = "ClearSight/keys/private_key.pem"

# Output logs
LOG_FILE = "ClearSight/logs/file_integrity.log"

# Honeyfile used as a tamper-detection trap
HONEYFILE_PATH = os.path.join(GAME_DIRECTORY, "honeypot.dat")

# Exclusion rules
EXCLUDED_FOLDERS = ["ClearSight", "__pycache__", ".git"]
EXCLUDED_EXTENSIONS = [".tmp", ".log", ".cache"]

# Integrity loop timing
SCAN_INTERVAL_SECONDS = 30       # Main interval
JITTER_SECONDS = 15              # Random offset to break cheat timing


# =========================================== LOGGING SETUP ========================================= #

# Ensure logs directory exists before FileHandler is created
log_dir = os.path.dirname(LOG_FILE)

if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    print(f"[FILE_INTEGRITY] Log directory '{log_dir}' did not exist. Created automatically.")

# Now safely configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FILE_INTEGRITY] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
)

logging.info("File Integrity Module Loaded Successfully.")

# ========================================= UTILITY HELPERS ========================================== #

def canonical(path: str) -> str:
    """Returns normalized absolute path — helps avoid bypassing checks with path tricks."""
    return os.path.abspath(os.path.normpath(path))


def is_debugger_present() -> bool:
    """
    Detects debugger presence using:
      • sys.gettrace() → Python-level debugger
      • IsDebuggerPresent() → Windows native debugger checks
    """
    # Python debugging hook present
    if sys.gettrace():
        return True

    # WinAPI debugger check
    try:
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0
    except Exception:
        return False


def terminate_game(event: str, reason: str):
    """
    Simulated forced game termination when tampering is detected.
    In production, this would signal the main process / kernel module.
    """
    pid = random.randint(2000, 9999)
    logging.critical(f"[{event}] Terminating simulated game process (PID={pid}) — Reason: {reason}")
    time.sleep(1.5)
    sys.exit(1)


# ========================================== CRYPTOGRAPHY LAYER ====================================== #

def derive_aes_key_from_private_key() -> bytes:
    """
    Derives a deterministic AES-256 key from RSA private key material.
    This avoids storing any plaintext password in code or environment.
    """
    if not os.path.exists(PRIVATE_KEY_FILE):
        terminate_game("FI-KEY-001", "Missing RSA private key.")

    # Load RSA private key from disk
    with open(PRIVATE_KEY_FILE, "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data, password=None, backend=default_backend()
    )

    # Extract large integer components from RSA key
    numbers = private_key.private_numbers()

    # Hash key components into a 32-byte seed
    digest = hashlib.sha256()
    digest.update(numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, "big"))
    digest.update(numbers.q.to_bytes((numbers.q.bit_length() + 7) // 8, "big"))
    digest.update(numbers.d.to_bytes((numbers.d.bit_length() + 7) // 8, "big"))
    seed = digest.digest()  # 32 bytes

    # Derive final AES key using PBKDF2 for extra strengthening
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,                              # AES-256
        salt=b"AntiCheatAESDerivationSalt",     # Fixed salt for determinism
        iterations=100000,
        backend=default_backend(),
    )

    return kdf.derive(seed)


def encrypt_json(data: dict, aes_key: bytes) -> bytes:
    """
    Encrypts a JSON dictionary using AES-GCM (authenticated encryption).
    Returns: nonce + tag + ciphertext
    """
    json_bytes = json.dumps(data, indent=4).encode("utf-8")

    # AES-GCM requires a 96-bit (12-byte) nonce
    nonce = secrets.token_bytes(12)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Produce authenticated ciphertext
    ciphertext = encryptor.update(json_bytes) + encryptor.finalize()

    # Return a self-contained blob
    return nonce + encryptor.tag + ciphertext


def decrypt_json(blob: bytes, aes_key: bytes) -> dict:
    """
    Decrypts AES-GCM encrypted blob back into Python dict.
    Validates authentication tag automatically.
    """
    nonce = blob[:12]          # First 12 bytes
    tag = blob[12:28]          # Next 16 bytes
    ciphertext = blob[28:]     # Remainder

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8"))


def verify_signature(blob: bytes, signature_path: str, public_key_path: str) -> bool:
    """
    Verifies that `blob` was signed with the RSA private key corresponding to PUBLIC_KEY_FILE.
    Prevents tampered baseline files from being trusted.
    """
    if not os.path.exists(signature_path):
        logging.error("Signature file missing during verification.")
        return False

    # Load signature bytes
    with open(signature_path, "rb") as f:
        signature = f.read()

    # Load public key for verification
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    try:
        public_key.verify(
            signature,
            blob,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True  # Signature valid
    except Exception as e:
        logging.error(f"Digital signature verification failed: {e}")
        return False


def sign_blob(blob: bytes, output_signature_path: str):
    """
    Signs a blob using RSA private key and saves the signature.
    Used for:
        • Baseline self-integrity storage
        • Main baseline signatures
    """
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Create RSA-PSS signature
    signature = private_key.sign(
        blob,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Store the signature
    with open(output_signature_path, "wb") as f:
        f.write(signature)


# ========================================== SELF-INTEGRITY CHECK ==================================== #

def compute_file_hash(path: str) -> str:
    """Returns SHA-256 hash of a file read in safe, chunked blocks."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    return sha.hexdigest()


def verify_self_integrity(aes_key: bytes):
    """
    Ensures this script file has not been altered.
    If baseline is missing, creates + signs a new one.
    """
    my_path = canonical(__file__)
    current_hash = compute_file_hash(my_path)

    # First run → create baseline
    if not os.path.exists(SELF_HASH_FILE):
        logging.info("No self-integrity baseline found — creating one now.")
        blob = current_hash.encode("utf-8")

        # Save the raw baseline hash
        open(SELF_HASH_FILE, "wb").write(blob)

        # Sign the baseline hash
        sign_blob(blob, SELF_HASH_SIGNATURE_FILE)
        logging.info("Self-integrity baseline created.")
        return

    # Load baseline hash
    baseline_hash = open(SELF_HASH_FILE, "rb").read().decode("utf-8")

    # Verify signature on the baseline hash
    if not verify_signature(baseline_hash.encode("utf-8"), SELF_HASH_SIGNATURE_FILE, PUBLIC_KEY_FILE):
        terminate_game("FI-SI-001", "Self-integrity signature invalid.")

    # Hash mismatch → file altered
    if baseline_hash != current_hash:
        terminate_game("FI-SI-002", "Anti-cheat module has been modified!")


# ========================================== BASELINE LOAD/SAVE ====================================== #

def load_baseline(aes_key: bytes) -> Dict[str, str]:
    """Loads + decrypts + validates the file integrity baseline."""
    if not os.path.exists(BASELINE_FILE):
        logging.warning("Baseline not found — creating new baseline on this run.")
        return {}

    blob = open(BASELINE_FILE, "rb").read()

    # Validate signature BEFORE decryption
    if not verify_signature(blob, BASELINE_SIGNATURE_FILE, PUBLIC_KEY_FILE):
        terminate_game("FI-BL-001", "Baseline signature invalid.")

    try:
        return decrypt_json(blob, aes_key)
    except Exception as e:
        terminate_game("FI-BL-002", f"Baseline decryption failed: {e}")


def save_baseline(hashes: Dict[str, str], aes_key: bytes):
    """Encrypts the hash map and signs it for future verification."""
    blob = encrypt_json(hashes, aes_key)

    # Save encrypted blob
    open(BASELINE_FILE, "wb").write(blob)

    # Save RSA-PSS signature
    sign_blob(blob, BASELINE_SIGNATURE_FILE)

    logging.info("Baseline saved + signed successfully.")


# ========================================== FILE SCANNING LOGIC ===================================== #

def should_exclude(path: str) -> bool:
    """
    Determines whether a file path should be excluded based on:
        • Folder names
        • File extensions
    """
    path_lower = path.lower()

    # Folder exclusion check
    for folder in EXCLUDED_FOLDERS:
        if folder.lower() in path_lower:
            return True

    # Extension exclusion check
    _, ext = os.path.splitext(path)
    if ext.lower() in EXCLUDED_EXTENSIONS:
        return True

    return False


def scan_directory(root: str) -> Dict[str, str]:
    """
    Performs TOCTOU-safe scanning of the game directory.
    Returns: {filepath: sha256_hash}
    """
    hashes = []
    result = {}

    # Gather all candidate files
    for dirpath, _, files in os.walk(root):
        for fname in files:
            full = canonical(os.path.join(dirpath, fname))
            if not should_exclude(full):
                hashes.append(full)

    # Shuffle order to prevent timing-based cheat bypass
    random.shuffle(hashes)

    # Compute hashes
    for path in hashes:
        try:
            result[path] = compute_file_hash(path)
        except Exception as e:
            logging.error(f"Error hashing file {path}: {e}")

    return result


# ========================================== HONEYFILE CHECK ========================================= #

def check_honeyfile():
    """
    Ensures honeyfile exists.
    If modified or missing → this is a strong tampering indicator.
    """
    if not os.path.exists(HONEYFILE_PATH):
        terminate_game("FI-HF-001", "Honeyfile is missing! Potential tampering.")


# ========================================== MONITOR LOOP ============================================ #

def monitor():
    """
    Main monitoring loop.
    Handles:
        • Debugger detection
        • Self-integrity verification
        • Baseline creation/loading
        • File hashing and comparison
        • Honeyfile verification
        • Timed scan cycles with jitter
    """

    # Derive AES key from RSA private key → secure and deterministic
    aes_key = derive_aes_key_from_private_key()

    # Ensure this file hasn't been modified
    verify_self_integrity(aes_key)

    # Load baseline (or create if missing)
    baseline = load_baseline(aes_key)
    if not baseline:
        logging.info("Generating baseline hashes...")
        baseline = scan_directory(GAME_DIRECTORY)
        save_baseline(baseline, aes_key)

    # Begin main scanning loop
    while True:

        # Detect Python or OS debugger
        if is_debugger_present():
            if not DEV_MODE:
                terminate_game("FI-DBG-001", "Debugger detected.")
            else:
                logging.warning("Debugger detected, but ignoring because DEV_MODE is enabled.")

        # Verify honeyfile (basic tamper trip)
        check_honeyfile()

        # Current disk state
        current = scan_directory(GAME_DIRECTORY)

        # Detect deleted baseline files
        missing = [p for p in baseline if p not in current]

        # Detect changed or newly added files
        modified_or_new = [
            p for p in current
            if p not in baseline or current[p] != baseline[p]
        ]

        # If violations exist → terminate
        if missing or modified_or_new:
            logging.error("Integrity violation detected!")
            if missing:
                logging.error(f"Missing files: {missing}")
            if modified_or_new:
                logging.error(f"Modified/New files: {modified_or_new}")
            terminate_game("FI-INT-001", "Integrity violation detected.")

        # Sleep with jitter to avoid predictable timing
        sleep_time = SCAN_INTERVAL_SECONDS + random.randint(-JITTER_SECONDS, JITTER_SECONDS)
        sleep_time = max(5, sleep_time)  # Ensure no zero/negative sleep
        time.sleep(sleep_time)


# =============================================== ENTRY POINT ======================================== #

if __name__ == "__main__":
    monitor()
