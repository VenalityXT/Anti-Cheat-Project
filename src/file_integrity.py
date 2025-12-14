# ==================================================================================================
# FILE_INTEGRITY.PY
#
# PURPOSE:
#   Provides secure, production-style file integrity monitoring for an FPS anti-cheat engine.
# =================================================================================================== #


# ============================================= IMPORTS ============================================= #
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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ============================================ CONSTANTS ============================================ #

# Developer debug output toggle
DEBUG_MODE = True
DEV_MODE = True

# Root directory of the game to monitor
GAME_DIRECTORY = r"C:\Users\mguaj\OneDrive\Desktop\MyFPSGame"

BASELINE_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "hashes.bin")
BASELINE_SIGNATURE_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "hashes.sig")

SELF_HASH_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "self_integrity.bin")
SELF_HASH_SIGNATURE_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "self_integrity.sig")

PUBLIC_KEY_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "keys", "public_key.pem")
PRIVATE_KEY_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "keys", "private_key.pem")

LOG_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "logs", "file_integrity.log")

HONEYFILE_PATH = os.path.join(GAME_DIRECTORY, "honeypot.dat")

EXCLUDED_FOLDERS = ["ClearSight", "__pycache__", ".git"]
EXCLUDED_EXTENSIONS = [".tmp", ".log", ".cache"]

SCAN_INTERVAL_SECONDS = 30
JITTER_SECONDS = 15


# =========================================== LOGGING SETUP ========================================= #

log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    print(f"[FILE_INTEGRITY] Log directory '{log_dir}' did not exist. Created automatically.")

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

def debug(msg: str):
    if DEBUG_MODE:
        print(f"{msg}")


def canonical(path: str) -> str:
    return os.path.abspath(os.path.normpath(path))


def is_debugger_present() -> bool:
    if sys.gettrace():
        return True

    try:
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0
    except Exception:
        return False


def terminate_game(event: str, reason: str):
    pid = random.randint(2000, 9999)
    logging.critical(f"[{event}] Terminating simulated game process (PID={pid}) — Reason: {reason}")
    time.sleep(1.5)
    sys.exit(1)


# ========================================== CRYPTOGRAPHY LAYER ====================================== #

def derive_aes_key_from_private_key() -> bytes:
    if not os.path.exists(PRIVATE_KEY_FILE):
        terminate_game("FI-KEY-001", "Missing RSA private key.")

    with open(PRIVATE_KEY_FILE, "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(key_data, password=None)
    numbers = private_key.private_numbers()

    digest = hashlib.sha256()
    digest.update(numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, "big"))
    digest.update(numbers.q.to_bytes((numbers.q.bit_length() + 7) // 8, "big"))
    digest.update(numbers.d.to_bytes((numbers.d.bit_length() + 7) // 8, "big"))
    seed = digest.digest()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"AntiCheatAESDerivationSalt",
        iterations=100000,
        backend=default_backend(),
    )

    return kdf.derive(seed)


def encrypt_json(data: dict, aes_key: bytes) -> bytes:
    json_bytes = json.dumps(data, indent=4).encode("utf-8")

    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(json_bytes) + encryptor.finalize()

    return nonce + encryptor.tag + ciphertext


def decrypt_json(blob: bytes, aes_key: bytes) -> dict:
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(plaintext.decode("utf-8"))


def verify_signature(blob: bytes, signature_path: str, public_key_path: str) -> bool:
    if not os.path.exists(signature_path):
        logging.error("Signature file missing during verification.")
        debug(f"Missing signature file: {signature_path}")
        return False

    signature = open(signature_path, "rb").read()

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,
            blob,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True

    except Exception as e:
        logging.error(f"Digital signature verification failed: {e}")
        debug(f"""
                --- SIGNATURE VERIFICATION FAILURE ---
                Blob size: {len(blob)} bytes
                Signature size: {len(signature)} bytes
                Signature path: {signature_path}
                Public key path: {public_key_path}
                Error: {e}
                -------------------------------------
            """)
        return False


def sign_blob(blob: bytes, output_signature_path: str):
    private_key = serialization.load_pem_private_key(open(PRIVATE_KEY_FILE, "rb").read(), password=None)

    signature = private_key.sign(
        blob,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    with open(output_signature_path, "wb") as f:
        f.write(signature)


# ========================================== SELF-INTEGRITY CHECK ==================================== #

def compute_file_hash(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    return sha.hexdigest()


def verify_self_integrity(aes_key: bytes):
    my_path = canonical(__file__)
    current_hash = compute_file_hash(my_path)

    if not os.path.exists(SELF_HASH_FILE):
        logging.info("No self-integrity baseline found — creating one now.")
        blob = current_hash.encode("utf-8")
        open(SELF_HASH_FILE, "wb").write(blob)
        sign_blob(blob, SELF_HASH_SIGNATURE_FILE)
        return

    baseline_hash = open(SELF_HASH_FILE, "rb").read().decode("utf-8")

    if not verify_signature(baseline_hash.encode("utf-8"), SELF_HASH_SIGNATURE_FILE, PUBLIC_KEY_FILE):
        debug("Self-integrity signature verification failed.")
        terminate_game("FI-SI-001", "Self-integrity signature invalid.")

    if baseline_hash != current_hash:
        debug(f"""
            --- SELF INTEGRITY HASH MISMATCH ---
            Expected hash: {baseline_hash}
            Current hash:  {current_hash}
            Script path:   {my_path}
            -----------------------------------
            """)
        terminate_game("FI-SI-002", "Anti-cheat module has been modified!")


# ========================================== BASELINE LOAD/SAVE ====================================== #

def load_baseline(aes_key: bytes) -> Dict[str, str]:
    if not os.path.exists(BASELINE_FILE):
        logging.warning("Baseline not found — creating new baseline on this run.")
        return {}

    blob = open(BASELINE_FILE, "rb").read()

    if not verify_signature(blob, BASELINE_SIGNATURE_FILE, PUBLIC_KEY_FILE):
        terminate_game("FI-BL-001", "Baseline signature invalid.")

    try:
        return decrypt_json(blob, aes_key)
    except Exception as e:
        debug(f"Baseline decryption failure: {e}")
        terminate_game("FI-BL-002", f"Baseline decryption failed: {e}")


def save_baseline(hashes: Dict[str, str], aes_key: bytes):
    blob = encrypt_json(hashes, aes_key)
    open(BASELINE_FILE, "wb").write(blob)
    sign_blob(blob, BASELINE_SIGNATURE_FILE)
    logging.info("Baseline saved + signed successfully.")


# ========================================== FILE SCANNING LOGIC ===================================== #

def should_exclude(path: str) -> bool:
    path_lower = path.lower()

    for folder in EXCLUDED_FOLDERS:
        if folder.lower() in path_lower:
            return True

    _, ext = os.path.splitext(path)
    return ext.lower() in EXCLUDED_EXTENSIONS


def scan_directory(root: str) -> Dict[str, str]:
    hashes = []
    result = {}

    for dirpath, _, files in os.walk(root):
        for fname in files:
            full = canonical(os.path.join(dirpath, fname))
            if not should_exclude(full):
                hashes.append(full)

    random.shuffle(hashes)

    for path in hashes:
        try:
            result[path] = compute_file_hash(path)
        except Exception as e:
            logging.error(f"Error hashing file {path}: {e}")
            debug(f"Hashing exception for {path}: {e}")

    return result


# ========================================== HONEYFILE CHECK ========================================= #

def check_honeyfile():
    if not os.path.exists(HONEYFILE_PATH):
        debug(f"Honeyfile missing at: {HONEYFILE_PATH}")
        terminate_game("FI-HF-001", "Honeyfile is missing! Potential tampering.")


# ========================================== MONITOR LOOP ============================================ #

def monitor():
    aes_key = derive_aes_key_from_private_key()
    verify_self_integrity(aes_key)

    baseline = load_baseline(aes_key)
    if not baseline:
        logging.info("Generating baseline hashes...")
        baseline = scan_directory(GAME_DIRECTORY)
        save_baseline(baseline, aes_key)

    while True:

        if is_debugger_present():
            if not DEV_MODE:
                terminate_game("FI-DBG-001", "Debugger detected.")
            else:
                logging.warning("Debugger detected, but ignoring due to DEV_MODE.")

        check_honeyfile()

        current = scan_directory(GAME_DIRECTORY)

        missing = [p for p in baseline if p not in current]
        modified_or_new = [p for p in current if p not in baseline or current[p] != baseline[p]]

        # DEBUG OUTPUT FOR MISSING FILES
        if DEBUG_MODE and missing:
            for p in missing:
                debug(f"FILE REMOVED: {p}")

        # DEBUG OUTPUT FOR MODIFIED OR NEW FILES
        if DEBUG_MODE and modified_or_new:
            for p in modified_or_new:
                old = baseline.get(p, "<NEW FILE>")
                new = current[p]

                debug(f"""
                    --- FILE MODIFIED/NEW DETECTED ---
                    Path: {p}
                    Old hash: {old}
                    New hash: {new}
                    ----------------------------------
                    """)

        if missing or modified_or_new:
            terminate_game("FI-INT-001", "Integrity violation detected.")

        sleep_time = SCAN_INTERVAL_SECONDS + random.randint(-JITTER_SECONDS, JITTER_SECONDS)
        time.sleep(max(5, sleep_time))


# =============================================== ENTRY POINT ======================================== #

if __name__ == "__main__":
    monitor()
