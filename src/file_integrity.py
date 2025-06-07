# FILE_INTEGRITY.PY
# 
# PURPOSE: 
# This file handles the integrity checking of important game files.
# It calculates and compares the SHA256 hash of game files with known good hashes.
#
# HOW IT WORKS:
# The script reads the file, calculates its SHA256 hash, and compares it with pre-defined hashes.
# If the hash of a file doesn't match the expected hash, the script logs the issue.


# ============================================= IMPORTS ============================================= #

# ~~~ Python Library Imports ~~~ #

import logging   # For structured logging of script events, errors, and info messages
import secrets   # For generating cryptographically secure random bytes (salt)
import hashlib   # For generating SHA256 hashes of files to verify integrity
import random    # For simulating process IDs when closing game on integrity failure
import time      # For adding delays between integrity check cycles
import json      # For serializing and deserializing baseline hashes to/from JSON format
import sys       # For exiting the script on critical errors or early termination
import os        # For interacting with the file system (walking directories, checking files)

# ~~~ Cryptography Library Imports ~~~ #

from cryptography.hazmat.primitives import serialization, hashes  
# Serialization: loading & saving crypto keys
# Hashes: crypto hashing algorithms (SHA256) used for signing and verification

from cryptography.hazmat.primitives.asymmetric import padding  
# Provides padding schemes (PSS) used in RSA digital signatures for security

from cryptography.hazmat.backends import default_backend  
# Specifies cryptographic backend (default implementation) used by cryptography primitives

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  
# PBKDF2 key derivation function to securely derive AES keys from passwords with salt

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
# Provides AES cipher algorithms and modes (CBC) used for encryption/decryption


# ============================================ CONSTANTS ============================================ #


GAME_DIRECTORY = r"C:\Users\mguaj\OneDrive\Desktop\MyFPSGame"
EXCLUDE_FOLDER_NAME = "ClearSight"

ENCRYPTED_HASHES_FILE = 'data/hashes.json.enc'
SIGNATURE_FILE = 'data/hashes.json.sig'
PUBLIC_KEY_FILE = 'keys/public_key.pem'
PRIVATE_KEY_FILE = 'keys/private_key.pem'

AES_PASSWORD_BYTES = b"v9#Xr!q7$LpZ@3mNk8*Fy%TwHsJ4&Vc"


# ========================================== LOGGING SETUP ========================================= #


logging.basicConfig( 
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("logs/file_integrity.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logging.info("File Integrity Script Started")


# ============================================ FUNCTIONS =========================================== #

# ~~~ CRYPTOGRAPHIC HELPERS ~~~ #

def create_AES(password: bytes, salt: bytes):
    """
    Derives a 32-byte AES key and 16-byte IV from a password and salt
    using PBKDF2 HMAC SHA256.
    """
    key_derivation_function = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,  # 32 bytes for key + 16 bytes for IV
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key_iv_bytes = key_derivation_function.derive(password)
    aes_key = key_iv_bytes[:32]
    aes_iv = key_iv_bytes[32:]
    return aes_key, aes_iv


def decrypt_AES(encrypted_data: bytes, password: bytes):
    """
    Decrypts AES CBC encrypted data.
    Assumes the first 16 bytes of encrypted_data are the salt.
    Removes PKCS7 padding after decryption.
    """
    salt = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    aes_key, aes_iv = create_AES(password, salt)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]

    return plaintext


def check_signature(data_bytes: bytes, signature_file_path: str, public_key_file_path: str):
    """
    Verifies a digital signature of data_bytes against the signature file using the public key.
    Returns True if valid, False otherwise.
    """
    # Read signature bytes from file
    with open(signature_file_path, 'rb') as signature_file:
        signature_bytes = signature_file.read()

    # Load public key for verification
    with open(public_key_file_path, 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read(), backend=default_backend())

    try:
        # Verify signature using PSS padding and SHA256 hash algorithm
        public_key.verify(
            signature_bytes,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256()
        )
        return True

    except Exception as verification_error:
        logging.error(f"Digital signature verification failed: {verification_error}")
        return False


# ~~~ FILE HASHING AND SCANNING ~~~ #

def get_hash(file_path: str):
    """
    Calculate SHA256 hash of a file and return as hex string.
    Returns None if file reading fails.
    """
    sha256_hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file_to_hash:
            while chunk := file_to_hash.read(4096):
                sha256_hasher.update(chunk)
        return sha256_hasher.hexdigest()
    except Exception as error:
        logging.error(f"Failed to hash file '{file_path}': {error}")
        return None


def scan_hashes(game_dir: str, exclude_folder_name: str = None):
    """
    Walk through game directory, hashing all files except those in exclude_folder_name.
    Returns a dictionary mapping full file paths to their SHA256 hashes.
    """
    file_hashes = {}

    for root_directory, subdirs, files_in_dir in os.walk(game_dir):
        for filename in files_in_dir:
            full_file_path = os.path.join(root_directory, filename)

            # Skip files inside excluded folder
            if exclude_folder_name and exclude_folder_name in full_file_path:
                continue

            file_hash = get_hash(full_file_path)
            if file_hash:
                file_hashes[full_file_path] = file_hash

    return file_hashes


# ~~~ HANDLE BASELINE HASHES ~~~ #

def verify_hashes():
    """
    Load the baseline hashes from the encrypted hashes file,
    decrypt it using AES password, and verify its digital signature.
    Returns the hashes dictionary if successful, or {} if no baseline exists.
    Terminates program if verification fails.
    """
    if not os.path.exists(ENCRYPTED_HASHES_FILE):
        logging.warning(f"Baseline encrypted hashes file '{ENCRYPTED_HASHES_FILE}' not found. Assuming first run.")
        return {}

    try:
        with open(ENCRYPTED_HASHES_FILE, 'rb') as encrypted_hash_file:
            encrypted_hash_data = encrypted_hash_file.read()
    except Exception as read_error:
        logging.error(f"Failed to read encrypted baseline hashes file: {read_error}")
        sys.exit(1)

    try:
        decrypted_json_bytes = decrypt_AES(encrypted_hash_data, AES_PASSWORD_BYTES)
    except Exception as decrypt_error:
        logging.error(f"Decryption of baseline hashes file failed: {decrypt_error}")
        sys.exit(1)

    if not check_signature(encrypted_hash_data, SIGNATURE_FILE, PUBLIC_KEY_FILE):
        logging.error("Digital signature verification failed — possible tampering detected!")
        sys.exit(1)

    try:
        baseline_hashes_dict = json.loads(decrypted_json_bytes.decode('utf-8'))
        logging.info("Baseline hashes loaded and verified successfully.")
        return baseline_hashes_dict
    except Exception as json_error:
        logging.error(f"Failed to parse baseline hashes JSON: {json_error}")
        sys.exit(1)


def save_hashes(hashes_dict):
    """
    Encrypts and saves baseline hashes to ENCRYPTED_HASHES_FILE,
    then signs the encrypted file with private key, saving signature to SIGNATURE_FILE.
    Requires PRIVATE_KEY_FILE to be present.
    """
    # Convert hashes dict to JSON bytes
    json_bytes = json.dumps(hashes_dict, indent=4).encode('utf-8')

    # Generate random salt for key derivation
    salt_bytes = secrets.token_bytes(16)

    # Derive AES key and IV from password and salt
    aes_key, aes_iv = create_AES(AES_PASSWORD_BYTES, salt_bytes)

    # Setup AES CBC cipher
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    encryptor = aes_cipher.encryptor()

    # Add PKCS7 padding to JSON bytes
    padding_length = 16 - (len(json_bytes) % 16)
    padded_json_bytes = json_bytes + bytes([padding_length]) * padding_length

    # Encrypt the padded JSON bytes
    encrypted_bytes = encryptor.update(padded_json_bytes) + encryptor.finalize()

    # Prepend salt for decryption use
    encrypted_data_with_salt = salt_bytes + encrypted_bytes

    # Save encrypted hashes file
    with open(ENCRYPTED_HASHES_FILE, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data_with_salt)

    logging.info(f"Encrypted baseline hashes saved to '{ENCRYPTED_HASHES_FILE}'.")

    # Load private RSA key for signing
    if not os.path.exists(PRIVATE_KEY_FILE):
        logging.error(f"Private key file '{PRIVATE_KEY_FILE}' not found. Cannot sign baseline hashes.")
        sys.exit(1)

    with open(PRIVATE_KEY_FILE, 'rb') as private_key_file:
        private_key_data = private_key_file.read()

    private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())

    # Create digital signature of encrypted data using RSA-PSS and SHA256
    digital_signature_bytes = private_key.sign(
        encrypted_data_with_salt,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save the signature bytes to signature file
    with open(SIGNATURE_FILE, 'wb') as signature_file:
        signature_file.write(digital_signature_bytes)

    logging.info(f"Digital signature saved to '{SIGNATURE_FILE}'.")


# ~~~ INTEGRITY MONITOR LOOP ~~~ #

def close_game():
    """
    Simulates closing the game process after integrity violation.
    """
    simulated_process_id = random.randint(1000, 9999)
    logging.error(f"Critical files modified or missing. Terminating game process with PID: {simulated_process_id} (simulated).")
    time.sleep(3)
    logging.info(f"Game process {simulated_process_id} terminated.")
    sys.exit(1)


def run_integrity_check():
    """
    Main loop that continuously monitors game files against the verified baseline hashes.
    Terminates the program if any file integrity violation is detected.
    """
    baseline_hashes = verify_hashes()

    # If baseline does not exist, create it for first time
    if not baseline_hashes:
        logging.info("Baseline hashes not found. Creating new baseline from current game files...")

        baseline_hashes = scan_hashes(GAME_DIRECTORY, EXCLUDE_FOLDER_NAME)

        # Save encrypted baseline and signature
        save_hashes(baseline_hashes)

    while True:
        logging.info("Starting file integrity check cycle...")
        current_hashes = scan_hashes(GAME_DIRECTORY, EXCLUDE_FOLDER_NAME)

        # Identify any files that are new or modified
        changed_or_new_files = [
            file_path for file_path, current_hash in current_hashes.items()
            if file_path not in baseline_hashes or baseline_hashes[file_path] != current_hash
        ]

        # Identify any files missing from current scan but present in baseline
        missing_files = [
            file_path for file_path in baseline_hashes
            if file_path not in current_hashes
        ]

        if changed_or_new_files or missing_files:
            logging.error("File integrity violation detected!")

            if changed_or_new_files:
                logging.error(f"Files changed or added: {changed_or_new_files}")
            if missing_files:
                logging.error(f"Files missing: {missing_files}")

            close_game()

        logging.info("File integrity check passed. No changes detected.")
        time.sleep(30)  # Delay before next check


# =========================================== ENTRY POINT ========================================== #


if __name__ == "__main__":
    run_integrity_check()
