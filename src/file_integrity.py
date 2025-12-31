__LICENSE__ = "Proprietary / Educational Use"
__AUTHOR__  = "Michael Guajardo"
__PROJECT__ = "SentinelGuard"
__MODULE__  = "File Integrity"
__VERSION__ = "1.2.5"

# -- [IMPORTS] -- #

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from typing import Dict

import logging
import secrets
import hashlib
import random
import ctypes
import time
import json
import sys
import os

# -- [VARIABLES] -- #

# Developer debug toggles
DEBUG_MODE = True
DEV_MODE = True

GAME_DIRECTORY = r"C:\Users\mguaj\OneDrive\Desktop\MyFPSGame"

SELF_HASH_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "self_integrity.bin")
SELF_HASH_SIGNATURE_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "self_integrity.sig")

BASELINE_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "hashes.bin")
BASELINE_SIGNATURE_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "data", "baseline", "hashes.sig")

PUBLIC_KEY_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "keys", "public_key.pem")
PRIVATE_KEY_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "keys", "private_key.pem")

LOG_FILE = os.path.join(GAME_DIRECTORY, "ClearSight", "logs", "file_integrity.log")

HONEYFILE_PATH = os.path.join(GAME_DIRECTORY, "honeypot.dat")

EXCLUDED_FOLDERS = ["ClearSight", "__pycache__", ".git"]
EXCLUDED_EXTENSIONS = [".tmp", ".log", ".cache"]

SCAN_INTERVAL_SECONDS = 30
JITTER_SECONDS = 15

# -- [LOGGING SETUP] -- #

LogDirectory = os.path.dirname(LOG_FILE)

if LogDirectory and not os.path.exists(LogDirectory):
    os.makedirs(LogDirectory, exist_ok = True)

logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s [FILE_INTEGRITY] [%(levelname)s] %(message)s",
    handlers = [logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)

logging.info("File Integrity Module Loaded Successfully")

# -- [FUNCTIONS] -- #

# Prints debug messages to the terminal if DEBUG_MODE is True
def Debug(Message: str) -> None:
    if DEBUG_MODE:
        print(Message)

# Disable check by setting DEV_MODE to True
def IsDebuggerPresent() -> bool:
    if sys.gettrace():
        return True

    try:
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0

    except Exception:
        return False

# Converts relative path -> absolute path while preventing:
#   - Duplicate Hash Evasion  
#   - Path Traversal Tricks
#   - Baseline Poisoning
def Canonical(Path: str) -> str:
    return os.path.abspath(os.path.normpath(Path))

def TerminateGame(Event: str, Reason: str, ProcessID: int = -1) -> None:
    logging.critical(
        f"[{Event}] Terminating protected process "
        f"(PID = {ProcessID}) - Reason: {Reason}"
    )

    # Small delay prevents immediate crash signatures and mirrors real world enforcement timing.
    time.sleep(1.5)
    sys.exit(1)

# -- [CRYPTOGRAPHY LAYER] -- #

# Obtains symmetric AES key from RSA private key using PBKDF2 (Does not store directly on disk)
def DeriveAESKeyFromPrivateKey() -> bytes:
    if not os.path.exists(PRIVATE_KEY_FILE):
        TerminateGame("FI-KEY-001", "Missing RSA private key")

    with open(PRIVATE_KEY_FILE, "rb") as File:
        KeyData = File.read()

    # Extracting the raw numerical values that constitutes the key
    PrivateKey = serialization.load_pem_private_key(KeyData, password = None)
    Numbers = PrivateKey.private_numbers()

    # Creating and feeding data to the hash object using SHA256
    #   - SHA256 is the industry standard providing the best mix of security and speed
    Digest = hashlib.sha256()
    Digest.update(Numbers.p.to_bytes((Numbers.p.bit_length() + 7) // 8, "big")) # Large prime factor
    Digest.update(Numbers.q.to_bytes((Numbers.q.bit_length() + 7) // 8, "big")) # Large prime factor
    Digest.update(Numbers.d.to_bytes((Numbers.d.bit_length() + 7) // 8, "big")) # The private exponent

    # Retrieve the binary digest
    Seed = Digest.digest()

    # Password Based Key Derivation Function 2
    KeyDerivationFunction = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = b"AntiCheatAESDerivationSalt",
        iterations = 100000,
        backend = default_backend()
    )

    return KeyDerivationFunction.derive(Seed)

# Encrypts structured integrity data using AES-GCM
def EncryptJSON(Data: dict, AESKey: bytes) -> bytes:
    JsonBytes = json.dumps(Data, indent = 4).encode("utf-8")

    Nonce = secrets.token_bytes(12)
    CipherObj = Cipher(algorithms.AES(AESKey), modes.GCM(Nonce), backend = default_backend())
    Encryptor = CipherObj.encryptor()

    CipherText = Encryptor.update(JsonBytes) + Encryptor.finalize()
    return Nonce + Encryptor.tag + CipherText

# Decrypts AES-GCM encrypted integrity data back into structured form
def DecryptJSON(Blob: bytes, AESKey: bytes) -> dict:
    Nonce, Tag, CipherText = Blob[:12], Blob[12:28], Blob[28:]

    CipherObj = Cipher(algorithms.AES(AESKey), modes.GCM(Nonce, Tag), backend = default_backend())
    Decryptor = CipherObj.decryptor()

    PlainText = Decryptor.update(CipherText) + Decryptor.finalize()
    return json.loads(PlainText.decode("utf-8"))

# Computes a SHA-256 hash of a file
def ComputeFileHash(Path: str) -> str:
    SHA = hashlib.sha256()

    with open(Path, "rb") as File:
        while Chunk := File.read(4096):
            SHA.update(Chunk)

    return SHA.hexdigest()

# Digitally signs integrity data using the RSA private key
def SignBlob(Blob: bytes, OutputSignaturePath: str) -> None:
    if not os.path.exists(PRIVATE_KEY_FILE):
        TerminateGame("FI-KEY-002", "Private key missing during signing")

    with open(PRIVATE_KEY_FILE, "rb") as File:
        PrivateKey = serialization.load_pem_private_key(
            File.read(), password = None
        )

    Signature = PrivateKey.sign(
        Blob,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(OutputSignaturePath, "wb") as SigFile:
        SigFile.write(Signature)

# Verifies the integrity of the anti-cheat module itself
def VerifySelfIntegrity() -> None:
    ScriptPath = Canonical(__file__)
    CurrentHash = ComputeFileHash(ScriptPath)

    if not os.path.exists(SELF_HASH_FILE):
        Blob = CurrentHash.encode("utf-8")
        open(SELF_HASH_FILE, "wb").write(Blob)
        SignBlob(Blob, SELF_HASH_SIGNATURE_FILE)
        return

    BaselineHash = open(SELF_HASH_FILE, "rb").read().decode("utf-8")

    if BaselineHash != CurrentHash:
        TerminateGame("FI-SI-002", "Anti-cheat module has been modified")

# -- [FILE SCANNING] -- #

def ShouldExclude(Path: str) -> bool:
    Lower = Path.lower()

    for Folder in EXCLUDED_FOLDERS:
        if Folder.lower() in Lower:
            return True

    _, Ext = os.path.splitext(Path)
    return Ext.lower() in EXCLUDED_EXTENSIONS

# Creates a file integrity snapshot through recursive scans and hashing
def ScanDirectory(Root: str) -> Dict[str, str]:
    Result, Files = {}, []

    for FileDirectory, _, Files in os.walk(Root):
        for File in Files:
            FullPath = Canonical(os.path.join(FileDirectory, File))

            # Filters out excluded files
            #   - Cache, logs, temp, etc.
            if not ShouldExclude(FullPath):
                Files.append(FullPath)

    # Shuffles file order to make timing based tampering harder
    random.shuffle(Files)

    for File in Files:
        try:
            Result[File] = ComputeFileHash(File)

        except Exception as Error:
            logging.error(f"Error hashing file {File}: {Error}")

    return Result

# -- [MONITOR LOOP] -- #

def Monitor() -> None:
    VerifySelfIntegrity()

    Baseline = ScanDirectory(GAME_DIRECTORY)

    while True:
        if IsDebuggerPresent() and not DEV_MODE:
            TerminateGame("FI-DBG-001", "Debugger detected")

        Current = ScanDirectory(GAME_DIRECTORY)

        if Baseline != Current:
            TerminateGame("FI-INT-001", "Integrity violation detected")

        SleepTime = SCAN_INTERVAL_SECONDS + random.randint(-JITTER_SECONDS, JITTER_SECONDS)
        time.sleep(max(5, SleepTime))

# -- [MONITOR] -- #

if __name__ == "__main__":
    Monitor()
