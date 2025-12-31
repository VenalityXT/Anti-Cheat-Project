__LICENSE__ = "Proprietary / Educational Use"
__AUTHOR__ = "Michael Guajardo"
__PROJECT__ = "SentinelGuard"
__CREATED__ = "12-2025"
__VERSION__ = "1.1.2"

# -- [IMPORTS] -- #

from collections import defaultdict

import logging
import random
import psutil
import time
import sys
import os

# -- [VARIABLES] -- #

MEMORY_LOG_FILE = r"C:\Users\mguaj\OneDrive\Desktop\MyFPSGame\ClearSight\logs\memory_monitor.log"
TARGET_PROCESS_NAMES = {"Game.exe"}
SUSPICIOUS_HIT_THRESHOLD = 3
MONITOR_INTERVAL = 30

# -- [LOGGING SETUP] -- #

LogDirectory = os.path.dirname(MEMORY_LOG_FILE)

if LogDirectory and not os.path.exists(LogDirectory):
    os.makedirs(LogDirectory, exist_ok = True)

logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s [MEMORY_MONITOR] [%(levelname)s] %(message)s",
    handlers = [logging.FileHandler(MEMORY_LOG_FILE), logging.StreamHandler(sys.stdout)]
)

logging.info("Memory Monitor Module Loaded Successfully!")

# -- [STATE TRACKING SETUP] -- #

# Track suspicious hits per PID across scans to enable behavioral enforcement
SuspiciousHitCounter = defaultdict(int)

# -- [FUNCTIONS] -- #

def CheckMemoryPatterns():
    for Process in psutil.process_iter(['pid', 'name']):

        try:
            ProcessName = Process.info.get('name')

            # Restricts scanning to listed application(s) only
            if ProcessName not in TARGET_PROCESS_NAMES:
                continue
            PID = Process.pid
            logging.debug(f"Scanning process {ProcessName} (PID = {PID})")

            try:
                MemoryMaps = Process.memory_maps()
                
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                logging.debug(f"Unable to access memory maps for {ProcessName} (PID = {PID})")
                continue

            for Region in MemoryMaps:
                Address = getattr(Region, "addr", "UNKNOWN")
                Permissions = getattr(Region, "perms", "")
                Path = getattr(Region, "path", "") or ""

                # Executable memory alone is normal
                # Suspicion arises when memory is:
                #   - Executable + writable (RWX)
                #   - Executable with no backing file (anonymous injection)
                IsExecutable = 'x' in Permissions
                IsWritable = 'w' in Permissions
                IsAnonymous = Path.strip() == ""

                if IsExecutable and (IsWritable or IsAnonymous):
                    SuspiciousHitCounter[PID] += 1

                    logging.warning(
                        f"Suspicious memory region detected | "
                        f"Process = {ProcessName} PID = {PID} "
                        f"Addr = {Address} Perms = {Permissions} Path = {Path or '[anonymous]'} "
                        f"HitCount={SuspiciousHitCounter[PID]}"
                    )

                    # Require repeated detections before enforcement.
                    if SuspiciousHitCounter[PID] >= SUSPICIOUS_HIT_THRESHOLD:
                        TerminateGame(
                            Event = "FI-MEM-001",
                            Reason =(
                                "Repeated detection of suspicious executable memory "
                                f"(RWX or anonymous) in process {ProcessName}"
                            ),
                            ProcessID = PID
                        )

        except psutil.NoSuchProcess:
            continue
        
        except Exception as Error:
            logging.error(f"Unhandled error while scanning memory: {Error}")


def TerminateGame(Event: str, ProcessID: int, Reason: str) -> None:
    logging.critical(
        f"[{Event}] Terminating protected process "
        f"(PID = {ProcessID}) - Reason: {Reason}"
    )

    # Small delay prevents immediate crash signatures and mirrors real world enforcement timing.
    time.sleep(1.5)
    sys.exit(1)


def MemoryMonitor() -> None:
    logging.info("Starting memory monitoring loop")

    while True:
        CheckMemoryPatterns()

        # Using jitter to reduce timing based evasion
        SleepTime = random.uniform(
            MONITOR_INTERVAL * 0.8,
            MONITOR_INTERVAL * 1.3
        )

        # :.0f formats time as a whole number
        logging.debug(f"Sleeping for {SleepTime:.0f} seconds before next scan.")
        time.sleep(SleepTime)

# -- [END] -- #

if __name__ == "__main__":
    MemoryMonitor()
