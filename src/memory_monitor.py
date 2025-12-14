# ==================================================================================================
# MEMORY_MONITOR.PY
#
# PURPOSE:
#   Monitors system memory for suspicious patterns, detecting potential code injections or memory tampering.
#   Designed to work alongside the file integrity module.
#
# DESIGN GOAL:
#   Highly secure, suitable for detecting in-memory tampering or malicious code injection attempts.
# =================================================================================================== #

import psutil
import logging
import random
import time
import sys
import os

# ================================================== CONSTANTS ====================================== #

# Developer debugging (extra internal prints)
DEBUG_MODE = False

# Log file path for memory monitoring
MEMORY_LOG_FILE = r"C:\Users\mguaj\OneDrive\Desktop\MyFPSGame\ClearSight\logs\memory_monitor.log"

# Monitoring interval in seconds
MONITOR_INTERVAL = 30

# ================================================== LOGGING SETUP ================================== #

log_dir = os.path.dirname(MEMORY_LOG_FILE)

if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    print(f"[MEMORY_MONITOR] Log directory '{log_dir}' did not exist. Created automatically.")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MEMORY_MONITOR] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(MEMORY_LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
)

logging.info("Memory Monitor Module Loaded Successfully.")

# ================================================== DEBUG HELPER =================================== #

def debug(msg: str):
    if DEBUG_MODE:
        print(f"[DEBUG] {msg}")

# ================================================== MEMORY MONITORING ================================= #

def check_for_suspicious_memory_patterns():
    """
    Detect suspicious memory patterns indicating possible code injection.
    Scans processes for executable memory regions.
    """
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                debug(f"Scanning process: {proc.name()} (PID={proc.pid})")

                memory_maps = proc.memory_maps()

                for region in memory_maps:
                    # Debug display full memory map entry
                    if DEBUG_MODE:
                        debug(f"Region: addr={getattr(region, 'addr', '')}, "
                              f"perms={getattr(region, 'perms', '')}, "
                              f"path={getattr(region, 'path', '')}")

                    # Skip regions without a path
                    if not hasattr(region, 'path'):
                        continue

                    # Look for executable regions
                    perms = getattr(region, 'perms', '')
                    if 'x' in perms:
                        suspicious_region = getattr(region, 'addr', 'UNKNOWN_ADDR')

                        debug(f"""
--- SUSPICIOUS EXECUTABLE MEMORY REGION ---
Process: {proc.name()} (PID={proc.pid})
Region Address: {suspicious_region}
Permissions: {perms}
Path: {region.path}
-------------------------------------------
""")

                        logging.warning(
                            f"Suspicious executable memory region found in {proc.name()} "
                            f"(PID={proc.pid}): {suspicious_region}"
                        )

                        terminate_game("FI-MEM-001",
                                       f"Suspicious executable memory detected in process {proc.name()}.")

            except psutil.AccessDenied:
                debug(f"Access denied when scanning process {proc.name()} (PID={proc.pid})")
                continue

            except psutil.NoSuchProcess:
                debug(f"Process disappeared before scanning completed.")
                continue

            except Exception as e:
                debug(f"Unhandled error while scanning process {proc.name()} (PID={proc.pid}): {e}")
                logging.error(f"Error reading memory maps for {proc.name()} (PID={proc.pid}): {e}")
                continue

    except Exception as e:
        debug(f"""
--- MEMORY SCANNING FATAL ERROR ---
Error: {e}
-----------------------------------
""")
        logging.error(f"Error scanning memory: {e}")
        terminate_game("FI-MEM-002", f"Memory scanning error: {e}")

def terminate_game(event: str, reason: str):
    """
    Simulate game termination due to suspicious memory detection.
    """
    pid = random.randint(2000, 9999)

    debug(f"""
--- GAME TERMINATION TRIGGERED ---
Event: {event}
Reason: {reason}
Simulated PID: {pid}
----------------------------------
""")

    logging.critical(f"[{event}] Terminating simulated game process (PID={pid}) — Reason: {reason}")
    time.sleep(1.5)
    sys.exit(1)

# ================================================== MONITORING LOOP ================================= #

def monitor_memory():
    """
    Main memory monitoring loop.
    """
    logging.info("Starting memory monitoring loop.")

    while True:
        debug("Running memory scan...")
        check_for_suspicious_memory_patterns()

        sleep_time = MONITOR_INTERVAL + random.randint(-5, 5)
        sleep_time = max(5, sleep_time)

        debug(f"Sleeping for {sleep_time} seconds before next scan...")
        time.sleep(sleep_time)

# ================================================== ENTRY POINT ====================================== #

if __name__ == "__main__":
    monitor_memory()
