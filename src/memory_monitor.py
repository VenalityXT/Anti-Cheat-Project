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

# Log file path for memory monitoring
MEMORY_LOG_FILE = r"C:\Users\mguaj\OneDrive\Desktop\MyFPSGame\ClearSight\logs\memory_monitor.log"

# Monitoring interval in seconds
MONITOR_INTERVAL = 30

# ================================================== LOGGING SETUP ================================== #

# Ensure logs directory exists before FileHandler is created
log_dir = os.path.dirname(MEMORY_LOG_FILE)

if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    print(f"[MEMORY_MONITOR] Log directory '{log_dir}' did not exist. Created automatically.")

# Configure logging for memory monitoring
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MEMORY_MONITOR] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(MEMORY_LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
)

logging.info("Memory Monitor Module Loaded Successfully.")

# ================================================== MEMORY MONITORING ================================= #

def check_for_suspicious_memory_patterns():
    """
    Detect suspicious memory patterns indicating possible code injection or tampering.
    This function scans processes and checks for unusual memory areas with executable permissions.
    """
    try:
        # List all processes on the system
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Get the memory map of the process
                memory_maps = proc.memory_maps()
                for region in memory_maps:
                    # Ensure we access the attributes safely
                    if hasattr(region, 'path') and region.path:
                        # Check for executable permissions by checking if the region is marked as executable (contains 'x')
                        if 'x' in getattr(region, 'perms', ''):  # Safe check for permissions
                            suspicious_region = region.addr
                            logging.warning(f"Suspicious memory region found in process {proc.name()} (PID={proc.pid}): {suspicious_region}")
                            terminate_game("FI-MEM-001", f"Suspicious executable memory detected in process {proc.name()}.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Handle access-denied errors or non-existent processes
                continue
    except Exception as e:
        logging.error(f"Error scanning memory: {e}")
        terminate_game("FI-MEM-002", f"Memory scanning error: {e}")

def terminate_game(event: str, reason: str):
    """
    Simulate game termination due to suspicious memory pattern detection.
    In production, this would signal the main process or kernel module.
    """
    pid = random.randint(2000, 9999)
    logging.critical(f"[{event}] Terminating simulated game process (PID={pid}) — Reason: {reason}")
    time.sleep(1.5)
    sys.exit(1)

# ================================================== MONITORING LOOP ================================= #

def monitor_memory():
    """
    Main memory monitoring loop. Scans system memory at regular intervals to detect tampering or injections.
    """
    logging.info("Starting memory monitoring loop.")
    
    while True:
        check_for_suspicious_memory_patterns()  # Check memory for tampering patterns
        
        # Sleep for the defined interval before the next scan
        sleep_time = MONITOR_INTERVAL + random.randint(-5, 5)  # Add random jitter to avoid predictable scanning windows
        sleep_time = max(5, sleep_time)  # Ensure no zero/negative sleep time
        time.sleep(sleep_time)

# ================================================== ENTRY POINT ====================================== #

if __name__ == "__main__":
    monitor_memory()
