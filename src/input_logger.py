__LICENSE__ = "Proprietary / Educational Use"
__AUTHOR__  = "Michael Guajardo"
__PROJECT__ = "SentinelGuard"
__MODULE__  = "Input Logger"
__VERSION__ = "1.1.0"

# -- [IMPORTS] -- #

from collections import deque
import logging
import random
import time
import sys
import os
import ctypes

# -- [VARIABLES] -- #

DEBUG_MODE = True
DEV_MODE = True

LOG_FILE = r"C:\Users\mguaj\OneDrive\Desktop\Python Projects\SentinelGuard\SentinelGuard\logs\input_logger.log"

# Timing window (shorter = higher fidelity)
WINDOW_SECONDS = 1.5

# Detection thresholds
MAX_EVENTS_PER_SECOND = 20
MAX_CV_THRESHOLD = 0.15   # Coefficient of variation (normalized variance)
MIN_EVENTS_FOR_ANALYSIS = 8

SCAN_INTERVAL_SECONDS = 0.1  # 10Hz sampling (critical improvement)
JITTER_SECONDS = 0.05

# Mouse virtual key codes
MOUSE_KEYS = (0x01, 0x02)  # Left / Right mouse button

# -- [LOGGING SETUP] -- #

LogDirectory = os.path.dirname(LOG_FILE)

if LogDirectory and not os.path.exists(LogDirectory):
    os.makedirs(LogDirectory, exist_ok = True)

logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s [INPUT_DETECTOR] [%(levelname)s] %(message)s",
    handlers = [logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
)

logging.info("Input Logger Detector Module Loaded Successfully")

# -- [STATE TRACKING] -- #

InputEvents = deque()

# -- [FUNCTIONS] -- #

def Debug(Message: str) -> None:
    if DEBUG_MODE:
        print(f"[DEBUG] {Message}")

def TerminateGame(Event: str, Reason: str, ProcessID: int = -1) -> None:
    logging.critical(
        f"[{Event}] Terminating protected process "
        f"(PID = {ProcessID}) - Reason: {Reason}"
    )
    time.sleep(1.5)
    sys.exit(1)

# Collect keyboard and mouse input events
def CollectInputEvents() -> None:
    Timestamp = time.time()

    # Mouse buttons (auto-clickers almost always hit these)
    for Key in MOUSE_KEYS:
        State = ctypes.windll.user32.GetAsyncKeyState(Key)
        if State & 0x8000:
            InputEvents.append(Timestamp)

# Analyze timing patterns for automation
def AnalyzeInputPatterns() -> None:
    Now = time.time()

    # Trim window
    while InputEvents and InputEvents[0] < Now - WINDOW_SECONDS:
        InputEvents.popleft()

    Count = len(InputEvents)
    if Count < MIN_EVENTS_FOR_ANALYSIS:
        return

    Intervals = [
        InputEvents[i + 1] - InputEvents[i]
        for i in range(Count - 1)
    ]

    if not Intervals:
        return

    Mean = sum(Intervals) / len(Intervals)
    Variance = sum((x - Mean) ** 2 for x in Intervals) / len(Intervals)
    StdDev = Variance ** 0.5

    # Coefficient of Variation = normalized regularity signal
    CV = StdDev / Mean if Mean > 0 else 0
    Rate = Count / WINDOW_SECONDS

    Debug(
        f"Rate={Rate:.2f}/s CV={CV:.4f} Events={Count}"
    )

    if (
        Rate > MAX_EVENTS_PER_SECOND and
        CV < MAX_CV_THRESHOLD and
        not DEV_MODE
    ):
        TerminateGame(
            Event="FI-INP-001",
            Reason="Detected highly regular high-frequency input (likely auto-clicker or macro)"
        )

# -- [MONITOR LOOP] -- #

def Monitor() -> None:
    logging.info("Starting input behavior monitoring loop")

    while True:
        CollectInputEvents()
        AnalyzeInputPatterns()

        SleepTime = SCAN_INTERVAL_SECONDS + random.uniform(-JITTER_SECONDS, JITTER_SECONDS)
        time.sleep(max(0.02, SleepTime))

if __name__ == "__main__":
    Monitor()
