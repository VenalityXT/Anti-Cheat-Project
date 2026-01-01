__LICENSE__ = "Proprietary / Educational Use"
__AUTHOR__  = "Michael Guajardo"
__PROJECT__ = "SentinelGuard"
__MODULE__  = "Process Watcher"
__VERSION__ = "1.0.0"

# -- [IMPORTS] -- #

import logging
import psutil
import random
import time
import sys
import os

# -- [VARIABLES] -- #

DEBUG_MODE = True
DEV_MODE = True

LOG_FILE =r"C:\Users\mguaj\OneDrive\Desktop\Python Projects\SentinelGuard\SentinelGuard\logs\process_watcher.log"

BLACKLISTED_PROCESS_NAMES = {
    # Memory Editors / Generic Cheat Engines
    "Cheat Engine", "CheatEngine", "Cheat", "Cheat Engine 64", "CheatEngine64", "Cheat64", "Cheat Engine 32", "CheatEngine32", "Cheat32", "Memory Editor", "MemoryEditor", "Memory", "Mem Edit", "MemEdit", "Mem", "Scan Mem", "ScanMem", "Scan",

    # Debuggers / Reverse Engineering
    "X64 Debugger", "X64Debugger", "X64Dbg", "X32 Debugger", "X32Debugger", "X32Dbg", "Olly Debugger", "OllyDebugger", "OllyDbg", "IDA", "IDAPro", "IDA", "IDA 64", "IDA64", "IDA64", "Win Debugger", "WinDebugger", "WinDbg", "Debug View", "DebugView", "DbgView", "Process Hacker", "ProcessHacker", "ProcHack",

    # DLL Injectors / Loaders
    "DLL Injector", "DLLInjector", "Injector", "Manual Map", "ManualMap", "Mapper", "Manual Mapper", "ManualMapper", "Mapper", "Loader", "Cheat Loader", "CheatLoader", "Loader", "Payload", "Payload", "Payload", "Bootstrap", "Bootstrap", "Bootstrap",

    # Overlay / ESP-Style Processes
    "Overlay", "Overlay", "Overlay", "ESP", "ESP", "ESP", "Wall Hack", "WallHack", "Wall", "Radar", "Radar", "Radar", "Glow", "Glow", "Glow", "Visuals", "Visuals", "Visuals", "Render Hook", "RenderHook", "Render", "DX Overlay", "DXOverlay", "DX", "OpenGL Overlay", "OpenGLOverlay", "OpenGL",

    # Aimbot / Automation Indicators
    "Aim Bot", "AimBot", "Aimbot", "Trigger Bot", "TriggerBot", "Trigger", "Aim Assist", "AimAssist", "Assist", "Recoil Control", "RecoilControl", "Recoil", "Auto Fire", "AutoFire", "Fire", "Macro", "Macro", "Macro", "Auto Clicker", "AutoClicker", "Clicker", "Rapid Fire", "RapidFire", "Rapid",

    # Script Runners / Automation Engines
    "Auto Hotkey", "AutoHotkey", "AHK", "Script Engine", "ScriptEngine", "Script", "Macro Engine", "MacroEngine", "Macro", "Bot", "Bot", "Bot", "Farm Bot", "FarmBot", "Farm", "Input Emulator", "InputEmulator", "Input",

    # Network Manipulation / Packet Tools
    "Packet Editor", "PacketEditor", "Packet", "Packet Injector", "PacketInjector", "Injector", "Net Sniffer", "NetSniffer", "Sniffer", "Proxifier", "Proxifier", "Proxy", "MITM", "MITM", "MITM", "Lag Switch", "LagSwitch", "Lag", "Net Debug", "NetDebug", "NetDbg",
}

SUSPICIOUS_PROCESS_THRESHOLD = 2

SCAN_INTERVAL_SECONDS = 15
JITTER_SECONDS =  5

 # -- [LOGGING SETUP] -- #

LogDirectory = os.path.dirname(LOG_FILE)

if LogDirectory and not os.path.exists(LogDirectory):
    os.makedirs(LogDirectory, exist_ok = True)

logging.basicConfig(
    level = logging.INFO,
    format = "",
    handlers = [
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ],
)

logging.info("Process Watcher Module Loaded Successfully")

# -- [STATE TRACKING] -- #

SuspiciousProcessCounter = {}

# -- [FUNCTIONS] -- #

def Debug(Message: str) -> None:
    if DEBUG_MODE:
        print(f"[DEBUG] {Message}")
    
def TerminateGame(Event: str, Reason: str, ProcessID: int = -1) -> None:
    logging.critical(
        f"[{Event}] Terminating protected process ",
        f"(PID = {ProcessID}) - Reason: {Reason}"
    )

    time.sleep(1.5)
    sys.exit(1)

def EvaluateProcess(Process: psutil.Process) -> None:
    try:
        ProcessName = (Process.info.get("Name") or "").lower()
        PID = Process.pid

        if ProcessName in BLACKLISTED_PROCESS_NAMES:
            SuspiciousProcessCounter[PID] = SuspiciousProcessCounter.get(PID, 0) + 1

            if SuspiciousProcessCounter[PID] >= SUSPICIOUS_PROCESS_THRESHOLD:
                TerminateGame(
                    Event = "FI-PROC-001",
                    Reason = f"Blacklisted process detected: {ProcessName}",
                    ProcessID= PID
                )

            else:
                logging.warning(
                    f"Blacklisted process detected | "
                    f"Process = {ProcessName} PID = {PID} "
                    f"HitCount = {SuspiciousProcessCounter[PID]}"
                )
        
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return
    
    except Exception as Error:
        logging.error(f"Unhandled error while evaluating process: {Error}")

# -- [MONITOR LOOP] -- #

def Monitor() -> None:
    logging.info("Starting process watcher loop")

    while True:
        for Process in psutil.process_iter(["pid", "name"]):
            EvaluateProcess(Process)

        SleepTime = SCAN_INTERVAL_SECONDS + random.randint(-JITTER_SECONDS, JITTER_SECONDS)
        time.sleep(max(5, SleepTime))

if __name__ == "__main__":
    Monitor()
