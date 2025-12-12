# Memory Monitor Module (`memory_monitor.py`)

A system memory monitoring module within the ClearSight Anti-Cheat framework.  
This module monitors system memory for suspicious patterns, detecting potential code injections or memory tampering attempts.

[View script](https://github.com/VenalityXT/Anti-Cheat-Project/blob/main/src/memory_monitor.py)

---

# Overview  

The Memory Monitor performs the following functions:

- Scans system memory for suspicious executable regions, indicating potential code injection or tampering  
- Detects memory regions with executable permissions in running processes  
- Logs suspicious memory detections at the `[WARNING]` level  
- Terminates the game process immediately when a suspicious memory pattern is found or when a memory scanning error occurs, using `[FATAL]` termination codes  
- Logs events using `[INFO]`, `[WARNING]`, `[ERROR]`, and `[FATAL]` levels  

When a validated memory tampering event is detected, the module triggers a simulated forced game termination recorded under `[FATAL]`.

---

# Memory Monitoring Architecture

The Memory Monitor uses `psutil` to iterate through running processes, checking their memory regions for unusual executable permissions that may indicate malicious code injection.

### Main Components:

1. **Memory Pattern Detection**  
   Scans each running process and its memory regions for executable sections marked with `'x'` permissions.  
   If detected, the region is flagged as suspicious.

2. **Logging**  
   The module logs all suspicious memory patterns detected using the Python `logging` module.  
   Logs are written to `memory_monitor.log` file.

3. **Game Termination**  
   If suspicious memory or an error is detected, the game is immediately terminated using a simulated process termination event.

---

# Memory Monitoring Process

The module works as follows:

1. **Memory Scan**  
   Scans all running processes' memory regions using `psutil` and checks for executable sections.  
   
2. **Logging**  
   Logs any suspicious memory regions found with the following message:
   
   `"[WARNING] Suspicious memory region found in process <process_name> (PID=<pid>): <memory_address>"`

3. **Termination**  
   If suspicious memory is found or a scanning error occurs, the game is terminated using the `terminate_game()` function with `[FATAL]` error codes.

---

# Memory Scan Error Handling

In case of any error during memory scanning (e.g., access-denied errors, missing process), the module will:

1. Log the error with a `[ERROR]` level message:
   
   `"[ERROR] Memory scanning error: <error_message>"`

2. Terminate the game using `[FATAL]` error code:
   
   `"[FATAL] FI-MEM-002 Memory scanning error: <error_message>"`

---

# Logging System

The module uses four severity levels:

- `[INFO]` — Normal operations, such as successful memory monitor startup or successful memory scan completion  
- `[WARNING]` — Suspicious activity detected, such as finding executable memory regions  
- `[ERROR]` — Memory scan errors or access-related issues  
- `[FATAL]` — Termination events due to suspicious memory or scanning errors

Example `[FATAL]` entry:

`2025-12-11 12:41:22,118 [MEMORY_MONITOR] [FATAL] [FI-MEM-001] Terminating simulated game process (PID=4211) — Reason: Suspicious executable memory detected.`

All logs are written to:

`ClearSight/logs/memory_monitor.log`

If the `logs/` directory does not exist, it is automatically created.

---

# Integrity Violation Codes

The module uses standardized event codes:

| Code         | Meaning                                    |
|--------------|--------------------------------------------|
| FI-MEM-001   | Suspicious executable memory detected      |
| FI-MEM-002   | Memory scanning error                      |
| FI-DBG-001   | Debugger detected                          |

---

# Development Workflow

During development:

- Enable `DEV_MODE = True`  
- Modify code freely  
- Logs are written at `[WARNING]` level for potential tampering  
- Debugger detection is ignored, and game termination becomes non-blocking  

Before production:

- Disable `DEV_MODE`  
- Regenerate final baselines  
- Protect key files and folders from modification  

---

# Runtime Flow

<img width="2039" height="862" alt="image" src="https://github.com/user-attachments/assets/94977ecb-7532-4eb2-a794-4fe5bba35a9d" />

---

# Summary

The Memory Monitor forms a critical part of the ClearSight Anti-Cheat system by providing:

- Memory tamper detection using executable permissions  
- Game termination when suspicious memory is detected  
- Robust logging to track all events  
- Error handling to gracefully terminate on scan issues

It is designed to be **secure**, **reliable**, and **production-ready**.

---

End of `docs/memory_monitor.md`.
