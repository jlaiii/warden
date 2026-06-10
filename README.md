# Hermes GMER — Windows Anti-Rootkit Scanner

A Python-based anti-rootkit scanner with a Windows Task Manager-style GUI.  
Cross-view detection engine inspired by GMER — compares multiple system enumeration methods to find rootkits hiding processes, threads, modules, services, files, registry keys, and more.

## Features

### Task Manager (clone)
- 7 standard tabs: Processes, Performance, App History, Details, Services, Startup, Users
- **Smart group mode** — same-name processes auto-collapsed (like real Task Manager)
- Process actions: End Task, End Tree, Priority, Affinity, Create Dump, Wait Chain

### Security Scanner (GMER-style)
- **12 scanner categories** with cross-view detection:
  - Hidden Processes — `psutil` vs `NtQuerySystemInformation`
  - Hidden Threads — `CreateToolhelp32Snapshot` vs `NtQuerySystemInformation`
  - Hidden Modules/DLLs — `Module32First` vs `SystemModuleInformation`
  - Hidden Services — SCM vs raw registry
  - Hidden Files — `FindFirstFile` vs `NtQueryDirectoryFile`
  - Hidden Disk Sectors — MBR boot signature check via `\\.\PhysicalDrive0`
  - Alternate Data Streams — `FindFirstStreamW` on system directories
  - Hidden Registry Keys — `RegEnumKey` vs `NtEnumerateKey`
  - Inline Hooks — on-disk `.text` section vs in-memory code comparison
  - SSDT / IDT / IRP Hooks — informational (requires kernel driver)

### Anti-Detection
- Randomized process mutex (UUID-based, different every launch)
- String obfuscation (XOR + base64 for sensitive literals)
- Temp-copy self-protection (random name + different hash)
- Inspired by GMER's approach of preventing malware from blocking by name/signature

## Requirements

- Windows 10 / 11 (64-bit)
- Python 3.10+
- Administrator privileges (for full scanning)

### Dependencies
```
psutil>=5.9.0
```

## Quick Start

### GUI Mode (Task Manager + Security)
```bash
python task_manager.py
```

### GUI Mode (Scanner Only)
```bash
python hermes_gmer.py
```

### CLI Mode
```bash
# Quick scan (5 priority scanners)
python hermes_gmer.py --cli --quick

# Full scan (all 12 scanners)
python hermes_gmer.py --cli

# JSON output
python hermes_gmer.py --json -o report.json
```

## Scanner Categories

| Scanner | Severity | Admin Required | Description |
|---------|----------|---------------|-------------|
| Hidden Processes | CRITICAL | Yes | Cross-view of psutil vs NtQuerySystemInformation |
| Hidden Threads | CRITICAL | Yes | Cross-view of ToolHelp32 vs NT syscall |
| Hidden Modules | HIGH | Yes | Kernel module cross-view + suspicious DLL detection |
| Hidden Services | HIGH | No | SCM vs registry cross-view |
| Hidden Files | HIGH | No | FindFirstFile vs NtQueryDirectoryFile |
| Disk Sectors | HIGH | Yes | MBR boot signature check |
| ADS Scanner | MEDIUM | No | Alternate Data Stream detection |
| Hidden Registry | HIGH | No | RegEnumKey vs NtEnumerateKey |
| Inline Hooks | CRITICAL | No | On-disk vs in-memory .text comparison |
| SSDT Hooks | INFO | — | Requires kernel driver |
| IDT Hooks | INFO | — | Requires kernel driver |
| IRP Hooks | INFO | — | Requires kernel driver |

## Architecture

```
hermes-gmer/
  task_manager.py          # Main app — 8-tab Task Manager with Security tab
  sec_scanner_engine.py    # Core — all 12 scanners, NT API wrappers, data model
  hermes_gmer.py           # Standalone scanner (CLI + GUI modes)
  anti_detect.py           # Anti-detection system (obfuscation, mutex, temp-copy)
  requirements.txt
```

## How It Works

Rootkits hide by hooking user-mode API functions (e.g., `NtQuerySystemInformation` in ntdll.dll). When a tool calls a hooked function, the rootkit filters out its own entries from the results.

**Cross-view detection** bypasses this by calling the same function through two different paths:
1. The user-mode API (via psutil / standard Win32 calls) — which may be hooked
2. A direct NT syscall (via ctypes → ntdll.dll) — which may skip user-mode hooks

Any entry visible via the NT path but missing from the user-mode path is a candidate hidden item.

## Limitations

- **Kernel-level hooks** (SSDT, IDT, IRP) cannot be detected from user-mode Python. These require a signed kernel driver, which this scanner does not include. These scanners show INFO-level findings explaining the limitation.
- **64-bit PatchGuard** prevents reading kernel memory directly. This scanner uses only documented, legal API calls.
- **False positives** can occur if processes/services are created/destroyed between the two enumeration calls. The scanner mitigates this by collecting both data sets as close together as possible.

## License

MIT

## Credits

Inspired by:
- [GMER](http://www.gmer.net/) — the original anti-rootkit scanner
- Windows Internals by Mark Russinovich
- psutil library by Giampaolo Rodola
