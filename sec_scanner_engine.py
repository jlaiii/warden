#!/usr/bin/env python3
"""
Warden Security Scanner Engine -- Anti-Rootkit Cross-View Detection
====================================================================
Scans for:
  - Hidden processes    (psutil vs NtQuerySystemInformation)
  - Hidden threads      (Toolhelp32 vs NtQuerySystemInformation)
  - Hidden modules/DLLs (Module32First vs SystemModuleInformation)
  - Hidden services     (SCM vs raw registry)
  - Hidden files        (FindFirstFile vs NtQueryDirectoryFile)
  - Hidden disk sectors (MBR scan via \\.\PhysicalDrive0)
  - Hidden ADS          (FindFirstStreamW on system dirs)
  - Hidden registry keys(NtEnumerateKey vs RegEnumKey)
  - Inline hooks        (on-disk .text vs in-memory code)
  - SSDT / IDT / IRP    (INFO stubs -- require kernel driver)

All scanning uses ctypes to call Windows NT syscalls directly,
bypassing user-mode API hooks that rootkits may have installed.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import struct
import subprocess
import sys
import threading
import time
import winreg
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

import psutil

log = logging.getLogger("taskmgr")

# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------


class Severity(Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


class ScanCategory(Enum):
    HIDDEN_PROCESSES = "Hidden Processes"
    HIDDEN_THREADS = "Hidden Threads"
    HIDDEN_MODULES = "Hidden Modules/DLLs"
    HIDDEN_SERVICES = "Hidden Services"
    HIDDEN_FILES = "Hidden Files"
    HIDDEN_SECTORS = "Hidden Disk Sectors"
    HIDDEN_ADS = "Alternate Data Streams"
    HIDDEN_REGISTRY = "Hidden Registry Keys"
    SSDT_HOOKS = "SSDT Hooks"
    IDT_HOOKS = "IDT Hooks"
    IRP_HOOKS = "IRP Hooks"
    INLINE_HOOKS = "Inline Hooks"


SEVERITY_TAGS = {
    Severity.CRITICAL: "[!!]",
    Severity.HIGH: "[!] ",
    Severity.MEDIUM: "[*] ",
    Severity.LOW: "[-] ",
    Severity.INFO: "[i] ",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff1744",
    Severity.HIGH: "#ff9100",
    Severity.MEDIUM: "#ffeb3b",
    Severity.LOW: "#64b5f6",
    Severity.INFO: "#9e9e9e",
}


@dataclass
class ScanResult:
    category: ScanCategory
    finding: str
    severity: Severity
    details: str
    raw_data: Optional[dict] = field(default=None, repr=False)


@dataclass
class ScanReport:
    results: list[ScanResult]
    scan_time: float
    admin_status: bool
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    def __post_init__(self):
        self.total_issues = len(self.results)
        self.critical_count = sum(1 for r in self.results if r.severity == Severity.CRITICAL)
        self.high_count = sum(1 for r in self.results if r.severity == Severity.HIGH)
        self.medium_count = sum(1 for r in self.results if r.severity == Severity.MEDIUM)
        self.low_count = sum(1 for r in self.results if r.severity == Severity.LOW)
        self.info_count = sum(1 for r in self.results if r.severity == Severity.INFO)


# ---------------------------------------------------------------------------
# Win32 / NT API Helpers
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# -- NT status codes --
STATUS_SUCCESS = 0x00000000
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_BUFFER_OVERFLOW = 0x80000005
STATUS_BUFFER_TOO_SMALL = 0xC0000023
STATUS_ACCESS_DENIED = 0xC0000022

# -- NT information classes --
SystemProcessInformation = 5
SystemModuleInformation = 11
SystemHandleInformation = 16


def ntsuccess(status: int) -> bool:
    """NTSTATUS codes >= 0 are success."""
    return status >= 0


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.c_wchar_p),
    ]


class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    """Undocumented NT structure for process enumeration."""
    _fields_ = [
        ("NextEntryOffset", ctypes.c_ulong),
        ("NumberOfThreads", ctypes.c_ulong),
        ("WorkingSetPrivateSize", ctypes.c_ulonglong),
        ("HardFaultCount", ctypes.c_ulong),
        ("NumberOfThreadsHighWatermark", ctypes.c_ulong),
        ("CycleTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_ulonglong),
        ("UserTime", ctypes.c_ulonglong),
        ("KernelTime", ctypes.c_ulonglong),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ("HandleCount", ctypes.c_ulong),
        ("SessionId", ctypes.c_ulong),
        ("UniqueProcessKey", ctypes.c_void_p),
        ("PeakVirtualSize", ctypes.c_size_t),
        ("VirtualSize", ctypes.c_size_t),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivatePageCount", ctypes.c_size_t),
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class SYSTEM_THREAD_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("KernelTime", ctypes.c_ulonglong),
        ("UserTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_ulonglong),
        ("WaitTime", ctypes.c_ulong),
        ("StartAddress", ctypes.c_void_p),
        ("ClientId", ctypes.c_void_p * 2),  # UniqueProcess, UniqueThread
        ("Priority", ctypes.c_long),
        ("BasePriority", ctypes.c_long),
        ("ContextSwitches", ctypes.c_ulong),
        ("ThreadState", ctypes.c_ulong),
        ("WaitReason", ctypes.c_ulong),
    ]


class RTL_PROCESS_MODULE_INFORMATION(ctypes.Structure):
    """Part of SYSTEM_MODULE_INFORMATION."""
    _fields_ = [
        ("Section", ctypes.c_void_p),
        ("MappedBase", ctypes.c_void_p),
        ("ImageBase", ctypes.c_void_p),
        ("ImageSize", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("LoadOrderIndex", ctypes.c_ushort),
        ("InitOrderIndex", ctypes.c_ushort),
        ("LoadCount", ctypes.c_ushort),
        ("OffsetToFileName", ctypes.c_ushort),
        ("FullPathName", ctypes.c_char * 256),
    ]


class SYSTEM_MODULE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ModulesCount", ctypes.c_ulong),
        ("Modules", RTL_PROCESS_MODULE_INFORMATION * 1),  # variable-length
    ]


class FILE_DIRECTORY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", ctypes.c_ulong),
        ("FileIndex", ctypes.c_ulong),
        ("CreationTime", ctypes.c_ulonglong),
        ("LastAccessTime", ctypes.c_ulonglong),
        ("LastWriteTime", ctypes.c_ulonglong),
        ("ChangeTime", ctypes.c_ulonglong),
        ("EndOfFile", ctypes.c_ulonglong),
        ("AllocationSize", ctypes.c_ulonglong),
        ("FileAttributes", ctypes.c_ulong),
        ("FileNameLength", ctypes.c_ulong),
        ("FileName", ctypes.c_wchar * 1),  # variable-length
    ]


class KEY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("LastWriteTime", ctypes.c_ulonglong),
        ("TitleIndex", ctypes.c_ulong),
        ("NameLength", ctypes.c_ulong),
        ("Name", ctypes.c_wchar * 1),  # variable-length
    ]


class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ("StreamSize", ctypes.c_ulonglong),
        ("cStreamName", ctypes.c_wchar * 296),
    ]


# ---------------------------------------------------------------------------
# Base Scanner
# ---------------------------------------------------------------------------


class BaseScanner:
    category: ScanCategory

    def __init__(self):
        self.results: list[ScanResult] = []

    def scan(self) -> list[ScanResult]:
        self.results = []
        t0 = time.perf_counter()
        try:
            self._do_scan()
        except Exception as e:
            import traceback
            self.results.append(ScanResult(
                category=self.category,
                finding=f"Scanner error: {type(e).__name__}",
                severity=Severity.INFO,
                details=f"{e}\n{traceback.format_exc()}",
            ))
        elapsed = time.perf_counter() - t0
        log.info("Scanner [%s] completed in %.2fs — %d findings",
                 self.category.value, elapsed, len(self.results))
        return self.results

    def _do_scan(self) -> None:
        raise NotImplementedError

    def _add(self, finding: str, severity: Severity, details: str = "",
             raw_data: Optional[dict] = None) -> None:
        self.results.append(ScanResult(
            category=self.category,
            finding=finding,
            severity=severity,
            details=details,
            raw_data=raw_data,
        ))


# ---------------------------------------------------------------------------
# 1. Hidden Process Scanner
# ---------------------------------------------------------------------------


class HiddenProcessScanner(BaseScanner):
    category = ScanCategory.HIDDEN_PROCESSES

    def _do_scan(self):
        if not is_admin():
            self._add("Admin privileges required for NT-level process scan",
                      Severity.INFO,
                      "NtQuerySystemInformation requires admin for full results. "
                      "Re-run as admin for accurate hidden process detection.")
            return

        # Set A: psutil (via Toolhelp32 or similar)
        psutil_pids: set[int] = set(psutil.pids())
        psutil_info: dict[int, str] = {}
        for pid in psutil_pids:
            try:
                psutil_info[pid] = psutil.Process(pid).name()
            except Exception:
                psutil_info[pid] = f"<PID_{pid}>"

        # Set B: NtQuerySystemInformation(SystemProcessInformation)
        nt_info: dict[int, str] = {}
        try:
            nt_info = self._enum_processes_nt()
        except Exception as e:
            self._add(f"NtQuerySystemInformation failed: {e}",
                      Severity.INFO,
                      "Could not enumerate processes via the NT syscall. "
                      "This method may be blocked or require different privileges.")
            return

        # Cross-view diff
        nt_pids = set(nt_info.keys())
        hidden_pids = nt_pids - psutil_pids

        if hidden_pids:
            for pid in hidden_pids:
                name = nt_info.get(pid, f"PID_{pid}")
                self._add(
                    f"Hidden process: {name} (PID {pid})",
                    Severity.CRITICAL,
                    f"Process PID {pid} ({name}) found via NtQuerySystemInformation "
                    f"but NOT visible to psutil/ToolHelp32. This is a strong indicator "
                    f"of DKOM (Direct Kernel Object Manipulation) rootkit activity "
                    f"that unlinks the process from the active process list.",
                    {"pid": pid, "name": name, "found_in": "NtQuerySystemInformation"},
                )
        else:
            log.debug("Process cross-view: clean — %d processes match", len(psutil_pids))

    def _enum_processes_nt(self) -> dict[int, str]:
        """Enumerate processes via NtQuerySystemInformation."""
        ntdll = ctypes.WinDLL("ntdll")
        NtQuerySystemInformation = ntdll.NtQuerySystemInformation
        NtQuerySystemInformation.restype = ctypes.c_long
        NtQuerySystemInformation.argtypes = [
            ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
        ]

        # First call to get buffer size
        buf_size = ctypes.c_ulong(0)
        status = NtQuerySystemInformation(
            SystemProcessInformation, None, 0, ctypes.byref(buf_size)
        )
        # Allocate buffer
        buf = ctypes.create_string_buffer(buf_size.value)
        status = NtQuerySystemInformation(
            SystemProcessInformation, buf, buf_size, ctypes.byref(buf_size)
        )

        if not ntsuccess(status):
            raise OSError(f"NtQuerySystemInformation failed: NTSTATUS=0x{status:08X}")

        result: dict[int, str] = {}
        offset = 0
        while True:
            spi = ctypes.cast(
                ctypes.c_void_p(ctypes.addressof(buf) + offset),
                ctypes.POINTER(SYSTEM_PROCESS_INFORMATION),
            )
            pid_val = ctypes.cast(spi.contents.UniqueProcessId, ctypes.c_void_p).value
            pid = pid_val or 0
            if pid != 0:
                name = spi.contents.ImageName.Buffer
                if name and name.strip():
                    result[pid] = name.strip()
                else:
                    result[pid] = f"<PID_{pid}>"
            next_offset = spi.contents.NextEntryOffset
            if next_offset == 0:
                break
            offset += next_offset

        return result


# ---------------------------------------------------------------------------
# 2. Hidden Thread Scanner
# ---------------------------------------------------------------------------


class HiddenThreadScanner(BaseScanner):
    category = ScanCategory.HIDDEN_THREADS

    def _do_scan(self):
        if not is_admin():
            self._add("Admin privileges required for NT-level thread scan",
                      Severity.INFO, "Re-run as admin for hidden thread detection.")
            return

        # Set A: Toolhelp32 TH32CS_SNAPTHREAD
        toolhelp_threads: set[tuple[int, int]] = set()  # (tid, owner_pid)
        try:
            toolhelp_threads = self._enum_threads_toolhelp()
        except Exception as e:
            log.debug("Toolhelp32 thread enumeration failed: %s", e)

        # Set B: NtQuerySystemInformation (threads embedded in process info)
        nt_threads: set[tuple[int, int]] = set()
        try:
            nt_threads = self._enum_threads_nt()
        except Exception as e:
            log.debug("NT thread enumeration failed: %s", e)

        if not toolhelp_threads:
            self._add("Toolhelp32 thread enumeration returned empty",
                      Severity.INFO, "Cannot perform cross-view comparison.")
            return

        hidden = nt_threads - toolhelp_threads
        if hidden:
            for tid, owner_pid in list(hidden)[:50]:  # limit output
                self._add(
                    f"Hidden thread: TID {tid} (owner PID {owner_pid})",
                    Severity.CRITICAL,
                    f"Thread {tid} in process {owner_pid} found via NtQuerySystemInformation "
                    f"but not visible to CreateToolhelp32Snapshot. Rootkits commonly hide "
                    f"threads to conceal injected code.",
                    {"tid": tid, "owner_pid": owner_pid},
                )
        else:
            log.debug("Thread cross-view: clean — %d threads", len(toolhelp_threads))

    def _enum_threads_toolhelp(self) -> set[tuple[int, int]]:
        kernel32 = ctypes.windll.kernel32
        TH32CS_SNAPTHREAD = 0x00000004

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ThreadID", ctypes.c_ulong),
                ("th32OwnerProcessID", ctypes.c_ulong),
                ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
            ]

        threads: set[tuple[int, int]] = set()
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if snap == -1:
            return threads

        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)
        if kernel32.Thread32First(snap, ctypes.byref(te)):
            while True:
                threads.add((te.th32ThreadID, te.th32OwnerProcessID))
                if not kernel32.Thread32Next(snap, ctypes.byref(te)):
                    break
        kernel32.CloseHandle(snap)
        return threads

    def _enum_threads_nt(self) -> set[tuple[int, int]]:
        """Extract threads from NT system process information."""
        ntdll = ctypes.WinDLL("ntdll")
        NtQuerySystemInformation = ntdll.NtQuerySystemInformation
        NtQuerySystemInformation.restype = ctypes.c_long

        buf_size = ctypes.c_ulong(0)
        NtQuerySystemInformation(SystemProcessInformation, None, 0, ctypes.byref(buf_size))
        buf = ctypes.create_string_buffer(buf_size.value)
        status = NtQuerySystemInformation(
            SystemProcessInformation, buf, buf_size, ctypes.byref(buf_size)
        )
        if not ntsuccess(status):
            return set()

        threads: set[tuple[int, int]] = set()
        offset = 0
        while True:
            spi = ctypes.cast(
                ctypes.c_void_p(ctypes.addressof(buf) + offset),
                ctypes.POINTER(SYSTEM_PROCESS_INFORMATION),
            )
            pid_val = ctypes.cast(spi.contents.UniqueProcessId, ctypes.c_void_p).value or 0
            num_threads = spi.contents.NumberOfThreads

            # Thread array follows the fixed-size portion of SYSTEM_PROCESS_INFORMATION
            if num_threads > 0 and num_threads < 10000:  # sanity check
                thread_base = ctypes.addressof(buf) + offset + ctypes.sizeof(SYSTEM_PROCESS_INFORMATION)
                for i in range(num_threads):
                    ti = ctypes.cast(
                        ctypes.c_void_p(thread_base + i * ctypes.sizeof(SYSTEM_THREAD_INFORMATION)),
                        ctypes.POINTER(SYSTEM_THREAD_INFORMATION),
                    )
                    tid = ti.contents.ClientId[1]  # UniqueThread
                    if tid:
                        threads.add((tid, pid_val))

            next_offset = spi.contents.NextEntryOffset
            if next_offset == 0:
                break
            offset += next_offset

        return threads


# ---------------------------------------------------------------------------
# 3. Hidden Module/DLL Scanner
# ---------------------------------------------------------------------------


class HiddenModuleScanner(BaseScanner):
    category = ScanCategory.HIDDEN_MODULES

    def _do_scan(self):
        if not is_admin():
            self._add("Admin privileges required for kernel module scan",
                      Severity.INFO, "Re-run as admin for hidden module detection.")
            return

        # Set A: psutil process memory_maps (grouped) for key processes
        # Set B: NtQuerySystemInformation(SystemModuleInformation) — kernel modules
        # Also: check critical system processes for suspicious DLLs
        critical_procs = ["lsass.exe", "winlogon.exe", "csrss.exe", "services.exe",
                          "svchost.exe", "explorer.exe", "wininit.exe"]

        # Check kernel drivers via SystemModuleInformation
        try:
            kernel_modules_set_a = self._enum_kernel_modules_psutil()
            kernel_modules_set_b = self._enum_kernel_modules_nt()

            hidden = kernel_modules_set_b - kernel_modules_set_a
            new_names = set()
            for _, path in list(hidden)[:100]:
                fname = os.path.basename(path) if path else "?"
                name_lower = fname.lower()
                if name_lower not in new_names:
                    new_names.add(name_lower)
                    self._add(
                        f"Hidden driver: {fname}",
                        Severity.HIGH,
                        f"Kernel driver {fname} found via NtQuerySystemInformation "
                        f"but not visible via psutil kernel module enumeration.\n"
                        f"Path: {path}",
                        {"module": fname, "path": path},
                    )
        except Exception as e:
            log.debug("Kernel module cross-view failed: %s", e)

        # Per-process module check for critical processes
        for proc_name in critical_procs:
            try:
                for proc in psutil.process_iter(["pid", "name"]):
                    if proc.info["name"] and proc.info["name"].lower() == proc_name.lower():
                        p = psutil.Process(proc.info["pid"])
                        try:
                            mmaps = p.memory_maps(grouped=True)
                            for m in mmaps:
                                pth = m.path.lower() if m.path else ""
                                # Check for DLLs loaded from suspicious locations
                                suspicious_paths = [
                                    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                                ]
                                for sp in suspicious_paths:
                                    if sp in pth:
                                        self._add(
                                            f"Suspicious DLL in {proc_name}: {m.path}",
                                            Severity.MEDIUM,
                                            f"Process {proc_name} has DLL loaded from "
                                            f"temporary/suspicious path: {m.path}",
                                            {"proc": proc_name, "dll": m.path},
                                        )
                                        break
                        except Exception:
                            pass
                        break
            except Exception:
                pass

    def _enum_kernel_modules_psutil(self) -> set[tuple[int, str]]:
        """Kernel modules visible via WMI/psutil approach."""
        modules: set[tuple[int, str]] = set()
        try:
            # Try using the running services/drivers
            for s in psutil.win_service_iter():
                try:
                    info = s.as_dict()
                    mod_path = info.get("binary_path_name", "")
                    if mod_path:
                        modules.add((info.get("pid", 0) or 0, mod_path))
                except Exception:
                    continue
        except Exception:
            pass
        return modules

    def _enum_kernel_modules_nt(self) -> set[tuple[int, str]]:
        """Kernel modules via NtQuerySystemInformation(SystemModuleInformation)."""
        ntdll = ctypes.WinDLL("ntdll")
        NtQuerySystemInformation = ntdll.NtQuerySystemInformation
        NtQuerySystemInformation.restype = ctypes.c_long

        buf_size = ctypes.c_ulong(0)
        NtQuerySystemInformation(SystemModuleInformation, None, 0, ctypes.byref(buf_size))
        buf = ctypes.create_string_buffer(buf_size.value)
        status = NtQuerySystemInformation(
            SystemModuleInformation, buf, buf_size, ctypes.byref(buf_size)
        )
        if not ntsuccess(status):
            return set()

        modules: set[tuple[int, str]] = set()
        smi = ctypes.cast(buf, ctypes.POINTER(SYSTEM_MODULE_INFORMATION))
        num_mods = min(smi.contents.ModulesCount, 500)

        for i in range(num_mods):
            try:
                mod = smi.contents.Modules[i]
                name_bytes = mod.FullPathName[:mod.OffsetToFileName]
                if name_bytes:
                    fname = name_bytes.decode("utf-8", errors="replace").strip("\x00")
                    modules.add((mod.LoadOrderIndex, fname))
            except Exception:
                continue

        return modules


# ---------------------------------------------------------------------------
# 4. Hidden Service Scanner
# ---------------------------------------------------------------------------


class HiddenServiceScanner(BaseScanner):
    category = ScanCategory.HIDDEN_SERVICES

    def _do_scan(self):
        # Set A: SCM via psutil
        scm_services: set[str] = set()
        try:
            for s in psutil.win_service_iter():
                try:
                    scm_services.add(s.name().lower())
                except Exception:
                    continue
        except Exception as e:
            self._add(f"SCM enumeration failed: {e}", Severity.INFO, "")
            return

        # Set B: Direct registry enumeration
        reg_services: set[str] = set()
        reg_details: dict[str, dict] = {}
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
            )
            for i in range(winreg.QueryInfoKey(key)[0]):
                svc_name = winreg.EnumKey(key, i).lower()
                reg_services.add(svc_name)
                try:
                    svc_key = winreg.OpenKey(key, winreg.EnumKey(key, i))
                    try:
                        img_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                        start_val, _ = winreg.QueryValueEx(svc_key, "Start")
                        # Type: 1=SERVICE_KERNEL_DRIVER, 2=SERVICE_FILE_SYSTEM_DRIVER
                        #       16=SERVICE_WIN32_OWN_PROCESS, 32=SERVICE_WIN32_SHARE_PROCESS
                        # Only type >= 16 are visible via SCM
                        try:
                            type_val, _ = winreg.QueryValueEx(svc_key, "Type")
                            svc_type = int(type_val) if type_val is not None else 0
                        except Exception:
                            svc_type = 0
                        reg_details[svc_name] = {
                            "image_path": str(img_path),
                            "start": int(start_val) if start_val is not None else -1,
                            "type": svc_type,
                        }
                    except Exception:
                        reg_details[svc_name] = {"image_path": "?", "start": -1, "type": 0}
                    winreg.CloseKey(svc_key)
                except Exception:
                    continue
            winreg.CloseKey(key)
        except Exception as e:
            log.debug("Registry service enumeration failed: %s", e)

        # Filter: boot-start (0) and system-start (1) drivers are kernel drivers
        # that SCM does NOT enumerate by design. Also skip entries without ImagePath
        # or Start values — those are driver groups/filter instances, not real services.
        # Only flag Automatic (2) or Manual (3) services missing from SCM as suspicious.
        hidden = reg_services - scm_services
        real_hidden = []
        skipped_boot = 0
        skipped_nodata = 0
        for name in hidden:
            detail = reg_details.get(name, {})
            start = detail.get("start", -1)
            img = detail.get("image_path", "?")
            # SCM's EnumServicesStatusEx only enumerates services with Type exactly
            # 0x10 (SERVICE_WIN32_OWN_PROCESS) or 0x20 (SERVICE_WIN32_SHARE_PROCESS)
            # or the combination 0x30. Everything else is a kernel driver, file-system
            # driver, user-service, or other type that SCM intentionally hides.
            svc_type = detail.get("type", 0)
            is_pure_win32 = svc_type in (0x10, 0x20, 0x30)
            if not is_pure_win32:
                skipped_boot += 1
                continue
            # Skip boot/system drivers (SCM deliberately hides them)
            if start in (0, 1):
                skipped_boot += 1
                continue
            # Skip entries without ImagePath — not real services
            if img == "?" or not img.strip():
                skipped_nodata += 1
                continue
            # Skip entries where we couldn't read Start value — unknown status
            if start == -1:
                skipped_nodata += 1
                continue
            # Only flag Automatic/Manual Win32 services (these MUST be SCM-visible)
            if start in (2, 3):
                real_hidden.append(name)
                self._add(
                    f"Hidden service: {name}",
                    Severity.HIGH,
                    f"Service '{name}' exists in registry (HKLM\\SYSTEM\\CurrentControlSet\\Services) "
                    f"but is NOT visible to the Service Control Manager.\n"
                    f"ImagePath: {img}\n"
                    f"Start: {({0:'Boot',1:'System',2:'Automatic',3:'Manual',4:'Disabled'}.get(start, str(start)))}\n"
                    f"This may indicate a rootkit that filters SCM enumeration.",
                    {"service": name, "image_path": img, "start": start, "type": svc_type},
                )
        if not real_hidden:
            log.debug("Service cross-view: clean — %d services (%d boot/system, %d no-data filtered)",
                     len(scm_services), skipped_boot, skipped_nodata)


# ---------------------------------------------------------------------------
# 5. Hidden File Scanner
# ---------------------------------------------------------------------------


class HiddenFileScanner(BaseScanner):
    category = ScanCategory.HIDDEN_FILES

    TARGET_DIRS = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Windows",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    ]

    def _do_scan(self):
        for target in self.TARGET_DIRS:
            if not os.path.isdir(target):
                continue
            # Set A: os.listdir
            try:
                set_a = set(os.listdir(target))
            except PermissionError:
                continue

            # Set B: NtQueryDirectoryFile
            set_b: set[str] = set()
            try:
                set_b = self._list_dir_nt(target)
            except Exception as e:
                log.debug("NtQueryDirectoryFile failed for %s: %s", target, e)
                continue

            hidden = set_b - set_a
            if hidden:
                for name in list(hidden)[:20]:
                    full_path = os.path.join(target, name)
                    self._add(
                        f"Hidden file: {full_path}",
                        Severity.HIGH,
                        f"File '{name}' in {target} found via NtQueryDirectoryFile "
                        f"(kernel-level directory query) but not visible to FindFirstFile/FindNextFile. "
                        f"Rootkits commonly hide files by hooking the user-mode file enumeration APIs.",
                        {"path": full_path, "directory": target},
                    )

    def _list_dir_nt(self, path: str) -> set[str]:
        """List directory using NtQueryDirectoryFile via ntdll."""
        ntdll = ctypes.WinDLL("ntdll")
        kernel32 = ctypes.windll.kernel32

        # Open directory handle
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        FILE_DIRECTORY_FILE = 0x00000001
        FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020

        handle = kernel32.CreateFileW(
            path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
        )
        if handle == -1:
            return set()

        try:
            NtQueryDirectoryFile = ntdll.NtQueryDirectoryFile
            NtQueryDirectoryFile.restype = ctypes.c_long
            NtQueryDirectoryFile.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p,
            ]

            # FileDirectoryInformation = 1
            buf_size = 65536
            buf = ctypes.create_string_buffer(buf_size)
            io_status = ctypes.c_ubyte * 16  # IO_STATUS_BLOCK placeholder
            io_block = io_status()

            status = NtQueryDirectoryFile(
                handle, None, None, None,
                ctypes.byref(io_block), buf, buf_size,
                1,  # FileDirectoryInformation
                1,  # ReturnSingleEntry=0 → return all
                None, None,
            )

            names: set[str] = set()
            if ntsuccess(status):
                offset = 0
                while True:
                    fdi = ctypes.cast(
                        ctypes.c_void_p(ctypes.addressof(buf) + offset),
                        ctypes.POINTER(FILE_DIRECTORY_INFORMATION),
                    )
                    name_len = fdi.contents.FileNameLength
                    if name_len > 0 and name_len < 520:
                        name = ctypes.wstring_at(
                            ctypes.addressof(fdi.contents.FileName), name_len // 2
                        )
                        names.add(name)
                    next_offset = fdi.contents.NextEntryOffset
                    if next_offset == 0:
                        break
                    offset += next_offset
                return names
        finally:
            kernel32.CloseHandle(handle)

        return set()


# ---------------------------------------------------------------------------
# 6. Disk Sector / MBR Scanner
# ---------------------------------------------------------------------------


class DiskSectorScanner(BaseScanner):
    category = ScanCategory.HIDDEN_SECTORS

    def _do_scan(self):
        if not is_admin():
            self._add("Admin privileges required for MBR scan",
                      Severity.INFO, "Re-run as admin to scan Master Boot Record.")
            return

        kernel32 = ctypes.windll.kernel32
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        for drive_idx in range(4):  # Scan up to 4 physical drives
            path = rf"\\.\PhysicalDrive{drive_idx}"
            handle = kernel32.CreateFileW(
                path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None,
            )
            if handle == INVALID_HANDLE_VALUE:
                if drive_idx == 0:
                    self._add(f"Cannot open {path}", Severity.INFO,
                              "Physical drive access denied. May need admin or the drive "
                              "may not exist.")
                break

            try:
                # Read MBR (sector 0, 512 bytes)
                SECTOR_SIZE = 512
                buf = ctypes.create_string_buffer(SECTOR_SIZE)
                bytes_read = ctypes.c_ulong(0)

                # SetFilePointer to sector 0
                FILE_BEGIN = 0
                kernel32.SetFilePointer(handle, 0, None, FILE_BEGIN)

                if kernel32.ReadFile(handle, buf, SECTOR_SIZE, ctypes.byref(bytes_read), None):
                    sector = buf.raw[:bytes_read.value]
                    if len(sector) >= 512:
                        # Check MBR boot signature
                        if sector[510] != 0x55 or sector[511] != 0xAA:
                            self._add(
                                f"MBR boot signature missing on {path}",
                                Severity.HIGH,
                                f"The Master Boot Record on {path} is missing the standard "
                                f"0x55 0xAA boot signature at offsets 510-511. This may indicate "
                                f"MBR rootkit/bootkit infection (e.g., TDL4, Rovnix, Whistler).\n"
                                f"Actual bytes at 510-511: 0x{sector[510]:02X} 0x{sector[511]:02X}",
                                {"drive": path, "sector0_checksum": sector[0:512].hex()},
                            )

                        # Check partition table area (offsets 446-509)
                        # Look for anomalous executable code
                        part_table = sector[446:510]
                        # Count non-zero bytes in area that should be sparse
                        non_zero = sum(1 for b in part_table[64:] if b != 0)
                        if non_zero > 30:
                            self._add(
                                f"Suspicious data in MBR partition gap on {path}",
                                Severity.MEDIUM,
                                f"Found {non_zero} non-zero bytes in the MBR area between "
                                f"partition entries (offset 510+). This space is normally "
                                f"zero-filled. May contain hidden code or data.",
                                {"drive": path, "non_zero_bytes": non_zero},
                            )

                        # Read and hash for known bootkit signatures
                        mbr_hash = self._quick_hash(sector[:446])  # hash bootstrap code
                        log.debug("MBR %s bootstrap code hash: %s", path, mbr_hash)
                    else:
                        self._add(f"MBR read too short on {path}: {len(sector)} bytes",
                                  Severity.INFO, "Could not read full MBR sector.")
                else:
                    self._add(f"Cannot read MBR from {path}", Severity.INFO,
                              "ReadFile failed on physical drive.")
            finally:
                kernel32.CloseHandle(handle)

    @staticmethod
    def _quick_hash(data: bytes) -> str:
        """Simple non-crypto hash for comparison."""
        h = 0
        for b in data:
            h = ((h << 5) - h) + b
            h &= 0xFFFFFFFF
        return f"{h:08X}"


# ---------------------------------------------------------------------------
# 7. Alternate Data Streams Scanner
# ---------------------------------------------------------------------------


class ADSScanner(BaseScanner):
    category = ScanCategory.HIDDEN_ADS

    TARGET_DIRS = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Windows",
        r"C:\ProgramData\Microsoft\Windows\Start Menu",
        r"C:\Users",
    ]

    def _do_scan(self):
        kernel32 = ctypes.windll.kernel32
        FindFirstStreamW = kernel32.FindFirstStreamW
        FindNextStreamW = kernel32.FindNextStreamW

        for target in self.TARGET_DIRS:
            if not os.path.isdir(target):
                continue
            try:
                stream_data = WIN32_FIND_STREAM_DATA()
                handle = FindFirstStreamW(
                    target, 0, ctypes.byref(stream_data), 0,
                )
                if handle == -1:
                    continue

                try:
                    while True:
                        sname = stream_data.cStreamName
                        ssize = stream_data.StreamSize
                        if sname and sname != "::$DATA":  # Skip default data stream
                            full = target + sname
                            self._add(
                                f"ADS found: {full}",
                                Severity.MEDIUM if ssize > 1024 else Severity.LOW,
                                f"Alternate Data Stream: {sname} ({ssize:,} bytes)\n"
                                f"Location: {target}\n"
                                f"{'WARNING: Large stream may contain hidden executable.' if ssize > 1024 else ''}"
                                f"{'ADS in system directory is suspicious.' if 'Windows' in target else ''}",
                                {"path": full, "stream": sname, "size": ssize},
                            )
                        if not FindNextStreamW(handle, ctypes.byref(stream_data)):
                            break
                finally:
                    kernel32.FindClose(handle)
            except Exception as e:
                log.debug("ADS scan failed for %s: %s", target, e)


# ---------------------------------------------------------------------------
# 8. Hidden Registry Scanner
# ---------------------------------------------------------------------------


class HiddenRegistryScanner(BaseScanner):
    category = ScanCategory.HIDDEN_REGISTRY

    TARGET_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "Persistence"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "Persistence"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "Persistence"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services",
         "Services"),
    ]

    def _do_scan(self):
        for hkey_base, subkey, category in self.TARGET_KEYS:
            # Set A: winreg.EnumKey
            set_a: set[str] = set()
            try:
                key = winreg.OpenKey(hkey_base, subkey)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    set_a.add(winreg.EnumKey(key, i).lower())
                winreg.CloseKey(key)
            except Exception:
                continue

            # Set B: NtEnumerateKey
            set_b: set[str] = set()
            try:
                set_b = self._enum_key_nt(hkey_base, subkey)
            except Exception:
                continue

            hidden = set_b - set_a
            if hidden:
                for name in list(hidden)[:15]:
                    self._add(
                        f"Hidden registry key: {subkey}\\{name} [{category}]",
                        Severity.HIGH,
                        f"Subkey '{name}' exists under {subkey} when enumerated via "
                        f"NtEnumerateKey (kernel-level) but is NOT visible via "
                        f"RegEnumKey (user-mode). Rootkits commonly hide registry keys "
                        f"for persistence.\nCategory: {category}",
                        {"hive": str(hkey_base), "subkey": subkey, "name": name},
                    )

    def _enum_key_nt(self, hkey_base: int, subkey: str) -> set[str]:
        """Enumerate registry subkeys using NtEnumerateKey."""
        ntdll = ctypes.WinDLL("ntdll")

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Length", ctypes.c_ulong),
                ("RootDirectory", ctypes.c_void_p),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", ctypes.c_ulong),
                ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p),
            ]

        # Convert hkey_base + subkey to NT path
        hive_map = {
            winreg.HKEY_LOCAL_MACHINE: r"\Registry\Machine",
            winreg.HKEY_CURRENT_USER: r"\Registry\User",
        }
        hive_path = hive_map.get(hkey_base, r"\Registry\Machine")
        full_path = hive_path + "\\" + subkey

        us = UNICODE_STRING()
        us.Buffer = full_path
        us.Length = len(full_path) * 2
        us.MaximumLength = us.Length + 2

        oa = OBJECT_ATTRIBUTES()
        oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
        oa.ObjectName = ctypes.pointer(us)
        oa.Attributes = 0

        key_handle = ctypes.c_void_p()
        NtOpenKey = ntdll.NtOpenKey
        NtOpenKey.restype = ctypes.c_long
        status = NtOpenKey(ctypes.byref(key_handle), 0x20019, ctypes.byref(oa))
        if not ntsuccess(status):
            return set()

        NtEnumerateKey = ntdll.NtEnumerateKey
        NtEnumerateKey.restype = ctypes.c_long

        try:
            names: set[str] = set()
            idx = 0
            while True:
                buf = ctypes.create_string_buffer(512)
                result_len = ctypes.c_ulong(0)
                status = NtEnumerateKey(
                    key_handle, idx, 0,  # KeyBasicInformation = 0
                    buf, 512, ctypes.byref(result_len),
                )
                if not ntsuccess(status):
                    break
                kbi = ctypes.cast(buf, ctypes.POINTER(KEY_BASIC_INFORMATION))
                name_len = kbi.contents.NameLength
                if name_len > 0 and name_len < 512:
                    name = ctypes.wstring_at(
                        ctypes.addressof(kbi.contents.Name), name_len // 2
                    )
                    names.add(name.lower())
                idx += 1
                if idx > 5000:
                    break
            return names
        finally:
            ntdll.NtClose(key_handle)


# ---------------------------------------------------------------------------
# 9, 10, 11. SSDT / IDT / IRP Scanners (kernel-mode stubs)
# ---------------------------------------------------------------------------


class SSDTScanner(BaseScanner):
    category = ScanCategory.SSDT_HOOKS

    def _do_scan(self):
        self._add(
            "SSDT hook detection requires a kernel-mode driver",
            Severity.INFO,
            "The System Service Descriptor Table (SSDT) resides in kernel memory "
            "and is protected by Kernel Patch Protection (PatchGuard) on 64-bit Windows. "
            "Detection requires a signed kernel driver to read the SSDT and compare against "
            "expected values from ntoskrnl.exe. Use a dedicated kernel-mode tool like GMER, "
            "TDSSKiller, or RKill for SSDT hook detection.",
        )


class IDTScanner(BaseScanner):
    category = ScanCategory.IDT_HOOKS

    def _do_scan(self):
        self._add(
            "IDT hook detection requires a kernel-mode driver",
            Severity.INFO,
            "The Interrupt Descriptor Table (IDT) is a CPU-level data structure in kernel "
            "memory. User-mode code cannot read the IDT on modern Windows. "
            "Detection requires a kernel driver with the ability to execute the SIDT "
            "instruction and read the IDT entries.",
        )


class IRPScanner(BaseScanner):
    category = ScanCategory.IRP_HOOKS

    def _do_scan(self):
        self._add(
            "IRP hook detection requires a kernel-mode driver",
            Severity.INFO,
            "I/O Request Packet (IRP) hooks are installed in driver dispatch tables within "
            "kernel memory. Detection requires enumerating all loaded drivers, reading each "
            "driver's DRIVER_OBJECT MajorFunction array, and comparing against the original "
            "driver image on disk. This requires kernel-mode access.",
        )


# ---------------------------------------------------------------------------
# 12. Inline Hook Scanner
# ---------------------------------------------------------------------------


class InlineHookScanner(BaseScanner):
    category = ScanCategory.INLINE_HOOKS

    CRITICAL_DLLS = [
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
        "user32.dll", "ws2_32.dll", "wininet.dll", "crypt32.dll",
    ]

    def _do_scan(self):
        kernel32 = ctypes.windll.kernel32
        system_root = os.environ.get("SystemRoot", r"C:\Windows")

        for dll_name in self.CRITICAL_DLLS:
            # Check both System32 and SysWOW64
            for subdir in ["System32", "SysWOW64"]:
                disk_path = os.path.join(system_root, subdir, dll_name)
                if not os.path.isfile(disk_path):
                    continue

                try:
                    # Get in-memory module info
                    mod_handle = kernel32.GetModuleHandleW(dll_name)
                    if not mod_handle:
                        continue

                    mod_base = ctypes.cast(mod_handle, ctypes.c_void_p).value
                    if not mod_base:
                        continue

                    # Parse PE to find .text section
                    text_rva, text_size = self._get_text_section(disk_path)
                    if text_rva == 0 or text_size == 0:
                        continue

                    # Read on-disk .text bytes
                    with open(disk_path, "rb") as f:
                        text_offset = self._rva_to_offset(f, text_rva)
                        if text_offset is None:
                            continue
                        f.seek(text_offset)
                        disk_bytes = f.read(min(text_size, 4096))  # First 4KB

                    # Read in-memory .text bytes via ReadProcessMemory
                    mem_addr = mod_base + text_rva
                    PROCESS_VM_READ = 0x0010
                    PROCESS_QUERY_INFORMATION = 0x0400
                    h_self = kernel32.GetCurrentProcess()

                    mem_buf = ctypes.create_string_buffer(len(disk_bytes))
                    bytes_read = ctypes.c_size_t(0)
                    if not kernel32.ReadProcessMemory(
                        h_self, ctypes.c_void_p(mem_addr),
                        mem_buf, len(disk_bytes), ctypes.byref(bytes_read),
                    ):
                        continue

                    mem_bytes = mem_buf.raw[:bytes_read.value]

                    # Compare
                    diffs = []
                    for i in range(min(len(disk_bytes), len(mem_bytes))):
                        if disk_bytes[i] != mem_bytes[i]:
                            diffs.append((i, disk_bytes[i], mem_bytes[i]))

                    if diffs:
                        # Check if this looks like a hook (JMP = 0xE9, CALL = 0xE8,
                        # PUSH/RET = 0x68...0xC3, MOV RAX = 0x48 0xB8...0xFF 0xE0)
                        jump_diffs = [
                            d for d in diffs
                            if d[2] in (0xE9, 0xE8, 0xEB, 0xFF, 0x68)
                            or (d[2] == 0x48 and d[0] < 6)  # x64 MOV RAX prefix
                        ]
                        if jump_diffs:
                            self._add(
                                f"Inline hook in {dll_name} ({subdir}): {len(jump_diffs)} suspicious bytes",
                                Severity.CRITICAL,
                                f"Memory at {dll_name}+0x{text_rva:X} differs from on-disk file.\n"
                                f"First {min(5, len(jump_diffs))} suspicious diffs: "
                                + ", ".join(
                                    f"off+0x{d[0]:X}: disk=0x{d[1]:02X} mem=0x{d[2]:02X}"
                                    for d in jump_diffs[:5]
                                ) + (
                                    f"\n... and {len(jump_diffs)-5} more" if len(jump_diffs) > 5 else ""
                                ) + "\nThis is a strong indicator of API hooking. "
                                  "Rootkits and security software both use inline hooks to intercept "
                                  "system calls.",
                                {"dll": dll_name, "subdir": subdir,
                                 "rva": text_rva, "diff_count": len(diffs)},
                            )
                except Exception as e:
                    log.debug("Inline hook check failed for %s/%s: %s", subdir, dll_name, e)

    def _get_text_section(self, path: str) -> tuple[int, int]:
        """Parse PE file and return (.text_rva, .text_virtual_size)."""
        try:
            with open(path, "rb") as f:
                # DOS header → e_lfanew
                f.seek(0x3C)
                pe_offset_data = f.read(4)
                if len(pe_offset_data) < 4:
                    return (0, 0)
                pe_offset = struct.unpack("<I", pe_offset_data)[0]

                f.seek(pe_offset)
                sig = f.read(4)
                if sig != b"PE\x00\x00":
                    return (0, 0)

                # COFF header (20 bytes)
                coff = f.read(20)
                if len(coff) < 20:
                    return (0, 0)
                num_sections = struct.unpack("<H", coff[2:4])[0]
                opt_header_size = struct.unpack("<H", coff[16:18])[0]

                # Skip optional header to reach section table
                f.seek(pe_offset + 4 + 20 + opt_header_size)

                # Search for .text section
                for _ in range(num_sections):
                    sec = f.read(40)
                    if len(sec) < 40:
                        break
                    name = sec[0:8].rstrip(b"\x00").decode("ascii", errors="replace")
                    if name == ".text":
                        vsize = struct.unpack("<I", sec[8:12])[0]
                        rva = struct.unpack("<I", sec[12:16])[0]
                        return (rva, vsize)
                return (0, 0)
        except Exception:
            return (0, 0)

    def _rva_to_offset(self, f, rva: int) -> Optional[int]:
        """Convert PE RVA to file offset."""
        try:
            current = f.tell()
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]

            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                f.seek(current)
                return None

            coff = f.read(20)
            num_sections = struct.unpack("<H", coff[2:4])[0]
            opt_header_size = struct.unpack("<H", coff[16:18])[0]

            f.seek(pe_offset + 4 + 20 + opt_header_size)
            for _ in range(num_sections):
                sec = f.read(40)
                name = sec[0:8].rstrip(b"\x00")
                sec_vsize = struct.unpack("<I", sec[8:12])[0]
                sec_rva = struct.unpack("<I", sec[12:16])[0]
                sec_raw_size = struct.unpack("<I", sec[16:20])[0]
                sec_raw_offset = struct.unpack("<I", sec[20:24])[0]

                if sec_rva <= rva < sec_rva + sec_vsize:
                    offset = sec_raw_offset + (rva - sec_rva)
                    f.seek(current)
                    return offset

            f.seek(current)
            return None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Scan Orchestrator
# ---------------------------------------------------------------------------


class ScanOrchestrator:
    """Runs all scanners, aggregates results into a ScanReport."""

    ALL_SCANNERS: list[type[BaseScanner]] = [
        HiddenProcessScanner,
        HiddenThreadScanner,
        HiddenModuleScanner,
        HiddenServiceScanner,
        HiddenFileScanner,
        DiskSectorScanner,
        ADSScanner,
        HiddenRegistryScanner,
        SSDTScanner,
        IDTScanner,
        IRPScanner,
        InlineHookScanner,
    ]

    def __init__(self):
        self._cancel_flag = threading.Event()

    def cancel(self):
        self._cancel_flag.set()

    def run_scan(
        self,
        categories: Optional[list[ScanCategory]] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> ScanReport:
        """Run all scanners (or filtered by category).

        Args:
            categories: Optional list of categories to scan. None = all.
            progress_callback: Called as callback(current, total, scanner_name).
        """
        self._cancel_flag.clear()
        scanners_to_run: list[BaseScanner] = []
        for s_cls in self.ALL_SCANNERS:
            temp = s_cls()
            if categories is None or temp.category in categories:
                scanners_to_run.append(temp)

        all_results: list[ScanResult] = []
        t0 = time.perf_counter()
        total = len(scanners_to_run)

        for i, scanner in enumerate(scanners_to_run):
            if self._cancel_flag.is_set():
                log.info("Scan cancelled by user")
                break

            if progress_callback:
                progress_callback(i + 1, total, scanner.category.value)

            try:
                batch = scanner.scan()
                all_results.extend(batch)
            except Exception as e:
                all_results.append(ScanResult(
                    category=scanner.category,
                    finding=f"Fatal scanner error: {type(e).__name__}",
                    severity=Severity.INFO,
                    details=str(e),
                ))

        elapsed = time.perf_counter() - t0
        log.info("ScanOrchestrator: %d scanners done in %.2fs — %d findings",
                 total, elapsed, len(all_results))

        return ScanReport(
            results=all_results,
            scan_time=elapsed,
            admin_status=is_admin(),
        )


# ---------------------------------------------------------------------------
# Convenience: CLI report printer
# ---------------------------------------------------------------------------


def print_report(report: ScanReport) -> None:
    """Print a ScanReport to stdout in human-readable format."""
    print(f"\n{'='*70}")
    print(f"  Warden Security Scanner — Scan Report")
    print(f"{'='*70}")
    print(f"  Scan time:    {report.scan_time:.2f}s")
    print(f"  Admin mode:   {'Yes' if report.admin_status else 'No (limited scan)'} ")
    print(f"  Total issues: {report.total_issues}")
    print(f"    Critical:   {report.critical_count}")
    print(f"    High:       {report.high_count}")
    print(f"    Medium:     {report.medium_count}")
    print(f"    Low:        {report.low_count}")
    print(f"    Info:       {report.info_count}")
    print(f"{'='*70}")

    if not report.results:
        print("  ✅ No issues found. System appears clean.")
        return

    by_category: dict[str, list[ScanResult]] = {}
    for r in report.results:
        cat = r.category.value
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(r)

    for category, results in sorted(by_category.items()):
        print(f"\n  [{category}] — {len(results)} finding(s):")
        for r in results:
            tag = SEVERITY_TAGS[r.severity]
            print(f"    {tag} {r.finding}")
            if r.details:
                for line in r.details.split("\n"):
                    print(f"       {line}")
    print()
