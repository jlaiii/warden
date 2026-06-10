#!/usr/bin/env python3
"""
Hermes Task Manager v3 -- Windows Task Manager 1:1 Clone
Built with tkinter + psutil + ctypes + winreg.

Tabs:
  Processes  -- tree/flat view, search, sort, end task/tree, priority, affinity
  Performance -- per-core CPU, memory composition, disk, network, GPU graphs
  App History -- CPU time per application
  Details    -- raw process list with extended columns (cmdline, description, etc.)
  Services   -- start / stop / restart
  Startup    -- enable / disable / open location
  Users      -- processes grouped by user account

Context Menu:  End Task | End Process Tree | Set Priority → | Set Affinity… |
               Create Dump File | Analyze Wait Chain | Go to Service(s) |
               View Details | Open File Location | Search Online | Copy | Properties

Keyboard:  Del=End Task  |  Ctrl+F=Search  |  F5=Refresh  |  Ctrl+Tab=Switch Tab
           Ctrl+C=Copy  |  Ctrl+Shift+E=End Tree  |  Ctrl+D=Dump  |  Escape=Clear
"""

from __future__ import annotations

import csv
import logging
import math
import os
import platform as plat
import subprocess
import sys
import threading
import time
import traceback
from collections import deque
from collections.abc import Callable
from datetime import datetime
from io import StringIO
from pathlib import Path
from tkinter import (
    BOTH,
    Checkbutton,
    END,
    HORIZONTAL,
    IntVar,
    LEFT,
    RIGHT,
    VERTICAL,
    Canvas,
    Frame,
    Label,
    Menu,
    StringVar,
    Tk,
    Toplevel,
    X,
    Y,
    messagebox,
    scrolledtext,
    ttk,
)

import psutil
import ctypes
import ctypes.wintypes
import winreg

from sec_scanner_engine import (
    Severity, ScanCategory, ScanResult, ScanReport, ScanOrchestrator,
    SEVERITY_COLORS, SEVERITY_TAGS,
)

# -- logging setup ----------------------------------------------------------
LOG_DIR = Path.home() / "task_manager_logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "task_manager.log"

# Rotate log if > 5 MB
if LOG_FILE.exists() and LOG_FILE.stat().st_size > 5 * 1024 * 1024:
    bak = LOG_DIR / f"task_manager_{datetime.now():%Y%m%d_%H%M%S}.log"
    LOG_FILE.rename(bak)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("taskmgr")

log.info("=" * 70)
log.info("Hermes Task Manager v3 starting -- %s", datetime.now().isoformat())
log.info("Log file: %s", LOG_FILE)
log.info("Python: %s  |  psutil: %s  |  Platform: %s %s",
         sys.version.split()[0], psutil.__version__, plat.system(), plat.release())
log.info("Machine: %s  |  CPU cores: %d logical / %d physical",
         plat.processor(), psutil.cpu_count(logical=True), psutil.cpu_count(logical=False))
_try_mem = psutil.virtual_memory()
log.info("Total RAM: %.1f GB  |  Available: %.1f GB",
         _try_mem.total / (1024**3), _try_mem.available / (1024**3))
try:
    log.info("Running as admin: %s", ctypes.windll.shell32.IsUserAnAdmin() != 0)
except Exception:
    log.info("Running as admin: unknown (ctypes error)")

# -- Win32 API helpers -----------------------------------------------------
def is_admin() -> bool:
    """Return True if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate() -> None:
    """Re-launch with admin privileges via UAC. Exits non-elevated instance on success."""
    if is_admin():
        log.debug("Already running as admin")
        return
    log.warning("Not running as admin -- requesting UAC elevation…")
    script = sys.argv[0]
    params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        if ret <= 32:
            log.error("ShellExecuteW failed with code %d (0x%x)", ret, ret)
        else:
            log.info("UAC elevation OK -- exiting non-elevated instance (ShellExecute ret=%d)", ret)
            sys.exit(0)
    except Exception as e:
        log.exception("Elevation exception: %s", e)


# -- constants --------------------------------------------------------------
REFRESH_INTERVAL_MS = 1500
CPU_POLL_INTERVAL = 0.1
GRAPH_HISTORY = 120  # data points
PROCESS_TAB_INDEX = 0
PERF_TAB_INDEX = 1
APP_HISTORY_TAB_INDEX = 2
DETAILS_TAB_INDEX = 3
SERVICES_TAB_INDEX = 4
STARTUP_TAB_INDEX = 5
USERS_TAB_INDEX = 6
SECURITY_TAB_INDEX = 7

# Process-tree columns
COLS = ("name", "pid", "cpu", "memory", "threads", "handles", "disk_io", "status", "user", "description")
COL_WIDTHS = {
    "name": 200, "pid": 70, "cpu": 65, "memory": 100, "threads": 65,
    "handles": 65, "disk_io": 100, "status": 90, "user": 140, "description": 140,
}
COL_LABELS = {
    "name": "Name", "pid": "PID", "cpu": "CPU %", "memory": "Memory",
    "threads": "Threads", "handles": "Handles", "disk_io": "Disk I/O",
    "status": "Status", "user": "User", "description": "Description",
}
VISIBLE_COLS = {c: True for c in COLS}  # can be toggled

# Details-tab columns
DET_COLS = ("det_name", "det_pid", "det_cpu", "det_memory", "det_status",
            "det_user", "det_session", "det_cmdline", "det_description",
            "det_priority", "det_cpu_time", "det_create_time")
DET_COL_WIDTHS = {
    "det_name": 180, "det_pid": 65, "det_cpu": 65, "det_memory": 100,
    "det_status": 85, "det_user": 120, "det_session": 65, "det_cmdline": 300,
    "det_description": 150, "det_priority": 80, "det_cpu_time": 90, "det_create_time": 130,
}
DET_COL_LABELS = {
    "det_name": "Name", "det_pid": "PID", "det_cpu": "CPU %", "det_memory": "Memory",
    "det_status": "Status", "det_user": "User Name", "det_session": "Session",
    "det_cmdline": "Command line", "det_description": "Description",
    "det_priority": "Priority", "det_cpu_time": "CPU Time", "det_create_time": "Started",
}

# App-history columns
HIST_COLS = ("hist_name", "hist_cpu_time", "hist_net_in", "hist_net_out",
             "hist_reads", "hist_writes", "hist_runtime")
HIST_COL_WIDTHS = {
    "hist_name": 200, "hist_cpu_time": 100, "hist_net_in": 110, "hist_net_out": 110,
    "hist_reads": 110, "hist_writes": 110, "hist_runtime": 130,
}
HIST_COL_LABELS = {
    "hist_name": "Name", "hist_cpu_time": "CPU time", "hist_net_in": "Network In",
    "hist_net_out": "Network Out", "hist_reads": "Disk Reads", "hist_writes": "Disk Writes",
    "hist_runtime": "Total Runtime",
}

# Services columns
SVC_COLS = ("svc_name", "svc_display", "svc_pid", "svc_status", "svc_start_type")
SVC_COL_WIDTHS = {"svc_name": 180, "svc_display": 300, "svc_pid": 70, "svc_status": 110, "svc_start_type": 130}
SVC_COL_LABELS = {"svc_name": "Name", "svc_display": "Display Name", "svc_pid": "PID",
                  "svc_status": "Status", "svc_start_type": "Startup Type"}

# Startup columns
SU_COLS = ("su_name", "su_publisher", "su_status", "su_impact", "su_command")
SU_COL_WIDTHS = {"su_name": 200, "su_publisher": 160, "su_status": 100, "su_impact": 100, "su_command": 400}
SU_COL_LABELS = {"su_name": "Name", "su_publisher": "Publisher", "su_status": "Status",
                 "su_impact": "Startup Impact", "su_command": "Command"}

GRAPH_COLORS = {
    "cpu": "#00bcd4",         "cpu2": "#006064",
    "memory": "#4caf50",      "memory_inuse": "#81c784",
    "mem_committed": "#ff9800",
    "disk_read": "#ff9800",   "disk_write": "#f44336",
    "net_sent": "#2196f3",    "net_recv": "#9c27b0",
    "grid": "#3a3a3d",        "label": "#888888",
    "bg": "#1e1e1e",          "gpu": "#e91e63",
    "svc_running": "#4caf50", "svc_stopped": "#f44336",
    "svc_paused": "#ff9800",
}

PRIORITY_LEVELS = {
    "Realtime":    psutil.REALTIME_PRIORITY_CLASS,
    "High":        psutil.HIGH_PRIORITY_CLASS,
    "Above Normal": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
    "Normal":      psutil.NORMAL_PRIORITY_CLASS,
    "Below Normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
    "Low":         psutil.IDLE_PRIORITY_CLASS,
}


# -- helpers ----------------------------------------------------------------
def fmt_bytes(n: int | float) -> str:
    if n < 0:
        return "--"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_bps(n: float) -> str:
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if abs(n) < 1000:
            return f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} Tbps"


def fmt_duration(seconds: float) -> str:
    """Human-readable duration string."""
    if seconds < 0:
        return "--"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    if h > 24:
        d, h2 = divmod(h, 24)
        return f"{d}d {h2}h {m:02d}m"
    if h > 0:
        return f"{h}h {m:02d}m {s:02d}s"
    if m > 0:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def safe_get(obj: Callable, default: object = "") -> str:
    """Safely call a lambda and return string result."""
    try:
        result = obj()
        return str(result) if result is not None else str(default)
    except Exception:
        return str(default)


def safe_int(obj: Callable, default: int = 0) -> int:
    try:
        r = obj()
        return int(r) if r is not None else default
    except Exception:
        return default


def get_process_description(proc: psutil.Process) -> str:
    """Best-effort to get a file description from the executable's version info."""
    try:
        exe = proc.exe()
        if not exe or not os.path.exists(exe):
            return ""

        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        GetFileVersionInfoSizeW = kernel32.GetFileVersionInfoSizeW
        GetFileVersionInfoW = kernel32.GetFileVersionInfoW
        VerQueryValueW = kernel32.VerQueryValueW

        size = GetFileVersionInfoSizeW(exe, None)
        if size == 0:
            return ""

        buf = ctypes.create_string_buffer(size)
        if not GetFileVersionInfoW(exe, 0, size, buf):
            return ""

        # Get the language + codepage to construct the sub-block path
        lang_cp = ctypes.c_void_p()
        lang_len = ctypes.c_uint(0)
        if VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(lang_cp), ctypes.byref(lang_len)):
            if lang_len.value >= 4:
                lang_id = ctypes.cast(lang_cp, ctypes.POINTER(ctypes.c_uint16))[0]
                cp_id = ctypes.cast(lang_cp, ctypes.POINTER(ctypes.c_uint16))[1]
                sub_path = f"\\StringFileInfo\\{lang_id:04x}{cp_id:04x}\\FileDescription"

                desc_ptr = ctypes.c_void_p()
                desc_len = ctypes.c_uint(0)
                if VerQueryValueW(buf, sub_path, ctypes.byref(desc_ptr), ctypes.byref(desc_len)):
                    return ctypes.wstring_at(desc_ptr, desc_len.value - 1) if desc_len.value > 1 else ""
    except Exception:
        pass
    return ""


# Win32 Wait Chain Traversal
def get_wait_chain(pid: int) -> str:
    """Use WCT to get blocking chain info for a process thread."""
    try:
        import ctypes.wintypes as w

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        WCT_OBJECT_TYPE_PROCESS = 1
        WCT_OBJECT_TYPE_THREAD = 0

        class WCT_OBJECT(ctypes.Structure):
            _fields_ = [
                ("ObjectType", w.DWORD),
                ("ProcessId", w.DWORD),
                ("ThreadId", w.DWORD),
                ("ObjectName", ctypes.c_char * 256),
            ]

        class WAITCHAIN_NODE_INFO(ctypes.Structure):
            _fields_ = [
                ("ObjectType", w.DWORD),
                ("ObjectStatus", w.DWORD),
                ("Union", ctypes.c_ubyte * 256),
            ]

        # Try to get the main thread
        proc = psutil.Process(pid)
        threads = proc.threads()
        if not threads:
            return "No threads found"

        tid = threads[0].id
        node_count = w.DWORD(16)
        nodes = (WAITCHAIN_NODE_INFO * 16)()

        # OpenThreadChain
        ret = advapi32.OpenThreadWaitChainSession(0, None)
        if not ret:
            return "WCT session failed"

        h_wct = w.HANDLE(ret)
        try:
            ret = advapi32.GetThreadWaitChain(
                h_wct, None, 0, tid, ctypes.byref(node_count), ctypes.byref(nodes), None
            )
            if not ret:
                return "WCT query failed (may need admin)"
            lines = []
            for i in range(node_count.value):
                obj_type = ["Thread", "Process", "CSwitch", "?"][min(nodes[i].ObjectType, 3)]
                status_codes = {
                    0: "Running", 1: "Blocked", 2: "Deadlock",
                    3: "Suspended", 4: "Terminated", 5: "Unknown",
                }
                status = status_codes.get(nodes[i].ObjectStatus, f"Status({nodes[i].ObjectStatus})")
                lines.append(f"Node {i}: {obj_type} -- {status}")
            return "\n".join(lines) if lines else "Empty chain"
        finally:
            advapi32.CloseThreadWaitChainSession(h_wct)
    except Exception as e:
        return f"WCT error: {e}"


# -- process data model -----------------------------------------------------
class ProcInfo:
    __slots__ = ("pid", "name", "cpu", "memory", "threads", "handles",
                 "disk_read", "disk_write", "status", "user",
                 "cmdline", "description", "cpu_time", "create_time",
                 "priority", "ppid", "session_id", "exe",
                 "num_ctx_switches", "io_other")

    def __init__(self, proc: psutil.Process):
        self.pid: int = proc.pid
        self.name: str = safe_get(proc.name, "?")
        self.cpu: float = -1.0
        self.memory: float = -1.0
        self.threads: int = -1
        self.handles: int = -1
        self.disk_read: int = -1
        self.disk_write: int = -1
        self.status: str = safe_get(lambda: proc.status(), "?")
        self.user: str = safe_get(proc.username, "?")
        self.cmdline: str = ""
        self.description: str = ""
        self.cpu_time: float = -1.0
        self.create_time: float = -1.0
        self.priority: int = -1
        self.ppid: int = -1
        self.session_id: int = -1
        self.exe: str = ""
        self.num_ctx_switches: int = -1
        self.io_other: int = -1

    def row_values(self) -> tuple:
        return (
            self.name,
            str(self.pid),
            f"{self.cpu:.1f}" if self.cpu >= 0 else "--",
            fmt_bytes(int(self.memory)) if self.memory >= 0 else "--",
            str(self.threads) if self.threads >= 0 else "--",
            str(self.handles) if self.handles >= 0 else "--",
            fmt_bytes(self.disk_read) if self.disk_read >= 0 else "--",
            self.status,
            self.user,
            self.description or "--",
        )

    def detail_row(self) -> tuple:
        """Row for the Details tab."""
        priority_names = {
            psutil.REALTIME_PRIORITY_CLASS: "Realtime",
            psutil.HIGH_PRIORITY_CLASS: "High",
            psutil.ABOVE_NORMAL_PRIORITY_CLASS: "Above Normal",
            psutil.NORMAL_PRIORITY_CLASS: "Normal",
            psutil.BELOW_NORMAL_PRIORITY_CLASS: "Below Normal",
            psutil.IDLE_PRIORITY_CLASS: "Low",
        }
        prio_str = priority_names.get(self.priority, str(self.priority)) if self.priority >= 0 else "--"
        cpu_time_str = fmt_duration(self.cpu_time) if self.cpu_time >= 0 else "--"
        create_str = datetime.fromtimestamp(self.create_time).strftime("%Y-%m-%d %H:%M:%S") \
            if self.create_time > 0 else "--"
        return (
            self.name, str(self.pid),
            f"{self.cpu:.1f}" if self.cpu >= 0 else "--",
            fmt_bytes(int(self.memory)) if self.memory >= 0 else "--",
            self.status, self.user,
            str(self.session_id) if self.session_id >= 0 else "--",
            self.cmdline[:200] if self.cmdline else "--",
            self.description or "--",
            prio_str, cpu_time_str, create_str,
        )


def collect_procs() -> list[ProcInfo]:
    """Fast first-pass collection -- name + pid only."""
    procs: list[ProcInfo] = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            procs.append(ProcInfo(p))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    log.debug("Collected %d process stubs", len(procs))
    return procs


def enrich_procs(procs: list[ProcInfo]) -> list[ProcInfo]:
    """Second pass -- fill in all metrics via oneshot()."""
    enriched = 0
    for pi in procs:
        try:
            p = psutil.Process(pi.pid)
            with p.oneshot():
                pi.cpu = p.cpu_percent() or 0.0
                pi.memory = p.memory_info().rss
                pi.threads = p.num_threads()
                pi.handles = p.num_handles() if hasattr(p, 'num_handles') else -1
                try:
                    io = p.io_counters()
                    pi.disk_read = io.read_bytes
                    pi.disk_write = io.write_bytes
                    pi.io_other = io.other_bytes
                except Exception:
                    pi.disk_read = 0
                    pi.disk_write = 0
                    pi.io_other = 0
                pi.status = p.status()
                try:
                    pi.user = p.username()
                except Exception:
                    pass
                pi.cmdline = " ".join(p.cmdline()) if safe_get(lambda: p.cmdline()) else ""
                pi.description = get_process_description(p)
                pi.priority = safe_int(lambda: p.nice(), -1)
                pi.ppid = safe_int(lambda: p.ppid(), -1)
                pi.cpu_time = sum(p.cpu_times()) if hasattr(p, 'cpu_times') else -1
                pi.create_time = safe_int(lambda: p.create_time(), -1)
                pi.session_id = safe_int(lambda: p.session_id(), -1)
                pi.exe = safe_get(p.exe)
                pi.num_ctx_switches = sum(p.num_ctx_switches()) \
                    if hasattr(p, 'num_ctx_switches') else -1
                enriched += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pi.cpu = 0.0
            pi.memory = 0.0
            pi.threads = 0
            pi.handles = 0
            pi.disk_read = 0
            pi.disk_write = 0
        except Exception as e:
            log.debug("enrich_procs: PID %d error: %s", pi.pid, e)
    log.debug("Enriched %d / %d processes", enriched, len(procs))
    return procs


# -- live graph canvas ------------------------------------------------------
class LiveGraph(Frame):
    """Scrolling line graph on a tkinter Canvas."""

    def __init__(self, parent, title: str, color: str, unit: str = "%",
                 max_val: float = 100.0, fixed_scale: bool = True,
                 warn_threshold: float | None = None,
                 second_line: tuple[str, str] | None = None,
                 bg: str = "#1e1e1e", fg: str = "#d4d4d4",
                 height: int = 120):
        super().__init__(parent, bg=bg, highlightthickness=0)
        self.title = title
        self.color = color
        self.unit = unit
        self.max_val = max_val
        self.fixed_scale = fixed_scale
        self.warn_threshold = warn_threshold
        self.second_line = second_line
        self.bg = bg
        self.fg = fg
        self.graph_height = height

        self.data: deque[float] = deque(maxlen=GRAPH_HISTORY)
        self.data2: deque[float] = deque(maxlen=GRAPH_HISTORY)

        self.lbl = Label(self, text=title, bg=bg, fg=fg,
                         font=("Segoe UI", 9, "bold"), anchor="w")
        self.lbl.pack(fill=X, padx=(8, 0), pady=(4, 0))

        self.val_lbl = Label(self, text=f"-- {unit}", bg=bg, fg="#888",
                             font=("Segoe UI", 8), anchor="w")
        self.val_lbl.pack(fill=X, padx=(8, 0), pady=(0, 2))

        self.canvas = Canvas(self, bg=bg, highlightthickness=0, height=height)
        self.canvas.pack(fill=BOTH, expand=True, padx=4, pady=(0, 4))
        self.canvas.bind("<Configure>", self._on_resize)

        self._last_w = 0
        self._last_h = 0

    def push(self, value: float, value2: float | None = None) -> None:
        self.data.append(value)
        if value2 is not None:
            self.data2.append(value2)

        if not self.fixed_scale and self.data:
            peak = max(self.data)
            self.max_val = max(peak * 1.2, 1.0)

        if self.second_line and self.data2:
            self.val_lbl.config(
                text=f"{value:.1f} {self.unit}  |  {self.second_line[0]}: {value2:.1f} {self.unit}")
        else:
            self.val_lbl.config(text=f"{value:.1f} {self.unit}")
        self._draw()

    def _draw(self) -> None:
        c = self.canvas
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 10 or h < 10:
            return

        c.delete("all")
        n = len(self.data)
        if n < 2:
            return

        grid_color = GRAPH_COLORS["grid"]
        for frac in (0.25, 0.5, 0.75):
            y = h - int(h * frac)
            c.create_line(0, y, w, y, fill=grid_color, dash=(2, 4))
            c.create_text(4, y, text=f"{self.max_val * frac:.0f}", anchor="w",
                          fill=GRAPH_COLORS["label"], font=("Consolas", 7))

        if self.warn_threshold is not None:
            yw = h - int(h * (self.warn_threshold / self.max_val))
            c.create_line(0, yw, w, yw, fill="#ffeb3b", dash=(4, 2), width=1)

        step_x = w / max(n - 1, 1)

        # main line
        points = []
        for i, v in enumerate(self.data):
            x = i * step_x
            y = h - (v / self.max_val * h)
            y = max(0, min(h, y))
            points.extend((x, y))
        if len(points) >= 4:
            c.create_line(*points, fill=self.color, width=1.5)

        # fill under main curve
        if points:
            fill_points = points[:]
            fill_points.extend((points[-2], h, 0, h))
            if len(fill_points) >= 8:
                c.create_polygon(*fill_points, fill=self.color, stipple="gray25", outline="")

        # second line
        if self.second_line and self.data2 and len(self.data2) >= 2:
            pts2 = []
            for i, v in enumerate(self.data2):
                x = i * step_x
                y = h - (v / self.max_val * h)
                y = max(0, min(h, y))
                pts2.extend((x, y))
            if len(pts2) >= 4:
                c.create_line(*pts2, fill=self.second_line[1], width=1.5)

    def _on_resize(self, event) -> None:
        if event.width != self._last_w or event.height != self._last_h:
            self._last_w = event.width
            self._last_h = event.height
            self._draw()


# -- per-core CPU compact view ----------------------------------------------
class PerCoreCpu(Frame):
    """Compact per-logical-CPU bar chart."""
    def __init__(self, parent, bg: str = "#1e1e1e"):
        super().__init__(parent, bg=bg, highlightthickness=0)
        self.bg = bg
        self._canvas = Canvas(self, bg=bg, highlightthickness=0, height=60)
        self._canvas.pack(fill=BOTH, expand=True, padx=4)
        self._canvas.bind("<Configure>", lambda e: self._draw())
        self._per_core: list[float] = []
        self._last_w = 0

    def update(self, per_core: list[float]) -> None:
        self._per_core = per_core
        self._draw()

    def _draw(self) -> None:
        c = self._canvas
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 10 or h < 10 or not self._per_core:
            return
        c.delete("all")
        n = len(self._per_core)
        bar_w = max(6, (w - 20) // n - 2)
        gap = 2
        for i, pct in enumerate(self._per_core):
            x = 10 + i * (bar_w + gap)
            bar_h = (pct / 100.0) * (h - 15)
            y1 = h - bar_h - 10
            y2 = h - 10
            # color based on usage
            if pct > 85:
                color = "#f44336"
            elif pct > 60:
                color = "#ff9800"
            elif pct > 30:
                color = "#00bcd4"
            else:
                color = "#4caf50"
            c.create_rectangle(x, y1, x + bar_w, y2, fill=color, outline="", tags="bar")
        self._last_w = w


# -- process tree builder ---------------------------------------------------
def build_process_tree(procs: list[ProcInfo]) -> dict[int, dict]:
    """Build a hierarchical tree from flat process list.
    Returns: {pid: {proc: ProcInfo, children: [pid, ...]}}
    """
    tree: dict[int, dict] = {}
    for p in procs:
        tree[p.pid] = {"proc": p, "children": []}

    # Link children to parents
    roots = {}
    for p in procs:
        parent = tree.get(p.ppid)
        if parent and p.ppid != p.pid:
            parent["children"].append(p.pid)
        else:
            roots[p.pid] = tree[p.pid]
    return roots


# -- main window ------------------------------------------------------------
class TaskManager(Tk):
    def __init__(self):
        super().__init__()
        self.title("Hermes Task Manager v3")
        self.geometry("1280x800")
        self.minsize(950, 600)

        # colors
        self.bg = "#1e1e1e"
        self.fg = "#d4d4d4"
        self.accent = "#0078d4"
        self.row_bg_odd = "#252526"
        self.row_bg_even = "#2d2d30"
        self.configure(bg=self.bg)

        # set app icon if possible
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        # -- ttk style --
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview",
                        background=self.row_bg_odd, foreground=self.fg,
                        fieldbackground=self.row_bg_odd, rowheight=24,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                        background="#333333", foreground=self.fg,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview",
                  background=[("selected", self.accent)],
                  foreground=[("selected", "#ffffff")])
        style.configure("TNotebook", background=self.bg, borderwidth=0)
        style.configure("TNotebook.Tab", background="#2d2d30", foreground=self.fg,
                        padding=(16, 4), font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", self.bg)],
                  foreground=[("selected", "#ffffff")])
        style.configure("TFrame", background=self.bg)

        # -- state --
        self.procs: list[ProcInfo] = []
        self._running = True
        self._refreshing = False  # prevent concurrent refresh cycles
        self._refresh_queued = False  # debounce: re-schedule if refresh was skipped
        self._sort_col = "name"
        self._sort_asc = True
        self._filter_text = ""
        self._refresh_job: str | None = None
        self._tree_mode = "group"  # "group", "flat", or "tree"
        self._expanded_groups: set[str] = set()  # track expanded group names across refreshes
        self._scan_results: list[ScanResult] = []  # Security tab scan results
        self._scan_running: bool = False  # prevent concurrent scans
        self._scan_orchestrator: ScanOrchestrator | None = None

        self._prev_disk = (0, 0)
        self._prev_net = (0, 0)
        self._prev_ts: float = time.perf_counter()

        # app history accumulator
        self._history: dict[str, dict] = {}

        # -- build UI --
        self._build_menubar()
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill=BOTH, expand=True, padx=(2, 2), pady=(2, 0))

        self._build_processes_tab()
        self._build_perf_tab()
        self._build_app_history_tab()
        self._build_details_tab()
        self._build_services_tab()
        self._build_startup_tab()
        self._build_users_tab()
        self._build_security_tab()

        self._build_statusbar()
        self._build_context_menus()
        self._bind_keys()

        # initial load
        log.info("Performing initial data scan…")
        self._refresh()

        # auto-refresh
        self._start_auto_refresh()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        log.info("Hermes Task Manager v3 ready -- %d tabs", self._notebook.index("end"))

    # -- menubar ------------------------------------------------------------
    def _build_menubar(self) -> None:
        menubar = Menu(self, bg="#2d2d30", fg=self.fg,
                       activebackground=self.accent, activeforeground="#fff",
                       font=("Segoe UI", 9))
        self.config(menu=menubar)

        # File
        file_menu = Menu(menubar, tearoff=0, bg="#2d2d30", fg=self.fg,
                         font=("Segoe UI", 9))
        file_menu.add_command(label="Run new task", command=self._run_new_task)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close, accelerator="Alt+F4")
        menubar.add_cascade(label="File", menu=file_menu)

        # View
        view_menu = Menu(menubar, tearoff=0, bg="#2d2d30", fg=self.fg,
                         font=("Segoe UI", 9))
        view_menu.add_command(label="Refresh now", command=self._refresh, accelerator="F5")
        view_menu.add_separator()
        self._auto_var = StringVar(value="on")
        view_menu.add_checkbutton(label="Auto-refresh", variable=self._auto_var,
                                  onvalue="on", offvalue="off", command=self._toggle_auto)
        view_menu.add_separator()
        view_menu.add_command(label="Select columns…", command=self._select_columns)
        view_menu.add_separator()
        view_menu.add_command(label="Processes tab", command=lambda: self._notebook.select(PROCESS_TAB_INDEX),
                              accelerator="Ctrl+1")
        view_menu.add_command(label="Performance tab", command=lambda: self._notebook.select(PERF_TAB_INDEX),
                              accelerator="Ctrl+2")
        view_menu.add_command(label="App History tab", command=lambda: self._notebook.select(APP_HISTORY_TAB_INDEX))
        view_menu.add_command(label="Details tab", command=lambda: self._notebook.select(DETAILS_TAB_INDEX),
                              accelerator="Ctrl+3")
        view_menu.add_command(label="Services tab", command=lambda: self._notebook.select(SERVICES_TAB_INDEX))
        view_menu.add_command(label="Startup tab", command=lambda: self._notebook.select(STARTUP_TAB_INDEX))
        view_menu.add_command(label="Users tab", command=lambda: self._notebook.select(USERS_TAB_INDEX))
        view_menu.add_separator()
        view_menu.add_command(label="Security tab", command=lambda: self._notebook.select(SECURITY_TAB_INDEX),
                              accelerator="Ctrl+6")
        menubar.add_cascade(label="View", menu=view_menu)

        # Options
        options_menu = Menu(menubar, tearoff=0, bg="#2d2d30", fg=self.fg,
                            font=("Segoe UI", 9))
        self._ontop_var = StringVar(value="off")
        options_menu.add_checkbutton(label="Always on top", variable=self._ontop_var,
                                     onvalue="on", offvalue="off",
                                     command=lambda: self.attributes("-topmost",
                                         self._ontop_var.get() == "on"))
        options_menu.add_separator()
        options_menu.add_command(label="Export process list to CSV…",
                                 command=self._export_csv)
        menubar.add_cascade(label="Options", menu=options_menu)

        # Help
        help_menu = Menu(menubar, tearoff=0, bg="#2d2d30", fg=self.fg,
                         font=("Segoe UI", 9))
        help_menu.add_command(label="View Logs", command=self._open_logs)
        help_menu.add_command(label="Open Log Folder", command=self._open_log_folder)
        help_menu.add_separator()
        help_menu.add_command(label="About Hermes Task Manager", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

    # -- tab: Processes -----------------------------------------------------
    def _build_processes_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="Processes")
        self._proc_tab = tab

        # search bar
        bar = Frame(tab, bg="#2d2d30", height=38)
        bar.pack(fill=X, side="top")
        bar.pack_propagate(False)

        Label(bar, text="Search:", bg="#2d2d30", fg=self.fg,
              font=("Segoe UI", 9)).pack(side=LEFT, padx=(12, 4), pady=6)
        self._search_var = StringVar()
        self._search_var.trace_add("write", lambda *a: self._on_search())
        self._search_entry = ttk.Entry(bar, textvariable=self._search_var, width=28,
                                       font=("Segoe UI", 9))
        self._search_entry.pack(side=LEFT, padx=(0, 12), pady=6, ipady=2)

        # Group/Flat/Tree toggle
        self._tree_mode_btn = ttk.Button(bar, text="Flat View", command=self._toggle_tree_mode)
        self._tree_mode_btn.pack(side=LEFT, padx=(4, 4), pady=4)

        ttk.Button(bar, text="+", width=3,
                   command=lambda: self._expand_collapse_all(True)).pack(side=LEFT, padx=(0, 1), pady=4)
        ttk.Button(bar, text="−", width=3,
                   command=lambda: self._expand_collapse_all(False)).pack(side=LEFT, padx=(0, 12), pady=4)

        Label(bar, text="|  Del=End  |  F5=Refresh  |  Ctrl+F=Search  |  Ctrl+Tab=Switch  |  Right-click=Menu",
              bg="#2d2d30", fg="#888", font=("Segoe UI", 8)).pack(side=LEFT, padx=(8, 0), pady=6)

        # treeview
        frame = Frame(tab, bg=self.bg)
        frame.pack(fill=BOTH, expand=True)

        vsb = ttk.Scrollbar(frame, orient=VERTICAL)
        hsb = ttk.Scrollbar(frame, orient=HORIZONTAL)

        self._tree = ttk.Treeview(
            frame, columns=COLS, show="tree headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._tree.yview)
        hsb.config(command=self._tree.xview)

        for col in COLS:
            self._tree.heading(col, text=COL_LABELS[col],
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=COL_WIDTHS[col], minwidth=40, anchor="w")
        for col in ("cpu", "memory", "pid", "threads", "handles", "disk_io"):
            self._tree.column(col, anchor="e")

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._tree.bind("<Button-3>", self._on_proc_right_click)
        self._tree.bind("<Double-1>", self._on_proc_double_click)

    # -- tab: Performance ---------------------------------------------------
    def _build_perf_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="Performance")
        self._perf_tab = tab

        # header
        header = Frame(tab, bg=self.bg, height=70)
        header.pack(fill=X, padx=8, pady=(8, 0))
        header.pack_propagate(False)

        cpu_name = plat.processor() or "CPU"
        self._perf_cpu_label = Label(header, text=f"CPU: {cpu_name}",
                                     bg=self.bg, fg=self.fg,
                                     font=("Segoe UI", 12, "bold"), anchor="w")
        self._perf_cpu_label.pack(fill=X)
        self._perf_detail_label = Label(header, text="", bg=self.bg, fg="#888",
                                        font=("Segoe UI", 9), anchor="w")
        self._perf_detail_label.pack(fill=X)
        self._perf_mem_detail_label = Label(header, text="", bg=self.bg, fg="#888",
                                            font=("Segoe UI", 9), anchor="w")
        self._perf_mem_detail_label.pack(fill=X)

        # main perf: scrollable
        canvas = Canvas(tab, bg=self.bg, highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient=VERTICAL, command=canvas.yview)
        perf_content = Frame(canvas, bg=self.bg)
        perf_content.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=perf_content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        # CPU section
        cpu_section = Frame(perf_content, bg=self.bg)
        cpu_section.pack(fill=X, padx=4, pady=(4, 8))

        Label(cpu_section, text="CPU -- % Utilization", bg=self.bg, fg=GRAPH_COLORS["label"],
              font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=(8, 0))

        self._graph_cpu = LiveGraph(cpu_section, "Overall CPU", GRAPH_COLORS["cpu"],
                                     unit="%", max_val=100.0, fixed_scale=True,
                                     warn_threshold=85.0, height=140)
        self._graph_cpu.pack(fill=X, padx=(0, 0), pady=(2, 4))

        # Per-core CPU
        self._percore_label = Label(cpu_section, text="Logical Processors", bg=self.bg,
                                     fg=GRAPH_COLORS["label"], font=("Segoe UI", 8))
        self._percore_label.pack(anchor="w", padx=(8, 0))
        self._percore_cpu = PerCoreCpu(cpu_section, bg=self.bg)
        self._percore_cpu.pack(fill=X, padx=(4, 4), pady=(2, 6))

        # Memory section
        mem_section = Frame(perf_content, bg=self.bg)
        mem_section.pack(fill=X, padx=4, pady=(0, 8))

        Label(mem_section, text="Memory", bg=self.bg, fg=GRAPH_COLORS["label"],
              font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=(8, 0))

        graph_row = Frame(mem_section, bg=self.bg)
        graph_row.pack(fill=X)
        graph_row.columnconfigure(0, weight=1)
        graph_row.columnconfigure(1, weight=1)

        self._graph_mem = LiveGraph(graph_row, "Memory Usage", GRAPH_COLORS["memory"],
                                     unit="%", max_val=100.0, fixed_scale=True,
                                     warn_threshold=85.0, height=110)
        self._graph_mem.grid(row=0, column=0, sticky="nsew", padx=(0, 2))

        self._graph_mem_comp = LiveGraph(graph_row, "Committed",
                                          GRAPH_COLORS["mem_committed"],
                                          unit="GB", max_val=32.0, fixed_scale=False,
                                          height=110)
        self._graph_mem_comp.grid(row=0, column=1, sticky="nsew", padx=(2, 0))

        # Disk section
        disk_section = Frame(perf_content, bg=self.bg)
        disk_section.pack(fill=X, padx=4, pady=(0, 8))

        Label(disk_section, text="Disk", bg=self.bg, fg=GRAPH_COLORS["label"],
              font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=(8, 0))

        self._graph_disk = LiveGraph(disk_section, "Disk I/O", GRAPH_COLORS["disk_read"],
                                      unit="MB/s", max_val=50.0, fixed_scale=False,
                                      second_line=("Write", GRAPH_COLORS["disk_write"]),
                                      height=110)
        self._graph_disk.pack(fill=X)

        # Network section
        net_section = Frame(perf_content, bg=self.bg)
        net_section.pack(fill=X, padx=4, pady=(0, 8))

        Label(net_section, text="Network", bg=self.bg, fg=GRAPH_COLORS["label"],
              font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=(8, 0))

        self._graph_net = LiveGraph(net_section, "Throughput", GRAPH_COLORS["net_sent"],
                                     unit="Mbps", max_val=100.0, fixed_scale=False,
                                     second_line=("Recv", GRAPH_COLORS["net_recv"]),
                                     height=110)
        self._graph_net.pack(fill=X)

        # GPU section
        gpu_section = Frame(perf_content, bg=self.bg)
        gpu_section.pack(fill=X, padx=4, pady=(0, 8))

        self._gpu_info = Label(gpu_section, text="GPU: Detecting…",
                               bg=self.bg, fg="#888", font=("Segoe UI", 9, "bold"), anchor="w")
        self._gpu_info.pack(fill=X, padx=(8, 0))

        self._graph_gpu = LiveGraph(gpu_section, "GPU Usage", GRAPH_COLORS["gpu"],
                                     unit="%", max_val=100.0, fixed_scale=True,
                                     warn_threshold=90.0, height=110)
        self._graph_gpu.pack(fill=X)

    # -- tab: App History ---------------------------------------------------
    def _build_app_history_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="App History")
        self._hist_tab = tab

        # info bar
        ibar = Frame(tab, bg="#2d2d30", height=36)
        ibar.pack(fill=X, side="top")
        ibar.pack_propagate(False)
        Label(ibar, text="Resource usage history by application (since launch)",
              bg="#2d2d30", fg="#888", font=("Segoe UI", 9)).pack(side=LEFT, padx=(12, 0), pady=6)
        Label(ibar, text="|  Data accumulates while app is running",
              bg="#2d2d30", fg="#666", font=("Segoe UI", 8)).pack(side=LEFT, padx=(8, 0), pady=6)

        # tree
        tframe = Frame(tab, bg=self.bg)
        tframe.pack(fill=BOTH, expand=True)

        vsb = ttk.Scrollbar(tframe, orient=VERTICAL)
        hsb = ttk.Scrollbar(tframe, orient=HORIZONTAL)

        self._hist_tree = ttk.Treeview(
            tframe, columns=HIST_COLS, show="headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._hist_tree.yview)
        hsb.config(command=self._hist_tree.xview)

        for col in HIST_COLS:
            self._hist_tree.heading(col, text=HIST_COL_LABELS[col],
                                    command=lambda c=col: self._sort_hist_by(c))
            self._hist_tree.column(col, width=HIST_COL_WIDTHS[col], minwidth=60, anchor="w")
        for col in ("hist_cpu_time", "hist_net_in", "hist_net_out", "hist_reads", "hist_writes"):
            self._hist_tree.column(col, anchor="e")

        self._hist_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)

        self._hist_sort_col = "hist_cpu_time"
        self._hist_sort_asc = False

        # reset button
        btn_frame = Frame(tab, bg=self.bg)
        btn_frame.pack(fill=X, padx=4, pady=(4, 0))
        ttk.Button(btn_frame, text="Reset History", command=self._reset_history).pack(side=RIGHT, padx=(0, 8))

    # -- tab: Details -------------------------------------------------------
    def _build_details_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="Details")
        self._det_tab = tab

        # search bar
        dbar = Frame(tab, bg="#2d2d30", height=36)
        dbar.pack(fill=X, side="top")
        dbar.pack_propagate(False)

        Label(dbar, text="Filter:", bg="#2d2d30", fg=self.fg,
              font=("Segoe UI", 9)).pack(side=LEFT, padx=(12, 4), pady=6)
        self._det_search_var = StringVar()
        self._det_search_var.trace_add("write", lambda *a: self._render_details())
        self._det_search_entry = ttk.Entry(dbar, textvariable=self._det_search_var, width=28,
                                            font=("Segoe UI", 9))
        self._det_search_entry.pack(side=LEFT, padx=(0, 12), pady=6, ipady=2)
        Label(dbar, text="|  Extended process details with command line, priority, CPU time",
              bg="#2d2d30", fg="#888", font=("Segoe UI", 8)).pack(side=LEFT, padx=(8, 0), pady=6)

        # tree
        tframe = Frame(tab, bg=self.bg)
        tframe.pack(fill=BOTH, expand=True)

        vsb = ttk.Scrollbar(tframe, orient=VERTICAL)
        hsb = ttk.Scrollbar(tframe, orient=HORIZONTAL)

        self._det_tree = ttk.Treeview(
            tframe, columns=DET_COLS, show="headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._det_tree.yview)
        hsb.config(command=self._det_tree.xview)

        for col in DET_COLS:
            self._det_tree.heading(col, text=DET_COL_LABELS[col],
                                   command=lambda c=col: self._sort_det_by(c))
            self._det_tree.column(col, width=DET_COL_WIDTHS[col], minwidth=45, anchor="w")
        for col in ("det_pid", "det_cpu", "det_memory", "det_session", "det_cpu_time"):
            self._det_tree.column(col, anchor="e")

        self._det_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)

        self._det_tree.bind("<Button-3>", self._on_det_right_click)
        self._det_sort_col = "det_name"
        self._det_sort_asc = True
        self._det_data: list[ProcInfo] = []

    # -- tab: Services ------------------------------------------------------
    def _build_services_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="Services")
        self._svc_tab = tab

        sbar = Frame(tab, bg="#2d2d30", height=36)
        sbar.pack(fill=X, side="top")
        sbar.pack_propagate(False)
        Label(sbar, text="Filter:", bg="#2d2d30", fg=self.fg,
              font=("Segoe UI", 9)).pack(side=LEFT, padx=(12, 4), pady=6)
        self._svc_search_var = StringVar()
        self._svc_search_var.trace_add("write", lambda *a: self._on_svc_search())
        self._svc_search_entry = ttk.Entry(sbar, textvariable=self._svc_search_var, width=28,
                                            font=("Segoe UI", 9))
        self._svc_search_entry.pack(side=LEFT, padx=(0, 12), pady=6, ipady=2)
        Label(sbar, text="|  Right-click → Start / Stop / Restart  |  Admin required",
              bg="#2d2d30", fg="#888", font=("Segoe UI", 8)).pack(side=LEFT, padx=(8, 0), pady=6)

        tframe = Frame(tab, bg=self.bg)
        tframe.pack(fill=BOTH, expand=True)
        vsb = ttk.Scrollbar(tframe, orient=VERTICAL)
        hsb = ttk.Scrollbar(tframe, orient=HORIZONTAL)

        self._svc_tree = ttk.Treeview(
            tframe, columns=SVC_COLS, show="headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._svc_tree.yview)
        hsb.config(command=self._svc_tree.xview)

        for col in SVC_COLS:
            self._svc_tree.heading(col, text=SVC_COL_LABELS[col],
                                   command=lambda c=col: self._sort_svc_by(c))
            self._svc_tree.column(col, width=SVC_COL_WIDTHS[col], minwidth=50, anchor="w")
        self._svc_tree.column("svc_pid", anchor="e")

        self._svc_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)
        self._svc_tree.bind("<Button-3>", self._on_svc_right_click)
        self._svc_data: list[dict] = []
        self._svc_sort_col = "svc_name"
        self._svc_sort_asc = True
        self._svc_filter = ""

        self._notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        # Defer initial services load to after mainloop starts (avoid thread/after race)
        self.after(100, self._refresh_services)

    # -- tab: Startup -------------------------------------------------------
    def _build_startup_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="Startup")
        self._su_tab = tab

        ibar = Frame(tab, bg="#2d2d30", height=36)
        ibar.pack(fill=X, side="top")
        ibar.pack_propagate(False)
        Label(ibar, text="Startup programs (registry Run keys)",
              bg="#2d2d30", fg="#888", font=("Segoe UI", 9)).pack(side=LEFT, padx=(12, 0), pady=6)
        Label(ibar, text="|  Right-click → Disable/Enable  |  Double-click → Open location",
              bg="#2d2d30", fg="#888", font=("Segoe UI", 8)).pack(side=LEFT, padx=(8, 0), pady=6)

        tframe = Frame(tab, bg=self.bg)
        tframe.pack(fill=BOTH, expand=True)
        vsb = ttk.Scrollbar(tframe, orient=VERTICAL)
        hsb = ttk.Scrollbar(tframe, orient=HORIZONTAL)

        self._su_tree = ttk.Treeview(
            tframe, columns=SU_COLS, show="headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._su_tree.yview)
        hsb.config(command=self._su_tree.xview)

        for col in SU_COLS:
            self._su_tree.heading(col, text=SU_COL_LABELS[col],
                                  command=lambda c=col: self._sort_su_by(c))
            self._su_tree.column(col, width=SU_COL_WIDTHS[col], minwidth=50, anchor="w")

        self._su_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)
        self._su_tree.bind("<Button-3>", self._on_su_right_click)
        self._su_tree.bind("<Double-1>", lambda e: self._su_open_location())
        self._su_data: list[dict] = []
        self._su_sort_col = "su_name"
        self._su_sort_asc = True
        self._load_startup()

    # -- tab: Users ---------------------------------------------------------
    def _build_users_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="Users")
        self._users_tab = tab

        ibar = Frame(tab, bg="#2d2d30", height=30)
        ibar.pack(fill=X, side="top")
        ibar.pack_propagate(False)
        Label(ibar, text="Processes grouped by user account",
              bg="#2d2d30", fg="#888", font=("Segoe UI", 9)).pack(side=LEFT, padx=(12, 0), pady=6)

        tframe = Frame(tab, bg=self.bg)
        tframe.pack(fill=BOTH, expand=True)
        vsb = ttk.Scrollbar(tframe, orient=VERTICAL)
        hsb = ttk.Scrollbar(tframe, orient=HORIZONTAL)

        self._users_tree = ttk.Treeview(
            tframe, columns=("u_user", "u_cpu", "u_mem", "u_count", "u_threads"),
            show="headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._users_tree.yview)
        hsb.config(command=self._users_tree.xview)

        for col, label, w in [
            ("u_user", "User", 220), ("u_cpu", "CPU %", 90),
            ("u_mem", "Memory", 140), ("u_count", "Processes", 100),
            ("u_threads", "Threads", 80),
        ]:
            self._users_tree.heading(col, text=label)
            self._users_tree.column(col, width=w, minwidth=60, anchor="w")
        self._users_tree.column("u_cpu", anchor="e")
        self._users_tree.column("u_mem", anchor="e")
        self._users_tree.column("u_threads", anchor="e")

        self._users_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)

    # -- tab: Security (GMER-style anti-rootkit) ------------------------------
    def _build_security_tab(self) -> None:
        tab = Frame(self._notebook, bg=self.bg)
        self._notebook.add(tab, text="Security")
        self._sec_tab = tab

        # -- Top status summary bar --
        header = Frame(tab, bg="#1a1a2e", height=52)
        header.pack(fill=X, side="top")
        header.pack_propagate(False)

        self._sec_status_icon = Label(header, text="🛡️", bg="#1a1a2e", fg="#4caf50",
                                       font=("Segoe UI", 16))
        self._sec_status_icon.pack(side=LEFT, padx=(12, 4), pady=8)

        self._sec_status_label = Label(
            header, text="Ready — Click a scan button to begin",
            bg="#1a1a2e", fg="#d4d4d4", font=("Segoe UI", 11, "bold"), anchor="w")
        self._sec_status_label.pack(side=LEFT, padx=(4, 0), pady=8)

        self._sec_stats_label = Label(
            header, text="", bg="#1a1a2e", fg="#888",
            font=("Segoe UI", 9), anchor="w")
        self._sec_stats_label.pack(side=LEFT, padx=(20, 0), pady=8)

        # -- Button bar --
        btn_frame = Frame(tab, bg="#2d2d30")
        btn_frame.pack(fill=X, side="top", pady=(0, 1))

        # Row 1: main scan buttons
        btn_row1 = Frame(btn_frame, bg="#2d2d30")
        btn_row1.pack(fill=X, padx=4, pady=(4, 2))

        ttk.Button(btn_row1, text="🔍 Scan All",
                   command=self._sec_scan_all).pack(side=LEFT, padx=(4, 2), pady=2)
        ttk.Button(btn_row1, text="Hidden Processes",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_PROCESSES)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row1, text="Hidden Modules",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_MODULES)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row1, text="Hidden Services",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_SERVICES)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row1, text="Hidden Files",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_FILES)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row1, text="Hidden Threads",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_THREADS)).pack(
            side=LEFT, padx=2, pady=2)

        # Row 2: more buttons
        btn_row2 = Frame(btn_frame, bg="#2d2d30")
        btn_row2.pack(fill=X, padx=4, pady=(0, 4))

        ttk.Button(btn_row2, text="MBR Scan",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_SECTORS)).pack(
            side=LEFT, padx=(4, 2), pady=2)
        ttk.Button(btn_row2, text="ADS Scan",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_ADS)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row2, text="Hidden Registry",
                   command=lambda: self._sec_run_category(ScanCategory.HIDDEN_REGISTRY)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row2, text="Inline Hooks",
                   command=lambda: self._sec_run_category(ScanCategory.INLINE_HOOKS)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row2, text="SSDT",
                   command=lambda: self._sec_run_category(ScanCategory.SSDT_HOOKS)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row2, text="IDT",
                   command=lambda: self._sec_run_category(ScanCategory.IDT_HOOKS)).pack(
            side=LEFT, padx=2, pady=2)
        ttk.Button(btn_row2, text="IRP",
                   command=lambda: self._sec_run_category(ScanCategory.IRP_HOOKS)).pack(
            side=LEFT, padx=2, pady=2)

        ttk.Button(btn_row2, text="⏹ Cancel", command=self._sec_cancel_scan).pack(
            side=RIGHT, padx=(8, 4), pady=2)
        ttk.Button(btn_row2, text="📋 Export Report", command=self._sec_export_report).pack(
            side=RIGHT, padx=2, pady=2)
        ttk.Button(btn_row2, text="🗑 Clear", command=self._sec_clear_results).pack(
            side=RIGHT, padx=2, pady=2)

        Label(btn_frame,
              text="⚠️ Admin privileges required for MBR, NT-level process, and kernel scans",
              bg="#2d2d30", fg="#ff9800", font=("Segoe UI", 8)).pack(
            side=LEFT, padx=(20, 0), pady=2)

        # -- Results tree --
        tframe = Frame(tab, bg=self.bg)
        tframe.pack(fill=BOTH, expand=True)

        vsb = ttk.Scrollbar(tframe, orient=VERTICAL)
        hsb = ttk.Scrollbar(tframe, orient=HORIZONTAL)

        SEC_COLS = ("sec_severity", "sec_category", "sec_finding", "sec_details")
        self._sec_tree = ttk.Treeview(
            tframe, columns=SEC_COLS, show="headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._sec_tree.yview)
        hsb.config(command=self._sec_tree.xview)

        self._sec_tree.heading("sec_severity", text="⚠", command=lambda: self._sec_sort("severity"))
        self._sec_tree.column("sec_severity", width=42, minwidth=36, anchor="center")
        self._sec_tree.heading("sec_category", text="Category")
        self._sec_tree.column("sec_category", width=170, minwidth=100, anchor="w")
        self._sec_tree.heading("sec_finding", text="Finding")
        self._sec_tree.column("sec_finding", width=340, minwidth=150, anchor="w")
        self._sec_tree.heading("sec_details", text="Details")
        self._sec_tree.column("sec_details", width=500, minwidth=200, anchor="w")

        self._sec_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)

        self._sec_tree.bind("<Button-3>", self._on_sec_right_click)
        self._sec_tree.bind("<Double-1>", lambda e: self._sec_view_details())

        # Severity tags
        self._sec_tree.tag_configure("sev_critical", foreground="#ffffff",
                                      background="#d32f2f", font=("Segoe UI", 9, "bold"))
        self._sec_tree.tag_configure("sev_high", foreground="#ffffff",
                                      background="#e65100")
        self._sec_tree.tag_configure("sev_medium", foreground="#1e1e1e",
                                      background="#fdd835")
        self._sec_tree.tag_configure("sev_low", foreground="#ffffff",
                                      background="#1565c0")
        self._sec_tree.tag_configure("sev_info", foreground="#ffffff",
                                      background="#616161")

        self._sec_sort_col = "severity"
        self._sec_sort_asc = True

    # -- status bar ---------------------------------------------------------
    def _build_statusbar(self) -> None:
        bar = Frame(self, bg="#007acc", height=28)
        bar.pack(fill=X, side="bottom")
        bar.pack_propagate(False)

        self._status_proc_count = Label(bar, text="Processes: 0", bg="#007acc", fg="#fff",
                                         font=("Segoe UI", 9))
        self._status_proc_count.pack(side=LEFT, padx=(12, 20), pady=2)

        self._status_cpu = Label(bar, text="CPU: --", bg="#007acc", fg="#fff",
                                 font=("Segoe UI", 9))
        self._status_cpu.pack(side=LEFT, padx=(0, 20), pady=2)

        self._status_mem = Label(bar, text="Memory: --", bg="#007acc", fg="#fff",
                                 font=("Segoe UI", 9))
        self._status_mem.pack(side=LEFT, padx=(0, 20), pady=2)

        self._status_disk = Label(bar, text="Disk: --", bg="#007acc", fg="#ccc",
                                   font=("Segoe UI", 9))
        self._status_disk.pack(side=LEFT, padx=(0, 20), pady=2)

        self._status_uptime = Label(bar, text="", bg="#007acc", fg="#ccc",
                                     font=("Segoe UI", 8))
        self._status_uptime.pack(side=RIGHT, padx=(0, 12), pady=2)

    # -- context menus ------------------------------------------------------
    def _build_context_menus(self) -> None:
        # -- Processes context menu --
        self._ctx_menu = Menu(self, tearoff=0, bg="#2d2d30", fg=self.fg,
                              activebackground=self.accent, activeforeground="#fff",
                              font=("Segoe UI", 9))
        self._ctx_menu.add_command(label="Expand / Collapse", command=self._toggle_expand_selected)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="End task", command=self._end_task)
        self._ctx_menu.add_command(label="End process tree", command=self._end_tree)
        self._ctx_menu.add_command(label="End group", command=self._end_group)
        self._ctx_menu.add_separator()

        # Priority submenu
        self._prio_menu = Menu(self._ctx_menu, tearoff=0, bg="#2d2d30", fg=self.fg,
                               activebackground=self.accent, activeforeground="#fff",
                               font=("Segoe UI", 9))
        for label in PRIORITY_LEVELS:
            self._prio_menu.add_command(label=label,
                                        command=lambda l=label: self._set_priority(l))
        self._ctx_menu.add_cascade(label="Set priority", menu=self._prio_menu)

        self._ctx_menu.add_command(label="Set affinity…", command=self._set_affinity)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Create dump file", command=self._create_dump)
        self._ctx_menu.add_command(label="Analyze wait chain", command=self._analyze_wait_chain)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Go to service(s)", command=self._go_to_services)
        self._ctx_menu.add_command(label="View details…", command=self._view_details)
        self._ctx_menu.add_command(label="Open file location", command=self._open_file_location)
        self._ctx_menu.add_command(label="Search online", command=self._search_online)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Copy", command=self._copy_selected)
        self._ctx_menu.add_command(label="Select all", command=self._select_all)
        self._ctx_menu.add_command(label="Properties", command=self._view_details)

        # -- Details context menu (same but for details tab) --
        self._det_ctx_menu = Menu(self, tearoff=0, bg="#2d2d30", fg=self.fg,
                                  activebackground=self.accent, activeforeground="#fff",
                                  font=("Segoe UI", 9))
        self._det_ctx_menu.add_command(label="End task", command=self._end_det_task)
        self._det_ctx_menu.add_command(label="End process tree", command=self._end_det_tree)
        self._det_ctx_menu.add_separator()
        self._det_prio_menu = Menu(self._det_ctx_menu, tearoff=0, bg="#2d2d30", fg=self.fg,
                                   activebackground=self.accent, activeforeground="#fff",
                                   font=("Segoe UI", 9))
        for label in PRIORITY_LEVELS:
            self._det_prio_menu.add_command(label=label,
                                            command=lambda l=label: self._set_priority_det(l))
        self._det_ctx_menu.add_cascade(label="Set priority", menu=self._det_prio_menu)
        self._det_ctx_menu.add_command(label="Set affinity…", command=self._set_affinity_det)
        self._det_ctx_menu.add_command(label="Create dump file", command=self._create_dump_det)
        self._det_ctx_menu.add_command(label="Analyze wait chain", command=self._analyze_wait_chain_det)
        self._det_ctx_menu.add_separator()
        self._det_ctx_menu.add_command(label="Copy", command=self._copy_det_selected)

        # -- Services context menu --
        self._svc_ctx_menu = Menu(self, tearoff=0, bg="#2d2d30", fg=self.fg,
                                  activebackground=self.accent, activeforeground="#fff",
                                  font=("Segoe UI", 9))
        self._svc_ctx_menu.add_command(label="Start", command=self._svc_action_start)
        self._svc_ctx_menu.add_command(label="Stop", command=self._svc_action_stop)
        self._svc_ctx_menu.add_command(label="Restart", command=self._svc_action_restart)

        # -- Startup context menu --
        self._su_ctx_menu = Menu(self, tearoff=0, bg="#2d2d30", fg=self.fg,
                                 activebackground=self.accent, activeforeground="#fff",
                                 font=("Segoe UI", 9))
        self._su_ctx_menu.add_command(label="Disable", command=self._su_toggle)
        self._su_ctx_menu.add_command(label="Enable", command=self._su_toggle)
        self._su_ctx_menu.add_separator()
        self._su_ctx_menu.add_command(label="Open file location", command=self._su_open_location)

    # -- keyboard bindings --------------------------------------------------
    def _bind_keys(self) -> None:
        self.bind("<Delete>", lambda e: self._end_task())
        self.bind("<Control-f>", lambda e: self._focus_search())
        self.bind("<F5>", lambda e: self._refresh())
        self.bind("<Escape>", lambda e: self._clear_filter())
        self.bind("<Control-Tab>", lambda e: self._next_tab())
        self.bind("<Control-Shift-Tab>", lambda e: self._prev_tab())
        self.bind("<Control-c>", lambda e: self._copy_selected())
        self.bind("<Control-a>", lambda e: self._select_all())
        self.bind("<Control-d>", lambda e: self._create_dump())
        self.bind("<Control-Shift-E>", lambda e: self._end_tree())
        self.bind("<Control-1>", lambda e: self._notebook.select(PROCESS_TAB_INDEX))
        self.bind("<Control-2>", lambda e: self._notebook.select(PERF_TAB_INDEX))
        self.bind("<Control-3>", lambda e: self._notebook.select(DETAILS_TAB_INDEX))
        self.bind("<Control-4>", lambda e: self._notebook.select(SERVICES_TAB_INDEX))
        self.bind("<Control-5>", lambda e: self._notebook.select(STARTUP_TAB_INDEX))
        self.bind("<Control-6>", lambda e: self._notebook.select(SECURITY_TAB_INDEX))

    # -- tab navigation -----------------------------------------------------
    def _next_tab(self) -> None:
        idx = (self._notebook.index("current") + 1) % self._notebook.index("end")
        self._notebook.select(idx)

    def _prev_tab(self) -> None:
        idx = (self._notebook.index("current") - 1) % self._notebook.index("end")
        self._notebook.select(idx)

    # -- data collection (all in background thread) --------------------------
    def _collect_data(self) -> dict:
        """Collect ALL data in worker thread. Returns dict for main-thread render."""
        t0 = time.perf_counter()
        result: dict = {}

        try:
            # CPU calibration
            psutil.cpu_percent(interval=None)
            per_core_before = psutil.cpu_percent(interval=None, percpu=True)
            # process stubs
            procs_raw = collect_procs()
            time.sleep(CPU_POLL_INTERVAL)
            procs = enrich_procs(procs_raw)

            # system metrics
            cpu = psutil.cpu_percent(interval=None)
            per_core = psutil.cpu_percent(interval=None, percpu=True)
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            uptime = time.time() - psutil.boot_time()

            # disk I/O delta
            disk_io = psutil.disk_io_counters()
            disk_read_delta = 0.0
            disk_write_delta = 0.0
            if disk_io:
                now = time.perf_counter()
                dt = now - self._prev_ts
                if dt > 0 and self._prev_disk[0] > 0:
                    disk_read_delta = (disk_io.read_bytes - self._prev_disk[0]) / dt / (1024 * 1024)
                    disk_write_delta = (disk_io.write_bytes - self._prev_disk[1]) / dt / (1024 * 1024)
                self._prev_disk = (disk_io.read_bytes, disk_io.write_bytes)

            # net I/O delta
            net_io = psutil.net_io_counters()
            net_sent_delta = 0.0
            net_recv_delta = 0.0
            if net_io:
                now = time.perf_counter()
                dt = now - self._prev_ts
                if dt > 0 and self._prev_net[0] > 0:
                    net_sent_delta = (net_io.bytes_sent - self._prev_net[0]) * 8 / dt / 1_000_000
                    net_recv_delta = (net_io.bytes_recv - self._prev_net[1]) * 8 / dt / 1_000_000
                self._prev_net = (net_io.bytes_sent, net_io.bytes_recv)
            self._prev_ts = time.perf_counter()

            # GPU
            gpu_util = 0.0
            gpu_mem_used = 0
            gpu_mem_total = 0
            gpu_temp = 0
            gpu_name = ""
            try:
                r = subprocess.run(
                    ["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                     "--format=csv,noheader,nounits"],
                    capture_output=True, text=True, timeout=3)
                if r.returncode == 0 and r.stdout.strip():
                    parts = [x.strip() for x in r.stdout.strip().split(",")]
                    if len(parts) >= 5:
                        gpu_name = parts[0]
                        gpu_util = float(parts[1]) if parts[1] else 0.0
                        gpu_mem_used = int(float(parts[2])) if parts[2] else 0
                        gpu_mem_total = int(float(parts[3])) if parts[3] else 0
                        gpu_temp = int(float(parts[4])) if parts[4] else 0
            except Exception:
                pass

            # disk info per partition
            disk_parts = []
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_parts.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "total": usage.total,
                        "used": usage.used,
                        "percent": usage.percent,
                    })
                except Exception:
                    pass

            # network interface info
            net_if_stats = []
            try:
                net_addrs = psutil.net_if_addrs()
                net_stats = psutil.net_if_stats()
                for name, stats in net_stats.items():
                    addrs = net_addrs.get(name, [])
                    ip = ""
                    for a in addrs:
                        if str(a.family).endswith("INET") or str(a.family).endswith("AF_INET"):
                            ip = a.address
                            break
                    net_if_stats.append({
                        "name": name,
                        "ip": ip,
                        "speed": stats.speed,
                        "isup": stats.isup,
                    })
            except Exception:
                pass

            result.update({
                "procs": procs,
                "cpu": cpu,
                "per_core": per_core,
                "mem_pct": mem.percent,
                "mem_used": mem.used,
                "mem_available": mem.available,
                "mem_total": mem.total,
                "mem_free": mem.free,
                "swap_pct": swap.percent,
                "swap_used": swap.used,
                "swap_total": swap.total,
                "uptime": uptime,
                "disk_read": max(0, disk_read_delta),
                "disk_write": max(0, disk_write_delta),
                "net_sent": max(0, net_sent_delta),
                "net_recv": max(0, net_recv_delta),
                "gpu_util": gpu_util,
                "gpu_mem_used": gpu_mem_used,
                "gpu_mem_total": gpu_mem_total,
                "gpu_temp": gpu_temp,
                "gpu_name": gpu_name,
                "disk_parts": disk_parts,
                "net_if_stats": net_if_stats,
            })

            # Update app history
            for p in procs:
                if p.cpu_time > 0:
                    key = p.name
                    if key not in self._history:
                        self._history[key] = {
                            "name": key,
                            "cpu_time": 0.0,
                            "net_in": 0.0,
                            "net_out": 0.0,
                            "reads": 0,
                            "writes": 0,
                            "sessions": 0,
                            "first_seen": time.time(),
                            "last_seen": time.time(),
                        }
                    h = self._history[key]
                    h["cpu_time"] += CPU_POLL_INTERVAL * (p.cpu / 100.0) if p.cpu > 0 else 0
                    h["reads"] += p.disk_read if p.disk_read > 0 else 0
                    h["writes"] += p.disk_write if p.disk_write > 0 else 0
                    h["sessions"] += 1
                    h["last_seen"] = time.time()

            elapsed = time.perf_counter() - t0
            log.debug("Data collection: %.2fs | %d procs | CPU %.1f%% | Mem %.1f%%",
                      elapsed, len(procs), cpu, mem.percent)
            if elapsed > 2.0:
                log.warning("Slow collection cycle: %.2fs", elapsed)
        except Exception:
            log.exception("Data collection FAILED!")
        return result

    # -- refresh cycle ------------------------------------------------------
    def _refresh(self) -> None:
        """Synchronous refresh (initial load / F5). Blocks until complete."""
        if self._refreshing:
            log.debug("Refresh skipped — already in progress")
            self._refresh_queued = True
            return
        self._refreshing = True
        try:
            data = self._collect_data()
            self._apply_all(data)
            log.debug("Sync refresh complete")
        except Exception:
            log.exception("Sync refresh failed!")
        finally:
            self._refreshing = False
            # If a refresh was requested while we were busy, run one more
            if self._refresh_queued:
                self._refresh_queued = False
                self.after(100, self._refresh_async)

    def _refresh_async(self) -> None:
        """Background-thread collection → main-thread apply."""
        if self._refreshing:
            log.debug("Async refresh skipped — already in progress")
            self._refresh_queued = True
            return
        self._refreshing = True
        def _do():
            try:
                data = self._collect_data()
                self.after(0, lambda: self._apply_all_safe(data))
            except Exception:
                log.exception("Async collection failed!")
                self.after(0, lambda: self._mark_refresh_done())
        threading.Thread(target=_do, daemon=True).start()

    def _apply_all_safe(self, data: dict) -> None:
        """Main-thread apply wrapper that manages refresh lock."""
        try:
            self._apply_all(data)
        finally:
            self._refreshing = False
            if self._refresh_queued:
                self._refresh_queued = False
                self.after(100, self._refresh_async)

    def _mark_refresh_done(self) -> None:
        """Release refresh lock on collection error."""
        self._refreshing = False

    def _apply_all(self, data: dict) -> None:
        """Main-thread: render all views from collected data."""
        try:
            self.procs = data["procs"]

            # Processes tab (only if visible to avoid wasted work)
            if self._notebook.index("current") == PROCESS_TAB_INDEX:
                self._render_processes()
            else:
                self._render_processes()  # still need to keep data fresh for switch

            # Details tab
            self._det_data = data["procs"]
            if self._notebook.index("current") == DETAILS_TAB_INDEX:
                self._render_details()

            # Status bar
            self._update_statusbar(data["cpu"], data["mem_pct"], data["disk_read"], data["uptime"])

            # Users tab
            self._update_users(data["procs"])

            # Performance tab (if visible)
            self._update_perf(data)

            # App History tab
            self._render_app_history()
        except Exception:
            log.exception("Apply data failed!")

    # -- processes tab rendering --------------------------------------------
    def _render_processes(self) -> None:
        tree = self._tree
        try:
            selected_pids = self._selected_pids()
        except Exception:
            selected_pids = set()

        # Save which group parents are expanded before clearing
        expanded_groups: set[str] = set()
        if self._tree_mode == "group":
            for iid in tree.get_children():
                try:
                    if tree.get_children(iid) and tree.item(iid, "open"):
                        name = tree.item(iid, "text") or ""
                        # Strip count suffix like " (12)" to get canonical name
                        base = name.rsplit(" (", 1)[0] if " (" in name else name
                        expanded_groups.add(base.lower())
                except Exception:
                    pass
            self._expanded_groups = expanded_groups

        children = tree.get_children()
        if children:
            try:
                tree.delete(*children)
            except Exception:
                pass  # items might already be gone

        # filter
        filt = self._filter_text.lower().strip()
        display = [p for p in self.procs
                   if (not filt or filt in p.name.lower() or filt in str(p.pid))]

        # sort
        reverse = not self._sort_asc
        key = self._sort_col
        sort_map = {
            "cpu": lambda p: p.cpu, "memory": lambda p: p.memory,
            "pid": lambda p: p.pid, "threads": lambda p: p.threads,
            "handles": lambda p: p.handles,
            "disk_io": lambda p: p.disk_read + p.disk_write,
        }
        if key in sort_map:
            display.sort(key=sort_map[key], reverse=reverse)
        else:
            display.sort(key=lambda p: str(getattr(p, key, "")).lower(), reverse=reverse)

        if self._tree_mode == "group":
            # group mode — same-name processes collapsed under parent
            self._render_grouped(tree, display, selected_pids)
        elif self._tree_mode == "flat":
            # flat mode
            for i, pi in enumerate(display):
                vals = tuple(pi.row_values()[j] for j, c in enumerate(COLS) if VISIBLE_COLS.get(c, True))
                cols_to_show = [c for c in COLS if VISIBLE_COLS.get(c, True)]
                tag = "odd" if i % 2 == 0 else "even"
                iid = tree.insert("", END, values=vals, tags=(tag,))
                if pi.pid in selected_pids:
                    tree.selection_add(iid)
        else:
            # tree mode
            roots = build_process_tree(display)
            self._insert_tree_nodes(tree, "", roots, selected_pids)

        tree.tag_configure("odd", background=self.row_bg_odd)
        tree.tag_configure("even", background=self.row_bg_even)

    def _insert_tree_nodes(self, tree, parent: str, nodes: dict,
                           selected_pids: set) -> None:
        """Recursively insert process tree nodes."""
        # Sort nodes by name for consistent display
        sorted_nodes = sorted(nodes.items(), key=lambda x: x[1]["proc"].name.lower())
        for pid, node in sorted_nodes:
            pi = node["proc"]
            vals = tuple(pi.row_values()[j] for j, c in enumerate(COLS) if VISIBLE_COLS.get(c, True))
            tag = "proc"
            iid = tree.insert(parent, END, text=pi.name, values=vals, tags=(tag,), open=False)
            if pi.pid in selected_pids:
                tree.selection_add(iid)
            if node["children"]:
                child_nodes = {cpid: {"proc": next((p for p in self.procs if p.pid == cpid), None),
                                     "children": []}
                              for cpid in node["children"]}
                # Filter out None procs
                child_nodes = {k: v for k, v in child_nodes.items() if v["proc"] is not None}
                self._insert_tree_nodes(tree, iid, child_nodes, selected_pids)

    def _render_grouped(self, tree, display: list, selected_pids: set) -> None:
        """Group same-named processes under a collapsible parent with aggregated stats."""
        # -- Group by lowercase name --
        groups: dict[str, dict] = {}  # key → {"name": display_name, "procs": [...], "first_key": ...}
        for p in display:
            key = p.name.lower()
            if key not in groups:
                groups[key] = {"name": p.name, "procs": [], "first_key": key}
            groups[key]["procs"].append(p)

        # -- Sort groups --
        reverse = not self._sort_asc
        key = self._sort_col
        # For groups, sort by sum of the sort metric across all children
        if key == "name":
            group_list = sorted(groups.values(), key=lambda g: g["name"].lower(), reverse=reverse)
        elif key == "cpu":
            group_list = sorted(groups.values(),
                               key=lambda g: sum(p.cpu for p in g["procs"] if p.cpu > 0),
                               reverse=reverse)
        elif key == "memory":
            group_list = sorted(groups.values(),
                               key=lambda g: sum(p.memory for p in g["procs"] if p.memory > 0),
                               reverse=reverse)
        elif key == "pid":
            group_list = sorted(groups.values(),
                               key=lambda g: min(p.pid for p in g["procs"]),
                               reverse=reverse)
        elif key == "threads":
            group_list = sorted(groups.values(),
                               key=lambda g: sum(p.threads for p in g["procs"] if p.threads > 0),
                               reverse=reverse)
        elif key == "handles":
            group_list = sorted(groups.values(),
                               key=lambda g: sum(p.handles for p in g["procs"] if p.handles > 0),
                               reverse=reverse)
        elif key == "disk_io":
            group_list = sorted(groups.values(),
                               key=lambda g: sum(p.disk_read + p.disk_write for p in g["procs"]),
                               reverse=reverse)
        else:
            group_list = sorted(groups.values(),
                               key=lambda g: str(getattr(g["procs"][0], key, "")).lower(),
                               reverse=reverse)

        # -- Insert each group --
        for gi, group in enumerate(group_list):
            procs = group["procs"]
            n = len(procs)
            display_name = f"{group['name']} ({n})"

            # Aggregate stats
            total_cpu = sum(p.cpu for p in procs if p.cpu > 0)
            total_mem = sum(p.memory for p in procs if p.memory > 0)
            total_threads = sum(p.threads for p in procs if p.threads > 0)
            total_handles = sum(p.handles for p in procs if p.handles > 0)
            total_disk = sum(p.disk_read + p.disk_write for p in procs if p.disk_read >= 0)
            # Status: show "Running" if any child is running, else the majority status
            statuses = [p.status for p in procs]
            agg_status = "Running" if "running" in statuses else (
                max(set(statuses), key=statuses.count) if statuses else "?"
            )
            # User: show first unique user or "# users"
            users = list(set(p.user for p in procs if p.user and p.user != "?"))
            if len(users) == 1:
                agg_user = users[0]
            elif len(users) > 1:
                agg_user = f"{len(users)} users"
            else:
                agg_user = "?"

            # Build aggregated row values (all 10 COLS)
            full_vals = [
                display_name,                   # name
                str(min(p.pid for p in procs)),  # pid (use min)
                f"{total_cpu:.1f}",              # cpu
                fmt_bytes(int(total_mem)),       # memory
                str(total_threads),              # threads
                str(total_handles),              # handles
                fmt_bytes(total_disk),           # disk_io
                agg_status,                      # status
                agg_user,                        # user
                "--",                            # description
            ]
            vals = tuple(full_vals[j] for j, c in enumerate(COLS) if VISIBLE_COLS.get(c, True))
            tag = "group_parent"
            # Restore previously expanded state
            should_open = group["name"].lower() in self._expanded_groups
            parent_iid = tree.insert(
                "", END, text=display_name, values=vals, tags=(tag,), open=should_open
            )
            # If any child PID was selected, select the group parent
            if any(p.pid in selected_pids for p in procs):
                tree.selection_add(parent_iid)

            # -- Insert children (respects restored expanded state) --
            # Sort children within group by PID
            procs_sorted = sorted(procs, key=lambda p: p.pid)
            for ci, child in enumerate(procs_sorted):
                child_vals = tuple(child.row_values()[j] for j, c in enumerate(COLS)
                                  if VISIBLE_COLS.get(c, True))
                child_tag = "odd" if ci % 2 == 0 else "even"
                child_iid = tree.insert(
                    parent_iid, END, text="", values=child_vals, tags=(child_tag,)
                )
                if child.pid in selected_pids:
                    tree.selection_add(child_iid)

        # -- tag styling --
        tree.tag_configure("group_parent",
                          background="#1a3a4a", foreground="#ffffff",
                          font=("Segoe UI", 9, "bold"))

    def _toggle_tree_mode(self) -> None:
        """Cycle through: group → flat → tree → group"""
        if self._tree_mode == "group":
            self._tree_mode = "flat"
            self._tree_mode_btn.config(text="Tree View")
            self._tree.configure(show="headings")
            log.info("Switched to Flat View")
        elif self._tree_mode == "flat":
            self._tree_mode = "tree"
            self._tree_mode_btn.config(text="Group View")
            self._tree.configure(show="tree headings")
            log.info("Switched to Tree View")
        else:  # tree → group
            self._tree_mode = "group"
            self._tree_mode_btn.config(text="Flat View")
            self._tree.configure(show="tree headings")
            log.info("Switched to Group View")
        # Rebuild visible columns
        self._apply_column_visibility()
        self._render_processes()

    def _apply_column_visibility(self) -> None:
        """Show/hide columns based on VISIBLE_COLS (flat mode)."""
        if self._tree_mode == "flat":
            display_columns = [c for c in COLS if VISIBLE_COLS.get(c, True)]
            self._tree["displaycolumns"] = display_columns

    # -- details tab rendering ----------------------------------------------
    def _render_details(self) -> None:
        tree = self._det_tree
        selected = set()
        try:
            for iid in tree.selection():
                vals = tree.item(iid, "values")
                if vals:
                    try:
                        selected.add(int(vals[1]))
                    except Exception:
                        pass
        except Exception:
            pass  # tree might be mid-update

        children = tree.get_children()
        if children:
            try:
                tree.delete(*children)
            except Exception:
                pass  # items might already be gone

        filt = (self._det_search_var.get() or "").lower().strip()
        display = [p for p in self._det_data
                   if (not filt or filt in p.name.lower() or filt in str(p.pid)
                       or filt in (p.description or "").lower())]

        reverse = not self._det_sort_asc
        key = self._det_sort_col.replace("det_", "")
        sort_map = {
            "cpu": lambda p: p.cpu, "memory": lambda p: p.memory,
            "pid": lambda p: p.pid, "cpu_time": lambda p: p.cpu_time,
        }
        if key in sort_map:
            display.sort(key=sort_map[key], reverse=reverse)
        else:
            display.sort(key=lambda p: str(getattr(p, key, "")).lower(), reverse=reverse)

        for i, p in enumerate(display):
            vals = p.detail_row()
            tag = "odd" if i % 2 == 0 else "even"
            iid = tree.insert("", END, values=vals, tags=(tag,))
            if p.pid in selected:
                tree.selection_add(iid)

        tree.tag_configure("odd", background=self.row_bg_odd)
        tree.tag_configure("even", background=self.row_bg_even)

    def _sort_det_by(self, col: str) -> None:
        if self._det_sort_col == col:
            self._det_sort_asc = not self._det_sort_asc
        else:
            self._det_sort_col = col
            self._det_sort_asc = True
        log.debug("Details sorted by %s %s", col, "ASC" if self._det_sort_asc else "DESC")
        self._render_details()

    # -- app history rendering ----------------------------------------------
    def _render_app_history(self) -> None:
        tree = self._hist_tree
        children = tree.get_children()
        if children:
            tree.delete(*children)

        entries = list(self._history.values())
        reverse = not self._hist_sort_asc
        key = self._hist_sort_col.replace("hist_", "")
        entries.sort(key=lambda e: e.get(key, 0.0) if isinstance(e.get(key, 0.0), (int, float))
                     else str(e.get(key, "")), reverse=reverse)

        for i, e in enumerate(entries):
            runtime = e.get("last_seen", 0) - e.get("first_seen", time.time())
            vals = (
                e["name"],
                fmt_duration(e["cpu_time"]),
                fmt_bytes(int(e.get("net_in", 0))) if e.get("net_in", 0) > 0 else "0 B",
                fmt_bytes(int(e.get("net_out", 0))) if e.get("net_out", 0) > 0 else "0 B",
                str(e.get("reads", 0)),
                str(e.get("writes", 0)),
                fmt_duration(runtime),
            )
            tag = "odd" if i % 2 == 0 else "even"
            tree.insert("", END, values=vals, tags=(tag,))
        tree.tag_configure("odd", background=self.row_bg_odd)
        tree.tag_configure("even", background=self.row_bg_even)

    def _sort_hist_by(self, col: str) -> None:
        if self._hist_sort_col == col:
            self._hist_sort_asc = not self._hist_sort_asc
        else:
            self._hist_sort_col = col
            self._hist_sort_asc = False  # default to descending for metrics
        self._render_app_history()

    def _reset_history(self) -> None:
        if messagebox.askyesno("Reset History", "Clear all accumulated app history?", parent=self):
            self._history.clear()
            self._render_app_history()
            log.info("App history reset")

    # -- performance tab update ---------------------------------------------
    def _update_perf(self, data: dict) -> None:
        try:
            cpu = data["cpu"]
            mem_total = data["mem_total"]
            mem_used = data["mem_used"]
            mem_available = data["mem_available"]
            mem_pct = data["mem_pct"]
            swap_used = data["swap_used"]
            swap_total = data["swap_total"]

            # CPU detail
            cores = psutil.cpu_count(logical=True)
            phys = psutil.cpu_count(logical=False)
            freq = psutil.cpu_freq()
            freq_str = f"{freq.current:.0f} MHz" if freq and freq.current else ""
            self._perf_detail_label.config(
                text=f"Utilization: {cpu:.1f}%  |  Speed: {freq_str}  |  "
                     f"Logical processors: {cores}  |  Sockets: 1  |  Virtualization: Enabled")

            # Memory detail
            committed = mem_used + swap_used if swap_total > 0 else mem_used
            self._perf_mem_detail_label.config(
                text=f"Memory: {fmt_bytes(mem_used)} / {fmt_bytes(mem_total)} in use ({mem_pct:.1f}%)  |  "
                     f"Available: {fmt_bytes(mem_available)}  |  "
                     f"Committed: {fmt_bytes(committed)} / {fmt_bytes(mem_total + swap_total)}  |  "
                     f"Paged pool: --  |  Non-paged pool: --")

            # graphs
            self._graph_cpu.push(cpu)
            self._graph_mem.push(mem_pct)
            committed_gb = committed / (1024 ** 3)
            self._graph_mem_comp.push(committed_gb)
            self._graph_disk.push(data["disk_read"], data["disk_write"])
            self._graph_net.push(data["net_sent"], data["net_recv"])

            # per-core
            per_core = data.get("per_core", [])
            if per_core:
                self._percore_cpu.update(per_core)
                self._percore_label.config(
                    text=f"Logical Processors ({len(per_core)} cores) -- {max(per_core):.0f}% max")

            # GPU
            gpu_util = data.get("gpu_util", 0)
            gpu_mem_used = data.get("gpu_mem_used", 0)
            gpu_mem_total = data.get("gpu_mem_total", 0)
            gpu_temp = data.get("gpu_temp", 0)
            gpu_name = data.get("gpu_name", "")
            if gpu_name:
                gpu_label = f"GPU: {gpu_name}"
                detail = f"Utilization: {gpu_util:.0f}%  |  VRAM: {gpu_mem_used}/{gpu_mem_total} MB  |  Temp: {gpu_temp}°C"
            else:
                gpu_label = "GPU: Not detected"
                detail = "nvidia-smi unavailable -- install NVIDIA drivers for GPU monitoring"
            self._gpu_info.config(text=f"{gpu_label}  --  {detail}")
            self._graph_gpu.push(gpu_util)
        except Exception:
            log.exception("Performance render failed!")

    # -- status bar ---------------------------------------------------------
    def _update_statusbar(self, cpu: float, mem_pct: float, disk_mbps: float,
                          uptime: float) -> None:
        try:
            total = len(self.procs)
            if self._tree_mode == "group":
                groups = len(self._tree.get_children())
                self._status_proc_count.config(
                    text=f"Processes: {total}  |  Groups: {groups}")
            else:
                count = len(self._tree.get_children())
                self._status_proc_count.config(
                    text=f"Processes: {count}" + (f" / {total}" if count and count != total else ""))
            self._status_cpu.config(text=f"CPU: {cpu:.1f}%")
            self._status_mem.config(text=f"Memory: {mem_pct:.1f}%")
            self._status_disk.config(text=f"Disk: {disk_mbps:.1f} MB/s")
            h, m = divmod(int(uptime), 3600)
            d, h = divmod(h, 24)
            self._status_uptime.config(text=f"Up: {d}d {h}h {m:02d}m")
        except Exception:
            pass

    # -- users tab ----------------------------------------------------------
    def _update_users(self, procs: list[ProcInfo]) -> None:
        try:
            tree = self._users_tree
            users: dict[str, dict] = {}
            for p in procs:
                u = p.user or "Unknown"
                if u not in users:
                    users[u] = {"cpu": 0.0, "mem": 0.0, "count": 0, "threads": 0}
                users[u]["cpu"] += p.cpu if p.cpu > 0 else 0
                users[u]["mem"] += p.memory if p.memory > 0 else 0
                users[u]["count"] += 1
                users[u]["threads"] += p.threads if p.threads > 0 else 0

            selected = set()
            for iid in tree.selection():
                vals = tree.item(iid, "values")
                if vals:
                    selected.add(vals[0])

            children = tree.get_children()
            if children:
                tree.delete(*children)

            sorted_users = sorted(users.items(), key=lambda x: x[1]["cpu"], reverse=True)
            for user, stats in sorted_users:
                vals = (user, f"{stats['cpu']:.1f}", fmt_bytes(int(stats['mem'])),
                        str(stats['count']), str(stats['threads']))
                iid = tree.insert("", END, values=vals)
                if user in selected:
                    tree.selection_add(iid)
        except Exception:
            log.exception("Users tab update failed!")

    # -- security tab actions ------------------------------------------------
    def _sec_scan_all(self) -> None:
        """Run all security scanners."""
        if self._scan_running:
            messagebox.showinfo("Scan Running", "A scan is already in progress.", parent=self)
            return
        if not is_admin():
            if not messagebox.askyesno("Admin Recommended",
                                       "Full scanning works best with administrator privileges. "
                                       "Continue anyway?\n\n"
                                       "(NT-level process scan, MBR scan, and kernel module "
                                       "scan will be limited.)",
                                       parent=self):
                return
        self._sec_do_scan(categories=None)

    def _sec_run_category(self, category: ScanCategory) -> None:
        """Run a single scanner category."""
        if self._scan_running:
            messagebox.showinfo("Scan Running", "A scan is already in progress.", parent=self)
            return
        self._sec_do_scan(categories=[category])

    def _sec_do_scan(self, categories: list[ScanCategory] | None) -> None:
        """Start scan in background thread."""
        self._scan_running = True
        self._sec_clear_results(silent=True)
        self._sec_status_label.config(text="⏳ Scanning…", fg="#ff9800")
        self._sec_status_icon.config(text="🔍")

        self._scan_orchestrator = ScanOrchestrator()

        def _run():
            try:
                report = self._scan_orchestrator.run_scan(
                    categories=categories,
                    progress_callback=self._sec_on_progress,
                )
                self.after(0, lambda: self._sec_render_report(report))
            except Exception:
                log.exception("Security scan failed!")
                self.after(0, lambda: self._sec_scan_error())

        threading.Thread(target=_run, daemon=True).start()

    def _sec_on_progress(self, current: int, total: int, name: str) -> None:
        """Progress callback from scanner thread."""
        def _update():
            self._sec_status_label.config(
                text=f"⏳ Scanning [{current}/{total}]: {name}", fg="#ff9800")
        self.after(0, _update)

    def _sec_render_report(self, report: ScanReport) -> None:
        """Render completed scan report in treeview."""
        self._scan_running = False
        self._scan_results = report.results

        tree = self._sec_tree
        children = tree.get_children()
        if children:
            try:
                tree.delete(*children)
            except Exception:
                pass

        # Sort by severity (critical first)
        sorted_results = sorted(report.results, key=lambda r: r.severity.value)

        for r in sorted_results:
            sev_label = {Severity.CRITICAL: "‼", Severity.HIGH: "▲",
                         Severity.MEDIUM: "●", Severity.LOW: "▪",
                         Severity.INFO: "ℹ"}[r.severity]
            sev_tag = {Severity.CRITICAL: "sev_critical", Severity.HIGH: "sev_high",
                       Severity.MEDIUM: "sev_medium", Severity.LOW: "sev_low",
                       Severity.INFO: "sev_info"}[r.severity]

            # Truncate details for the row
            detail_preview = r.details[:120].replace("\n", " ") + ("…" if len(r.details) > 120 else "")
            vals = (sev_label, r.category.value, r.finding, detail_preview)
            tree.insert("", END, values=vals, tags=(sev_tag,))

        # Update status header
        if report.critical_count > 0:
            self._sec_status_icon.config(text="⚠️", fg="#d32f2f")
            status_text = f"Scan complete — {report.critical_count} CRITICAL issue(s) found!"
            status_color = "#d32f2f"
        elif report.high_count > 0:
            self._sec_status_icon.config(text="⚠", fg="#ff9100")
            status_text = f"Scan complete — {report.high_count} high-severity issue(s)"
            status_color = "#ff9100"
        elif report.total_issues > 0:
            self._sec_status_icon.config(text="ℹ", fg="#ffeb3b")
            status_text = f"Scan complete — {report.total_issues} issue(s) found"
            status_color = "#fdd835"
        else:
            self._sec_status_icon.config(text="✅", fg="#4caf50")
            status_text = "Scan complete — No issues found. System appears clean."
            status_color = "#4caf50"

        self._sec_status_label.config(text=status_text, fg=status_color)
        self._sec_stats_label.config(
            text=f"⏱ {report.scan_time:.1f}s  |  "
                 f"Critical: {report.critical_count}  High: {report.high_count}  "
                 f"Med: {report.medium_count}  Low: {report.low_count}  "
                 f"Info: {report.info_count}")
        log.info("Security scan complete: %d findings in %.1fs",
                 report.total_issues, report.scan_time)

    def _sec_scan_error(self) -> None:
        """Handle scan error."""
        self._scan_running = False
        self._sec_status_label.config(text="❌ Scan failed — check logs", fg="#d32f2f")
        self._sec_status_icon.config(text="❌")
        log.error("Security scan failed!")

    def _sec_cancel_scan(self) -> None:
        """Cancel a running scan."""
        if self._scan_orchestrator:
            self._scan_orchestrator.cancel()
        self._scan_running = False
        self._sec_status_label.config(text="⏹ Scan cancelled", fg="#888")
        self._sec_status_icon.config(text="⏹")
        log.info("Security scan cancelled by user")

    def _sec_clear_results(self, silent: bool = False) -> None:
        """Clear all scan results."""
        self._scan_results = []
        tree = self._sec_tree
        children = tree.get_children()
        if children:
            try:
                tree.delete(*children)
            except Exception:
                pass
        if not silent:
            self._sec_status_label.config(text="Ready — Click a scan button to begin",
                                           fg="#d4d4d4")
            self._sec_status_icon.config(text="🛡️", fg="#4caf50")
            self._sec_stats_label.config(text="")

    def _sec_export_report(self) -> None:
        """Export scan results to CSV file."""
        if not self._scan_results:
            messagebox.showinfo("Export", "No scan results to export.", parent=self)
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV Files", "*.csv")],
            initialfile=f"hermes_scan_{datetime.now():%Y%m%d_%H%M%S}.csv",
            parent=self)
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["Severity", "Category", "Finding", "Details"])
                for r in self._scan_results:
                    writer.writerow([r.severity.name, r.category.value, r.finding, r.details])
            log.info("Exported %d scan results to %s", len(self._scan_results), path)
            messagebox.showinfo("Export", f"Exported {len(self._scan_results)} results to:\n{path}",
                                parent=self)
        except Exception as e:
            log.exception("Scan export failed!")
            messagebox.showerror("Error", f"Export failed:\n{e}", parent=self)

    def _sec_view_details(self) -> None:
        """View full details of selected scan result."""
        selected = self._sec_tree.selection()
        if not selected:
            return
        win = Toplevel(self)
        win.title("Scan Finding Details")
        win.geometry("750x500")
        win.configure(bg=self.bg)
        win.transient(self)
        win.grab_set()

        text = scrolledtext.ScrolledText(
            win, wrap="word", bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#fff", font=("Consolas", 10),
            relief="flat", borderwidth=8)
        text.pack(fill=BOTH, expand=True)

        # Insert full details for each selected result
        for iid in selected:
            vals = self._sec_tree.item(iid, "values")
            if vals:
                cat = vals[1]
                finding = vals[2]
                # Find the full result
                for r in self._scan_results:
                    if r.finding == finding and r.category.value == cat:
                        text.insert(END, f"Category: {r.category.value}\n")
                        text.insert(END, f"Severity: {r.severity.name}\n")
                        text.insert(END, f"Finding:  {r.finding}\n")
                        text.insert(END, "-" * 60 + "\n")
                        text.insert(END, f"{r.details}\n")
                        if r.raw_data:
                            text.insert(END, f"\nRaw data: {r.raw_data}\n")
                        text.insert(END, "\n" + "=" * 60 + "\n\n")
                        break

        text.config(state="disabled")

    def _sec_sort(self, col: str) -> None:
        """Sort security results by column."""
        if self._sec_sort_col == col:
            self._sec_sort_asc = not self._sec_sort_asc
        else:
            self._sec_sort_col = col
            self._sec_sort_asc = True
        # Re-render with sort
        if self._scan_results:
            report = ScanReport(
                results=self._scan_results,
                scan_time=0.0,
                admin_status=is_admin(),
            )
            self._sec_render_report(report)

    def _on_sec_right_click(self, event) -> None:
        """Right-click context menu for security results."""
        iid = self._sec_tree.identify_row(event.y)
        if iid:
            if iid not in self._sec_tree.selection():
                self._sec_tree.selection_set(iid)
            # Create a simple context menu on the fly
            menu = Menu(self, tearoff=0, bg="#2d2d30", fg=self.fg,
                        activebackground=self.accent, activeforeground="#fff",
                        font=("Segoe UI", 9))
            menu.add_command(label="View Details", command=self._sec_view_details)
            menu.add_command(label="Copy", command=self._sec_copy)
            menu.add_separator()
            menu.add_command(label="Search Online", command=self._sec_search_online)
            menu.post(event.x_root, event.y_root)

    def _sec_copy(self) -> None:
        """Copy selected security results to clipboard."""
        rows = self._sec_tree.selection()
        if not rows:
            return
        lines = []
        cols = self._sec_tree["columns"]
        headers = [self._sec_tree.heading(c, "text") for c in cols]
        lines.append("\t".join(headers))
        for iid in rows:
            vals = self._sec_tree.item(iid, "values")
            lines.append("\t".join(str(v) for v in vals))
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        log.info("Copied %d security result(s) to clipboard", len(rows))

    def _sec_search_online(self) -> None:
        """Search selected finding online."""
        import webbrowser
        for iid in self._sec_tree.selection():
            vals = self._sec_tree.item(iid, "values")
            if vals and len(vals) >= 3:
                query = vals[2]  # finding
                webbrowser.open(f"https://www.google.com/search?q={query}+rootkit+windows")

    def _refresh_security(self) -> None:
        """Called when switching to Security tab — no-op, scans are manual."""
        pass

    # -- sorting ------------------------------------------------------------
    def _sort_by(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        log.debug("Processes sorted by %s %s", col, "ASC" if self._sort_asc else "DESC")
        self._render_processes()

    # -- search -------------------------------------------------------------
    def _on_search(self) -> None:
        self._filter_text = self._search_var.get()
        self._render_processes()

    def _focus_search(self) -> None:
        current_tab = self._notebook.index("current")
        if current_tab == PROCESS_TAB_INDEX:
            self._search_entry.focus_set()
        elif current_tab == DETAILS_TAB_INDEX:
            self._det_search_entry.focus_set()

    def _clear_filter(self) -> None:
        self._search_var.set("")
        self._det_search_var.set("")
        self._svc_search_var.set("")
        self._tree.focus_set()

    # -- selection ----------------------------------------------------------
    def _selected_pids(self) -> set[int]:
        pids: set[int] = set()
        try:
            for iid in self._tree.selection():
                try:
                    if self._tree_mode == "group":
                        # Check if it's a group parent (has children)
                        children = self._tree.get_children(iid)
                        if children:
                            # Group parent selected → include all child PIDs
                            for child_iid in children:
                                vals = self._tree.item(child_iid, "values")
                                if vals:
                                    pid_col = list(COLS).index("pid")
                                    pid_val = vals[pid_col] if pid_col < len(vals) else vals[1]
                                    pids.add(int(pid_val))
                        else:
                            # A child leaf was selected directly
                            vals = self._tree.item(iid, "values")
                            if vals:
                                pid_col = list(COLS).index("pid")
                                pid_val = vals[pid_col] if pid_col < len(vals) else vals[1]
                                pids.add(int(pid_val))
                    elif self._tree_mode == "tree":
                        vals = self._tree.item(iid, "values")
                        if vals and len(vals) > 1:
                            pids.add(int(vals[1]))
                    else:
                        vals = self._tree.item(iid, "values")
                        if vals:
                            pid_col = list(COLS).index("pid")
                            pid_val = vals[pid_col] if pid_col < len(vals) else vals[1]
                            pids.add(int(pid_val))
                except (ValueError, IndexError, KeyError):
                    pass
        except Exception:
            pass  # tree might be mid-update
        return pids

    def _get_selected_procs(self) -> list[ProcInfo]:
        pids = self._selected_pids()
        return [p for p in self.procs if p.pid in pids]

    def _selected_det_pids(self) -> set[int]:
        pids: set[int] = set()
        try:
            for iid in self._det_tree.selection():
                vals = self._det_tree.item(iid, "values")
                try:
                    pids.add(int(vals[1]))
                except (ValueError, IndexError):
                    pass
        except Exception:
            pass  # tree might be mid-update
        return pids

    def _get_selected_det_procs(self) -> list[ProcInfo]:
        pids = self._selected_det_pids()
        return [p for p in self.procs if p.pid in pids]

    # -- actions: end task --------------------------------------------------
    def _end_task(self) -> None:
        procs = self._get_selected_procs()
        if not procs:
            messagebox.showinfo("End Task", "No process selected.", parent=self)
            return
        self._terminate_procs(procs)

    def _end_det_task(self) -> None:
        procs = self._get_selected_det_procs()
        if not procs:
            messagebox.showinfo("End Task", "No process selected.", parent=self)
            return
        self._terminate_procs(procs)

    def _terminate_procs(self, procs: list[ProcInfo]) -> None:
        names = ", ".join(f"{p.name} ({p.pid})" for p in procs[:5])
        if len(procs) > 5:
            names += f" and {len(procs) - 5} more"
        if not messagebox.askyesno("End Task",
                                   f"Are you sure you want to end:\n\n{names}\n\n"
                                   "Unsaved data may be lost.", parent=self):
            log.info("User cancelled End Task")
            return

        killed = 0
        for pi in procs:
            try:
                p = psutil.Process(pi.pid)
                log.warning("Terminating: %s (PID %d)", pi.name, pi.pid)
                p.terminate()
                try:
                    p.wait(timeout=3)
                    log.info("PID %d terminated gracefully.", pi.pid)
                except psutil.TimeoutExpired:
                    log.warning("PID %d unresponsive -- force killing…", pi.pid)
                    p.kill()
                    log.info("PID %d killed.", pi.pid)
                killed += 1
            except psutil.NoSuchProcess:
                log.info("PID %d already gone.", pi.pid)
                killed += 1
            except psutil.AccessDenied:
                log.error("Access denied for PID %d (%s)", pi.pid, pi.name)
                messagebox.showerror("Access Denied",
                                     f"Cannot end {pi.name} (PID {pi.pid}).\nAccess denied.",
                                     parent=self)
            except Exception:
                log.exception("Error ending PID %d", pi.pid)
        log.info("End Task: %d/%d processes terminated", killed, len(procs))
        self._refresh()

    def _end_tree(self) -> None:
        procs = self._get_selected_procs()
        if not procs:
            messagebox.showinfo("End Process Tree", "No process selected.", parent=self)
            return
        names = ", ".join(f"{p.name} ({p.pid})" for p in procs[:5])
        if not messagebox.askyesno("End Process Tree",
                                   f"End the entire process tree for:\n\n{names}\n\n"
                                   "All child processes will also be terminated.",
                                   parent=self):
            return
        for pi in procs:
            self._kill_tree(pi.pid)
        self._refresh()

    def _end_det_tree(self) -> None:
        procs = self._get_selected_det_procs()
        if not procs:
            messagebox.showinfo("End Process Tree", "No process selected.", parent=self)
            return
        names = ", ".join(f"{p.name} ({p.pid})" for p in procs[:5])
        if not messagebox.askyesno("End Process Tree",
                                   f"End the entire process tree for:\n\n{names}?",
                                   parent=self):
            return
        for pi in procs:
            self._kill_tree(pi.pid)
        self._refresh()

    def _kill_tree(self, pid: int) -> None:
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return
        kids = 0
        for child in parent.children(recursive=True):
            try:
                log.warning("Killing child: %s (PID %d)", child.name(), child.pid)
                child.kill()
                kids += 1
            except Exception:
                pass
        try:
            log.warning("Killing parent: %s (PID %d)", parent.name(), pid)
            parent.kill()
            log.info("Killed PID %d + %d children", pid, kids)
        except Exception:
            pass

    # -- actions: end group --------------------------------------------------
    def _end_group(self) -> None:
        """End all processes in selected group(s)."""
        if self._tree_mode != "group":
            return
        pids = self._selected_pids()
        if not pids:
            messagebox.showinfo("End Group", "No group selected.", parent=self)
            return
        procs = [p for p in self.procs if p.pid in pids]
        # Get the first selected item's text for display
        try:
            first_iid = self._tree.selection()[0]
            group_name = self._tree.item(first_iid, "text") or self._tree.item(first_iid, "values")[0]
        except Exception:
            group_name = f"{len(procs)} processes"
        if not messagebox.askyesno("End Group",
                                   f"End all {len(procs)} processes in:\n\n{group_name}?\n\n"
                                   "Unsaved data may be lost.", parent=self):
            return
        killed = 0
        for pi in procs:
            try:
                p = psutil.Process(pi.pid)
                log.warning("End group: terminating %s (PID %d)", pi.name, pi.pid)
                p.terminate()
                try:
                    p.wait(timeout=2)
                except psutil.TimeoutExpired:
                    p.kill()
                killed += 1
            except psutil.NoSuchProcess:
                killed += 1
            except Exception:
                log.exception("End group failed for PID %d", pi.pid)
        log.info("End Group: %d/%d processes terminated", killed, len(procs))
        self._refresh()

    def _toggle_expand_selected(self) -> None:
        """Toggle expand/collapse on selected tree items."""
        for iid in self._tree.selection():
            try:
                if self._tree.get_children(iid):
                    # Has children — toggle
                    current = self._tree.item(iid, "open")
                    self._tree.item(iid, open=not current)
                    # Keep expanded_groups in sync
                    name = (self._tree.item(iid, "text") or "").rsplit(" (", 1)[0].lower()
                    if not current:  # was collapsed, now expanding
                        self._expanded_groups.add(name)
                    else:  # was expanded, now collapsing
                        self._expanded_groups.discard(name)
            except Exception:
                pass

    def _expand_collapse_all(self, expand: bool) -> None:
        """Expand or collapse all group/tree parent nodes."""
        def _recurse(iid):
            if self._tree.get_children(iid):
                self._tree.item(iid, open=expand)
                name = (self._tree.item(iid, "text") or "").rsplit(" (", 1)[0].lower()
                if expand:
                    self._expanded_groups.add(name)
                else:
                    self._expanded_groups.discard(name)
                for child in self._tree.get_children(iid):
                    _recurse(child)

        for iid in self._tree.get_children():
            _recurse(iid)
        log.info("%s all nodes", "Expanded" if expand else "Collapsed")

    # -- actions: set priority ----------------------------------------------
    def _set_priority(self, level: str) -> None:
        self._apply_priority(level, self._get_selected_procs())

    def _set_priority_det(self, level: str) -> None:
        self._apply_priority(level, self._get_selected_det_procs())

    def _apply_priority(self, level: str, procs: list[ProcInfo]) -> None:
        if not procs:
            messagebox.showinfo("Set Priority", "No process selected.", parent=self)
            return
        prio_class = PRIORITY_LEVELS.get(level, psutil.NORMAL_PRIORITY_CLASS)
        names = ", ".join(p.name for p in procs[:5])
        if not messagebox.askyesno("Set Priority",
                                   f"Set priority to \"{level}\" for:\n{names}?",
                                   parent=self):
            return
        for pi in procs:
            try:
                p = psutil.Process(pi.pid)
                p.nice(prio_class)
                log.info("Set priority %s for %s (PID %d)", level, pi.name, pi.pid)
            except Exception as e:
                log.error("Priority set failed for PID %d: %s", pi.pid, e)
                messagebox.showerror("Error", f"Cannot set priority for {pi.name}:\n{e}", parent=self)

    # -- actions: set affinity ----------------------------------------------
    def _set_affinity(self) -> None:
        self._apply_affinity(self._get_selected_procs())

    def _set_affinity_det(self) -> None:
        self._apply_affinity(self._get_selected_det_procs())

    def _apply_affinity(self, procs: list[ProcInfo]) -> None:
        if not procs:
            messagebox.showinfo("Set Affinity", "No process selected.", parent=self)
            return
        cpu_count_logical = psutil.cpu_count(logical=True) or 8

        win = Toplevel(self)
        win.title("Processor Affinity")
        win.geometry("420x360")
        win.configure(bg=self.bg)
        win.transient(self)
        win.grab_set()

        Label(win, text=f"Select which processors can run: {procs[0].name}",
              bg=self.bg, fg=self.fg, font=("Segoe UI", 10, "bold"),
              wraplength=380).pack(padx=12, pady=(12, 8), anchor="w")

        # Get current affinity mask
        current_mask = 0
        try:
            p = psutil.Process(procs[0].pid)
            current_mask = p.cpu_affinity() or []
        except Exception:
            current_mask = list(range(cpu_count_logical))

        check_vars = []
        for i in range(cpu_count_logical):
            v = IntVar(value=1 if i in current_mask else 0)
            check_vars.append(v)
            cb = Checkbutton(win, text=f"CPU {i}", variable=v,
                             bg=self.bg, fg=self.fg,
                             selectcolor="#333", activebackground=self.bg,
                             activeforeground=self.fg,
                             font=("Segoe UI", 9))
            cb.pack(anchor="w", padx=20, pady=1)

        def _apply():
            new_affinity = [i for i, v in enumerate(check_vars) if v.get() == 1]
            if not new_affinity:
                messagebox.showwarning("Invalid", "At least one CPU must be selected.", parent=win)
                return
            for pi in procs:
                try:
                    p = psutil.Process(pi.pid)
                    p.cpu_affinity(new_affinity)
                    log.info("Set affinity for %s (PID %d): %s", pi.name, pi.pid, new_affinity)
                except Exception as e:
                    log.error("Affinity set failed for PID %d: %s", pi.pid, e)
            win.destroy()

        btn_frame = Frame(win, bg=self.bg)
        btn_frame.pack(fill=X, padx=12, pady=(12, 12))
        ttk.Button(btn_frame, text="Select All",
                   command=lambda: [v.set(1) for v in check_vars]).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text="Deselect All",
                   command=lambda: [v.set(0) for v in check_vars]).pack(side=LEFT)
        ttk.Button(btn_frame, text="OK", command=_apply).pack(side=RIGHT, padx=(8, 0))
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(side=RIGHT)

    # -- actions: create dump file ------------------------------------------
    def _create_dump(self) -> None:
        self._do_create_dump(self._get_selected_procs())

    def _create_dump_det(self) -> None:
        self._do_create_dump(self._get_selected_det_procs())

    def _do_create_dump(self, procs: list[ProcInfo]) -> None:
        if not procs:
            messagebox.showinfo("Create Dump", "No process selected.", parent=self)
            return
        if not is_admin():
            messagebox.showwarning("Admin Required",
                                   "Creating dump files requires administrator privileges.",
                                   parent=self)
            return
        for pi in procs:
            dump_path = Path.home() / f"{pi.name}_{pi.pid}_{datetime.now():%Y%m%d_%H%M%S}.dmp"
            try:
                log.warning("Creating dump for %s (PID %d) → %s", pi.name, pi.pid, dump_path)
                # Use Win32 API MiniDumpWriteDump
                import ctypes.wintypes as w
                dbghelp = ctypes.windll.dbghelp
                kernel32 = ctypes.windll.kernel32

                # Open process with required access
                PROCESS_ALL_ACCESS = 0x1F0FFF
                hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pi.pid)
                if not hProcess:
                    raise OSError("Cannot open process -- run as admin")

                MiniDumpNormal = 0x00000000
                MiniDumpWithFullMemory = 0x00000002
                hFile = kernel32.CreateFileW(
                    str(dump_path), 0x40000000, 0, None, 2, 0x80, None)
                if hFile == -1 or not hFile:
                    kernel32.CloseHandle(hProcess)
                    raise OSError("Cannot create dump file")

                ret = dbghelp.MiniDumpWriteDump(
                    hProcess, pi.pid, hFile,
                    MiniDumpNormal | MiniDumpWithFullMemory,
                    None, None, None)
                kernel32.CloseHandle(hFile)
                kernel32.CloseHandle(hProcess)

                if ret:
                    log.info("Dump created: %s (%.1f MB)", dump_path,
                             dump_path.stat().st_size / (1024 * 1024) if dump_path.exists() else 0)
                else:
                    raise OSError(f"MiniDumpWriteDump failed (error {kernel32.GetLastError()})")
            except Exception as e:
                log.error("Dump failed for PID %d: %s", pi.pid, e)
                messagebox.showerror("Error", f"Cannot create dump for {pi.name}:\n{e}", parent=self)
        messagebox.showinfo("Create Dump", f"Dump file(s) saved to:\n{Path.home()}", parent=self)

    # -- actions: analyze wait chain ----------------------------------------
    def _analyze_wait_chain(self) -> None:
        self._do_wait_chain(self._get_selected_procs())

    def _analyze_wait_chain_det(self) -> None:
        self._do_wait_chain(self._get_selected_det_procs())

    def _do_wait_chain(self, procs: list[ProcInfo]) -> None:
        if not procs:
            messagebox.showinfo("Wait Chain", "No process selected.", parent=self)
            return
        win = Toplevel(self)
        win.title("Analyze Wait Chain")
        win.geometry("700x450")
        win.configure(bg=self.bg)
        win.transient(self)
        win.grab_set()

        text = scrolledtext.ScrolledText(
            win, wrap="word", bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#fff", font=("Consolas", 10),
            relief="flat", borderwidth=8)
        text.pack(fill=BOTH, expand=True)

        for pi in procs:
            text.insert(END, f"-- {pi.name} (PID {pi.pid}) --\n")
            text.insert(END, f"  Status: {pi.status}\n")
            text.insert(END, f"  Threads: {pi.threads}\n\n")
            chain = get_wait_chain(pi.pid)
            text.insert(END, f"  Wait Chain Analysis:\n{chain}\n\n")
            text.insert(END, "-" * 40 + "\n")
            log.info("Wait chain analyzed for PID %d", pi.pid)
        text.config(state="disabled")

    # -- actions: go to service(s) ------------------------------------------
    def _go_to_services(self) -> None:
        procs = self._get_selected_procs()
        if not procs:
            messagebox.showinfo("Go to Service(s)", "No process selected.", parent=self)
            return
        # Find matching services by PID
        matched = []
        for pi in procs:
            try:
                for s in psutil.win_service_iter():
                    try:
                        if s.pid() == pi.pid:
                            matched.append(s.name())
                    except Exception:
                        continue
            except Exception:
                pass
        if matched:
            # Switch to services tab and filter
            self._notebook.select(SERVICES_TAB_INDEX)
            self._svc_search_var.set(" ".join(matched))
            self._refresh_services()
            log.info("Go to service(s): matched %d services", len(matched))
        else:
            messagebox.showinfo("Go to Service(s)",
                                f"No matching services found for the selected processes.",
                                parent=self)

    # -- actions: view details ----------------------------------------------
    def _view_details(self) -> None:
        procs = self._get_selected_procs()
        if not procs:
            messagebox.showinfo("View Details", "No process selected.", parent=self)
            return
        self._show_details_window(procs)

    def _show_details_window(self, procs: list[ProcInfo]) -> None:
        win = Toplevel(self)
        win.title("Process Details")
        win.geometry("700x550")
        win.configure(bg=self.bg)
        win.transient(self)
        win.grab_set()

        text = scrolledtext.ScrolledText(
            win, wrap="word", bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#fff", font=("Consolas", 10),
            relief="flat", borderwidth=8)
        text.pack(fill=BOTH, expand=True)

        for pi in procs:
            try:
                p = psutil.Process(pi.pid)
                with p.oneshot():
                    io = None
                    try:
                        io = p.io_counters()
                    except Exception:
                        pass
                    conns = 0
                    try:
                        conns = len(p.connections(kind="all"))
                    except Exception:
                        pass
                    ctx = 0
                    try:
                        ctx = sum(p.num_ctx_switches())
                    except Exception:
                        pass
                    info = {
                        "Name": p.name(),
                        "PID": str(p.pid),
                        "PPID": str(p.ppid()),
                        "Status": p.status(),
                        "User": safe_get(p.username),
                        "Session ID": str(safe_int(lambda: p.session_id(), -1)),
                        "CPU %": f"{p.cpu_percent():.2f}",
                        "CPU Time": fmt_duration(sum(p.cpu_times()) if hasattr(p, 'cpu_times') else 0),
                        "Memory RSS": fmt_bytes(p.memory_info().rss),
                        "Memory VMS": fmt_bytes(p.memory_info().vms),
                        "Threads": str(p.num_threads()),
                        "Handles": str(p.num_handles()) if hasattr(p, 'num_handles') else "N/A",
                        "Priority": str(p.nice()),
                        "Context Switches": str(ctx),
                        "Created": datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
                        "Exe": safe_get(p.exe, "N/A"),
                        "CWD": safe_get(p.cwd, "N/A"),
                        "Cmdline": " ".join(p.cmdline()[:10]) if safe_get(lambda: p.cmdline()) else "N/A",
                        "Description": get_process_description(p) or "N/A",
                        "I/O Read": fmt_bytes(io.read_bytes) if io else "N/A",
                        "I/O Write": fmt_bytes(io.write_bytes) if io else "N/A",
                        "Connections": str(conns),
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info = {"Error": f"PID {pi.pid} no longer accessible."}
            except Exception:
                info = {"Error": traceback.format_exc()}

            text.insert(END, f"-- {pi.name} (PID {pi.pid}) --\n")
            for k, v in info.items():
                text.insert(END, f"  {k:20s}: {v}\n")
            text.insert(END, "\n")
        text.config(state="disabled")
        log.info("Details viewed for %d process(es)", len(procs))

    # -- actions: open file location ----------------------------------------
    def _open_file_location(self) -> None:
        for pi in self._get_selected_procs():
            try:
                exe = psutil.Process(pi.pid).exe()
                if exe and os.path.exists(exe):
                    os.startfile(os.path.dirname(exe))
                    log.info("Opened: %s", os.path.dirname(exe))
            except Exception:
                log.exception("Open location failed for PID %d", pi.pid)

    # -- actions: search online ---------------------------------------------
    def _search_online(self) -> None:
        import webbrowser
        for pi in self._get_selected_procs():
            webbrowser.open(f"https://www.google.com/search?q={pi.name}+process+windows")
            log.info("Search online: %s", pi.name)

    # -- actions: copy ------------------------------------------------------
    def _copy_selected(self) -> None:
        self._do_copy(self._tree)

    def _copy_det_selected(self) -> None:
        self._do_copy(self._det_tree)

    def _do_copy(self, tree: ttk.Treeview) -> None:
        rows = tree.selection()
        if not rows:
            return
        lines = []
        # header
        cols = tree["columns"]
        headers = [tree.heading(c, "text") for c in cols]
        lines.append("\t".join(headers))
        for iid in rows:
            vals = tree.item(iid, "values")
            lines.append("\t".join(str(v) for v in vals))

        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        log.info("Copied %d row(s) to clipboard", len(rows))

    def _select_all(self) -> None:
        tab = self._notebook.index("current")
        if tab == PROCESS_TAB_INDEX:
            for item in self._tree.get_children():
                self._tree.selection_add(item)
        elif tab == DETAILS_TAB_INDEX:
            for item in self._det_tree.get_children():
                self._det_tree.selection_add(item)

    # -- actions: select columns dialog -------------------------------------
    def _select_columns(self) -> None:
        win = Toplevel(self)
        win.title("Select Columns")
        win.geometry("300x420")
        win.configure(bg=self.bg)
        win.transient(self)
        win.grab_set()

        Label(win, text="Choose which columns to show:",
              bg=self.bg, fg=self.fg, font=("Segoe UI", 10, "bold")).pack(padx=12, pady=(12, 8), anchor="w")

        check_vars = {}
        for col in COLS:
            v = IntVar(value=1 if VISIBLE_COLS.get(col, True) else 0)
            check_vars[col] = v
            cb = Checkbutton(win, text=COL_LABELS[col], variable=v,
                             bg=self.bg, fg=self.fg,
                             selectcolor="#333", activebackground=self.bg,
                             activeforeground=self.fg,
                             font=("Segoe UI", 9))
            cb.pack(anchor="w", padx=20, pady=2)

        def _apply():
            for col, v in check_vars.items():
                VISIBLE_COLS[col] = v.get() == 1
            self._apply_column_visibility()
            self._render_processes()
            log.info("Column visibility updated: %s",
                     {c: v for c, v in VISIBLE_COLS.items() if v})
            win.destroy()

        btn_frame = Frame(win, bg=self.bg)
        btn_frame.pack(fill=X, padx=12, pady=(12, 12))
        ttk.Button(btn_frame, text="Select All",
                   command=lambda: [v.set(1) for v in check_vars.values()]).pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text="OK", command=_apply).pack(side=RIGHT, padx=(8, 0))
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(side=RIGHT)

    # -- export CSV ---------------------------------------------------------
    def _export_csv(self) -> None:
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV Files", "*.csv")],
            initialfile=f"processes_{datetime.now():%Y%m%d_%H%M%S}.csv",
            parent=self)
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow([COL_LABELS[c] for c in COLS])
                for p in self.procs:
                    writer.writerow(p.row_values())
            log.info("Exported %d processes to %s", len(self.procs), path)
            messagebox.showinfo("Export", f"Exported {len(self.procs)} processes to:\n{path}", parent=self)
        except Exception as e:
            log.exception("CSV export failed!")
            messagebox.showerror("Error", f"Export failed:\n{e}", parent=self)

    # -- run new task -------------------------------------------------------
    def _run_new_task(self) -> None:
        win = Toplevel(self)
        win.title("Run new task")
        win.geometry("450x140")
        win.configure(bg=self.bg)
        win.transient(self)
        win.grab_set()
        Label(win, text="Open:", bg=self.bg, fg=self.fg,
              font=("Segoe UI", 10)).pack(padx=12, pady=(12, 4), anchor="w")
        entry_var = StringVar()
        entry = ttk.Entry(win, textvariable=entry_var, width=50, font=("Segoe UI", 10))
        entry.pack(padx=12, pady=(0, 6), fill=X)
        entry.focus_set()

        admin_var = IntVar(value=0)
        cb = Checkbutton(win, text="Create this task with administrative privileges",
                         variable=admin_var, bg=self.bg, fg=self.fg,
                         selectcolor="#333", activebackground=self.bg,
                         activeforeground=self.fg, font=("Segoe UI", 9))
        cb.pack(anchor="w", padx=12, pady=(0, 6))

        def _run():
            cmd = entry_var.get().strip()
            if cmd:
                log.info("Run new task: %s (admin=%s)", cmd, bool(admin_var.get()))
                try:
                    if admin_var.get():
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", cmd, None, None, 1)
                    elif os.path.exists(cmd):
                        os.startfile(cmd)
                    else:
                        os.system(f'start "" {cmd}')
                except Exception as e:
                    log.exception("Run failed: %s", cmd)
                    messagebox.showerror("Error", str(e), parent=win)
            win.destroy()
        entry.bind("<Return>", lambda e: _run())
        ttk.Button(win, text="OK", command=_run).pack(side=RIGHT, padx=12, pady=(0, 12))
        ttk.Button(win, text="Cancel", command=win.destroy).pack(side=RIGHT, padx=(0, 6), pady=(0, 12))

    # -- double-click handler -----------------------------------------------
    def _on_proc_double_click(self, event) -> None:
        """Double-click: expand/collapse group in group mode, view details in other modes."""
        iid = self._tree.identify_row(event.y)
        if not iid:
            return
        if self._tree_mode == "group" and self._tree.get_children(iid):
            # Group parent — toggle expand/collapse
            current = self._tree.item(iid, "open")
            self._tree.item(iid, open=not current)
            log.debug("Toggled group: %s → %s", self._tree.item(iid, "text"),
                      "expanded" if not current else "collapsed")
        else:
            self._view_details()

    # -- right-click handlers -----------------------------------------------
    def _on_proc_right_click(self, event) -> None:
        iid = self._tree.identify_row(event.y)
        if iid:
            if iid not in self._tree.selection():
                self._tree.selection_set(iid)
            # In group mode, rename "End process tree" to "End group" when on a group parent
            if self._tree_mode == "group" and self._tree.get_children(iid):
                self._ctx_menu.entryconfigure("End group", state="normal")
                self._ctx_menu.entryconfigure("End process tree", state="normal")
            else:
                self._ctx_menu.entryconfigure("End group", state="disabled")
            self._ctx_menu.post(event.x_root, event.y_root)

    def _on_det_right_click(self, event) -> None:
        iid = self._det_tree.identify_row(event.y)
        if iid:
            if iid not in self._det_tree.selection():
                self._det_tree.selection_set(iid)
            self._det_ctx_menu.post(event.x_root, event.y_root)

    # -- services tab logic -------------------------------------------------
    def _on_tab_changed(self, event) -> None:
        try:
            current = self._notebook.index("current")
            if current == SERVICES_TAB_INDEX:
                self._refresh_services()
            elif current == STARTUP_TAB_INDEX:
                self._load_startup()
            elif current == SECURITY_TAB_INDEX:
                self._refresh_security()
        except Exception:
            pass

    def _refresh_services(self) -> None:
        def _collect():
            svcs = []
            try:
                for s in psutil.win_service_iter():
                    try:
                        svcs.append({
                            "name": s.name() or "?",
                            "display_name": s.display_name() or "",
                            "pid": s.pid() or 0,
                            "status": s.status() or "unknown",
                            "start_type": s.start_type() or "?",
                        })
                    except Exception:
                        continue
                log.debug("Collected %d services", len(svcs))
            except Exception:
                log.exception("Service collection failed!")
            self.after(0, lambda: self._render_services(svcs))
        threading.Thread(target=_collect, daemon=True).start()

    def _render_services(self, svcs: list[dict]) -> None:
        try:
            self._svc_data = svcs
            tree = self._svc_tree
            selected = set()
            for iid in tree.selection():
                vals = tree.item(iid, "values")
                if vals:
                    selected.add(vals[0])

            children = tree.get_children()
            if children:
                tree.delete(*children)

            filt = self._svc_filter.lower().strip()
            display = [s for s in svcs if (not filt or
                       filt in s["name"].lower() or filt in s["display_name"].lower())]

            reverse = not self._svc_sort_asc
            key = self._svc_sort_col
            if key == "svc_pid":
                display.sort(key=lambda s: s.get("pid", 0), reverse=reverse)
            else:
                display.sort(key=lambda s: str(s.get(key.replace("svc_", ""), "")).lower(),
                             reverse=reverse)

            status_tags = {
                "running": "svc_run", "start_pending": "svc_pend",
                "stop_pending": "svc_pend", "paused": "svc_paused",
                "continue_pending": "svc_pend", "pause_pending": "svc_pend",
            }

            for s in display:
                svals = (s["name"], s["display_name"], str(s["pid"]) if s["pid"] else "",
                         s["status"], s["start_type"])
                stag = status_tags.get(s["status"], "svc_stop")
                iid = tree.insert("", END, values=svals, tags=(stag,))
                if s["name"] in selected:
                    tree.selection_add(iid)

            tree.tag_configure("svc_run", foreground=GRAPH_COLORS["svc_running"])
            tree.tag_configure("svc_stop", foreground=GRAPH_COLORS["svc_stopped"])
            tree.tag_configure("svc_paused", foreground=GRAPH_COLORS["svc_paused"])
            tree.tag_configure("svc_pend", foreground="#888888")
        except Exception:
            log.exception("Services render failed!")

    def _on_svc_search(self) -> None:
        self._svc_filter = self._svc_search_var.get()
        self._render_services(self._svc_data)

    def _sort_svc_by(self, col: str) -> None:
        if self._svc_sort_col == col:
            self._svc_sort_asc = not self._svc_sort_asc
        else:
            self._svc_sort_col = col
            self._svc_sort_asc = True
        self._render_services(self._svc_data)

    def _on_svc_right_click(self, event) -> None:
        iid = self._svc_tree.identify_row(event.y)
        if iid:
            if iid not in self._svc_tree.selection():
                self._svc_tree.selection_set(iid)
            self._svc_ctx_menu.post(event.x_root, event.y_root)

    def _get_selected_svcs(self) -> list[str]:
        names = []
        for iid in self._svc_tree.selection():
            vals = self._svc_tree.item(iid, "values")
            if vals:
                names.append(vals[0])
        return names

    def _svc_action_start(self) -> None:
        self._svc_action("start", self._get_selected_svcs())

    def _svc_action_stop(self) -> None:
        self._svc_action("stop", self._get_selected_svcs())

    def _svc_action_restart(self) -> None:
        self._svc_action("restart", self._get_selected_svcs())

    def _svc_action(self, action: str, names: list[str]) -> None:
        if not names:
            messagebox.showinfo("Services", "No service selected.", parent=self)
            return
        if not is_admin():
            messagebox.showwarning("Admin Required",
                                   f"Cannot {action} services without administrator privileges.\n\n"
                                   "Please restart the app as administrator.", parent=self)
            return
        for name in names:
            try:
                svc = psutil.win_service_get(name)
                getattr(svc, action)()
                log.info("Service %s: %s succeeded", action, name)
            except Exception as e:
                log.error("Service %s %s failed: %s", name, action, e)
                messagebox.showerror("Error", f"Cannot {action} {name}:\n{e}", parent=self)
        self._refresh_services()

    # -- startup tab logic --------------------------------------------------
    def _load_startup(self) -> None:
        entries = []
        registry_paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        ]
        disabled = set()
        try:
            dkey = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run")
            for i in range(winreg.QueryInfoKey(dkey)[1]):
                name, value, _ = winreg.EnumValue(dkey, i)
                if value and isinstance(value, bytes) and len(value) >= 12:
                    if value[0] == 0x03:
                        disabled.add(name)
            winreg.CloseKey(dkey)
        except Exception:
            pass

        for hkey, path, source in registry_paths:
            try:
                key = winreg.OpenKey(hkey, path)
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    cmd = str(value) if value else ""
                    publisher = ""
                    fsize = 0
                    exe_path = ""
                    if cmd:
                        if '"' in cmd:
                            parts = cmd.split('"')
                            exe_path = parts[1] if len(parts) > 1 else ""
                        else:
                            exe_path = cmd.split()[0] if cmd.split() else ""
                        if exe_path and os.path.exists(exe_path):
                            try:
                                fsize = os.path.getsize(exe_path)
                            except Exception:
                                fsize = 0
                            publisher = os.path.splitext(os.path.basename(exe_path))[0]

                    if fsize > 50 * 1024 * 1024:
                        impact = "High"
                    elif fsize > 10 * 1024 * 1024:
                        impact = "Medium"
                    elif fsize > 0:
                        impact = "Low"
                    else:
                        impact = "Not measured"

                    entries.append({
                        "name": name, "publisher": publisher or "--",
                        "enabled": name not in disabled,
                        "impact": impact, "command": cmd,
                        "source_path": path, "source_hkey": hkey,
                        "source_name": source, "exe_path": exe_path,
                    })
                winreg.CloseKey(key)
            except Exception:
                log.debug("Could not read startup key: %s", path)

        self._su_data = entries
        self._render_startup()
        log.info("Loaded %d startup entries (%d disabled)", len(entries), len(disabled))

    def _render_startup(self) -> None:
        tree = self._su_tree
        selected = set()
        for iid in tree.selection():
            vals = tree.item(iid, "values")
            if vals:
                selected.add(vals[0])

        children = tree.get_children()
        if children:
            tree.delete(*children)

        display = list(self._su_data)
        reverse = not self._su_sort_asc
        display.sort(key=lambda s: str(s.get(self._su_sort_col.replace("su_", ""), "")).lower(),
                     reverse=reverse)

        for s in display:
            status = "Enabled" if s["enabled"] else "Disabled"
            svals = (s["name"], s["publisher"], status, s["impact"], s["command"])
            tag = "su_on" if s["enabled"] else "su_off"
            iid = tree.insert("", END, values=svals, tags=(tag,))
            if s["name"] in selected:
                tree.selection_add(iid)

        tree.tag_configure("su_on", foreground=GRAPH_COLORS["svc_running"])
        tree.tag_configure("su_off", foreground=GRAPH_COLORS["svc_stopped"])

    def _sort_su_by(self, col: str) -> None:
        if self._su_sort_col == col:
            self._su_sort_asc = not self._su_sort_asc
        else:
            self._su_sort_col = col
            self._su_sort_asc = True
        self._render_startup()

    def _on_su_right_click(self, event) -> None:
        iid = self._su_tree.identify_row(event.y)
        if iid:
            if iid not in self._su_tree.selection():
                self._su_tree.selection_set(iid)
            self._su_ctx_menu.post(event.x_root, event.y_root)

    def _get_selected_su(self) -> list[dict]:
        result = []
        for iid in self._su_tree.selection():
            vals = self._su_tree.item(iid, "values")
            if vals:
                for entry in self._su_data:
                    if entry["name"] == vals[0]:
                        result.append(entry)
                        break
        return result

    def _su_toggle(self) -> None:
        entries = self._get_selected_su()
        if not entries:
            return
        if not is_admin():
            messagebox.showwarning("Admin Required",
                                   "Cannot modify startup entries without administrator privileges.",
                                   parent=self)
            return
        for entry in entries:
            new_state = not entry["enabled"]
            try:
                dkey = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                    0, winreg.KEY_SET_VALUE)
                if new_state:
                    winreg.SetValueEx(dkey, entry["name"], 0, winreg.REG_BINARY,
                                      b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                else:
                    winreg.SetValueEx(dkey, entry["name"], 0, winreg.REG_BINARY,
                                      b'\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                winreg.CloseKey(dkey)
                log.info("Startup %s: %s", "enabled" if new_state else "disabled", entry["name"])
            except Exception as e:
                log.error("Toggle startup %s failed: %s", entry["name"], e)
                messagebox.showerror("Error", str(e), parent=self)
        self._load_startup()

    def _su_open_location(self) -> None:
        for entry in self._get_selected_su():
            exe_path = entry.get("exe_path", "")
            if exe_path and os.path.exists(exe_path):
                try:
                    os.startfile(os.path.dirname(exe_path))
                    log.info("Opened startup location: %s", os.path.dirname(exe_path))
                except Exception:
                    pass

    # -- auto-refresh -------------------------------------------------------
    def _start_auto_refresh(self) -> None:
        self._schedule_refresh()

    def _schedule_refresh(self) -> None:
        if self._auto_var.get() == "on" and self._running:
            self._refresh_job = self.after(REFRESH_INTERVAL_MS, self._do_auto_refresh)

    def _do_auto_refresh(self) -> None:
        if not self._running:
            return
        self._refresh_async()
        self._schedule_refresh()

    def _toggle_auto(self) -> None:
        if self._auto_var.get() == "off":
            if self._refresh_job:
                self.after_cancel(self._refresh_job)
                self._refresh_job = None
            log.info("Auto-refresh disabled")
        else:
            log.info("Auto-refresh enabled")
            self._schedule_refresh()

    # -- logs / about -------------------------------------------------------
    def _open_logs(self) -> None:
        try:
            os.startfile(str(LOG_FILE))
        except Exception:
            messagebox.showerror("Error", f"Could not open log file:\n{LOG_FILE}", parent=self)

    def _open_log_folder(self) -> None:
        try:
            os.startfile(str(LOG_DIR))
        except Exception:
            messagebox.showerror("Error", f"Could not open log folder:\n{LOG_DIR}", parent=self)

    def _show_about(self) -> None:
        mem = psutil.virtual_memory()
        info_text = (
            f"Hermes Task Manager v3\n\n"
            f"Windows Task Manager 1:1 Clone\n"
            f"Built with tkinter + psutil + ctypes + winreg\n\n"
            f"Tabs:\n"
            f"  • Processes  -- tree/flat view, search, end task/tree, priority, affinity\n"
            f"  • Performance -- CPU (per-core), Memory, Disk, Network, GPU graphs\n"
            f"  • App History -- CPU time per application\n"
            f"  • Details -- extended columns (command line, priority, CPU time, etc.)\n"
            f"  • Services -- start / stop / restart\n"
            f"  • Startup -- enable / disable / open file location\n"
            f"  • Users -- processes grouped by user account\n"
            f"  • Security -- anti-rootkit scanning (GMER-style)\n\n"
            f"System:\n"
            f"  CPU: {plat.processor()}\n"
            f"  Cores: {psutil.cpu_count(logical=True)} logical / {psutil.cpu_count(logical=False)} physical\n"
            f"  RAM: {fmt_bytes(mem.total)}\n"
            f"  OS: {plat.system()} {plat.release()}\n\n"
            f"Log file: {LOG_FILE}\n"
            f"Python: {sys.version.split()[0]}  |  psutil: {psutil.__version__}"
        )
        messagebox.showinfo("About Hermes Task Manager", info_text, parent=self)

    # -- shutdown -----------------------------------------------------------
    def _on_close(self) -> None:
        log.info("Shutting down Hermes Task Manager v3…")
        self._running = False
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None
        session_dur = ""
        if hasattr(self, '_start_time'):
            session_dur = f"Session duration: {fmt_duration(time.time() - self._start_time)}"
        self.destroy()
        if session_dur:
            log.info("Exited cleanly. %s", session_dur)
        else:
            log.info("Exited cleanly.")


def main():
    import time as _time
    start_ts = _time.time()
    log.info("-" * 70)
    log.info("Launching Hermes Task Manager v3")

    # Request elevation
    elevate()

    try:
        app = TaskManager()
        app._start_time = start_ts  # for session duration in shutdown log
        app.mainloop()
    except KeyboardInterrupt:
        log.info("Keyboard interrupt -- exiting")
    except Exception:
        log.critical("FATAL ERROR!", exc_info=True)
        import traceback as _tb
        messagebox.showerror("Fatal Error",
                             f"Hermes Task Manager crashed:\n\n{_tb.format_exc()}\n\n"
                             f"Check {LOG_FILE} for details.")
        raise


if __name__ == "__main__":
    main()
