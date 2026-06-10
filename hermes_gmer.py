#!/usr/bin/env python3
"""
Hermes GMER — Standalone Anti-Rootkit Scanner
===============================================
Cross-view rootkit/hidden-item detection for Windows.
Inspired by GMER's approach of comparing multiple enumeration methods.

Usage:
    python hermes_gmer.py                  # Interactive GUI mode
    python hermes_gmer.py --cli            # Command-line text output
    python hermes_gmer.py --cli --quick    # Quick scan (processes + services)
    python hermes_gmer.py --json           # JSON report to stdout
    python hermes_gmer.py --json --output report.json  # Save to file (quiet)
    python hermes_gmer.py --cli --full     # Full deep scan (all 12 scanners)

Scanner categories:
    Hidden Processes    — psutil vs NtQuerySystemInformation cross-view
    Hidden Threads      — ToolHelp32 vs NtQuerySystemInformation cross-view
    Hidden Modules/DLLs — Module32First vs SystemModuleInformation cross-view
    Hidden Services     — SCM vs raw registry cross-view
    Hidden Files        — FindFirstFile vs NtQueryDirectoryFile cross-view
    Hidden Disk Sectors — MBR boot signature check via \\\\.\\PhysicalDrive
    Alternate Streams   — FindFirstStreamW on system directories
    Hidden Registry     — RegEnumKey vs NtEnumerateKey cross-view
    SSDT/IDT/IRP Hooks  — Informational (requires kernel driver)
    Inline Hooks        — On-disk .text vs in-memory code comparison

Requirements:
    - Windows 10/11 (uses NT syscalls via ctypes)
    - Administrator privileges for full scanning
    - Python 3.10+ with psutil
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from tkinter import (
    BOTH, END, Frame, Label, Menu, StringVar, Tk, Toplevel,
    messagebox, scrolledtext, ttk,
)
from tkinter import filedialog

# Add script directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sec_scanner_engine import (
    Severity, ScanCategory, ScanResult, ScanReport,
    ScanOrchestrator, is_admin, print_report, SEVERITY_COLORS, SEVERITY_TAGS,
    HiddenProcessScanner, HiddenThreadScanner, HiddenModuleScanner,
    HiddenServiceScanner, HiddenFileScanner, DiskSectorScanner,
    ADSScanner, HiddenRegistryScanner, SSDTScanner, IDTScanner,
    IRPScanner, InlineHookScanner,
)
from anti_detect import AntiDetect, StringObfuscator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_DIR = Path.home() / "task_manager_logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "gmer.log"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
log = logging.getLogger("taskmgr")

# Reduce noise from other loggers
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("PIL").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# CLI Mode
# ---------------------------------------------------------------------------

def run_cli(quick: bool = False, json_mode: bool = False, output_path: str | None = None) -> int:
    """Run scanner in CLI mode.

    Returns exit code: 0 = clean, 1 = issues found, 2 = error.
    """
    log.info("=" * 70)
    log.info("Hermes GMER CLI Scan — %s", datetime.now().isoformat())
    log.info("Admin: %s", is_admin())
    log.info("=" * 70)

    # Anti-detection
    ad = AntiDetect(app_name="HermesGMER_CLI")
    ad.arm()

    try:
        if quick:
            categories = [
                ScanCategory.HIDDEN_PROCESSES,
                ScanCategory.HIDDEN_SERVICES,
                ScanCategory.HIDDEN_FILES,
                ScanCategory.HIDDEN_ADS,
                ScanCategory.HIDDEN_REGISTRY,
            ]
            mode_label = "Quick Scan"
        else:
            categories = None  # all scanners
            mode_label = "Full Scan"

        if not json_mode:
            print(f"\n[Hermes GMER] {mode_label}")
            print(f"   Admin: {'[YES]' if is_admin() else '[NO - limited]'}")
            print(f"   Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   Log: {LOG_FILE}\n")

        orchestrator = ScanOrchestrator()

        def progress_cb(current: int, total: int, name: str) -> None:
            if not json_mode:
                bar_len = 30
                filled = int(bar_len * current / total)
                bar = "#" * filled + "-" * (bar_len - filled)
                print(f"\r   [{bar}] {current}/{total} — {name}", end="", flush=True)

        report = orchestrator.run_scan(
            categories=categories,
            progress_callback=progress_cb,
        )

        if not json_mode:
            print("\r" + " " * 80 + "\r", end="")  # clear progress bar
            print_report(report)

        if json_mode:
            # Build JSON-compatible report
            json_report = {
                "timestamp": datetime.now().isoformat(),
                "scan_time_seconds": report.scan_time,
                "admin_mode": report.admin_status,
                "total_issues": report.total_issues,
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
                "results": [
                    {
                        "severity": r.severity.name,
                        "category": r.category.value,
                        "finding": r.finding,
                        "details": r.details,
                        "raw_data": r.raw_data,
                    }
                    for r in report.results
                ],
            }

            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(json_report, f, indent=2, ensure_ascii=False)
                print(f"Report saved to: {output_path}")
            else:
                print(json.dumps(json_report, indent=2, ensure_ascii=False))

        ad.disarm()

        if report.critical_count > 0 or report.high_count > 0:
            return 1  # Issues found
        return 0  # Clean

    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user")
        ad.disarm()
        return 2
    except Exception as e:
        log.exception("CLI scan failed!")
        print(f"\n[ERROR] Scan error: {e}")
        print(f"   Check log: {LOG_FILE}")
        ad.disarm()
        return 2


# ---------------------------------------------------------------------------
# GUI Mode (Standalone tkinter window)
# ---------------------------------------------------------------------------

class GMERGUI(Tk):
    """Standalone GMER scanner GUI."""

    def __init__(self):
        super().__init__()
        self.title("Hermes GMER — Anti-Rootkit Scanner")
        self.geometry("1100x700")
        self.minsize(800, 500)

        # Anti-detection
        self._ad = AntiDetect(app_name="HermesGMER_GUI")
        self._ad.arm()

        # Colors
        self.bg = "#1e1e1e"
        self.fg = "#d4d4d4"
        self.accent = "#0078d4"
        self.configure(bg=self.bg)

        # ttk style
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background="#252526", foreground=self.fg,
                        fieldbackground="#252526", rowheight=24,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#333333", foreground=self.fg,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview",
                  background=[("selected", self.accent)],
                  foreground=[("selected", "#ffffff")])
        style.configure("TFrame", background=self.bg)

        # State
        self._scan_running = False
        self._orchestrator: ScanOrchestrator | None = None
        self._results: list[ScanResult] = []

        # Build UI
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        # Header
        header = Frame(self, bg="#1a1a2e", height=60)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        Label(header, text="🛡️ Hermes GMER", bg="#1a1a2e", fg="#4caf50",
              font=("Segoe UI", 18, "bold")).pack(side="left", padx=(16, 8), pady=12)

        self._status_lbl = Label(
            header, text="Ready — Select scan type below",
            bg="#1a1a2e", fg="#d4d4d4", font=("Segoe UI", 11), anchor="w")
        self._status_lbl.pack(side="left", padx=(4, 0), pady=12)

        self._stats_lbl = Label(
            header, text="", bg="#1a1a2e", fg="#888", font=("Segoe UI", 9), anchor="w")
        self._stats_lbl.pack(side="left", padx=(20, 0), pady=12)

        # Button bar
        btn_frame = Frame(self, bg="#2d2d30")
        btn_frame.pack(fill="x", side="top", pady=(0, 1))

        btn_row = Frame(btn_frame, bg="#2d2d30")
        btn_row.pack(fill="x", padx=6, pady=(6, 4))

        ttk.Button(btn_row, text="🔍 Full Scan (All 12 Scanners)",
                   command=self._scan_full).pack(side="left", padx=(4, 4))
        ttk.Button(btn_row, text="⚡ Quick Scan (5 Priority Scanners)",
                   command=self._scan_quick).pack(side="left", padx=4)
        ttk.Button(btn_row, text="📋 Export Report",
                   command=self._export).pack(side="right", padx=4)
        ttk.Button(btn_row, text="🗑 Clear",
                   command=self._clear).pack(side="right", padx=4)
        ttk.Button(btn_row, text="⏹ Cancel",
                   command=self._cancel).pack(side="right", padx=4)

        # Results tree
        tframe = Frame(self, bg=self.bg)
        tframe.pack(fill="both", expand=True)

        vsb = ttk.Scrollbar(tframe, orient="vertical")
        hsb = ttk.Scrollbar(tframe, orient="horizontal")

        cols = ("sev", "cat", "finding", "details")
        self._tree = ttk.Treeview(
            tframe, columns=cols, show="headings", selectmode="extended",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._tree.yview)
        hsb.config(command=self._tree.xview)

        self._tree.heading("sev", text="⚠")
        self._tree.column("sev", width=42, anchor="center")
        self._tree.heading("cat", text="Category")
        self._tree.column("cat", width=180, anchor="w")
        self._tree.heading("finding", text="Finding")
        self._tree.column("finding", width=320, anchor="w")
        self._tree.heading("details", text="Details")
        self._tree.column("details", width=450, anchor="w")

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)

        # Tags
        self._tree.tag_configure("crit", foreground="#ffffff", background="#d32f2f",
                                  font=("Segoe UI", 9, "bold"))
        self._tree.tag_configure("high", foreground="#ffffff", background="#e65100")
        self._tree.tag_configure("med", foreground="#1e1e1e", background="#fdd835")
        self._tree.tag_configure("low", foreground="#ffffff", background="#1565c0")
        self._tree.tag_configure("info", foreground="#ffffff", background="#616161")

        self._tree.bind("<Double-1>", lambda e: self._view_details())
        self._tree.bind("<Button-3>", self._on_right_click)

        # Bottom bar
        bot = Frame(self, bg="#007acc", height=24)
        bot.pack(fill="x", side="bottom")
        bot.pack_propagate(False)
        Label(bot, text=f"Log: {LOG_FILE}  |  Admin: {'Yes' if is_admin() else 'No'}",
              bg="#007acc", fg="#fff", font=("Segoe UI", 8)).pack(
            side="left", padx=(12, 0), pady=2)

    # -- Scan actions --

    def _scan_full(self) -> None:
        if self._scan_running:
            return
        self._do_scan(categories=None, label="Full Scan (12 scanners)")

    def _scan_quick(self) -> None:
        if self._scan_running:
            return
        cats = [
            ScanCategory.HIDDEN_PROCESSES, ScanCategory.HIDDEN_SERVICES,
            ScanCategory.HIDDEN_FILES, ScanCategory.HIDDEN_ADS,
            ScanCategory.HIDDEN_REGISTRY,
        ]
        self._do_scan(categories=cats, label="Quick Scan (5 scanners)")

    def _do_scan(self, categories, label: str) -> None:
        self._scan_running = True
        self._clear(silent=True)
        self._status_lbl.config(text=f"⏳ {label} — Running…", fg="#ff9800")

        self._orchestrator = ScanOrchestrator()

        def _run():
            try:
                report = self._orchestrator.run_scan(
                    categories=categories,
                    progress_callback=self._progress_cb,
                )
                self.after(0, lambda: self._display_report(report))
            except Exception:
                log.exception("GUI scan failed!")
                self.after(0, lambda: self._scan_error())

        threading.Thread(target=_run, daemon=True).start()

    def _progress_cb(self, current: int, total: int, name: str) -> None:
        def _update():
            self._status_lbl.config(
                text=f"⏳ [{current}/{total}] {name}", fg="#ff9800")
        self.after(0, _update)

    def _display_report(self, report: ScanReport) -> None:
        self._scan_running = False
        self._results = report.results

        tree = self._tree
        for child in tree.get_children():
            try:
                tree.delete(child)
            except Exception:
                pass

        sev_labels = {Severity.CRITICAL: "‼", Severity.HIGH: "▲",
                      Severity.MEDIUM: "●", Severity.LOW: "▪", Severity.INFO: "ℹ"}
        sev_tags = {Severity.CRITICAL: "crit", Severity.HIGH: "high",
                    Severity.MEDIUM: "med", Severity.LOW: "low", Severity.INFO: "info"}

        for r in sorted(report.results, key=lambda x: x.severity.value):
            preview = r.details[:150].replace("\n", " ") + ("…" if len(r.details) > 150 else "")
            tree.insert("", END, values=(
                sev_labels[r.severity], r.category.value, r.finding, preview,
            ), tags=(sev_tags[r.severity],))

        # Status
        if report.critical_count > 0:
            status = f"⚠️ {report.critical_count} CRITICAL issue(s) found!"
            color = "#d32f2f"
        elif report.high_count > 0:
            status = f"⚠ {report.high_count} high-severity issue(s)"
            color = "#ff9100"
        elif report.total_issues > 0:
            status = f"ℹ {report.total_issues} issue(s) found"
            color = "#fdd835"
        else:
            status = "✅ Clean — No issues found"
            color = "#4caf50"

        self._status_lbl.config(text=status, fg=color)
        self._stats_lbl.config(
            text=f"⏱ {report.scan_time:.1f}s  |  C:{report.critical_count} "
                 f"H:{report.high_count} M:{report.medium_count} "
                 f"L:{report.low_count} I:{report.info_count}")

    def _scan_error(self) -> None:
        self._scan_running = False
        self._status_lbl.config(text="❌ Scan failed — check gmer.log", fg="#d32f2f")

    def _cancel(self) -> None:
        if self._orchestrator:
            self._orchestrator.cancel()
        self._scan_running = False
        self._status_lbl.config(text="⏹ Scan cancelled", fg="#888")

    def _clear(self, silent: bool = False) -> None:
        self._results = []
        for child in self._tree.get_children():
            try:
                self._tree.delete(child)
            except Exception:
                pass
        if not silent:
            self._status_lbl.config(text="Ready — Select scan type below", fg="#d4d4d4")
            self._stats_lbl.config(text="")

    def _export(self) -> None:
        if not self._results:
            messagebox.showinfo("Export", "No results to export.", parent=self)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json")],
            initialfile=f"hermes_gmer_{datetime.now():%Y%m%d_%H%M%S}.csv",
            parent=self)
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["Severity", "Category", "Finding", "Details"])
                for r in self._results:
                    writer.writerow([r.severity.name, r.category.value, r.finding, r.details])
            messagebox.showinfo("Export", f"Exported {len(self._results)} results.", parent=self)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self)

    def _view_details(self) -> None:
        selected = self._tree.selection()
        if not selected:
            return
        win = Toplevel(self)
        win.title("Finding Details")
        win.geometry("750x500")
        win.configure(bg=self.bg)
        win.transient(self)

        text = scrolledtext.ScrolledText(
            win, wrap="word", bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#fff", font=("Consolas", 10),
            relief="flat", borderwidth=8)
        text.pack(fill="both", expand=True)

        for iid in selected:
            vals = self._tree.item(iid, "values")
            if vals:
                for r in self._results:
                    if r.finding == vals[2] and r.category.value == vals[1]:
                        text.insert("end", f"Category: {r.category.value}\n")
                        text.insert("end", f"Severity: {r.severity.name}\n")
                        text.insert("end", f"Finding:  {r.finding}\n")
                        text.insert("end", "-" * 60 + "\n")
                        text.insert("end", f"{r.details}\n")
                        if r.raw_data:
                            text.insert("end", f"\nRaw data: {r.raw_data}\n")
                        text.insert("end", "\n" + "=" * 60 + "\n\n")
                        break
        text.config(state="disabled")

    def _on_right_click(self, event) -> None:
        iid = self._tree.identify_row(event.y)
        if iid:
            if iid not in self._tree.selection():
                self._tree.selection_set(iid)
            menu = Menu(self, tearoff=0, bg="#2d2d30", fg=self.fg,
                        activebackground=self.accent, activeforeground="#fff",
                        font=("Segoe UI", 9))
            menu.add_command(label="View Details", command=self._view_details)
            menu.add_command(label="Copy", command=self._copy)
            menu.post(event.x_root, event.y_root)

    def _copy(self) -> None:
        rows = self._tree.selection()
        if not rows:
            return
        lines = []
        for iid in rows:
            vals = self._tree.item(iid, "values")
            lines.append("\t".join(str(v) for v in vals))
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def _on_close(self) -> None:
        self._ad.disarm()
        self.destroy()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Hermes GMER — Anti-Rootkit Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hermes_gmer.py                     # GUI mode
  python hermes_gmer.py --cli               # CLI text mode, full scan
  python hermes_gmer.py --cli --quick       # Quick scan only
  python hermes_gmer.py --json              # JSON output to stdout
  python hermes_gmer.py --json -o report.json  # Save JSON report to file
        """,
    )
    parser.add_argument("--cli", action="store_true",
                        help="Run in command-line mode (text output)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (implies --cli)")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan only (5 priority scanners)")
    parser.add_argument("--full", action="store_true",
                        help="Full scan (default, all 12 scanners)")
    parser.add_argument("-o", "--output", type=str, metavar="FILE",
                        help="Save report to FILE (JSON mode)")

    args = parser.parse_args()

    # Determine mode
    if args.cli or args.json:
        if args.json:
            exit_code = run_cli(quick=args.quick, json_mode=True, output_path=args.output)
        else:
            exit_code = run_cli(quick=args.quick, json_mode=False)

        if args.output and not args.json:
            # Allow saving CSV from CLI too
            # (handled inside run_cli for JSON, for text it's just stdout)
            pass

        sys.exit(exit_code)
    else:
        # GUI mode
        app = GMERGUI()
        app.mainloop()


if __name__ == "__main__":
    main()
