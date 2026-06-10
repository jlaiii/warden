#!/usr/bin/env python3
"""
Warden Anti-Detection System
=============================
Prevents malware from detecting or blocking the scanner by:
  - Obfuscating sensitive string literals (XOR + base64)
  - Randomizing process mutex names (UUID-based, different every launch)
  - Creating randomized temp copies with different file hashes
  - Self-deleting temp copies on exit
  - Randomized window class identifiers

Inspired by GMER's anti-detection approach — if malware can't
predict the executable name or detect known mutex/class names,
it cannot block the scanner.

Usage:
    from anti_detect import AntiDetect
    ad = AntiDetect()
    ad.arm()  # sets up mutex, temp copy, atexit handlers
    # ... run scanner ...
    ad.disarm()  # cleanup
"""

from __future__ import annotations

import atexit
import ctypes
import logging
import os
import random
import shutil
import signal
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

log = logging.getLogger("taskmgr")


class AntiDetect:
    """Manages all anti-detection measures.

    Call `arm()` at startup and `disarm()` on clean shutdown.
    The atexit handler and signal handlers provide automatic cleanup.
    """

    def __init__(self, app_name: str = "Warden"):
        self._app_name = app_name
        self._armed = False
        self._mutex_name: str = ""
        self._mutex_handle: int = 0
        self._temp_path: str = ""
        self._original_working_dir: str = os.getcwd()
        self._cleanup_lock = threading.Lock()

    # ---- Public API ---------------------------------------------------------

    def arm(self) -> None:
        """Activate all anti-detection measures."""
        if self._armed:
            return

        log.info("AntiDetect: arming protection systems…")
        self._setup_mutex()
        self._setup_exit_handlers()
        self._armed = True
        log.info("AntiDetect: armed — mutex='%s'", self._mutex_name)

    def disarm(self) -> None:
        """Clean shutdown — release mutex, delete temp copy."""
        with self._cleanup_lock:
            if not self._armed:
                return
            log.info("AntiDetect: disarming…")
            self._release_mutex()
            self._delete_temp_copy()
            self._armed = False

    @property
    def mutex_name(self) -> str:
        return self._mutex_name

    @property
    def temp_path(self) -> str:
        return self._temp_path

    # ---- Randomized Mutex ---------------------------------------------------

    def _setup_mutex(self) -> None:
        """Create a cross-process named mutex with a randomized name.

        This prevents malware from detecting the scanner by looking for
        a well-known mutex name (e.g., "GMER_MUTEX", "ROOTKIT_SCANNER").
        The mutex name is a random UUID on every launch.
        """
        kernel32 = ctypes.windll.kernel32

        # Generate a unique 16-char hex name (no predictable prefix)
        random_part = uuid.uuid4().hex[:16]
        self._mutex_name = f"Global\\{random_part}"

        # Create the mutex (fails if it already exists — highly unlikely with UUID)
        handle = kernel32.CreateMutexW(None, False, self._mutex_name)
        if handle:
            self._mutex_handle = handle
            log.debug("AntiDetect: mutex created — %s (handle 0x%X)",
                      self._mutex_name, handle)
        else:
            log.warning("AntiDetect: CreateMutexW failed (error %d)",
                        kernel32.GetLastError())

    def _release_mutex(self) -> None:
        """Release the randomized mutex."""
        if self._mutex_handle:
            kernel32 = ctypes.windll.kernel32
            kernel32.CloseHandle(self._mutex_handle)
            self._mutex_handle = 0
            log.debug("AntiDetect: mutex released")

    # ---- Exit Handlers ------------------------------------------------------

    def _setup_exit_handlers(self) -> None:
        """Register cleanup routines for normal and abnormal exit."""
        atexit.register(self._atexit_cleanup)

        # Also handle Ctrl+C / console close
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except Exception:
            pass  # Not available in all contexts

    def _signal_handler(self, signum, frame) -> None:
        """Handle SIGINT/SIGTERM — clean up and exit."""
        log.info("AntiDetect: received signal %d — cleaning up", signum)
        self.disarm()
        sys.exit(0)

    def _atexit_cleanup(self) -> None:
        """Cleanup handler registered with atexit."""
        try:
            if self._armed:
                self.disarm()
        except Exception:
            pass

    # ---- Temp Copy Cleanup --------------------------------------------------

    def _delete_temp_copy(self) -> None:
        """Delete the temporary executable copy if one was created."""
        if self._temp_path and os.path.isfile(self._temp_path):
            try:
                os.unlink(self._temp_path)
                log.info("AntiDetect: deleted temp copy — %s", self._temp_path)
            except Exception as e:
                log.debug("AntiDetect: could not delete temp copy: %s", e)
            self._temp_path = ""

    # ---- Randomized Window Class --------------------------------------------

    @staticmethod
    def random_window_title(base: str = "Warden Task Manager") -> str:
        """Return a window title with a random suffix to foil window-name detection.

        Malware often looks for windows with titles containing "GMER",
        "Rootkit Scanner", "Process Hacker", etc. By appending a random
        suffix, we make window-title-based detection unreliable.
        """
        suffix = uuid.uuid4().hex[:6].upper()
        return f"{base} [{suffix}]"


# ---------------------------------------------------------------------------
# Standalone: temp-copy self-protection
# ---------------------------------------------------------------------------

def spawn_temp_copy() -> tuple[str, str] | None:
    """Copy the current executable to %TEMP% with a random name and
    different hash, then return the new path.

    Returns (temp_path, random_name) or None if the copy failed.
    The caller is responsible for launching the temp copy.

    Like GMER's random executable naming, this prevents malware from
    blocking the scanner based on its original filename.
    """
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller bundle
        original = sys.executable
    else:
        original = sys.argv[0]

    if not os.path.isfile(original):
        log.warning("Cannot create temp copy — original not found: %s", original)
        return None

    try:
        random_name = f"{uuid.uuid4().hex[:12]}.exe"
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, random_name)

        # Copy the executable
        shutil.copy2(original, temp_path)

        # Append random bytes to the overlay to change the file hash
        # This ensures the temp copy has a different SHA256 than the original
        with open(temp_path, "ab") as f:
            f.write(os.urandom(random.randint(256, 2048)))

        log.info("Temp copy created: %s (original: %s)", temp_path, original)
        return (temp_path, random_name)
    except Exception as e:
        log.error("Failed to create temp copy: %s", e)
        return None


# ---------------------------------------------------------------------------
# String Obfuscation Utility
# ---------------------------------------------------------------------------

class StringObfuscator:
    """XOR + base64 string obfuscation for sensitive literals.

    Stores strings in encrypted form so static analysis ("strings" tool,
    hex editors, YARA rules) cannot find sensitive keywords like
    "NtQuerySystemInformation", "rootkit", "GMER" in the binary.

    Usage:
        obf = StringObfuscator()
        ntdll_func = obf.get("nt_query")  # returns "NtQuerySystemInformation"
    """

    def __init__(self, key: bytes | None = None):
        if key is None:
            # Derive key from a combination of factors
            key = self._derive_key()
        self._key = key
        self._cache: dict[str, str] = {}

    @staticmethod
    def _derive_key() -> bytes:
        """Derive a deterministic but environment-varying key."""
        seed = int(time.time() * 1000) % (2**32)
        rng = random.Random(seed)
        return bytes(rng.getrandbits(8) for _ in range(32))

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string (for build-time use)."""
        import base64
        raw = plaintext.encode("utf-8")
        encrypted = bytes(b ^ self._key[i % len(self._key)] for i, b in enumerate(raw))
        return base64.b64encode(encrypted).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string at runtime."""
        import base64
        encrypted = base64.b64decode(ciphertext.encode("ascii"))
        decrypted = bytes(b ^ self._key[i % len(self._key)] for i, b in enumerate(encrypted))
        return decrypted.decode("utf-8")

    def get(self, name: str) -> str:
        """Look up a string by its key name from the obfuscated store."""
        if name in self._cache:
            return self._cache[name]

        encoded = _OBFUSCATED_STRINGS.get(name)
        if encoded is None:
            raise KeyError(f"Obfuscated string '{name}' not found in store")

        result = self.decrypt(encoded)
        self._cache[name] = result
        return result


# Pre-obfuscated string store (generated at build time)
# In production, this would be populated by build_obfuscated.py
_OBFUSCATED_STRINGS: dict[str, str] = {
    # Placeholder — populated at build time
    # "nt_query": base64(xor("NtQuerySystemInformation")),
    # "app_name": base64(xor("Warden")),
}
