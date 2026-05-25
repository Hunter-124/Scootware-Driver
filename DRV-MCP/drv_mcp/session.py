"""
session.py
==========

Owns the helper subprocess lifecycle and creates the DriverClient that
talks to it over stdio.

Flow:

  1. Detect any pre-existing scootware.exe (your ImGui GUI, an old
     helper from a crashed session) and terminate it. The kernel driver
     only attaches to one scootware.exe at a time; that slot has to be
     our helper.
  2. Spawn ``helper/scootware.exe`` with stdin/stdout pipes. The helper
     allocates its IPC buffer in its own ``.bss`` (inside its PE image,
     which is where the driver's discovery thread scans) and emits a
     ``ready ipc_va=...`` line on stdout.
  3. Wrap the helper's stdio in a DriverClient.
  4. Optionally wait for the driver to PING successfully through that
     pipe (proves discovery thread found the helper).

Teardown sends ``bye`` so the helper zeros its magic before exiting —
the driver's discovery loop notices the burned magic and tears down its
kernel mapping cleanly.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .driver import DriverClient
from .win32 import find_pids_by_name, terminate_pid

log = logging.getLogger("drv_mcp.session")
_HELPER_NAME = "scootware.exe"


@dataclass
class SessionConfig:
    helper_path: Path
    kill_existing:      bool  = True
    handshake_timeout_s: float = 30.0
    spawn_helper:       bool  = True


@dataclass
class SessionStatus:
    helper_pid:      Optional[int] = None
    helper_running:  bool          = False
    ipc_va:          Optional[int] = None
    driver_attached: bool          = False
    last_ping_us:    Optional[float] = None
    killed_pids:     list[int]     = field(default_factory=list)


class Session:
    def __init__(self, config: SessionConfig):
        self.config        = config
        self._helper:      Optional[subprocess.Popen] = None
        self._client:      Optional[DriverClient]     = None
        self._ipc_va:      Optional[int]              = None
        self._killed_pids: list[int]                  = []
        self._stop_lock    = threading.Lock()
        self._stopped      = False

    @property
    def client(self) -> DriverClient:
        if not self._client:
            raise RuntimeError("Session is not started")
        return self._client

    def start(self) -> SessionStatus:
        if self._client:
            return self.status()

        if self.config.kill_existing:
            self._killed_pids = self._kill_existing_scootware()

        if self.config.spawn_helper:
            self._spawn_helper()

        return self.status()

    def wait_for_driver(self, timeout_s: Optional[float] = None) -> bool:
        if not self._client:
            raise RuntimeError("Session is not started")
        t = timeout_s if timeout_s is not None else self.config.handshake_timeout_s
        return self._client.wait_for_handshake(t)

    def stop(self) -> None:
        with self._stop_lock:
            if self._stopped:
                return
            self._stopped = True

        # Send `bye` so helper burns the IPC magic and exits cleanly. The
        # driver's discovery loop notices the burned magic within ~100 ms
        # and releases its kernel mapping.
        if self._client:
            try:
                self._client.burn_magic()
            except Exception as e:
                log.warning("burn_magic failed: %s", e)

        if self._helper:
            try:
                self._helper.wait(timeout=3)
            except subprocess.TimeoutExpired:
                log.warning("Helper didn't exit on bye; terminating")
                self._helper.terminate()
                try:
                    self._helper.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._helper.kill()
            self._helper = None

        self._client = None
        self._ipc_va = None

    def status(self) -> SessionStatus:
        helper_pid     = self._helper.pid if self._helper else None
        helper_running = bool(self._helper and self._helper.poll() is None)

        ping_us = None
        attached = False
        if self._client and helper_running:
            r = self._client.ping(timeout_ms=500)
            attached = r.success
            ping_us  = r.elapsed_us if r.success else None

        return SessionStatus(
            helper_pid=helper_pid,
            helper_running=helper_running,
            ipc_va=self._ipc_va,
            driver_attached=attached,
            last_ping_us=ping_us,
            killed_pids=list(self._killed_pids),
        )

    def __enter__(self) -> "Session":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── Internals ──────────────────────────────────────────────────────
    def _kill_existing_scootware(self) -> list[int]:
        own_pid = os.getpid()
        pids = [p for p in find_pids_by_name(_HELPER_NAME) if p != own_pid]
        killed: list[int] = []
        for pid in pids:
            log.warning("Terminating pre-existing %s pid=%d", _HELPER_NAME, pid)
            if terminate_pid(pid):
                killed.append(pid)
        if killed:
            # Give Windows + the driver discovery a moment to notice.
            time.sleep(0.5)
        return killed

    def _spawn_helper(self) -> None:
        if not self.config.helper_path.exists():
            raise FileNotFoundError(
                f"Helper executable not found at {self.config.helper_path}. "
                f"Build it with helper/build.bat first."
            )
        if self.config.helper_path.name.lower() != _HELPER_NAME:
            raise RuntimeError(
                f"Helper exe must be named {_HELPER_NAME!r} so the kernel "
                f"driver discovers it. Got {self.config.helper_path.name!r}."
            )

        self._helper = subprocess.Popen(
            [str(self.config.helper_path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, bufsize=1,
            close_fds=True,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        log.info("Spawned helper %s pid=%d", _HELPER_NAME, self._helper.pid)

        # Wait for the helper's READY line — it includes the IPC VA, which
        # we record for diagnostics. If the helper dies before READY, we
        # surface a clear error.
        deadline = time.monotonic() + 5.0
        ready_line = ""
        while time.monotonic() < deadline:
            if self._helper.poll() is not None:
                stderr = self._helper.stderr.read() if self._helper.stderr else ""
                raise RuntimeError(
                    f"Helper exited immediately with code "
                    f"{self._helper.returncode}. stderr: {stderr!r}"
                )
            line = self._helper.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            ready_line = line.strip()
            if ready_line.startswith("ready"):
                break
        if not ready_line.startswith("ready"):
            raise RuntimeError(
                f"Helper did not announce READY within 5s (got {ready_line!r})"
            )

        # Parse ipc_va=<hex> out of the ready line
        for tok in ready_line.split():
            if tok.startswith("ipc_va="):
                self._ipc_va = int(tok.split("=", 1)[1], 16)
                break
        log.info("Helper ready; ipc_va=0x%X", self._ipc_va or 0)

        self._client = DriverClient(self._helper)
