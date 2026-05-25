"""
suspend.py
==========

Spin-patch process suspension. The classic SuspendThread/NtSuspendProcess
approach gets a target's threads to ``WrSuspended`` and bumps
SuspendCount — both observable to anti-cheat. Instead we patch a 2-byte
infinite loop (``EB FE`` = ``JMP $-2``) at a function the target
executes. Threads that reach the patched VA "run" forever inside the
JMP, so:

  * No process/thread handle is opened.
  * WaitReason stays at ``Executive`` / whatever the runtime expects —
    threads are technically running CPU instructions.
  * SuspendCount stays 0.
  * RIP-driven detection (KiUserApcDispatcher hooks, etc.) sees a
    normal user-mode thread.

When we restore the bytes, x86 cache-coherency (MESI snooping the L1i)
makes the executing core re-fetch the new instruction at the same RIP.
The thread resumes seamlessly.

Caveats:

  * Selectivity — every thread that hits the VA is frozen. Pick a low-
    traffic location (e.g. a game tick function) to freeze just the main
    thread; use a hotter location to freeze more threads.
  * Shared pages — DO NOT patch ntdll/kernel32/etc. text in a target;
    those physical pages are shared via KnownDlls and writing through
    the CR3 pipe will corrupt other processes. Always patch in the
    target's own modules.
  * Restore atomicity — if a thread is mid-``EB FE`` when we restore,
    the JMP completes, RIP rewinds 2 bytes, the core re-fetches the new
    bytes from the snooped cache line, execution resumes. No race.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .driver import DriverClient, DriverError


# ``EB FE`` = JMP rel8 -2, an infinite loop on the same two bytes.
SPIN_INSTRUCTION = b'\xEB\xFE'


@dataclass
class FreezeRecord:
    pid:        int
    address:    int
    length:     int
    original:   bytes
    note:       str
    when:       str

    def as_dict(self) -> dict:
        return {
            "pid":      self.pid,
            "address":  f"0x{self.address:X}",
            "length":   self.length,
            "original": self.original.hex(),
            "patched":  (SPIN_INSTRUCTION + b'\x90' * (self.length - 2)).hex(),
            "note":     self.note,
            "when":     self.when,
        }


class ProcessFreezer:
    """Patches ``EB FE`` at a target VA; undoes on demand."""

    def __init__(self, client: DriverClient):
        self._c = client
        self._frozen: dict[tuple[int, int], FreezeRecord] = {}

    def freeze(self, pid: int, address: int, length: int = 2,
               note: str = "", use_cr3: bool = True) -> FreezeRecord:
        if length < 2 or length > 16:
            raise ValueError("length must be in [2, 16] bytes")
        key = (pid, address)
        if key in self._frozen:
            raise ValueError(
                f"already frozen at pid={pid} va=0x{address:X}; "
                f"unfreeze first"
            )

        original = self._c.read_memory(pid, address, length, use_cr3=use_cr3)
        # Sanity: we want the bytes back after restore — if the location
        # is unreadable, fail before writing anything.
        patch = SPIN_INSTRUCTION + b'\x90' * (length - 2)
        self._c.write_memory(pid, address, patch, use_cr3=use_cr3)

        rec = FreezeRecord(
            pid=pid, address=address, length=length,
            original=bytes(original), note=note,
            when=datetime.now().isoformat(timespec='seconds'))
        self._frozen[key] = rec
        return rec

    def unfreeze(self, pid: int, address: Optional[int] = None,
                 use_cr3: bool = True) -> list[FreezeRecord]:
        """Restore one specific freeze, or every freeze for this PID."""
        if address is not None:
            keys = [(pid, address)]
        else:
            keys = [k for k in self._frozen if k[0] == pid]

        restored: list[FreezeRecord] = []
        for k in keys:
            rec = self._frozen.pop(k, None)
            if not rec:
                continue
            try:
                self._c.write_memory(rec.pid, rec.address, rec.original,
                                      use_cr3=use_cr3)
            except DriverError:
                # Re-add to registry so the user can retry later
                self._frozen[k] = rec
                raise
            restored.append(rec)
        return restored

    def unfreeze_all(self, use_cr3: bool = True) -> list[FreezeRecord]:
        restored: list[FreezeRecord] = []
        for key in list(self._frozen.keys()):
            rec = self._frozen.pop(key, None)
            if not rec:
                continue
            try:
                self._c.write_memory(rec.pid, rec.address, rec.original,
                                      use_cr3=use_cr3)
                restored.append(rec)
            except DriverError:
                self._frozen[key] = rec
        return restored

    def list_frozen(self) -> list[FreezeRecord]:
        return list(self._frozen.values())

    def is_frozen(self, pid: int, address: int) -> bool:
        return (pid, address) in self._frozen
