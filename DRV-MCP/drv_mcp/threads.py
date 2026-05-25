"""
threads.py
==========

Enumerate threads of a target process via
``NtQuerySystemInformation(SystemProcessInformation)`` — a single
syscall that returns the kernel's whole-system snapshot of all
processes and their threads. It does NOT open a handle on the target,
which keeps the operation off the typical anti-cheat detection surface
(no ``OpenProcess`` / ``OpenThread``, no thread access mask).

Returned per-thread info:

  * TID and start address (the kernel-side start address — what
    ``CREATE_SUSPENDED`` would have set)
  * ThreadState + WaitReason (helps pick which thread is mid-syscall
    vs. doing real work)
  * Kernel/user time (for picking the "hot" thread to freeze)
"""

from __future__ import annotations

import ctypes
import struct
from dataclasses import dataclass
from typing import Optional

from . import win32

# ─── Thread state / wait reason enums ──────────────────────────────────
_THREAD_STATES = {
    0: "Initialized", 1: "Ready",       2: "Running",
    3: "Standby",     4: "Terminated",  5: "Waiting",
    6: "Transition",  7: "DeferredReady", 8: "GateWait",
}

_WAIT_REASONS = {
    0: "Executive",   1: "FreePage",    2: "PageIn",
    3: "PoolAllocation",  4: "DelayExecution", 5: "Suspended",
    6: "UserRequest", 7: "WrExecutive", 8: "WrFreePage",
    9: "WrPageIn",   10: "WrPoolAllocation", 11: "WrDelayExecution",
    12: "WrSuspended", 13: "WrUserRequest", 14: "WrEventPair",
    15: "WrQueue",   16: "WrLpcReceive", 17: "WrLpcReply",
    18: "WrVirtualMemory", 19: "WrPageOut", 20: "WrRendezvous",
    21: "WrKeyedEvent", 22: "WrTerminated", 23: "WrProcessInSwap",
    24: "WrCpuRateControl", 25: "WrCalloutStack", 26: "WrKernel",
    27: "WrResource", 28: "WrPushLock", 29: "WrMutex",
    30: "WrQuantumEnd", 31: "WrDispatchInt", 32: "WrPreempted",
    33: "WrYieldExecution", 34: "WrFastMutex", 35: "WrGuardedMutex",
    36: "WrRundown", 37: "WrAlertByThreadId", 38: "WrDeferredPreempt",
}


def thread_state_name(s: int) -> str:
    return _THREAD_STATES.get(s, f"State{s}")


def wait_reason_name(r: int) -> str:
    return _WAIT_REASONS.get(r, f"Reason{r}")


# ─── ntdll prototype ───────────────────────────────────────────────────
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

NtQuerySystemInformation = ntdll.NtQuerySystemInformation
NtQuerySystemInformation.argtypes = [
    ctypes.c_ulong,                       # SYSTEM_INFORMATION_CLASS
    ctypes.c_void_p,                      # SystemInformation buffer
    ctypes.c_ulong,                       # SystemInformationLength
    ctypes.POINTER(ctypes.c_ulong),       # ReturnLength
]
NtQuerySystemInformation.restype = ctypes.c_long  # NTSTATUS

SYSTEM_PROCESS_INFORMATION = 5

# Per-thread record size in the kernel struct (x64, with alignment padding).
# Layout (offsets within SYSTEM_THREAD_INFORMATION):
#   0x00 KernelTime LARGE_INTEGER
#   0x08 UserTime LARGE_INTEGER
#   0x10 CreateTime LARGE_INTEGER
#   0x18 WaitTime ULONG     (+4 padding to align PVOID)
#   0x20 StartAddress PVOID
#   0x28 ClientId.UniqueProcess PVOID
#   0x30 ClientId.UniqueThread PVOID
#   0x38 Priority KPRIORITY (LONG)
#   0x3C BasePriority LONG
#   0x40 ContextSwitches ULONG
#   0x44 ThreadState ULONG
#   0x48 WaitReason ULONG
#   0x4C (4 bytes pad to 0x50)
_THREAD_INFO_SIZE = 0x50

# SYSTEM_PROCESS_INFORMATION header size on x64 (before Threads[]).
_PROCESS_INFO_HEADER_SIZE = 0x100


@dataclass
class ThreadInfo:
    tid:               int
    start_address:     int
    state:             int
    wait_reason:       int
    kernel_time_100ns: int
    user_time_100ns:   int
    create_time_100ns: int
    priority:          int
    base_priority:     int
    context_switches:  int

    @property
    def state_name(self) -> str:
        return thread_state_name(self.state)

    @property
    def wait_reason_name(self) -> str:
        return wait_reason_name(self.wait_reason)


@dataclass
class ProcessThreadSnapshot:
    pid:           int
    image_name:    str
    thread_count:  int
    threads:       list[ThreadInfo]


def _query_snapshot() -> tuple[ctypes.Array, int, int]:
    """Call NtQuerySystemInformation until the buffer is large enough.
    Returns (buffer, used_size, buffer_base_address). The caller needs
    buffer_base_address to convert UNICODE_STRING.Buffer pointers
    (which the kernel wrote as VAs into this buffer) into offsets."""
    size = ctypes.c_ulong(0)
    NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION, None, 0, ctypes.byref(size))
    if size.value == 0:
        size.value = 256 * 1024  # fallback
    # Add slack: processes appear between the two calls.
    buf_size = size.value + 256 * 1024
    buf = (ctypes.c_ubyte * buf_size)()
    status = NtQuerySystemInformation(
        SYSTEM_PROCESS_INFORMATION, buf, buf_size, ctypes.byref(size))
    if status < 0:
        raise OSError(
            f"NtQuerySystemInformation(SystemProcessInformation) failed "
            f"with NTSTATUS 0x{status & 0xFFFFFFFF:08X}"
        )
    return buf, size.value, ctypes.addressof(buf)


def list_threads(pid: int) -> Optional[ProcessThreadSnapshot]:
    """
    Return the thread list for ``pid``. ``None`` if the process isn't
    found in the snapshot (likely terminated).
    """
    buf, used, base_addr = _query_snapshot()
    blob = bytes(buf[:used])

    offset = 0
    while True:
        if offset + _PROCESS_INFO_HEADER_SIZE > len(blob):
            return None
        next_off  = struct.unpack_from('<I', blob, offset + 0x00)[0]
        n_threads = struct.unpack_from('<I', blob, offset + 0x04)[0]
        # ImageName UNICODE_STRING at +0x38: Length (USHORT), MaxLen (USHORT),
        # padding (DWORD), Buffer (PVOID). The Buffer pointer is a VA inside
        # our `buf` allocation — convert to a blob offset.
        name_len = struct.unpack_from('<H', blob, offset + 0x38)[0]
        name_ptr = struct.unpack_from('<Q', blob, offset + 0x40)[0]
        unique_pid = struct.unpack_from('<Q', blob, offset + 0x50)[0]

        if unique_pid == pid:
            image = ""
            if name_ptr and name_len:
                name_offset = name_ptr - base_addr
                if 0 <= name_offset and name_offset + name_len <= len(blob):
                    image = blob[name_offset:name_offset + name_len].decode(
                        'utf-16-le', errors='replace')

            threads: list[ThreadInfo] = []
            t_off = offset + _PROCESS_INFO_HEADER_SIZE
            for _ in range(n_threads):
                if t_off + _THREAD_INFO_SIZE > len(blob):
                    break
                kt   = struct.unpack_from('<q', blob, t_off + 0x00)[0]
                ut   = struct.unpack_from('<q', blob, t_off + 0x08)[0]
                ct   = struct.unpack_from('<q', blob, t_off + 0x10)[0]
                # WaitTime + padding at 0x18 (skipped)
                sa   = struct.unpack_from('<Q', blob, t_off + 0x20)[0]
                tid  = struct.unpack_from('<Q', blob, t_off + 0x30)[0]
                pri  = struct.unpack_from('<i', blob, t_off + 0x38)[0]
                bpri = struct.unpack_from('<i', blob, t_off + 0x3C)[0]
                cs   = struct.unpack_from('<I', blob, t_off + 0x40)[0]
                ts   = struct.unpack_from('<I', blob, t_off + 0x44)[0]
                wr   = struct.unpack_from('<I', blob, t_off + 0x48)[0]
                threads.append(ThreadInfo(
                    tid=int(tid), start_address=int(sa),
                    state=int(ts), wait_reason=int(wr),
                    kernel_time_100ns=int(kt), user_time_100ns=int(ut),
                    create_time_100ns=int(ct),
                    priority=int(pri), base_priority=int(bpri),
                    context_switches=int(cs)))
                t_off += _THREAD_INFO_SIZE

            return ProcessThreadSnapshot(
                pid=pid, image_name=image,
                thread_count=n_threads, threads=threads)

        if next_off == 0:
            return None
        offset += next_off
