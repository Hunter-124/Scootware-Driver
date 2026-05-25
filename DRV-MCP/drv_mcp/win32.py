"""
win32.py
========

Thin ctypes wrappers around the handful of Win32 APIs the MCP server needs:
named file mappings (CreateFileMappingW / MapViewOfFile), events, process
enumeration, and termination. Kept here so the rest of the codebase stays
Python-flavoured.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
from typing import Iterator

# ─── Loaders ────────────────────────────────────────────────────────────
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi    = ctypes.WinDLL("psapi",    use_last_error=True)

# ─── Constants ──────────────────────────────────────────────────────────
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PAGE_READWRITE       = 0x04
FILE_MAP_ALL_ACCESS  = 0xF001F
SECTION_MAP_READ     = 0x0004
SECTION_MAP_WRITE    = 0x0002

EVENT_ALL_ACCESS     = 0x1F0003

PROCESS_TERMINATE              = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION      = 0x0400
PROCESS_VM_READ                = 0x0010

TH32CS_SNAPPROCESS   = 0x00000002

# ─── Function prototypes ────────────────────────────────────────────────
CreateFileMappingW = kernel32.CreateFileMappingW
CreateFileMappingW.argtypes = [
    wt.HANDLE,   # hFile
    ctypes.c_void_p,  # lpAttributes
    wt.DWORD,    # flProtect
    wt.DWORD,    # dwMaximumSizeHigh
    wt.DWORD,    # dwMaximumSizeLow
    wt.LPCWSTR,  # lpName
]
CreateFileMappingW.restype = wt.HANDLE

OpenFileMappingW = kernel32.OpenFileMappingW
OpenFileMappingW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
OpenFileMappingW.restype  = wt.HANDLE

MapViewOfFile = kernel32.MapViewOfFile
MapViewOfFile.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t]
MapViewOfFile.restype  = ctypes.c_void_p

UnmapViewOfFile = kernel32.UnmapViewOfFile
UnmapViewOfFile.argtypes = [ctypes.c_void_p]
UnmapViewOfFile.restype  = wt.BOOL

CreateEventW = kernel32.CreateEventW
CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
CreateEventW.restype  = wt.HANDLE

SetEvent = kernel32.SetEvent
SetEvent.argtypes = [wt.HANDLE]
SetEvent.restype  = wt.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype  = wt.BOOL

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
CreateToolhelp32Snapshot.restype  = wt.HANDLE


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize',              wt.DWORD),
        ('cntUsage',            wt.DWORD),
        ('th32ProcessID',       wt.DWORD),
        ('th32DefaultHeapID',   ctypes.c_void_p),
        ('th32ModuleID',        wt.DWORD),
        ('cntThreads',          wt.DWORD),
        ('th32ParentProcessID', wt.DWORD),
        ('pcPriClassBase',      wt.LONG),
        ('dwFlags',             wt.DWORD),
        ('szExeFile',           wt.WCHAR * 260),
    ]


Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32FirstW.restype  = wt.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32NextW.restype  = wt.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
OpenProcess.restype  = wt.HANDLE

TerminateProcess = kernel32.TerminateProcess
TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
TerminateProcess.restype  = wt.BOOL

GetCurrentProcessId = kernel32.GetCurrentProcessId
GetCurrentProcessId.argtypes = []
GetCurrentProcessId.restype  = wt.DWORD

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
WaitForSingleObject.restype  = wt.DWORD


# ─── Helpers ────────────────────────────────────────────────────────────
class Win32Error(OSError):
    def __init__(self, fn: str, code: int | None = None):
        if code is None:
            code = ctypes.get_last_error()
        super().__init__(code, f"{fn} failed: WinError {code}")
        self.win_function = fn
        self.win_code = code


def _winerr(fn: str) -> Win32Error:
    return Win32Error(fn)


class SharedMemory:
    """Owner of a named Win32 file mapping plus its mapped view."""

    def __init__(self, name: str, size: int):
        self.name = name
        self.size = size
        self.handle: int | None = None
        self.address: int | None = None

    def create(self) -> int:
        """Create (or open) the named mapping and map a view of it."""
        size_high = (self.size >> 32) & 0xFFFFFFFF
        size_low  = self.size & 0xFFFFFFFF
        self.handle = CreateFileMappingW(
            wt.HANDLE(INVALID_HANDLE_VALUE),
            None,
            PAGE_READWRITE,
            size_high,
            size_low,
            self.name,
        )
        if not self.handle:
            raise _winerr("CreateFileMappingW")
        self.address = MapViewOfFile(self.handle, FILE_MAP_ALL_ACCESS, 0, 0, self.size)
        if not self.address:
            err = ctypes.get_last_error()
            CloseHandle(self.handle)
            self.handle = None
            raise Win32Error("MapViewOfFile", err)
        return self.address

    def close(self) -> None:
        if self.address:
            UnmapViewOfFile(ctypes.c_void_p(self.address))
            self.address = None
        if self.handle:
            CloseHandle(self.handle)
            self.handle = None

    def __enter__(self) -> "SharedMemory":
        self.create()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class NamedEvent:
    """Auto-reset named event used to signal the helper to exit."""

    def __init__(self, name: str):
        self.name = name
        self.handle: int | None = None

    def create(self, manual_reset: bool = True) -> int:
        self.handle = CreateEventW(None, manual_reset, False, self.name)
        if not self.handle:
            raise _winerr("CreateEventW")
        return self.handle

    def set(self) -> None:
        if self.handle and not SetEvent(self.handle):
            raise _winerr("SetEvent")

    def close(self) -> None:
        if self.handle:
            CloseHandle(self.handle)
            self.handle = None


def iter_processes() -> Iterator[tuple[int, str]]:
    """Yield (pid, exe_name) for every running process. Names are lowercase."""
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or snap == 0:
        raise _winerr("CreateToolhelp32Snapshot")
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not Process32FirstW(snap, ctypes.byref(pe)):
            return
        while True:
            yield pe.th32ProcessID, pe.szExeFile.lower()
            if not Process32NextW(snap, ctypes.byref(pe)):
                break
    finally:
        CloseHandle(snap)


def find_pids_by_name(name: str) -> list[int]:
    target = name.lower()
    return [pid for pid, exe in iter_processes() if exe == target]


def terminate_pid(pid: int, exit_code: int = 0) -> bool:
    h = OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    try:
        return bool(TerminateProcess(h, exit_code))
    finally:
        CloseHandle(h)


def current_pid() -> int:
    return GetCurrentProcessId()
