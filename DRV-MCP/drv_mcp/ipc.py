"""
ipc.py
======

Python ctypes mirror of ``shared_memory_ipc.h`` from the kernel driver.
Layout must match the kernel struct byte-for-byte; the driver scans the
target process for ``IPC_MAGIC`` and then indexes into this exact layout.

Anything you add here must also be added to the driver header (or the
driver will read garbage). The reverse is not required — the driver
struct has fields the MCP never touches.
"""

from __future__ import annotations

import ctypes

# ─── Constants (mirror shared_memory_ipc.h) ────────────────────────────
# Non-printable handshake; bytes 13 AE E2 C8 B5 F2 A1 CD in little-endian
# memory order have no overlap with the printable ASCII range so user-mode
# string scanners cannot locate the IPC buffer by grep.
IPC_MAGIC           = 0xCDA1F2B5C8E2AE13
IPC_VERSION         = 2

IPC_MAX_SLOTS       = 16
IPC_SLOT_DATA_SIZE  = 0x1000

# Slot lifecycle
SLOT_STATE_FREE     = 0
SLOT_STATE_BUSY     = 1

# Commands (subset — the kernel knows more; we only expose what we use)
CMD_IDLE                = 0
CMD_READ_MEMORY         = 1
CMD_WRITE_MEMORY        = 2
CMD_GET_BASE_ADDRESS    = 3
CMD_RESOLVE_DTB         = 4
CMD_GET_GUARDED_REGION  = 5
CMD_MOUSE_MOVE          = 6
CMD_INJECT_DLL          = 7
CMD_PING                = 8
CMD_SHUTDOWN            = 9
CMD_GET_PEB             = 10
CMD_GET_MODULE          = 11
CMD_GET_PID             = 12
CMD_ALLOCATE            = 13
CMD_FREE                = 14
CMD_HANDOFF             = 15

# Status codes
STATUS_IPC_IDLE         = 0
STATUS_IPC_PROCESSING   = 1
STATUS_IPC_SUCCESS      = 2
STATUS_IPC_ERROR        = 3

# Command name lookup for error messages
_COMMAND_NAMES = {
    CMD_IDLE:                "IDLE",
    CMD_READ_MEMORY:         "READ_MEMORY",
    CMD_WRITE_MEMORY:        "WRITE_MEMORY",
    CMD_GET_BASE_ADDRESS:    "GET_BASE_ADDRESS",
    CMD_RESOLVE_DTB:         "RESOLVE_DTB",
    CMD_GET_GUARDED_REGION:  "GET_GUARDED_REGION",
    CMD_MOUSE_MOVE:          "MOUSE_MOVE",
    CMD_INJECT_DLL:          "INJECT_DLL",
    CMD_PING:                "PING",
    CMD_SHUTDOWN:            "SHUTDOWN",
    CMD_GET_PEB:             "GET_PEB",
    CMD_GET_MODULE:          "GET_MODULE",
    CMD_GET_PID:             "GET_PID",
    CMD_ALLOCATE:            "ALLOCATE",
    CMD_FREE:                "FREE",
    CMD_HANDOFF:             "HANDOFF",
}


def command_name(cmd: int) -> str:
    return _COMMAND_NAMES.get(cmd, f"CMD_{cmd}")


# ─── Per-command argument structs (#pragma pack(1) in C) ───────────────
class IPC_RW_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('target_address', ctypes.c_uint64),
        ('buffer_size',    ctypes.c_uint64),
        ('is_write',       ctypes.c_uint32),
        ('use_cr3',        ctypes.c_uint32),
    ]


class IPC_RESULT_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('result', ctypes.c_uint64)]


class IPC_MOUSE_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('x',             ctypes.c_int32),
        ('y',             ctypes.c_int32),
        ('button_flags',  ctypes.c_uint16),
    ]


class IPC_INJECT_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('target_pid',       ctypes.c_uint64),
        ('dll_usermode_ptr', ctypes.c_uint64),
        ('dll_size',         ctypes.c_uint32),
        ('alloc_mode',       ctypes.c_uint32),
    ]


class IPC_MODULE_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('name_len', ctypes.c_uint32),
        ('result',   ctypes.c_uint64),
    ]


class IPC_PID_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('name_len',   ctypes.c_uint32),
        ('result_pid', ctypes.c_uint32),
    ]


class IPC_ALLOC_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('address',         ctypes.c_uint64),
        ('size',            ctypes.c_uint64),
        ('allocation_type', ctypes.c_uint32),
        ('protect',         ctypes.c_uint32),
        ('result',          ctypes.c_uint64),
    ]


class IPC_FREE_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('address',   ctypes.c_uint64),
        ('free_type', ctypes.c_uint32),
    ]


class IPC_HANDOFF_DATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('target_pid', ctypes.c_uint32),
        ('reserved',   ctypes.c_uint32),
        ('ipc_va',     ctypes.c_uint64),
    ]


class _CmdDataUnion(ctypes.Union):
    _pack_ = 1
    _fields_ = [
        ('rw',      IPC_RW_DATA),
        ('result',  IPC_RESULT_DATA),
        ('mouse',   IPC_MOUSE_DATA),
        ('inject',  IPC_INJECT_DATA),
        ('module',  IPC_MODULE_DATA),
        ('pid',     IPC_PID_DATA),
        ('alloc',   IPC_ALLOC_DATA),
        ('free',    IPC_FREE_DATA),
        ('handoff', IPC_HANDOFF_DATA),
        ('pad',     ctypes.c_uint8 * 0x30),
    ]


class IPC_SLOT(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('slot_state',  ctypes.c_uint32),                       # 0x00
        ('status',      ctypes.c_uint32),                       # 0x04
        ('command',     ctypes.c_uint32),                       # 0x08
        ('process_id',  ctypes.c_uint32),                       # 0x0C
        ('cr3_cached',  ctypes.c_uint64),                       # 0x10
        ('cmd_data',    _CmdDataUnion),                         # 0x18  (0x30 bytes)
        ('_reserved',   ctypes.c_uint8 * 0xB8),                 # 0x48  ->  0x100
        ('data_buffer', ctypes.c_uint8 * IPC_SLOT_DATA_SIZE),   # 0x100 -> 0x1100
    ]


class IPC_MEMORY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('magic',        ctypes.c_uint64),               # 0x00
        ('version',      ctypes.c_uint32),               # 0x08
        ('active_slots', ctypes.c_uint32),               # 0x0C
        ('slots',        IPC_SLOT * IPC_MAX_SLOTS),      # 0x10
    ]


IPC_TOTAL_SIZE = ctypes.sizeof(IPC_MEMORY)


# ─── Sanity check: layout must match the driver header ─────────────────
# Offsets are taken directly from the comments in shared_memory_ipc.h.
def _assert_layout() -> None:
    slot_offs = {
        'slot_state':  0x00,
        'status':      0x04,
        'command':     0x08,
        'process_id':  0x0C,
        'cr3_cached':  0x10,
        'cmd_data':    0x18,
        '_reserved':   0x48,
        'data_buffer': 0x100,
    }
    for name, expected in slot_offs.items():
        actual = getattr(IPC_SLOT, name).offset
        if actual != expected:
            raise AssertionError(
                f"IPC_SLOT.{name} offset is 0x{actual:X}, expected 0x{expected:X} "
                f"— layout drifted from shared_memory_ipc.h"
            )
    assert ctypes.sizeof(IPC_SLOT) == 0x1100, \
        f"IPC_SLOT size is 0x{ctypes.sizeof(IPC_SLOT):X}, expected 0x1100"
    assert ctypes.sizeof(IPC_MEMORY) == 0x10 + 0x1100 * IPC_MAX_SLOTS, \
        f"IPC_MEMORY size is 0x{ctypes.sizeof(IPC_MEMORY):X}"


_assert_layout()
