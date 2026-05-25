"""
test_target.py
==============

A controlled victim process for the MCP function tests. Allocates a 1 MiB
RWX buffer, writes a known sentinel pattern, prints the buffer's VA, and
sleeps forever. The test harness reads/writes/scans/disassembles inside
that buffer so the tests never depend on (or risk corrupting) any real
target like a game.

Run via:

    python test_target.py [--sentinel <hex>]

Stdout (line-flushed):

    BUFFER_VA=<hex>
    SENTINEL=<hex>
    SIZE=<int>
    READY
"""

from __future__ import annotations

import argparse
import ctypes
import os
import struct
import sys
import time

# Buffer layout (offsets within the 1 MiB region):
#   0x000000 : sentinel u32 (used for value-scan tests)
#   0x000004 : reserved (zero)
#   0x000008 : a u64 "pointer" that points to 0x000100 within the buffer (for pointer-chain tests)
#   0x000010 : f32 health = 100.0
#   0x000014 : i32 ammo  = 30
#   0x000020 : ASCII string "DRV_MCP_TEST_STRING_v1"
#   0x000040 : UTF-16LE string "ScootwareDriverMCP"
#   0x000080 : x64 code: 48 89 5C 24 08  push rbx prologue + ret  (for disasm test)
#   0x000100 : leaf "value" (the pointer at 0x000008 points here) u64 = 0xDEADC0DE_BEEFCAFE
#   ...      : remaining zero
SIZE     = 1 * 1024 * 1024  # 1 MiB
SENTINEL_DEFAULT = 0xDECAFBAD


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sentinel", default=hex(SENTINEL_DEFAULT))
    args = ap.parse_args()
    sentinel = int(args.sentinel, 16) if args.sentinel.startswith("0x") else int(args.sentinel)

    # Allocate RWX so write_memory tests don't fight page protection.
    PAGE_EXECUTE_READWRITE = 0x40
    MEM_COMMIT_RESERVE     = 0x3000
    VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    VirtualAlloc.restype  = ctypes.c_void_p
    addr = VirtualAlloc(None, SIZE, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        print("ALLOC_FAILED", flush=True)
        return 1

    # Get an addressable view as a c_ubyte array
    buf = (ctypes.c_ubyte * SIZE).from_address(addr)
    # zero
    ctypes.memset(addr, 0, SIZE)

    def write_at(off: int, data: bytes) -> None:
        for i, b in enumerate(data):
            buf[off + i] = b

    # Sentinel
    write_at(0x000000, struct.pack("<I", sentinel))
    # Pointer to leaf at 0x100
    write_at(0x000008, struct.pack("<Q", addr + 0x100))
    # Health float = 100.0
    write_at(0x000010, struct.pack("<f", 100.0))
    # Ammo i32 = 30
    write_at(0x000014, struct.pack("<i", 30))
    # ASCII tag
    write_at(0x000020, b"DRV_MCP_TEST_STRING_v1\x00")
    # UTF-16LE tag
    write_at(0x000040, "ScootwareDriverMCP".encode("utf-16-le") + b"\x00\x00")
    # Tiny x64 prologue + ret (for disassembler smoke)
    #   48 89 5C 24 08         mov [rsp+8], rbx
    #   48 89 74 24 10         mov [rsp+10h], rsi
    #   57                     push rdi
    #   48 83 EC 20            sub rsp, 20h
    #   C3                     ret
    write_at(0x000080, bytes.fromhex("48895C2408 4889742410 57 4883EC20 C3".replace(" ", "")))
    # Leaf u64 at 0x100
    write_at(0x000100, struct.pack("<Q", 0xDEADC0DEBEEFCAFE))

    # Tell harness where the buffer lives
    print(f"BUFFER_VA=0x{addr:X}", flush=True)
    print(f"SENTINEL=0x{sentinel:08X}", flush=True)
    print(f"SIZE={SIZE}", flush=True)
    print(f"PID={os.getpid()}", flush=True)
    print("READY", flush=True)

    # Live forever, but yield so the OS can suspend us if needed.
    while True:
        time.sleep(60)


if __name__ == "__main__":
    sys.exit(main())
