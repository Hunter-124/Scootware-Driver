"""
driver.py
=========

Driver client. Talks to the kernel driver indirectly: the
``scootware.exe`` helper process owns the IPC buffer (in its own .bss
where the driver's discovery actually scans) and bridges it to us over
stdio.

Wire protocol (one line per request/response):

    Request:  <cmd> <id> [args...]
    Response: ok  <id> [key=value key=value ...]
              err <id> reason=<percent-encoded>

The ``DriverClient`` API is unchanged from the previous in-process
shared-memory implementation — only the transport differs. Callers
(``analysis``, ``hunting``, ``suspend``, ``server.py``) don't notice.
"""

from __future__ import annotations

import ctypes
import itertools
import re
import shutil
import struct
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class DriverError(RuntimeError):
    """Raised when a driver command fails (timeout, parse error, or
    STATUS_IPC_ERROR from the kernel)."""


@dataclass
class CommandResult:
    success: bool
    elapsed_us: float
    timed_out: bool


# ─── Response parser ───────────────────────────────────────────────────
_RESPONSE_RE = re.compile(r'^(ok|err)\s+(\d+)(?:\s+(.*))?$')


def _parse_response(line: str) -> tuple[bool, int, dict[str, str]]:
    """Returns (success, id, kvs)."""
    m = _RESPONSE_RE.match(line.strip())
    if not m:
        raise DriverError(f"malformed helper response: {line!r}")
    success = (m.group(1) == "ok")
    rid     = int(m.group(2))
    kvs: dict[str, str] = {}
    rest = (m.group(3) or "").strip()
    if rest:
        for tok in rest.split():
            if '=' in tok:
                k, v = tok.split('=', 1)
                kvs[k] = urllib.parse.unquote(v)
    return success, rid, kvs


# ─── DriverClient: subprocess wrapper around scootware.exe helper ──────
class DriverClient:
    """
    Wraps the helper subprocess. All command calls go through a single
    serialized request/response over the helper's stdio pipes.
    """

    def __init__(self, helper_proc: subprocess.Popen):
        self._p   = helper_proc
        self._id  = itertools.count(1)
        self._lock = threading.Lock()
        # CR3 reads/writes need the driver to have cached the target's
        # DTB (it's resolved + cached server-side on RESOLVE_DTB). Without
        # that, the CR3 path returns STATUS_IPC_ERROR. We auto-resolve on
        # first use and remember which PIDs we've primed.
        self._cr3_primed: set[int] = set()
        if self._p.stdin is None or self._p.stdout is None:
            raise DriverError("helper subprocess has no stdio pipes")

    # ── Low-level request/response ──────────────────────────────────────
    def _send(self, cmd: str, *args, timeout_s: float = 15.0) -> dict[str, str]:
        with self._lock:
            if self._p.poll() is not None:
                raise DriverError(
                    f"helper has exited (returncode={self._p.returncode})"
                )
            rid = next(self._id)
            line = f"{cmd} {rid}" + ("".join(f" {a}" for a in args)) + "\n"
            try:
                self._p.stdin.write(line)
                self._p.stdin.flush()
            except (BrokenPipeError, OSError) as e:
                raise DriverError(f"helper stdin write failed: {e}") from e

            # Read one line back. The helper always replies with exactly
            # one line per request.
            deadline = time.monotonic() + timeout_s
            response: Optional[str] = None
            while time.monotonic() < deadline:
                response = self._p.stdout.readline()
                if response:
                    break
                if self._p.poll() is not None:
                    raise DriverError(
                        f"helper exited mid-call (returncode={self._p.returncode})"
                    )
                time.sleep(0.001)
            if not response:
                raise DriverError(f"{cmd} timed out after {timeout_s}s")

            ok, replied_id, kvs = _parse_response(response)
            if replied_id != rid:
                raise DriverError(
                    f"id mismatch: sent {rid} got {replied_id} "
                    f"({response!r})"
                )
            if not ok:
                raise DriverError(
                    f"{cmd} failed: {kvs.get('reason', 'unknown')}"
                )
            return kvs

    # ── Lifecycle ──────────────────────────────────────────────────────
    def burn_magic(self) -> None:
        """Tell the helper to zero its IPC magic + exit, so the driver
        tears down its kernel mapping cleanly."""
        try:
            with self._lock:
                if self._p.poll() is not None:
                    return
                rid = next(self._id)
                self._p.stdin.write(f"bye {rid}\n")
                self._p.stdin.flush()
                # Best-effort read of the ack; don't block teardown forever.
                self._p.stdout.readline()
        except Exception:
            pass

    # ── Ping / handshake ───────────────────────────────────────────────
    def ping(self, timeout_ms: int = 2000) -> CommandResult:
        try:
            kvs = self._send("ping", timeout_s=timeout_ms / 1000.0 + 1.0)
            us = float(kvs.get("elapsed_us", "0"))
            return CommandResult(True, us, False)
        except DriverError:
            return CommandResult(False, 0.0, True)

    def wait_for_handshake(self, timeout_s: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.ping(timeout_ms=2000).success:
                return True
            time.sleep(0.3)
        return False

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        try:
            self._send("shutdown", timeout_s=timeout_ms / 1000.0 + 1.0)
            return True
        except DriverError:
            return False

    # ── Process discovery ──────────────────────────────────────────────
    def get_pid_by_name(self, process_name: str) -> int:
        if not process_name or len(process_name) > 255:
            raise DriverError("process_name must be 1–255 chars")
        try:
            kvs = self._send("getpid", process_name)
        except DriverError:
            return 0
        return int(kvs.get("pid", "0"))

    # ── Per-process introspection ──────────────────────────────────────
    def get_base_address(self, pid: int) -> int:
        kvs = self._send("getbase", pid)
        return int(kvs.get("base", "0"), 16)

    def get_peb(self, pid: int) -> int:
        kvs = self._send("getpeb", pid)
        return int(kvs.get("peb", "0"), 16)

    def resolve_dtb(self, pid: int) -> int:
        try:
            kvs = self._send("getdtb", pid)
        except DriverError:
            return 0
        return int(kvs.get("cr3", "0"), 16)

    def get_guarded_region(self) -> int:
        try:
            kvs = self._send("guarded")
        except DriverError:
            return 0
        return int(kvs.get("addr", "0"), 16)

    def get_module_base(self, pid: int, module_name: str) -> int:
        if not module_name or len(module_name) > 256:
            raise DriverError("module_name must be 1–256 chars")
        try:
            kvs = self._send("getmodule", pid, module_name)
        except DriverError:
            return 0
        return int(kvs.get("base", "0"), 16)

    # ── Memory R/W (helper-side chunking; helper does one IPC per call,
    #    we chunk here for sizes > IPC_SLOT_DATA_SIZE). ─────────────────
    _SLOT_DATA_SIZE = 0x1000  # mirrors IPC_SLOT_DATA_SIZE in shared_memory_ipc.h

    def _ensure_cr3_primed(self, pid: int) -> None:
        if pid in self._cr3_primed:
            return
        # resolve_dtb is non-raising; if it can't resolve (process gone,
        # EAC obfuscation hits an error path) we still mark primed so we
        # don't hammer the driver every call. The caller's first read
        # will surface the underlying STATUS_IPC_ERROR.
        try:
            self.resolve_dtb(pid)
        except DriverError:
            pass
        self._cr3_primed.add(pid)

    def _do_read_chunk(self, pid: int, addr: int, size: int,
                        cr3_flag: int, timeout_s: float) -> bytes:
        kvs = self._send(
            "read", pid, f"0x{addr:X}", size, cr3_flag,
            timeout_s=timeout_s,
        )
        chunk_bytes = bytes.fromhex(kvs.get("data_hex", ""))
        if len(chunk_bytes) != size:
            raise DriverError(
                f"short read: asked for {size}, got {len(chunk_bytes)}"
            )
        return chunk_bytes

    def read_memory(self, pid: int, address: int, size: int,
                    use_cr3: bool = True, timeout_ms: int = 10_000,
                    allow_mm_fallback: bool = True) -> bytes:
        """
        Read `size` bytes from `pid`'s VA `address`. With ``use_cr3=True``
        (default), goes through the driver's physical-memory pipeline
        (bypasses EAC hooks on MmCopyVirtualMemory). If the CR3 path
        returns an error — typically because the page is paged-out and
        the physical-walk has nothing to read — falls back transparently
        to ``MmCopyVirtualMemory`` (which can fault pages in).

        Pass ``allow_mm_fallback=False`` to disable the fallback when
        you specifically need the stealth properties of the CR3 path.
        """
        if size <= 0:
            return b""
        if use_cr3:
            self._ensure_cr3_primed(pid)
        out = bytearray()
        offset = 0
        timeout_s = timeout_ms / 1000.0 + 1.0
        while offset < size:
            chunk = min(size - offset, self._SLOT_DATA_SIZE)
            addr  = address + offset
            try:
                out += self._do_read_chunk(pid, addr, chunk, 1 if use_cr3 else 0,
                                            timeout_s)
            except DriverError:
                if not (use_cr3 and allow_mm_fallback):
                    raise
                # CR3 read failed — try MmCopy which can fault paged-out
                # pages back in. This is per-chunk so a single bad page
                # doesn't take down the whole read.
                out += self._do_read_chunk(pid, addr, chunk, 0, timeout_s)
            offset += chunk
        return bytes(out)

    def _do_write_chunk(self, pid: int, addr: int, data: bytes,
                         cr3_flag: int, timeout_s: float) -> None:
        self._send(
            "write", pid, f"0x{addr:X}", data.hex(), cr3_flag,
            timeout_s=timeout_s,
        )

    def write_memory(self, pid: int, address: int, data: bytes,
                     use_cr3: bool = True, timeout_ms: int = 10_000,
                     allow_mm_fallback: bool = True) -> int:
        """
        Write `data` to `pid`'s VA `address`. Same CR3+fallback semantics
        as :meth:`read_memory`.
        """
        if not data:
            return 0
        if use_cr3:
            self._ensure_cr3_primed(pid)
        offset = 0
        total = len(data)
        timeout_s = timeout_ms / 1000.0 + 1.0
        while offset < total:
            chunk = min(total - offset, self._SLOT_DATA_SIZE)
            payload = data[offset:offset + chunk]
            addr    = address + offset
            try:
                self._do_write_chunk(pid, addr, payload, 1 if use_cr3 else 0,
                                      timeout_s)
            except DriverError:
                if not (use_cr3 and allow_mm_fallback):
                    raise
                self._do_write_chunk(pid, addr, payload, 0, timeout_s)
            offset += chunk
        return total

    # ── Typed convenience readers ──────────────────────────────────────
    def read_u8 (self, pid: int, addr: int) -> int: return self.read_memory(pid, addr, 1)[0]
    def read_u16(self, pid: int, addr: int) -> int: return int.from_bytes(self.read_memory(pid, addr, 2), 'little')
    def read_u32(self, pid: int, addr: int) -> int: return int.from_bytes(self.read_memory(pid, addr, 4), 'little')
    def read_u64(self, pid: int, addr: int) -> int: return int.from_bytes(self.read_memory(pid, addr, 8), 'little')
    def read_i32(self, pid: int, addr: int) -> int: return int.from_bytes(self.read_memory(pid, addr, 4), 'little', signed=True)
    def read_i64(self, pid: int, addr: int) -> int: return int.from_bytes(self.read_memory(pid, addr, 8), 'little', signed=True)
    def read_f32(self, pid: int, addr: int) -> float:
        return ctypes.c_float.from_buffer_copy(self.read_memory(pid, addr, 4)).value
    def read_f64(self, pid: int, addr: int) -> float:
        return ctypes.c_double.from_buffer_copy(self.read_memory(pid, addr, 8)).value

    def read_cstring(self, pid: int, addr: int, max_len: int = 256,
                     use_cr3: bool = True) -> str:
        raw = self.read_memory(pid, addr, max_len, use_cr3=use_cr3)
        nul = raw.find(b'\x00')
        if nul >= 0:
            raw = raw[:nul]
        return raw.decode('utf-8', errors='replace')

    def read_wstring(self, pid: int, addr: int, max_chars: int = 256,
                     use_cr3: bool = True) -> str:
        raw = self.read_memory(pid, addr, max_chars * 2, use_cr3=use_cr3)
        end = -1
        for i in range(0, len(raw) - 1, 2):
            if raw[i] == 0 and raw[i + 1] == 0:
                end = i
                break
        if end >= 0:
            raw = raw[:end]
        return raw.decode('utf-16-le', errors='replace')

    # ── Pattern scanning (chunked, Python-side) ────────────────────────
    def scan_memory(self, pid: int, start_addr: int, region_size: int,
                    pattern: bytes, mask: Optional[bytes] = None,
                    use_cr3: bool = True, max_matches: int = 64,
                    chunk_size: int = 64 * 1024) -> list[int]:
        if not pattern:
            return []
        if mask is not None and len(mask) != len(pattern):
            raise DriverError("mask length must match pattern length")

        plen = len(pattern)
        results: list[int] = []
        offset = 0
        overlap = plen - 1

        while offset < region_size and len(results) < max_matches:
            to_read = min(chunk_size, region_size - offset)
            try:
                buf = self.read_memory(pid, start_addr + offset, to_read,
                                       use_cr3=use_cr3)
            except DriverError:
                offset += 0x1000
                continue

            if mask is None:
                # Fast path: simple bytes search
                base = start_addr + offset
                pos = 0
                while True:
                    idx = buf.find(pattern, pos)
                    if idx < 0:
                        break
                    results.append(base + idx)
                    if len(results) >= max_matches:
                        return results
                    pos = idx + 1
            else:
                for i in range(0, len(buf) - plen + 1):
                    match = True
                    for j in range(plen):
                        if mask[j] == 0xFF and buf[i + j] != pattern[j]:
                            match = False
                            break
                    if match:
                        results.append(start_addr + offset + i)
                        if len(results) >= max_matches:
                            return results

            if offset + to_read >= region_size:
                break
            offset += max(1, to_read - overlap)
        return results
