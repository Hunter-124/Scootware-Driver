"""
analysis.py
===========

Higher-level dynamic-analysis primitives built on top of the CR3 R/W
pipeline. None of these tools open a handle on the target, none of them
touch the debug API (DbgUi, DebugActiveProcess, NtCreateDebugObject) and
none of them poke hardware debug registers / TF flag / page guards.
Every observation goes through ``DriverClient.read_memory`` and every
mutation through ``DriverClient.write_memory``. As long as those don't
trip detection (the whole point of the CR3 bypass), nothing here will.

What you get:
  * :class:`ModuleWalker` — enumerate loaded DLLs via PEB->Ldr.
  * :class:`PointerChain` — follow a base+offsets pointer chain.
  * :class:`StringFinder` — find ASCII / UTF-16LE strings in a region.
  * :class:`MemoryWatcher` — poll a VA for changes and report diffs.
  * :class:`PatchRegistry` — write bytes with named undo records.
  * :class:`MemoryProbe` — heuristic memory map by sparse-page probing.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable, Optional

from .driver import DriverClient, DriverError


# ─── Module enumeration ────────────────────────────────────────────────
# x64 PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY offsets are stable across
# Windows versions for the fields we read (DllBase, SizeOfImage,
# BaseDllName). If MS ever reshuffles, fix here.
_PEB_LDR_OFFSET                 = 0x18  # PEB.Ldr
_LDR_IN_LOAD_ORDER_LIST_OFFSET  = 0x10  # PEB_LDR_DATA.InLoadOrderModuleList
_LDE_DLL_BASE_OFFSET            = 0x30  # LDR_DATA_TABLE_ENTRY.DllBase
_LDE_ENTRY_POINT_OFFSET         = 0x38  # LDR_DATA_TABLE_ENTRY.EntryPoint
_LDE_SIZE_OF_IMAGE_OFFSET       = 0x40  # LDR_DATA_TABLE_ENTRY.SizeOfImage
_LDE_FULL_DLL_NAME_OFFSET       = 0x48  # UNICODE_STRING
_LDE_BASE_DLL_NAME_OFFSET       = 0x58  # UNICODE_STRING


@dataclass
class LoadedModule:
    base:         int
    entry_point:  int
    size:         int
    name:         str
    full_path:    str

    @property
    def end(self) -> int:
        return self.base + self.size


class ModuleWalker:
    """Walk PEB->Ldr->InLoadOrderModuleList. PEB is obtained via the driver."""

    def __init__(self, client: DriverClient):
        self._c = client

    def list_modules(self, pid: int, peb: Optional[int] = None,
                     max_modules: int = 4096) -> list[LoadedModule]:
        if peb is None:
            peb = self._c.get_peb(pid)
        if not peb:
            raise DriverError(f"Could not resolve PEB for pid={pid}")

        ldr = self._c.read_u64(pid, peb + _PEB_LDR_OFFSET)
        if not ldr:
            raise DriverError(f"PEB.Ldr is NULL for pid={pid} (process still init'ing?)")

        # LIST_ENTRY at PEB_LDR_DATA + InLoadOrderModuleList — its Flink
        # points at the first LDR_DATA_TABLE_ENTRY's InLoadOrderLinks
        # field, which is at offset 0 of the entry, so we can treat it
        # as the entry address directly.
        head_addr  = ldr + _LDR_IN_LOAD_ORDER_LIST_OFFSET
        first_link = self._c.read_u64(pid, head_addr)
        if not first_link or first_link == head_addr:
            return []  # Empty list

        out: list[LoadedModule] = []
        current = first_link
        for _ in range(max_modules):
            if current == head_addr or current == 0:
                break
            try:
                module = self._read_entry(pid, current)
                if module.base != 0 and module.size != 0:
                    out.append(module)
            except DriverError:
                break
            # Flink lives at offset 0
            current = self._c.read_u64(pid, current)
        return out

    def _read_entry(self, pid: int, entry_va: int) -> LoadedModule:
        base = self._c.read_u64(pid, entry_va + _LDE_DLL_BASE_OFFSET)
        ep   = self._c.read_u64(pid, entry_va + _LDE_ENTRY_POINT_OFFSET)
        size = self._c.read_u32(pid, entry_va + _LDE_SIZE_OF_IMAGE_OFFSET)
        full = self._read_unicode_string(pid, entry_va + _LDE_FULL_DLL_NAME_OFFSET)
        name = self._read_unicode_string(pid, entry_va + _LDE_BASE_DLL_NAME_OFFSET)
        return LoadedModule(base=base, entry_point=ep, size=size,
                            name=name, full_path=full)

    def _read_unicode_string(self, pid: int, addr: int) -> str:
        # UNICODE_STRING (x64) = USHORT Length, USHORT MaxLength, ULONG pad, PVOID Buffer
        hdr = self._c.read_memory(pid, addr, 16)
        length = struct.unpack_from('<H', hdr, 0)[0]
        buf    = struct.unpack_from('<Q', hdr, 8)[0]
        if not buf or not length:
            return ""
        if length > 1024:  # sane upper bound
            length = 1024
        raw = self._c.read_memory(pid, buf, length)
        return raw.decode('utf-16-le', errors='replace')

    def find_module(self, pid: int, name: str) -> Optional[LoadedModule]:
        """Case-insensitive name lookup. Matches base or full DLL name."""
        target = name.lower()
        for m in self.list_modules(pid):
            if m.name.lower() == target or m.full_path.lower().endswith("\\" + target):
                return m
        return None


# ─── Pointer chains ────────────────────────────────────────────────────
@dataclass
class PointerChainResult:
    final_address:  int
    steps:          list[int]    # each intermediate VA after dereference + offset
    raw_dereferences: list[int]  # dereferenced QWORDs at each step


class PointerChain:
    """
    Resolve a Cheat-Engine style pointer chain:

        ptr0 = base + offsets[0]
        ptr1 = read_u64(ptr0)
        ptr2 = read_u64(ptr1) + offsets[1]
        ...
        final = ptr_{n-1} + offsets[n-1]

    The first offset is added without a dereference; every subsequent
    offset is added after one dereference. The final value is returned
    as the address (not dereferenced).
    """

    def __init__(self, client: DriverClient):
        self._c = client

    def follow(self, pid: int, base: int, offsets: list[int]) -> PointerChainResult:
        if not offsets:
            return PointerChainResult(final_address=base, steps=[base],
                                       raw_dereferences=[])

        steps: list[int] = []
        derefs: list[int] = []
        cur = base + offsets[0]
        steps.append(cur)
        for off in offsets[1:]:
            v = self._c.read_u64(pid, cur)
            derefs.append(v)
            if v == 0:
                raise DriverError(
                    f"NULL pointer dereferenced at step {len(steps)} "
                    f"(addr=0x{cur:X}, offsets so far={offsets[:len(steps)]})"
                )
            cur = v + off
            steps.append(cur)
        return PointerChainResult(final_address=cur, steps=steps,
                                   raw_dereferences=derefs)


# ─── String search ─────────────────────────────────────────────────────
@dataclass
class StringHit:
    address:   int
    text:      str
    encoding:  str  # 'ascii' or 'utf16le'


class StringFinder:
    """
    Scan a VA range for printable strings. Looks for both ASCII (single-
    byte, ``[0x20, 0x7E]`` + tabs/newlines) and UTF-16LE (every other
    byte is 0 with printable ASCII).
    """

    _PRINTABLE = bytes(range(0x20, 0x7F)) + b'\t\n\r'

    def __init__(self, client: DriverClient):
        self._c = client

    def find(self, pid: int, start: int, region_size: int,
             min_length: int = 6,
             encodings: tuple[str, ...] = ('ascii', 'utf16le'),
             max_hits: int = 256,
             chunk_size: int = 64 * 1024) -> list[StringHit]:
        hits: list[StringHit] = []
        offset = 0
        # We overlap chunks so a string straddling a boundary isn't lost.
        # 4 KiB overlap > any reasonable string we want.
        overlap = max(min_length * 2, 4096)
        printable = set(self._PRINTABLE)

        while offset < region_size and len(hits) < max_hits:
            n = min(chunk_size, region_size - offset)
            buf = self._c.read_memory(pid, start + offset, n)

            if 'ascii' in encodings:
                self._scan_ascii(buf, start + offset, min_length, printable, hits, max_hits)
                if len(hits) >= max_hits:
                    break
            if 'utf16le' in encodings:
                self._scan_utf16(buf, start + offset, min_length, printable, hits, max_hits)
                if len(hits) >= max_hits:
                    break

            if offset + n >= region_size:
                break
            offset += max(1, n - overlap)
        return hits

    @staticmethod
    def _scan_ascii(buf: bytes, base: int, min_len: int,
                    printable: set[int], hits: list[StringHit],
                    max_hits: int) -> None:
        i = 0
        n = len(buf)
        while i < n and len(hits) < max_hits:
            if buf[i] in printable:
                j = i + 1
                while j < n and buf[j] in printable:
                    j += 1
                if j - i >= min_len:
                    hits.append(StringHit(
                        address=base + i,
                        text=buf[i:j].decode('ascii', errors='replace'),
                        encoding='ascii'))
                i = j
            else:
                i += 1

    @staticmethod
    def _scan_utf16(buf: bytes, base: int, min_len: int,
                     printable: set[int], hits: list[StringHit],
                     max_hits: int) -> None:
        # UTF-16LE printable runs: every other byte is 0 and the
        # interleaving byte is printable ASCII.
        i = 0
        n = len(buf) & ~1   # round down to even
        while i < n - 1 and len(hits) < max_hits:
            if buf[i] in printable and buf[i + 1] == 0:
                j = i + 2
                while j < n - 1 and buf[j] in printable and buf[j + 1] == 0:
                    j += 2
                char_count = (j - i) // 2
                if char_count >= min_len:
                    hits.append(StringHit(
                        address=base + i,
                        text=buf[i:j].decode('utf-16-le', errors='replace'),
                        encoding='utf16le'))
                i = j
            else:
                i += 2


# ─── Memory watch ──────────────────────────────────────────────────────
@dataclass
class MemoryWatchEvent:
    elapsed_ms:   float
    timestamp:    str
    old_hex:      str
    new_hex:      str
    byte_diffs:   list[tuple[int, int, int]]   # (offset, old_byte, new_byte)


@dataclass
class MemoryWatchResult:
    pid:               int
    address:           int
    size:              int
    duration_seconds:  float
    poll_interval_ms:  int
    poll_count:        int
    events:            list[MemoryWatchEvent]
    final_hex:         str


class MemoryWatcher:
    """
    Poll a memory region at fixed intervals and record every observed
    change. This is the read-side equivalent of a data breakpoint —
    without hardware DR registers and without any debug API contact.
    """

    def __init__(self, client: DriverClient):
        self._c = client

    def watch(self, pid: int, address: int, size: int,
              duration_seconds: float = 5.0,
              poll_interval_ms: int = 50,
              max_events: int = 256,
              use_cr3: bool = True) -> MemoryWatchResult:
        if size <= 0 or size > 4096:
            raise ValueError("watch size must be in (0, 4096] bytes")
        if duration_seconds <= 0 or duration_seconds > 600:
            raise ValueError("duration_seconds must be in (0, 600]")
        if poll_interval_ms < 1 or poll_interval_ms > 60000:
            raise ValueError("poll_interval_ms must be in [1, 60000]")

        prev = self._c.read_memory(pid, address, size, use_cr3=use_cr3)
        start = time.monotonic()
        end   = start + duration_seconds
        events: list[MemoryWatchEvent] = []
        polls = 1

        while time.monotonic() < end and len(events) < max_events:
            time.sleep(poll_interval_ms / 1000.0)
            try:
                cur = self._c.read_memory(pid, address, size, use_cr3=use_cr3)
            except DriverError:
                # Process may have died or the page unmapped; record and stop
                break
            polls += 1
            if cur != prev:
                diffs = [(i, prev[i], cur[i])
                         for i in range(len(prev)) if prev[i] != cur[i]]
                events.append(MemoryWatchEvent(
                    elapsed_ms=(time.monotonic() - start) * 1000.0,
                    timestamp=datetime.now().isoformat(timespec='milliseconds'),
                    old_hex=prev.hex(),
                    new_hex=cur.hex(),
                    byte_diffs=diffs))
                prev = cur

        return MemoryWatchResult(
            pid=pid, address=address, size=size,
            duration_seconds=duration_seconds,
            poll_interval_ms=poll_interval_ms,
            poll_count=polls, events=events,
            final_hex=prev.hex())


# ─── Patch registry ────────────────────────────────────────────────────
@dataclass
class PatchRecord:
    name:        str
    pid:         int
    address:     int
    original:    bytes
    patched:     bytes
    timestamp:   str

    def as_dict(self) -> dict:
        return {
            'name':     self.name,
            'pid':      self.pid,
            'address':  f"0x{self.address:X}",
            'size':     len(self.patched),
            'original': self.original.hex(),
            'patched':  self.patched.hex(),
            'when':     self.timestamp,
        }


class PatchRegistry:
    """Named write-and-undo records. Backed by ``DriverClient.write_memory``."""

    def __init__(self, client: DriverClient):
        self._c = client
        self._patches: dict[str, PatchRecord] = {}

    def patch(self, pid: int, address: int, new_bytes: bytes,
              name: str, use_cr3: bool = True) -> PatchRecord:
        if not name:
            raise ValueError("patch name is required (used for restore lookup)")
        if name in self._patches:
            raise ValueError(
                f"a patch named {name!r} already exists — restore or "
                f"choose a different name"
            )
        if not new_bytes:
            raise ValueError("patch bytes are empty")
        if len(new_bytes) > 65536:
            raise ValueError("patch capped at 64 KiB")

        original = self._c.read_memory(pid, address, len(new_bytes), use_cr3=use_cr3)
        self._c.write_memory(pid, address, new_bytes, use_cr3=use_cr3)
        rec = PatchRecord(
            name=name, pid=pid, address=address,
            original=original, patched=bytes(new_bytes),
            timestamp=datetime.now().isoformat(timespec='seconds'))
        self._patches[name] = rec
        return rec

    def nop(self, pid: int, address: int, size: int,
            name: str, use_cr3: bool = True) -> PatchRecord:
        return self.patch(pid, address, b'\x90' * size, name, use_cr3=use_cr3)

    def restore(self, name: str, use_cr3: bool = True) -> PatchRecord:
        rec = self._patches.pop(name, None)
        if not rec:
            raise KeyError(f"no patch named {name!r}")
        self._c.write_memory(rec.pid, rec.address, rec.original, use_cr3=use_cr3)
        return rec

    def restore_all(self, use_cr3: bool = True) -> list[PatchRecord]:
        restored: list[PatchRecord] = []
        for name in list(self._patches.keys()):
            try:
                restored.append(self.restore(name, use_cr3=use_cr3))
            except DriverError:
                continue
        return restored

    def list(self) -> list[PatchRecord]:
        return list(self._patches.values())

    def get(self, name: str) -> Optional[PatchRecord]:
        return self._patches.get(name)


# ─── Memory probe (heuristic memory map) ───────────────────────────────
@dataclass
class MappedRange:
    start:  int
    end:    int
    pages:  int

    @property
    def size(self) -> int:
        return self.end - self.start


class MemoryProbe:
    """
    Build a heuristic memory map by probing the first byte of each page
    in a range. Mapped → read succeeds, unmapped → driver returns ERROR.

    Cheaper alternative to VirtualQueryEx (which would need a handle on
    the target). At 4 KiB step, ~1000 probes per second through the
    driver pipeline.
    """

    def __init__(self, client: DriverClient):
        self._c = client

    def probe(self, pid: int, start: int, end: int,
              step: int = 4096, max_probes: int = 8192,
              use_cr3: bool = True) -> list[MappedRange]:
        if end <= start:
            raise ValueError("end must be > start")
        if step <= 0:
            raise ValueError("step must be > 0")
        probes_needed = (end - start + step - 1) // step
        if probes_needed > max_probes:
            raise ValueError(
                f"would need {probes_needed} probes, capped at {max_probes}. "
                f"Narrow the range or raise step."
            )

        ranges: list[MappedRange] = []
        cur_start: Optional[int] = None
        addr = start
        while addr < end:
            try:
                self._c.read_memory(pid, addr, 1, use_cr3=use_cr3)
                mapped = True
            except DriverError:
                mapped = False

            if mapped:
                if cur_start is None:
                    cur_start = addr
            else:
                if cur_start is not None:
                    ranges.append(MappedRange(
                        start=cur_start, end=addr,
                        pages=(addr - cur_start) // step))
                    cur_start = None
            addr += step

        if cur_start is not None:
            ranges.append(MappedRange(
                start=cur_start, end=end,
                pages=(end - cur_start) // step))
        return ranges
