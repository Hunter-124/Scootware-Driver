"""
hunting.py
==========

Pointer-offset and value-hunting primitives — the core workflow for
finding stable base+offset chains to interesting values (health,
ammo, currency, etc.) the way Cheat Engine does it:

  1. Scan all of process memory for a known value.
  2. Take an action that changes the value (take damage, etc.).
  3. Filter the previous candidate set by the new value.
  4. Repeat until ~1 address survives.
  5. Walk back: find pointers that point to that address, then
     pointers that point to *those* addresses, until you reach a static
     pointer in a module's .data/.rdata.

Tools provided here:

  * :class:`ValueScanner` — stateful, typed value scanner with filter
    operators (eq/ne/changed/increased/decreased/...).
  * :class:`PointerHunter` — find every 8-byte pointer in a region
    pointing to (or within ``tolerance`` of) a target VA.
  * :class:`SnapshotStore` — named byte snapshots with diff-vs-live
    and diff-vs-snapshot.
  * :class:`XrefFinder` — find code that references a VA via
    RIP-relative addressing or direct call/jmp targets.

All of these read through the existing CR3 R/W pipeline. No new
syscalls, no handles on the target.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .driver import DriverClient, DriverError


# ─── Value scanning ────────────────────────────────────────────────────
# (size_in_bytes, struct format) for every supported scalar type.
_TYPE_INFO: dict[str, tuple[int, str]] = {
    'u8':  (1, '<B'),
    'u16': (2, '<H'),
    'u32': (4, '<I'),
    'u64': (8, '<Q'),
    'i8':  (1, '<b'),
    'i16': (2, '<h'),
    'i32': (4, '<i'),
    'i64': (8, '<q'),
    'f32': (4, '<f'),
    'f64': (8, '<d'),
}


def type_size(name: str) -> int:
    return _TYPE_INFO[name][0]


def pack_value(value: Any, type_name: str) -> bytes:
    sz, fmt = _TYPE_INFO[type_name]
    if type_name in ('f32', 'f64'):
        return struct.pack(fmt, float(value))
    return struct.pack(fmt, int(value))


def unpack_value(raw: bytes, type_name: str) -> Any:
    _, fmt = _TYPE_INFO[type_name]
    return struct.unpack(fmt, raw)[0]


@dataclass
class ScanCandidate:
    address:    int
    last_value: Any


@dataclass
class ValueScan:
    scan_id:     str
    pid:         int
    type_name:   str
    region_start: int
    region_size:  int
    candidates:  list[ScanCandidate] = field(default_factory=list)
    history:     list[str]           = field(default_factory=list)
    when:        str                 = ""


class ValueScanner:
    """
    Stateful Cheat-Engine-style scanner. Create a scan with an initial
    value; filter against subsequent values to narrow down to one or
    a few candidate addresses.

    Filter operations:

      ``eq``         — value equals ``value``
      ``ne``         — value not equal ``value``
      ``gt``         — value greater than ``value``
      ``lt``         — value less than ``value``
      ``changed``    — value changed since last filter / new
      ``unchanged``  — value unchanged
      ``increased``  — value greater than last seen
      ``decreased``  — value less than last seen
      ``range``      — value in [``value``, ``value2``]
    """

    def __init__(self, client: DriverClient):
        self._c = client
        self._scans: dict[str, ValueScan] = {}
        self._next_id = 0

    # ── New scan ───────────────────────────────────────────────────────
    def new_scan(self, pid: int, value: Any, type_name: str,
                 region_start: int, region_size: int,
                 alignment: Optional[int] = None,
                 max_candidates: int = 1_000_000,
                 use_cr3: bool = True) -> ValueScan:
        if type_name not in _TYPE_INFO:
            raise ValueError(
                f"unknown type {type_name!r}; supported: {sorted(_TYPE_INFO)}"
            )
        sz = type_size(type_name)
        if alignment is None:
            alignment = sz
        pattern = pack_value(value, type_name)
        hits = self._c.scan_memory(
            pid, region_start, region_size, pattern, mask=None,
            max_matches=max_candidates, use_cr3=use_cr3)
        # Honor the requested alignment (driver scan_memory finds at any offset)
        hits = [h for h in hits if h % alignment == 0]
        candidates = [ScanCandidate(address=h, last_value=value) for h in hits]

        scan_id = f"scan{self._next_id}"
        self._next_id += 1
        scan = ValueScan(
            scan_id=scan_id, pid=pid, type_name=type_name,
            region_start=region_start, region_size=region_size,
            candidates=candidates,
            history=[f"new value={value} → {len(candidates)} hits"],
            when=datetime.now().isoformat(timespec='seconds'))
        self._scans[scan_id] = scan
        return scan

    # ── Filter ─────────────────────────────────────────────────────────
    def filter(self, scan_id: str, op: str, value: Any = None,
               value2: Any = None, use_cr3: bool = True) -> ValueScan:
        scan = self._scans.get(scan_id)
        if not scan:
            raise KeyError(f"unknown scan {scan_id!r}")

        sz = type_size(scan.type_name)
        _, fmt = _TYPE_INFO[scan.type_name]

        def cmp_(cur: Any, prev: Any) -> bool:
            if op == 'eq':         return cur == value
            if op == 'ne':         return cur != value
            if op == 'gt':         return cur >  value
            if op == 'lt':         return cur <  value
            if op == 'changed':    return cur != prev
            if op == 'unchanged':  return cur == prev
            if op == 'increased':  return cur >  prev
            if op == 'decreased':  return cur <  prev
            if op == 'range':
                if value is None or value2 is None:
                    raise ValueError("range needs value and value2")
                lo, hi = (value, value2) if value <= value2 else (value2, value)
                return lo <= cur <= hi
            raise ValueError(f"unknown filter op {op!r}")

        kept: list[ScanCandidate] = []
        for c in scan.candidates:
            try:
                raw = self._c.read_memory(scan.pid, c.address, sz, use_cr3=use_cr3)
                cur = struct.unpack(fmt, raw)[0]
            except DriverError:
                continue
            if cmp_(cur, c.last_value):
                c.last_value = cur
                kept.append(c)

        scan.candidates = kept
        descr = f"{op}"
        if value is not None: descr += f" value={value}"
        if value2 is not None: descr += f"..{value2}"
        scan.history.append(f"{descr} → {len(kept)} remain")
        return scan

    # ── Inspection ────────────────────────────────────────────────────
    def list_candidates(self, scan_id: str,
                         limit: int = 64) -> list[ScanCandidate]:
        scan = self._scans.get(scan_id)
        if not scan:
            raise KeyError(scan_id)
        return scan.candidates[:limit]

    def refresh_values(self, scan_id: str, limit: int = 64,
                        use_cr3: bool = True) -> list[ScanCandidate]:
        """Re-read current values for the first ``limit`` candidates."""
        scan = self._scans.get(scan_id)
        if not scan:
            raise KeyError(scan_id)
        sz = type_size(scan.type_name)
        _, fmt = _TYPE_INFO[scan.type_name]
        out = []
        for c in scan.candidates[:limit]:
            try:
                raw = self._c.read_memory(scan.pid, c.address, sz, use_cr3=use_cr3)
                c.last_value = struct.unpack(fmt, raw)[0]
            except DriverError:
                pass
            out.append(c)
        return out

    def get_scan(self, scan_id: str) -> ValueScan:
        scan = self._scans.get(scan_id)
        if not scan:
            raise KeyError(scan_id)
        return scan

    def delete(self, scan_id: str) -> bool:
        return self._scans.pop(scan_id, None) is not None

    def list_scans(self) -> list[ValueScan]:
        return list(self._scans.values())


# ─── Pointer hunter ────────────────────────────────────────────────────
@dataclass
class PointerHit:
    address:        int   # where the pointer lives
    pointer_value:  int   # what the pointer points to
    delta:          int   # pointer_value - target_va (for tolerance hits)


class PointerHunter:
    """
    Find every 8-byte aligned ``uint64`` in a memory region equal to
    (or within ``tolerance`` of) a target VA. Use repeatedly to walk
    pointer chains backward from a known leaf address up to module-
    relative bases.
    """

    def __init__(self, client: DriverClient):
        self._c = client

    def find_pointers_to(self, pid: int, scan_start: int, scan_size: int,
                          target_va: int, tolerance: int = 0,
                          alignment: int = 8,
                          max_results: int = 1024,
                          chunk_size: int = 64 * 1024,
                          use_cr3: bool = True) -> list[PointerHit]:
        if alignment not in (4, 8):
            raise ValueError("alignment must be 4 or 8")
        if tolerance < 0:
            raise ValueError("tolerance must be >= 0")

        results: list[PointerHit] = []
        offset = 0
        # Overlap so a pointer straddling a chunk boundary isn't missed
        # (with 8-byte values we just need ≥ 8 bytes overlap).
        overlap = 8

        while offset < scan_size and len(results) < max_results:
            to_read = min(chunk_size, scan_size - offset)
            try:
                buf = self._c.read_memory(pid, scan_start + offset, to_read,
                                          use_cr3=use_cr3)
            except DriverError:
                # Hit an unmapped page — skip ahead a page and continue
                offset += 0x1000
                continue
            n = (len(buf) // 8) * 8
            for i in range(0, n, 8):
                v = struct.unpack_from('<Q', buf, i)[0]
                addr = scan_start + offset + i
                if addr % alignment:
                    continue
                if v == target_va:
                    results.append(PointerHit(address=addr,
                                              pointer_value=v, delta=0))
                elif tolerance > 0 and target_va <= v <= target_va + tolerance:
                    results.append(PointerHit(address=addr,
                                              pointer_value=v,
                                              delta=v - target_va))
                if len(results) >= max_results:
                    return results
            if offset + to_read >= scan_size:
                break
            offset += max(1, to_read - overlap)
        return results


# ─── Snapshot store ────────────────────────────────────────────────────
@dataclass
class Snapshot:
    label:    str
    pid:      int
    address:  int
    data:     bytes
    when:     str

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class DiffRecord:
    offset:   int     # byte offset from snapshot's base
    address:  int     # absolute VA
    old:      int
    new:      int


class SnapshotStore:
    """Named byte snapshots with size cap (default 1 MiB each, 64 MiB total)."""

    def __init__(self, client: DriverClient,
                 per_snapshot_cap: int = 1 << 20,
                 total_cap: int = 64 << 20):
        self._c = client
        self._snaps: dict[str, Snapshot] = {}
        self._per_cap = per_snapshot_cap
        self._total_cap = total_cap

    @property
    def total_bytes(self) -> int:
        return sum(s.size for s in self._snaps.values())

    def save(self, label: str, pid: int, address: int, size: int,
             use_cr3: bool = True) -> Snapshot:
        if not label:
            raise ValueError("label required")
        if label in self._snaps:
            raise ValueError(f"snapshot {label!r} already exists")
        if size <= 0 or size > self._per_cap:
            raise ValueError(
                f"size must be in (0, {self._per_cap}] bytes; got {size}"
            )
        if self.total_bytes + size > self._total_cap:
            raise ValueError(
                f"snapshot store full ({self.total_bytes}/{self._total_cap} bytes); "
                f"delete some first"
            )
        data = self._c.read_memory(pid, address, size, use_cr3=use_cr3)
        snap = Snapshot(label=label, pid=pid, address=address, data=bytes(data),
                       when=datetime.now().isoformat(timespec='seconds'))
        self._snaps[label] = snap
        return snap

    def get(self, label: str) -> Optional[Snapshot]:
        return self._snaps.get(label)

    def delete(self, label: str) -> bool:
        return self._snaps.pop(label, None) is not None

    def list(self) -> list[Snapshot]:
        return list(self._snaps.values())

    def diff_live(self, label: str, max_records: int = 256,
                  use_cr3: bool = True) -> list[DiffRecord]:
        snap = self._snaps.get(label)
        if not snap:
            raise KeyError(label)
        cur = self._c.read_memory(snap.pid, snap.address, len(snap.data),
                                   use_cr3=use_cr3)
        return self._diff(snap.address, snap.data, cur, max_records)

    def diff(self, label_a: str, label_b: str,
             max_records: int = 256) -> list[DiffRecord]:
        a = self._snaps.get(label_a)
        b = self._snaps.get(label_b)
        if not a or not b:
            missing = label_a if not a else label_b
            raise KeyError(f"snapshot {missing!r} not found")
        if a.address != b.address or len(a.data) != len(b.data):
            raise ValueError(
                "snapshots have different base/size — diff requires same shape"
            )
        return self._diff(a.address, a.data, b.data, max_records)

    @staticmethod
    def _diff(base: int, a: bytes, b: bytes,
              max_records: int) -> list[DiffRecord]:
        out: list[DiffRecord] = []
        for i in range(min(len(a), len(b))):
            if a[i] != b[i]:
                out.append(DiffRecord(
                    offset=i, address=base + i, old=a[i], new=b[i]))
                if len(out) >= max_records:
                    break
        return out


# ─── Xref finder (RIP-relative + direct call/jmp) ──────────────────────
@dataclass
class XrefHit:
    address:   int
    mnemonic:  str
    op_str:    str
    kind:      str   # 'rip-rel-mem' | 'call-imm' | 'jmp-imm' | 'lea-rip-rel'
    insn_size: int


class XrefFinder:
    """
    Find code that references a VA. Two reference classes detected:

      * RIP-relative memory operands: ``mov reg, [rip+disp]``,
        ``lea reg, [rip+disp]``, ``call qword ptr [rip+disp]``, etc.
        Target = ``insn_end + disp32_signed``.
      * Direct call/jmp immediates: ``call rel32``, ``jmp rel32``, the
        short jumps too. Target = ``insn_end + imm_signed``.

    Uses Capstone in detail mode; slower than blind pattern scans, but
    no false positives.
    """

    def __init__(self, client: DriverClient):
        self._c = client

    def find_xrefs(self, pid: int, target_va: int,
                   scan_start: int, scan_size: int,
                   mode: str = "x64",
                   max_results: int = 64,
                   chunk_size: int = 64 * 1024,
                   use_cr3: bool = True) -> list[XrefHit]:
        try:
            import capstone
            from capstone import x86 as cs_x86
        except ImportError as e:
            raise RuntimeError(
                "capstone is required for xref scanning; pip install capstone"
            ) from e

        if mode == "x64":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            rip_reg = cs_x86.X86_REG_RIP
        elif mode == "x86":
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            rip_reg = cs_x86.X86_REG_EIP
        else:
            raise ValueError("mode must be 'x64' or 'x86'")
        md.detail = True

        # Mnemonics that take an absolute target in their imm operand
        # (capstone gives us the resolved absolute address in op.imm).
        CONTROL_MNEMONICS = {
            'call', 'jmp',
            'je', 'jne', 'jz', 'jnz', 'js', 'jns',
            'ja', 'jae', 'jb', 'jbe',
            'jg', 'jge', 'jl', 'jle',
            'jo', 'jno', 'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz',
            'loop', 'loope', 'loopne',
        }

        results: list[XrefHit] = []
        offset = 0
        overlap = 16  # max instr length on x86

        while offset < scan_size and len(results) < max_results:
            to_read = min(chunk_size, scan_size - offset)
            try:
                code = self._c.read_memory(pid, scan_start + offset, to_read,
                                            use_cr3=use_cr3)
            except DriverError:
                offset += 0x1000   # skip an unmapped page
                continue

            for insn in md.disasm(code, scan_start + offset):
                for op in insn.operands:
                    if op.type == cs_x86.X86_OP_IMM:
                        # Direct call/jmp/jcc — capstone already resolved
                        # the target to an absolute address.
                        if insn.mnemonic in CONTROL_MNEMONICS and op.imm == target_va:
                            kind = 'call-imm' if insn.mnemonic == 'call' else 'jmp-imm'
                            results.append(XrefHit(
                                address=insn.address, mnemonic=insn.mnemonic,
                                op_str=insn.op_str, kind=kind,
                                insn_size=insn.size))
                            break
                    elif op.type == cs_x86.X86_OP_MEM:
                        m = op.mem
                        if m.base == rip_reg and m.index == 0:
                            # RIP-relative: target = end_of_insn + disp32
                            tgt = insn.address + insn.size + m.disp
                            if tgt == target_va:
                                kind = ('lea-rip-rel'
                                        if insn.mnemonic == 'lea'
                                        else 'rip-rel-mem')
                                results.append(XrefHit(
                                    address=insn.address, mnemonic=insn.mnemonic,
                                    op_str=insn.op_str, kind=kind,
                                    insn_size=insn.size))
                                break
                if len(results) >= max_results:
                    break

            if offset + to_read >= scan_size:
                break
            offset += max(1, to_read - overlap)

        return results
