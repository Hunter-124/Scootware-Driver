"""
server.py
=========

MCP server entry point. Exposes the driver as a set of tools the agent
can call: process discovery, module/base/PEB resolution, raw memory R/W,
hex dumps, and pattern scanning.

All addresses accept hex strings (``"0x7ff8aabb..."``) or decimal ints.
"""

from __future__ import annotations

import atexit
import binascii
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from . import disasm, ipc, threads as thread_enum, win32
from .analysis import (
    MemoryProbe, MemoryWatcher, ModuleWalker, PatchRegistry,
    PointerChain, StringFinder,
)
from .driver import DriverClient, DriverError
from .hunting import (
    PointerHunter, SnapshotStore, ValueScanner, XrefFinder,
    pack_value, type_size,
)
from .pe import PEParser, directory_name
from .session import Session, SessionConfig
from .suspend import ProcessFreezer

# ─── Setup logging to stderr (stdio is owned by MCP JSON-RPC) ──────────
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="[%(asctime)s %(levelname)s %(name)s] %(message)s",
)
log = logging.getLogger("drv_mcp")


# ─── Resolve helper path ───────────────────────────────────────────────
PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
HELPER_PATH  = Path(
    os.environ.get(
        "SCOOTWARE_HELPER_PATH",
        str(PROJECT_ROOT / "helper" / "scootware.exe"),
    )
)


# ─── Construct the singleton Session ───────────────────────────────────
_SESSION: Optional[Session] = None


def _build_session() -> Session:
    cfg = SessionConfig(
        helper_path=HELPER_PATH,
        kill_existing=True,
    )
    return Session(cfg)


def _get_session() -> Session:
    """
    Lazy-init: we start the session on the first tool call so the MCP
    server can be loaded by Claude Code even when the driver isn't ready
    yet. If `start()` fails we surface a clear error.
    """
    global _SESSION
    if _SESSION is None:
        _SESSION = _build_session()
        _SESSION.start()
        atexit.register(_safe_stop)
    return _SESSION


# ─── Per-session analysis helpers (created lazily, share one DriverClient) ─
_PATCH_REGISTRY:   Optional[PatchRegistry]   = None
_FREEZER:          Optional[ProcessFreezer]  = None
_VALUE_SCANNER:    Optional[ValueScanner]    = None
_POINTER_HUNTER:   Optional[PointerHunter]   = None
_SNAPSHOT_STORE:   Optional[SnapshotStore]   = None
_XREF_FINDER:      Optional[XrefFinder]      = None


def _client() -> DriverClient:
    return _get_session().client


def _bind(name: str, factory):
    """Lazy-bind a per-session helper; recreate if the session restarts."""
    global _PATCH_REGISTRY, _FREEZER, _VALUE_SCANNER
    global _POINTER_HUNTER, _SNAPSHOT_STORE, _XREF_FINDER
    sess_client = _client()
    table = {
        "_PATCH_REGISTRY": _PATCH_REGISTRY,
        "_FREEZER":        _FREEZER,
        "_VALUE_SCANNER":  _VALUE_SCANNER,
        "_POINTER_HUNTER": _POINTER_HUNTER,
        "_SNAPSHOT_STORE": _SNAPSHOT_STORE,
        "_XREF_FINDER":    _XREF_FINDER,
    }
    cur = table[name]
    if cur is None or cur._c is not sess_client:
        cur = factory(sess_client)
        globals()[name] = cur
    return cur


def _patch_registry() -> PatchRegistry: return _bind("_PATCH_REGISTRY", PatchRegistry)
def _freezer()        -> ProcessFreezer: return _bind("_FREEZER",       ProcessFreezer)
def _value_scanner()  -> ValueScanner:   return _bind("_VALUE_SCANNER", ValueScanner)
def _pointer_hunter() -> PointerHunter:  return _bind("_POINTER_HUNTER",PointerHunter)
def _snapshot_store() -> SnapshotStore:  return _bind("_SNAPSHOT_STORE",SnapshotStore)
def _xref_finder()    -> XrefFinder:     return _bind("_XREF_FINDER",   XrefFinder)


def _bytes_reader_for(pid: int, use_cr3: bool = True):
    """Adapter for pe.PEParser (which expects ``read(addr, size) -> bytes``)."""
    c = _client()
    return lambda addr, size: c.read_memory(pid, addr, size, use_cr3=use_cr3)


def _safe_stop() -> None:
    global _SESSION
    if _SESSION is not None:
        try:
            _SESSION.stop()
        except Exception as e:
            log.warning("session.stop() failed at exit: %s", e)
        _SESSION = None


# ─── Input parsing helpers ─────────────────────────────────────────────
def _parse_int(v) -> int:
    """Accept int, hex string ('0x...'), or decimal string."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        v = v.strip()
        if v.lower().startswith("0x"):
            return int(v, 16)
        return int(v, 0)
    raise ValueError(f"Cannot parse integer from {v!r}")


def _parse_hex_bytes(s: str) -> bytes:
    """Parse '48 8B C8' or '488BC8' or '48,8B,C8' as bytes."""
    cleaned = (
        s.replace(",", " ")
         .replace("0x", "")
         .replace("\\x", "")
         .replace(":", " ")
    )
    parts = cleaned.split()
    if parts and all(len(p) <= 2 for p in parts):
        return bytes(int(p, 16) for p in parts)
    # Fallback: contiguous hex
    return binascii.unhexlify(cleaned.replace(" ", ""))


def _fmt_hex_dump(addr: int, data: bytes, width: int = 16) -> str:
    """xxd-style hex+ASCII dump."""
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{addr + i:016X}  {hex_part}  {ascii_part}")
    return "\n".join(out)


# ─── MCP server definition ─────────────────────────────────────────────
mcp = FastMCP("scootware-driver")


# ── Session / driver state ────────────────────────────────────────────
@mcp.tool()
def driver_status() -> dict:
    """
    Report the current driver session: helper PID, IPC buffer VA, whether
    the kernel driver is answering PINGs, and the round-trip in microseconds.

    Call this first to confirm the driver is loaded and responsive.
    """
    s = _get_session().status()
    return {
        "helper_pid":      s.helper_pid,
        "helper_running":  s.helper_running,
        "ipc_va":          f"0x{s.ipc_va:X}" if s.ipc_va else None,
        "driver_attached": s.driver_attached,
        "last_ping_us":    s.last_ping_us,
        "killed_pids":     s.killed_pids,
        "helper_path":     str(HELPER_PATH),
    }


_CR3_MODE_NAMES = {
    0: "cr3_swap",         # kernel CR3 in physical::m_stored_dtb — best stealth
    1: "mdl_attach",       # KeStackAttachProcess + MDL  — KPTI fallback
    2: "expanded_stack",   # KeExpandKernelStackAndCalloutEx — last resort
}

_STEALTH_HEX_OUT_FIELDS = (
    "cave_address", "cave_module_base",
    "ret_gadget_address", "ret_gadget_module_base",
    "target_cr3", "target_base",
)


@mcp.tool()
def driver_stealth_status() -> dict:
    """
    Query the driver's current stealth parameters, including thread spoofing
    (code cave location, size, module), stack isolation (ret gadget address),
    KPTI/CR3 swap state, the resolved NtFreeVirtualMemory SSN, and the
    currently attached target process (pid + DTB + image name).

    Adds two derived fields on top of the raw driver snapshot:
      ``cr3_mode_name``  — string label for ``cr3_mode``
                            (``cr3_swap`` / ``mdl_attach`` / ``expanded_stack``).
      ``warnings``       — list of human-readable warnings when the snapshot
                            indicates a feature failed to initialize
                            (cave missing ENDBR64, SSN unresolved, etc).
    """
    res = _get_session().client.get_stealth_status()

    # Convert raw integer addresses to hex strings for human readability.
    for k in _STEALTH_HEX_OUT_FIELDS:
        if k in res and isinstance(res[k], int):
            res[k] = f"0x{res[k]:X}"

    # Label cr3_mode.
    cr3_mode = res.get("cr3_mode")
    if isinstance(cr3_mode, int):
        res["cr3_mode_name"] = _CR3_MODE_NAMES.get(cr3_mode, f"unknown({cr3_mode})")

    # Label ssn_resolution_path (matches the enum in shared_memory_ipc.h's
    # IPC_STEALTH_STATUS comment block).
    ssn_path_labels = {
        0:  "not_yet_called",
        1:  "dynamic_ntdll_stub",
        2:  "ZwQuerySystemInformation_failed",
        3:  "ExAllocatePool_failed",
        4:  "ntdll_not_in_kernel_module_list",
        5:  "ntdll_PE_walk_faulted",
        6:  "NtFreeVirtualMemory_export_missing",
        7:  "syscall_stub_pattern_mismatch",
        8:  "static_table_match",
        9:  "static_catch_all_0x1F",
        10: "RtlGetVersion_unresolved",
        # Target-process resolver paths (ResolveSSN_ViaTargetProcess)
        11: "target_process_unavailable",
        12: "PsGetProcessPeb_unresolved",
        13: "target_attach_generic_failure",
        14: "target_has_no_PEB",
        15: "target_has_no_LDR",
        16: "ntdll_not_in_target_PEB",
    }
    ssn_path = res.get("ssn_resolution_path")
    if isinstance(ssn_path, int):
        res["ssn_resolution_path_name"] = ssn_path_labels.get(
            ssn_path, f"unknown({ssn_path})"
        )

    # Build warnings list.  Each entry is a short sentence describing what
    # looks wrong; an empty list means everything checked passed.
    warnings: list[str] = []

    if not res.get("thread_spoof_active"):
        warnings.append("thread_spoof_active=0 — no code cave patched; "
                        "worker thread Win32StartAddress is in unbacked memory.")
    if not res.get("stack_isolation_active"):
        warnings.append("stack_isolation_active=0 — RET gadget not resolved; "
                        "syscall stack walks will reveal the driver.")
    if res.get("cr3_swap_capable") == 0:
        warnings.append("cr3_swap_capable=0 — kernel CR3 not stored; driver "
                        "is on a KPTI fallback path (mdl_attach/expanded_stack).")
    if res.get("ntfvm_ssn", 0) == 0 or res.get("ssn_resolved_dynamic") == 0:
        warnings.append("ntfvm_ssn unresolved — SpoofedNtFreeVirtualMemory "
                        "will fall back to ZwFreeVirtualMemory (detectable).")

    # Verify ENDBR64 prefix on the patched cave bytes.  The driver wrote
    # `F3 0F 1E FA <jmp>` — if those first four bytes are not present, the
    # patch either failed or was overwritten by something later in boot.
    patch_hex = res.get("cave_patch_bytes")
    if isinstance(patch_hex, str) and patch_hex:
        if not patch_hex.lower().startswith("f30f1efa"):
            warnings.append(
                f"cave_patch_bytes={patch_hex} — ENDBR64 prefix (F3 0F 1E FA) "
                "missing; CET-IBT CPUs will #CP on first dispatch."
            )

    if res.get("target_attached") == 0:
        warnings.append("target_attached=0 — driver has no usermode session; "
                        "memory R/W commands will all fail.")

    res["warnings"] = warnings
    return res


@mcp.tool()
def wait_for_driver(timeout_seconds: float = 30.0) -> dict:
    """
    Block until the kernel driver responds to PING (or timeout). Use this
    after loading the driver service if you want to confirm the handshake
    before issuing commands.
    """
    ok = _get_session().wait_for_driver(timeout_seconds)
    return {"attached": ok}


@mcp.tool()
def driver_shutdown() -> dict:
    """
    Send CMD_SHUTDOWN to the driver, which unloads it from the kernel.
    The helper process is also terminated and the MCP session resets.
    Subsequent tool calls will spawn a fresh helper but require the driver
    service to be loaded again.
    """
    sess = _get_session()
    try:
        ok = sess.client.shutdown()
    except DriverError as e:
        ok = False
        log.warning("shutdown returned error: %s", e)
    _safe_stop()
    return {"shutdown_sent": ok}


# ── Process enumeration ───────────────────────────────────────────────
@mcp.tool()
def list_processes(name_filter: str = "") -> list[dict]:
    """
    Enumerate running processes via Toolhelp32 (local — does not go through
    the driver). Optional substring filter on the image name.
    """
    needle = name_filter.lower()
    procs = []
    for pid, exe in win32.iter_processes():
        if not needle or needle in exe:
            procs.append({"pid": pid, "name": exe})
    return procs


@mcp.tool()
def find_pid(process_name: str, prefer_driver: bool = False) -> dict:
    """
    Find a process by image name. By default uses local Toolhelp32; set
    ``prefer_driver=True`` to use the driver's PsActiveProcessHead walk
    (useful if you suspect the process is hidden from usermode enumeration).

    Returns ``{"pid": int}`` — 0 if not found.
    """
    if prefer_driver:
        pid = _get_session().client.get_pid_by_name(process_name)
        if pid:
            return {"pid": pid, "source": "driver"}
        # Fall through to local enum if driver didn't find it
    matches = [p for p, n in win32.iter_processes()
               if n == process_name.lower()]
    if matches:
        return {"pid": matches[0], "source": "local",
                "duplicates": matches[1:] if len(matches) > 1 else None}
    return {"pid": 0, "source": "local"}


# ── Process introspection ─────────────────────────────────────────────
@mcp.tool()
def get_base_address(pid: int | str) -> dict:
    """
    Main module base address of the target process. Driver walks EPROCESS
    → SectionBaseAddress, so this works on EAC-protected processes.
    """
    pid_i = _parse_int(pid)
    addr = _get_session().client.get_base_address(pid_i)
    return {"pid": pid_i, "base_address": f"0x{addr:X}", "raw": addr}


@mcp.tool()
def get_peb(pid: int | str) -> dict:
    """
    PEB (Process Environment Block) address for the target process.
    Returns a usermode VA in the target's address space.
    """
    pid_i = _parse_int(pid)
    addr = _get_session().client.get_peb(pid_i)
    return {"pid": pid_i, "peb": f"0x{addr:X}", "raw": addr}


@mcp.tool()
def get_module_base(pid: int | str, module_name: str) -> dict:
    """
    Look up a module's load base in the target process by name (e.g.
    ``"ntdll.dll"`` or ``"kernel32.dll"``). Walks the PEB's LDR list.
    Returns 0 if the module isn't loaded.
    """
    pid_i = _parse_int(pid)
    addr = _get_session().client.get_module_base(pid_i, module_name)
    return {
        "pid": pid_i,
        "module": module_name,
        "base": f"0x{addr:X}",
        "raw": addr,
    }


@mcp.tool()
def resolve_dtb(pid: int | str) -> dict:
    """
    Resolve the CR3 / Directory Table Base for a process via the driver's
    decryption routine. Required for the use_cr3=True memory-access path
    that bypasses EAC's MmCopyVirtualMemory hooks.
    """
    pid_i = _parse_int(pid)
    cr3 = _get_session().client.resolve_dtb(pid_i)
    return {"pid": pid_i, "cr3": f"0x{cr3:X}" if cr3 else "0x0", "raw": cr3}


@mcp.tool()
def get_guarded_region() -> dict:
    """
    Return the EAC "TnoC" big-pool guarded region address (if any). Used
    for finding the EAC integrity-check region. Not bound to a process.
    """
    addr = _get_session().client.get_guarded_region()
    return {"guarded_region": f"0x{addr:X}", "raw": addr}


# ── Memory R/W ────────────────────────────────────────────────────────
@mcp.tool()
def read_memory(pid: int | str, address: int | str, size: int,
                use_cr3: bool = True) -> dict:
    """
    Read ``size`` bytes from process VA ``address``. Returns the data as
    a hex string and a UTF-8-replaced ASCII preview. For more than ~4 KiB
    consider ``dump_memory`` (returns formatted output) or split the read.

    ``use_cr3`` (default True): use the CR3/physical pipeline that
    bypasses EAC. Set False to use MmCopyVirtualMemory (more compatible).
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    if size <= 0 or size > 16 * 1024 * 1024:
        raise ValueError("size must be in (0, 16 MiB]")
    data = _get_session().client.read_memory(pid_i, addr_i, size,
                                              use_cr3=use_cr3)
    return {
        "pid": pid_i,
        "address": f"0x{addr_i:X}",
        "size": size,
        "hex": data.hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
    }


@mcp.tool()
def dump_memory(pid: int | str, address: int | str, size: int = 256,
                use_cr3: bool = True) -> str:
    """
    xxd-style hex+ASCII dump of process memory. Default 256 bytes.
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    if size <= 0 or size > 65536:
        raise ValueError("size must be in (0, 65536]")
    data = _get_session().client.read_memory(pid_i, addr_i, size,
                                              use_cr3=use_cr3)
    return _fmt_hex_dump(addr_i, data)


@mcp.tool()
def read_typed(pid: int | str, address: int | str, type_name: str,
               use_cr3: bool = True) -> dict:
    """
    Read a primitive value from process memory.

    ``type_name`` is one of:
      ``u8``, ``u16``, ``u32``, ``u64``,
      ``i32``, ``i64``,
      ``f32``, ``f64``,
      ``cstring`` (NUL-terminated ASCII/UTF-8, max 256 bytes),
      ``wstring`` (NUL-terminated UTF-16LE, max 256 chars),
      ``ptr`` (synonym for ``u64``).
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    c = _get_session().client
    t = type_name.lower()
    handlers = {
        "u8":  lambda: c.read_u8 (pid_i, addr_i),
        "u16": lambda: c.read_u16(pid_i, addr_i),
        "u32": lambda: c.read_u32(pid_i, addr_i),
        "u64": lambda: c.read_u64(pid_i, addr_i),
        "ptr": lambda: c.read_u64(pid_i, addr_i),
        "i32": lambda: c.read_i32(pid_i, addr_i),
        "i64": lambda: c.read_i64(pid_i, addr_i),
        "f32": lambda: c.read_f32(pid_i, addr_i),
        "f64": lambda: c.read_f64(pid_i, addr_i),
        "cstring": lambda: c.read_cstring(pid_i, addr_i, use_cr3=use_cr3),
        "wstring": lambda: c.read_wstring(pid_i, addr_i, use_cr3=use_cr3),
    }
    if t not in handlers:
        raise ValueError(
            f"Unknown type_name {type_name!r}. "
            f"Supported: {sorted(handlers.keys())}"
        )
    value = handlers[t]()
    result = {"pid": pid_i, "address": f"0x{addr_i:X}", "type": t, "value": value}
    if isinstance(value, int) and t != "u8":
        result["hex"] = f"0x{value & 0xFFFFFFFFFFFFFFFF:X}"
    return result


@mcp.tool()
def write_memory(pid: int | str, address: int | str, hex_data: str,
                 use_cr3: bool = True) -> dict:
    """
    Write bytes to process VA. ``hex_data`` accepts ``"48 8B C8"``,
    ``"488BC8"``, ``"48,8B,C8"`` — case-insensitive, separators optional.

    THIS IS DESTRUCTIVE. The driver does not validate ranges; writing
    over the wrong VA can crash the target. Double-check the address.
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    data = _parse_hex_bytes(hex_data)
    if not data:
        raise ValueError("hex_data is empty")
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("write capped at 16 MiB")
    n = _get_session().client.write_memory(pid_i, addr_i, data,
                                            use_cr3=use_cr3)
    return {
        "pid": pid_i,
        "address": f"0x{addr_i:X}",
        "bytes_written": n,
        "preview": data[:32].hex(),
    }


@mcp.tool()
def scan_memory(pid: int | str, start_address: int | str, region_size: int,
                pattern_hex: str, mask_hex: str = "",
                max_matches: int = 32, use_cr3: bool = True) -> dict:
    """
    Linear pattern scan in ``[start_address, start_address + region_size)``.

    ``pattern_hex``: bytes to search for, e.g. ``"48 8B 05 ?? ?? ?? ??"``.
    ``mask_hex``: optional per-byte mask. ``ff`` = match, ``00`` = wildcard.
      If empty AND pattern contains ``??``, ``??`` bytes are auto-wildcarded.

    Returns absolute VAs of matches (capped at ``max_matches``).
    """
    pid_i = _parse_int(pid)
    start = _parse_int(start_address)
    if region_size <= 0 or region_size > 256 * 1024 * 1024:
        raise ValueError("region_size must be in (0, 256 MiB]")

    # Auto-wildcards: convert "?? ?? 8B" to pattern + mask.
    if "??" in pattern_hex and not mask_hex:
        pat_bytes = bytearray()
        mask_bytes = bytearray()
        for tok in pattern_hex.replace(",", " ").split():
            if tok == "??":
                pat_bytes.append(0)
                mask_bytes.append(0)
            else:
                pat_bytes.append(int(tok, 16))
                mask_bytes.append(0xFF)
        pattern = bytes(pat_bytes)
        mask    = bytes(mask_bytes)
    else:
        pattern = _parse_hex_bytes(pattern_hex)
        mask    = _parse_hex_bytes(mask_hex) if mask_hex else None

    hits = _get_session().client.scan_memory(
        pid_i, start, region_size, pattern, mask,
        use_cr3=use_cr3, max_matches=max_matches,
    )
    return {
        "pid": pid_i,
        "start": f"0x{start:X}",
        "region_size": region_size,
        "pattern_len": len(pattern),
        "match_count": len(hits),
        "matches": [f"0x{a:X}" for a in hits],
    }


# ─── Dynamic-analysis tools (no debug API contact) ────────────────────
# Every tool below reads/writes only via the existing CR3 R/W primitives.
# Nothing here opens a handle on the target, calls DebugActiveProcess,
# touches DR0-DR7, sets TF, or uses page guards. Anti-cheat surface =
# whatever the underlying CR3 R/W already exposes.

# ── Module / PE introspection ─────────────────────────────────────────
@mcp.tool()
def list_modules(pid: int | str) -> list[dict]:
    """
    Enumerate every loaded module in the target via PEB->Ldr walk.
    Returns name, full path, base, entry point, and image size for each.

    Equivalent to a debugger's "Modules" pane, but done purely by
    dereferencing pointers through the CR3 R/W pipeline.
    """
    pid_i = _parse_int(pid)
    walker = ModuleWalker(_client())
    mods = walker.list_modules(pid_i)
    return [{
        "name":        m.name,
        "full_path":   m.full_path,
        "base":        f"0x{m.base:X}",
        "entry_point": f"0x{m.entry_point:X}",
        "size":        f"0x{m.size:X}",
        "end":         f"0x{m.end:X}",
    } for m in mods]


@mcp.tool()
def parse_pe(pid: int | str, module_base: int | str | None = None,
             module_name: str | None = None) -> dict:
    """
    Parse the PE headers of a loaded module. Identify it either by
    ``module_base`` (e.g. from ``get_base_address``/``list_modules``) or
    by ``module_name``.

    Returns the basics from the optional header plus every section's
    name / RVA / size / characteristics.
    """
    pid_i = _parse_int(pid)
    if module_base is None and module_name is None:
        raise ValueError("provide module_base or module_name")

    if module_base is None:
        m = ModuleWalker(_client()).find_module(pid_i, module_name)
        if not m:
            raise ValueError(f"module {module_name!r} not loaded in pid={pid_i}")
        base_i = m.base
    else:
        base_i = _parse_int(module_base)

    parser = PEParser(_bytes_reader_for(pid_i), base_i)
    info = parser.parse_headers()

    return {
        "base":              f"0x{base_i:X}",
        "image_base":        f"0x{info.image_base:X}",
        "is_64bit":          info.is_64bit,
        "machine":           f"0x{info.machine:X}",
        "entry_point":       f"0x{base_i + info.entry_point_rva:X}",
        "entry_point_rva":   f"0x{info.entry_point_rva:X}",
        "size_of_image":     f"0x{info.size_of_image:X}",
        "size_of_headers":   f"0x{info.size_of_headers:X}",
        "num_sections":      info.num_sections,
        "subsystem":         info.subsystem,
        "dll_characteristics": f"0x{info.dll_characteristics:X}",
        "sections": [{
            "name":           s.name,
            "rva":            f"0x{s.virtual_address:X}",
            "va":             f"0x{base_i + s.virtual_address:X}",
            "virtual_size":   f"0x{s.virtual_size:X}",
            "raw_size":       f"0x{s.raw_size:X}",
            "perms":          s.perms_str(),
            "characteristics": f"0x{s.characteristics:X}",
        } for s in info.sections],
        "data_directories": [{
            "index": i, "name": directory_name(i),
            "rva":  f"0x{d.rva:X}",
            "size": f"0x{d.size:X}",
        } for i, d in enumerate(info.data_directories) if d.rva or d.size],
    }


@mcp.tool()
def list_exports(pid: int | str, module_base: int | str | None = None,
                 module_name: str | None = None,
                 name_filter: str = "") -> dict:
    """
    Walk a module's export table. Optional case-insensitive substring
    filter on the export name. Returns ordinal + RVA + VA + forwarder.
    """
    pid_i = _parse_int(pid)
    if module_base is None and module_name is None:
        raise ValueError("provide module_base or module_name")
    if module_base is None:
        m = ModuleWalker(_client()).find_module(pid_i, module_name)
        if not m:
            raise ValueError(f"module {module_name!r} not loaded in pid={pid_i}")
        base_i = m.base
    else:
        base_i = _parse_int(module_base)

    parser = PEParser(_bytes_reader_for(pid_i), base_i)
    exports = parser.parse_exports()
    needle = name_filter.lower()
    out = []
    for e in exports:
        if needle and (e.name is None or needle not in e.name.lower()):
            continue
        out.append({
            "name":     e.name,
            "ordinal":  e.ordinal,
            "rva":      f"0x{e.rva:X}",
            "va":       f"0x{e.va:X}" if e.va else None,
            "forwarder": e.forwarder,
        })
    return {
        "module_base": f"0x{base_i:X}",
        "total_exports": len(exports),
        "shown": len(out),
        "exports": out,
    }


@mcp.tool()
def list_imports(pid: int | str, module_base: int | str | None = None,
                 module_name: str | None = None,
                 dll_filter: str = "") -> dict:
    """
    Walk a module's import descriptors. Returns per-DLL function lists
    including the current resolved address in the IAT — useful for
    spotting hooks (bound_va outside the source module's image).
    """
    pid_i = _parse_int(pid)
    if module_base is None and module_name is None:
        raise ValueError("provide module_base or module_name")
    if module_base is None:
        m = ModuleWalker(_client()).find_module(pid_i, module_name)
        if not m:
            raise ValueError(f"module {module_name!r} not loaded in pid={pid_i}")
        base_i = m.base
    else:
        base_i = _parse_int(module_base)

    parser = PEParser(_bytes_reader_for(pid_i), base_i)
    modules = parser.parse_imports()
    needle = dll_filter.lower()
    out = []
    for m in modules:
        if needle and needle not in m.dll_name.lower():
            continue
        out.append({
            "dll":   m.dll_name,
            "count": len(m.functions),
            "functions": [{
                "name":     f.name,
                "ordinal":  f.ordinal,
                "iat_va":   f"0x{f.iat_va:X}",
                "bound_va": f"0x{f.bound_va:X}",
            } for f in m.functions],
        })
    return {"module_base": f"0x{base_i:X}", "modules": out}


@mcp.tool()
def resolve_export(pid: int | str, module_name: str,
                   function_name: str) -> dict:
    """
    Resolve an exported function's VA — like ``GetProcAddress`` in the
    target's address space, done via PE parsing through our R/W. Returns
    a follow-through ``forwarder`` field if the export is forwarded.
    """
    pid_i = _parse_int(pid)
    walker = ModuleWalker(_client())
    m = walker.find_module(pid_i, module_name)
    if not m:
        raise ValueError(f"module {module_name!r} not loaded in pid={pid_i}")
    parser = PEParser(_bytes_reader_for(pid_i), m.base)
    e = parser.resolve_export(function_name)
    if not e:
        return {"found": False, "module": module_name, "function": function_name}
    return {
        "found":      True,
        "module":     module_name,
        "module_base": f"0x{m.base:X}",
        "function":   function_name,
        "ordinal":    e.ordinal,
        "rva":        f"0x{e.rva:X}",
        "va":         f"0x{e.va:X}" if e.va else None,
        "forwarder":  e.forwarder,
    }


# ── Disassembly ───────────────────────────────────────────────────────
@mcp.tool()
def disassemble(pid: int | str, address: int | str,
                byte_count: int = 64,
                max_instructions: int = 32,
                mode: str = "x64",
                use_cr3: bool = True) -> dict:
    """
    Read ``byte_count`` bytes from process VA and disassemble them with
    Capstone. Useful for inspecting function prologues, hook trampolines,
    or jump tables. Returns a list of decoded instructions and a
    pre-formatted listing.

    ``mode`` is ``"x64"`` (default) or ``"x86"``.
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    if byte_count <= 0 or byte_count > 16 * 1024:
        raise ValueError("byte_count must be in (0, 16 KiB]")
    if not disasm.have_capstone():
        raise RuntimeError("capstone not installed; pip install capstone")
    code = _client().read_memory(pid_i, addr_i, byte_count, use_cr3=use_cr3)
    insns = disasm.disassemble(code, addr_i, mode=mode,
                               max_instructions=max_instructions)
    return {
        "pid":         pid_i,
        "address":     f"0x{addr_i:X}",
        "mode":        mode,
        "bytes_read":  len(code),
        "instructions": [{
            "address":  f"0x{i.address:X}",
            "size":     i.size,
            "bytes":    i.bytes_.hex(),
            "mnemonic": i.mnemonic,
            "op_str":   i.op_str,
        } for i in insns],
        "listing": disasm.format_listing(insns),
    }


# ── Pointer chain (Cheat Engine style) ────────────────────────────────
@mcp.tool()
def follow_pointer_chain(pid: int | str, base: int | str,
                         offsets: list[int | str]) -> dict:
    """
    Resolve a Cheat-Engine pointer chain:

        ptr = base + offsets[0]                  # no deref on the first
        for off in offsets[1:]:
            ptr = read_u64(ptr) + off

    Returns every intermediate address and the final resolved address.
    """
    pid_i  = _parse_int(pid)
    base_i = _parse_int(base)
    offs   = [_parse_int(o) for o in offsets]
    result = PointerChain(_client()).follow(pid_i, base_i, offs)
    return {
        "pid":           pid_i,
        "base":          f"0x{base_i:X}",
        "offsets":       [f"0x{o:X}" for o in offs],
        "steps":         [f"0x{s:X}" for s in result.steps],
        "dereferences":  [f"0x{d:X}" for d in result.raw_dereferences],
        "final_address": f"0x{result.final_address:X}",
    }


# ── String search ─────────────────────────────────────────────────────
@mcp.tool()
def search_strings(pid: int | str, start_address: int | str,
                   region_size: int, min_length: int = 6,
                   encodings: str = "ascii,utf16le",
                   max_hits: int = 128, use_cr3: bool = True) -> dict:
    """
    Find printable ASCII and/or UTF-16LE strings in a VA range. Useful
    for fingerprinting modules, finding error messages, locating config
    strings, etc.

    ``encodings`` is a comma-separated list of ``ascii`` and/or ``utf16le``.
    """
    pid_i = _parse_int(pid)
    start = _parse_int(start_address)
    if region_size <= 0 or region_size > 64 * 1024 * 1024:
        raise ValueError("region_size must be in (0, 64 MiB]")
    enc = tuple(e.strip().lower() for e in encodings.split(',') if e.strip())
    if not all(e in ('ascii', 'utf16le') for e in enc):
        raise ValueError("encodings must be from {ascii, utf16le}")
    hits = StringFinder(_client()).find(
        pid_i, start, region_size, min_length=min_length,
        encodings=enc, max_hits=max_hits)
    return {
        "pid":   pid_i,
        "start": f"0x{start:X}",
        "region_size": region_size,
        "encodings": list(enc),
        "match_count": len(hits),
        "matches": [{
            "address":  f"0x{h.address:X}",
            "encoding": h.encoding,
            "text":     h.text,
        } for h in hits],
    }


# ── Memory watch (data-breakpoint replacement) ────────────────────────
@mcp.tool()
def watch_memory(pid: int | str, address: int | str, size: int,
                 duration_seconds: float = 5.0,
                 poll_interval_ms: int = 50,
                 max_events: int = 128,
                 use_cr3: bool = True) -> dict:
    """
    Poll a memory region at fixed intervals for ``duration_seconds`` and
    report every observed change with timestamp + per-byte diff.

    This is the read-side equivalent of a data breakpoint. No hardware
    DR registers, no DBG_CONTROL_C — just CR3 reads on a timer. Useful
    for watching health values, network buffers, or function pointers.

    Caveats: poll-based, so writes faster than ``poll_interval_ms`` may
    be missed (you'll see only the eventual state).
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    result = MemoryWatcher(_client()).watch(
        pid_i, addr_i, size,
        duration_seconds=duration_seconds,
        poll_interval_ms=poll_interval_ms,
        max_events=max_events,
        use_cr3=use_cr3)
    return {
        "pid":               result.pid,
        "address":           f"0x{result.address:X}",
        "size":              result.size,
        "duration_seconds":  result.duration_seconds,
        "poll_interval_ms":  result.poll_interval_ms,
        "poll_count":        result.poll_count,
        "event_count":       len(result.events),
        "final_hex":         result.final_hex,
        "events": [{
            "elapsed_ms": round(e.elapsed_ms, 2),
            "timestamp":  e.timestamp,
            "old_hex":    e.old_hex,
            "new_hex":    e.new_hex,
            "byte_diffs": [{"offset": o, "old": f"0x{a:02X}", "new": f"0x{b:02X}"}
                           for o, a, b in e.byte_diffs[:32]],
        } for e in result.events],
    }


# ── Patch registry ────────────────────────────────────────────────────
@mcp.tool()
def patch_code(pid: int | str, address: int | str, hex_data: str,
               name: str, use_cr3: bool = True) -> dict:
    """
    Write bytes at a VA and record an undo entry under ``name``. Restore
    later with ``restore_patch(name)``. Original bytes are stored in the
    registry for the lifetime of the MCP process.

    Use this for hot-patching: NOP an instruction, swap a jump target,
    bypass a check — all reversibly.
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    data = _parse_hex_bytes(hex_data)
    rec = _patch_registry().patch(pid_i, addr_i, data, name, use_cr3=use_cr3)
    return rec.as_dict()


@mcp.tool()
def nop_code(pid: int | str, address: int | str, size: int,
             name: str, use_cr3: bool = True) -> dict:
    """
    Convenience: write ``size`` 0x90 bytes at ``address`` and record an
    undo entry. Equivalent to ``patch_code(... hex_data="90 90 ...")``.
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    if size <= 0 or size > 4096:
        raise ValueError("nop size must be in (0, 4096]")
    rec = _patch_registry().nop(pid_i, addr_i, size, name, use_cr3=use_cr3)
    return rec.as_dict()


@mcp.tool()
def restore_patch(name: str, use_cr3: bool = True) -> dict:
    """Undo a named patch from the registry."""
    rec = _patch_registry().restore(name, use_cr3=use_cr3)
    return {**rec.as_dict(), "restored": True}


@mcp.tool()
def list_patches() -> list[dict]:
    """List every active patch (name, pid, VA, original/patched bytes)."""
    return [r.as_dict() for r in _patch_registry().list()]


@mcp.tool()
def restore_all_patches(use_cr3: bool = True) -> dict:
    """Restore every patch in the registry. Returns the list restored."""
    restored = _patch_registry().restore_all(use_cr3=use_cr3)
    return {"restored": [r.as_dict() for r in restored], "count": len(restored)}


# ── Memory map probe ──────────────────────────────────────────────────
@mcp.tool()
def probe_memory_map(pid: int | str, start: int | str, end: int | str,
                     step: int = 4096, max_probes: int = 8192,
                     use_cr3: bool = True) -> dict:
    """
    Heuristic memory map: probe one byte from each ``step``-sized page
    in ``[start, end)``. Reads that succeed mark the page mapped; reads
    that fail mark it unmapped. Adjacent mapped pages are coalesced.

    Slower than ``VirtualQueryEx`` but doesn't need a target handle.
    Cap your range — ``max_probes`` is the safety limit.
    """
    pid_i  = _parse_int(pid)
    start_ = _parse_int(start)
    end_   = _parse_int(end)
    ranges = MemoryProbe(_client()).probe(
        pid_i, start_, end_, step=step,
        max_probes=max_probes, use_cr3=use_cr3)
    return {
        "pid":   pid_i,
        "start": f"0x{start_:X}",
        "end":   f"0x{end_:X}",
        "step":  step,
        "range_count": len(ranges),
        "total_mapped_bytes": sum(r.size for r in ranges),
        "ranges": [{
            "start": f"0x{r.start:X}",
            "end":   f"0x{r.end:X}",
            "size":  f"0x{r.size:X}",
            "pages": r.pages,
        } for r in ranges],
    }


# ── Process freeze (stealth spin-patch suspend) ───────────────────────
@mcp.tool()
def freeze_at_va(pid: int | str, address: int | str, length: int = 2,
                 note: str = "") -> dict:
    """
    Freeze the target by patching ``EB FE`` (a 2-byte infinite loop) at
    ``address``. Every thread that reaches the patched VA spins on the
    JMP — no SuspendThread / NtSuspendProcess, no process handle opened,
    no WaitReason flip to ``WrSuspended``, no SuspendCount bump. From
    the kernel's perspective the threads are still "running".

    Pick the target VA carefully:
      - A function in the GAME's own module (.text), never a shared DLL
        like ntdll/kernel32 (those physical pages are COW-shared via
        KnownDlls and writing through CR3 would corrupt other processes).
      - A hot function = freezes most/all threads; a cold function =
        freezes only the threads that reach it.

    ``length`` (default 2) lets you pad to a longer NOP-sled so the
    patch overlaps subsequent instructions cleanly — useful if the
    target instruction is longer than 2 bytes and you need to preserve
    instruction boundaries after restore.

    Use ``unfreeze`` (or ``unfreeze_all``) to restore the original bytes.
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    rec = _freezer().freeze(pid_i, addr_i, length=length, note=note)
    return rec.as_dict()


@mcp.tool()
def unfreeze(pid: int | str, address: int | str | None = None) -> list[dict]:
    """
    Restore one specific freeze (when ``address`` is given) or every
    freeze for this PID. Threads stuck in the ``EB FE`` loop resume
    seamlessly once the bytes are restored — x86 cache coherency makes
    the executing core re-fetch the new instruction at the same RIP.
    """
    pid_i = _parse_int(pid)
    addr  = _parse_int(address) if address is not None else None
    rest  = _freezer().unfreeze(pid_i, addr)
    return [r.as_dict() for r in rest]


@mcp.tool()
def unfreeze_all() -> dict:
    """Restore every active freeze across all PIDs."""
    rest = _freezer().unfreeze_all()
    return {"restored": [r.as_dict() for r in rest], "count": len(rest)}


@mcp.tool()
def list_frozen() -> list[dict]:
    """Show every active spin-patch freeze (pid, va, original bytes, note)."""
    return [r.as_dict() for r in _freezer().list_frozen()]


# ── Value scanning (Cheat-Engine style) ───────────────────────────────
@mcp.tool()
def value_scan_new(pid: int | str, value: float | int,
                   type_name: str, region_start: int | str,
                   region_size: int, alignment: int | None = None,
                   use_cr3: bool = True) -> dict:
    """
    Start a new typed value scan. Returns a ``scan_id`` you pass to
    ``value_scan_filter`` to narrow the candidate set.

    ``type_name`` is one of: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64.

    Typical workflow for finding the address of a game value:

      1. ``value_scan_new(pid, value=100, type_name='f32',
                           region_start=heap_start, region_size=0x4000000)``
         → returns scan_id and N candidates.
      2. (do something in-game that changes the value)
      3. ``value_scan_filter(scan_id, 'eq', 75)`` → narrows to far fewer.
      4. Repeat 2-3 until 1 candidate survives — that's the address.
    """
    pid_i  = _parse_int(pid)
    start_ = _parse_int(region_start)
    scan = _value_scanner().new_scan(
        pid_i, value, type_name, start_, region_size,
        alignment=alignment, use_cr3=use_cr3)
    return {
        "scan_id": scan.scan_id,
        "pid":     scan.pid,
        "type":    scan.type_name,
        "region_start": f"0x{scan.region_start:X}",
        "region_size":  scan.region_size,
        "candidate_count": len(scan.candidates),
        "samples": [f"0x{c.address:X}" for c in scan.candidates[:8]],
        "history": scan.history,
    }


@mcp.tool()
def value_scan_filter(scan_id: str, op: str,
                       value: float | int | None = None,
                       value2: float | int | None = None,
                       use_cr3: bool = True) -> dict:
    """
    Narrow a candidate set by re-reading and applying a comparator:

      ``eq``         current value == ``value``
      ``ne``         current value != ``value``
      ``gt``         current value >  ``value``
      ``lt``         current value <  ``value``
      ``range``      current value in [``value``, ``value2``]
      ``changed``    current value differs from last seen
      ``unchanged``  current value matches last seen
      ``increased``  current value > last seen
      ``decreased``  current value < last seen

    Use ``changed`` / ``unchanged`` / ``increased`` / ``decreased`` when
    you don't know the exact new value — perfect for "took damage,
    value went down".
    """
    scan = _value_scanner().filter(scan_id, op, value=value, value2=value2,
                                    use_cr3=use_cr3)
    return {
        "scan_id":         scan.scan_id,
        "candidate_count": len(scan.candidates),
        "samples": [{"address": f"0x{c.address:X}",
                     "value":   c.last_value}
                    for c in scan.candidates[:16]],
        "history": scan.history,
    }


@mcp.tool()
def value_scan_list(scan_id: str, limit: int = 64,
                    refresh: bool = False, use_cr3: bool = True) -> dict:
    """
    Show the current candidate addresses + last-seen values for a scan.
    Pass ``refresh=True`` to re-read live values first (slow if there are
    many candidates).
    """
    scanner = _value_scanner()
    if refresh:
        scanner.refresh_values(scan_id, limit=limit, use_cr3=use_cr3)
    scan = scanner.get_scan(scan_id)
    return {
        "scan_id":         scan.scan_id,
        "pid":             scan.pid,
        "type":            scan.type_name,
        "candidate_count": len(scan.candidates),
        "candidates": [{"address": f"0x{c.address:X}",
                        "value":   c.last_value}
                       for c in scan.candidates[:limit]],
        "history": scan.history,
    }


@mcp.tool()
def value_scan_delete(scan_id: str) -> dict:
    """Free a scan's candidate state."""
    return {"deleted": _value_scanner().delete(scan_id)}


@mcp.tool()
def value_scan_all() -> list[dict]:
    """List every active value scan."""
    return [{
        "scan_id":         s.scan_id,
        "pid":             s.pid,
        "type":            s.type_name,
        "candidate_count": len(s.candidates),
        "when":            s.when,
    } for s in _value_scanner().list_scans()]


# ── Pointer hunting ───────────────────────────────────────────────────
@mcp.tool()
def find_pointers_to(pid: int | str, scan_start: int | str,
                      scan_size: int, target_va: int | str,
                      tolerance: int = 0, alignment: int = 8,
                      max_results: int = 256,
                      use_cr3: bool = True) -> dict:
    """
    Find every 8-byte aligned uint64 in ``[scan_start, scan_start+scan_size)``
    that equals (or, with ``tolerance>0``, falls within ``tolerance`` of)
    ``target_va``. Core building block for walking pointer chains
    backward from a known value's address up to a static module base.

    Iterative pointer-chain hunt for a leaf address ``L``:

      1. ``find_pointers_to(pid, heap_start, heap_size, L)`` → addresses A
      2. For each A in results: ``find_pointers_to(pid, ..., A)`` → B
      3. Stop when an address falls inside a module's .data/.rdata
         (use ``parse_pe`` to get section ranges). The chain is then
         ``module_base + (B - module_base) → ... → L``.

    ``tolerance`` lets you catch pointers into the middle of a struct
    (e.g. base+0x40 is a pointer to a struct whose interesting field is
    at +0x40; passing tolerance=0x100 finds those too — ``delta`` in
    the result tells you the offset).
    """
    pid_i = _parse_int(pid)
    start = _parse_int(scan_start)
    tgt   = _parse_int(target_va)
    hits = _pointer_hunter().find_pointers_to(
        pid_i, start, scan_size, tgt,
        tolerance=tolerance, alignment=alignment,
        max_results=max_results, use_cr3=use_cr3)
    return {
        "pid":           pid_i,
        "target":        f"0x{tgt:X}",
        "tolerance":     tolerance,
        "scan_range":    [f"0x{start:X}", f"0x{start + scan_size:X}"],
        "match_count":   len(hits),
        "matches": [{
            "address":  f"0x{h.address:X}",
            "value":    f"0x{h.pointer_value:X}",
            "delta":    h.delta,
        } for h in hits],
    }


# ── Snapshots ─────────────────────────────────────────────────────────
@mcp.tool()
def snapshot_save(label: str, pid: int | str, address: int | str,
                  size: int, use_cr3: bool = True) -> dict:
    """
    Capture ``size`` bytes from the target's VA under a named label
    (max 1 MiB per snapshot, 64 MiB total in the store). Use
    ``snapshot_diff_live`` later to see what's changed.
    """
    pid_i  = _parse_int(pid)
    addr_i = _parse_int(address)
    snap = _snapshot_store().save(label, pid_i, addr_i, size, use_cr3=use_cr3)
    return {
        "label":   snap.label,
        "pid":     snap.pid,
        "address": f"0x{snap.address:X}",
        "size":    snap.size,
        "when":    snap.when,
    }


@mcp.tool()
def snapshot_diff_live(label: str, max_records: int = 256,
                        use_cr3: bool = True) -> dict:
    """
    Diff a saved snapshot against the current memory contents at the
    same VA. Returns per-byte differences (limited to ``max_records``).
    """
    diffs = _snapshot_store().diff_live(label, max_records=max_records,
                                         use_cr3=use_cr3)
    return {
        "label": label,
        "diff_count": len(diffs),
        "diffs": [{
            "offset":  d.offset,
            "address": f"0x{d.address:X}",
            "old":     f"0x{d.old:02X}",
            "new":     f"0x{d.new:02X}",
        } for d in diffs],
    }


@mcp.tool()
def snapshot_diff(label_a: str, label_b: str,
                  max_records: int = 256) -> dict:
    """Diff two saved snapshots (must share the same VA and size)."""
    diffs = _snapshot_store().diff(label_a, label_b, max_records=max_records)
    return {
        "a": label_a, "b": label_b,
        "diff_count": len(diffs),
        "diffs": [{
            "offset":  d.offset,
            "address": f"0x{d.address:X}",
            "a":       f"0x{d.old:02X}",
            "b":       f"0x{d.new:02X}",
        } for d in diffs],
    }


@mcp.tool()
def snapshot_list() -> list[dict]:
    """List every saved snapshot."""
    return [{
        "label":   s.label,
        "pid":     s.pid,
        "address": f"0x{s.address:X}",
        "size":    s.size,
        "when":    s.when,
    } for s in _snapshot_store().list()]


@mcp.tool()
def snapshot_delete(label: str) -> dict:
    """Drop a saved snapshot from the store."""
    return {"deleted": _snapshot_store().delete(label)}


# ── Xref finder ───────────────────────────────────────────────────────
@mcp.tool()
def find_xrefs(pid: int | str, target_va: int | str,
                scan_start: int | str, scan_size: int,
                mode: str = "x64", max_results: int = 64,
                use_cr3: bool = True) -> dict:
    """
    Find code that references ``target_va`` in ``[scan_start, scan_start+
    scan_size)``. Detected reference classes:

      * RIP-relative memory operands: ``mov reg, [rip+disp]`` /
        ``lea reg, [rip+disp]`` / ``call qword ptr [rip+disp]`` etc.
      * Direct call/jmp/jcc with absolute imm matching ``target_va``.

    Uses capstone with detail mode — no pattern false-positives.
    Typical use: feed a function VA you got from ``resolve_export`` and
    a ``.text`` range to find every caller.
    """
    pid_i = _parse_int(pid)
    tgt   = _parse_int(target_va)
    start = _parse_int(scan_start)
    hits = _xref_finder().find_xrefs(
        pid_i, tgt, start, scan_size, mode=mode,
        max_results=max_results, use_cr3=use_cr3)
    return {
        "pid":         pid_i,
        "target":      f"0x{tgt:X}",
        "scan_range":  [f"0x{start:X}", f"0x{start + scan_size:X}"],
        "match_count": len(hits),
        "hits": [{
            "address":  f"0x{h.address:X}",
            "kind":     h.kind,
            "mnemonic": h.mnemonic,
            "op_str":   h.op_str,
            "size":     h.insn_size,
        } for h in hits],
    }


# ── Thread enumeration ────────────────────────────────────────────────
@mcp.tool()
def list_threads(pid: int | str) -> dict:
    """
    Enumerate every thread of ``pid`` via ``NtQuerySystemInformation``.
    No handle is opened on the target. Returns TID, start address,
    state, wait reason, kernel/user time.

    Combine with ``freeze_at_va``: pick the thread that's running (state
    == Running, low wait_time) — its start_address is usually inside the
    module hosting the game's main loop. Freeze a function in that
    module to halt the main thread without touching workers.
    """
    pid_i = _parse_int(pid)
    snap = thread_enum.list_threads(pid_i)
    if snap is None:
        return {"pid": pid_i, "found": False, "threads": []}
    return {
        "pid":          snap.pid,
        "image_name":   snap.image_name,
        "thread_count": snap.thread_count,
        "found":        True,
        "threads": [{
            "tid":             t.tid,
            "start_address":   f"0x{t.start_address:X}",
            "state":           t.state_name,
            "wait_reason":     t.wait_reason_name,
            "kernel_time_us":  t.kernel_time_100ns // 10,
            "user_time_us":    t.user_time_100ns // 10,
            "priority":        t.priority,
            "context_switches": t.context_switches,
        } for t in snap.threads],
    }


# ─── Resources: expose IPC layout for debugging the MCP itself ─────────
@mcp.resource("ipc://layout")
def ipc_layout() -> str:
    """The current IPC struct layout (matches kernel shared_memory_ipc.h)."""
    return (
        f"IPC_MAGIC         = 0x{ipc.IPC_MAGIC:X}\n"
        f"IPC_VERSION       = {ipc.IPC_VERSION}\n"
        f"IPC_MAX_SLOTS     = {ipc.IPC_MAX_SLOTS}\n"
        f"IPC_SLOT_DATA_SIZE= 0x{ipc.IPC_SLOT_DATA_SIZE:X}\n"
        f"IPC_SLOT size     = 0x{__import__('ctypes').sizeof(ipc.IPC_SLOT):X}\n"
        f"IPC_TOTAL_SIZE    = 0x{ipc.IPC_TOTAL_SIZE:X}\n"
    )


# ─── Entry points ──────────────────────────────────────────────────────
def main() -> None:
    """Run the MCP server over stdio (the standard transport)."""
    log.info("Scootware driver MCP starting; helper=%s", HELPER_PATH)
    mcp.run()


if __name__ == "__main__":
    main()
