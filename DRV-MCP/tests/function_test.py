"""
function_test.py
================

Drive the MCP server via JSON-RPC over stdio and exercise every tool
against the loaded kernel driver. Prints a PASS/FAIL summary at the end.

Usage:

    python tests/function_test.py

Spawns ``test_target.py`` as a victim, captures its buffer VA, then runs
every tool against that buffer / against the test_target process. No
risky targets are touched.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE       = Path(__file__).resolve().parent
PROJECT    = HERE.parent
TARGET_SCRIPT = HERE / "test_target.py"

RESULTS: list[tuple[str, bool, str]] = []


# ─── JSON-RPC client over stdio ────────────────────────────────────────
class MCPClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "drv_mcp"],
            cwd=str(PROJECT),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, bufsize=1,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        self._next_id = 0
        self._stderr_lines: list[str] = []
        # Drain stderr in the background so a chatty server doesn't fill
        # the OS pipe buffer (which would block the server).
        import threading
        def drain():
            try:
                for line in self.proc.stderr:
                    self._stderr_lines.append(line.rstrip())
            except Exception:
                pass
        threading.Thread(target=drain, daemon=True).start()

    def _call(self, method: str, params: dict | None = None,
              timeout_s: float = 30.0) -> dict:
        self._next_id += 1
        req = {"jsonrpc": "2.0", "id": self._next_id,
               "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        # Read one JSON-RPC reply line
        start = time.monotonic()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                # Server died — surface its last stderr lines for debugging.
                tail = "\n".join(self._stderr_lines[-20:])
                raise RuntimeError(
                    f"MCP closed stdout (method={method}, args={params}). "
                    f"Server stderr tail:\n{tail}"
                )
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == self._next_id:
                return msg
            if time.monotonic() - start > timeout_s:
                raise TimeoutError(f"{method} took >{timeout_s}s")

    def notify(self, method: str, params: dict | None = None) -> None:
        req = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()

    def initialize(self) -> dict:
        r = self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "function_test", "version": "0"},
        })
        self.notify("notifications/initialized")
        return r

    def tool(self, tool_name: str, **args) -> dict:
        return self._call("tools/call",
                           {"name": tool_name, "arguments": args},
                           timeout_s=60.0)

    def stop(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


# ─── Test helpers ──────────────────────────────────────────────────────
def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    marker = "PASS" if ok else "FAIL"
    print(f"[{marker}] {name}  {detail}", flush=True)


def expect_tool(client: MCPClient, tool_name: str, **args) -> tuple[bool, Any, str]:
    """Call a tool, return (ok, payload, error_message)."""
    try:
        r = client.tool(tool_name, **args)
    except Exception as e:
        return False, None, f"raised {type(e).__name__}: {e}"
    if "error" in r:
        return False, None, f"rpc error: {r['error']}"
    res = r.get("result", {})
    if res.get("isError"):
        text = (res.get("content") or [{}])[0].get("text", "")
        return False, None, f"isError: {text[:300]}"
    # Prefer structured content, fall back to text
    sc = res.get("structuredContent")
    if sc:
        return True, sc.get("result", sc), ""
    content = res.get("content") or []
    if content and content[0].get("type") == "text":
        try:
            return True, json.loads(content[0]["text"]), ""
        except Exception:
            return True, content[0]["text"], ""
    return True, res, ""


def spawn_target() -> tuple[subprocess.Popen, dict]:
    """Spawn test_target.py and read its buffer info."""
    p = subprocess.Popen(
        [sys.executable, str(TARGET_SCRIPT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    info = {}
    for _ in range(20):
        line = p.stdout.readline().strip()
        if line == "READY":
            break
        if "=" in line:
            k, v = line.split("=", 1)
            info[k] = v
    info["pid"] = p.pid
    return p, info


# ─── Test sequence ─────────────────────────────────────────────────────
def main() -> int:
    print(f"[*] Spawning MCP server: cwd={PROJECT}", flush=True)
    client = MCPClient()
    try:
        client.initialize()

        # ── Session ────────────────────────────────────────────────
        ok, status, err = expect_tool(client, "driver_status")
        record("driver_status", ok, f"{status}" if ok else err)
        if ok:
            print(f"     helper_pid={status.get('helper_pid')} attached={status.get('driver_attached')}", flush=True)

        # If driver isn't attached yet, wait for handshake.
        if not (ok and status.get("driver_attached")):
            ok, w, err = expect_tool(client, "wait_for_driver", timeout_seconds=15)
            record("wait_for_driver", ok, str(w) if ok else err)
            ok, status, err = expect_tool(client, "driver_status")
            record("driver_status (rechecked)", ok,
                   f"attached={status.get('driver_attached')}" if ok else err)
            if not (ok and status.get("driver_attached")):
                print("[-] Driver not attached. Bailing on driver-dependent tests.", flush=True)
                return 1
        else:
            record("wait_for_driver", True, "already attached, skipped")

        # ── Spawn test target ──────────────────────────────────────
        print("[*] Spawning test_target.py...", flush=True)
        tgt_proc, tgt = spawn_target()
        print(f"     target_pid={tgt['pid']} BUFFER_VA={tgt.get('BUFFER_VA')} SENTINEL={tgt.get('SENTINEL')}", flush=True)
        target_pid     = int(tgt["pid"])
        buffer_va_int  = int(tgt["BUFFER_VA"], 16)
        buffer_size    = int(tgt["SIZE"])
        sentinel_int   = int(tgt["SENTINEL"], 16)
        buffer_va_hex  = f"0x{buffer_va_int:X}"

        try:
            # ── Process discovery ──────────────────────────────────
            ok, r, err = expect_tool(client, "list_processes", name_filter="python")
            ok2 = ok and any(p["pid"] == target_pid for p in r) if isinstance(r, list) else False
            record("list_processes", ok2, f"found target_pid in {len(r) if isinstance(r,list) else '?'} matches" if ok else err)

            ok, r, err = expect_tool(client, "find_pid", process_name="python.exe", prefer_driver=False)
            record("find_pid (local)", ok, f"pid={r.get('pid')}" if ok else err)

            ok, r, err = expect_tool(client, "find_pid", process_name="python.exe", prefer_driver=True)
            record("find_pid (driver)", ok, f"pid={r.get('pid')} source={r.get('source')}" if ok else err)

            ok, r, err = expect_tool(client, "get_base_address", pid=target_pid)
            target_base = int(r["base_address"], 16) if ok else None
            record("get_base_address", ok, f"base={r.get('base_address')}" if ok else err)

            ok, r, err = expect_tool(client, "get_peb", pid=target_pid)
            target_peb = int(r["peb"], 16) if ok and r.get("peb") and r["peb"] != "0x0" else None
            record("get_peb", ok and target_peb is not None,
                   f"peb={r.get('peb')}" if ok else err)

            ok, r, err = expect_tool(client, "get_module_base", pid=target_pid, module_name="ntdll.dll")
            ntdll_base = int(r["base"], 16) if ok and r.get("base") and r["base"] != "0x0" else None
            record("get_module_base (ntdll.dll)",
                   ok and ntdll_base is not None,
                   f"ntdll={r.get('base')}" if ok else err)

            ok, r, err = expect_tool(client, "resolve_dtb", pid=target_pid)
            record("resolve_dtb", ok and r.get("raw", 0) != 0,
                   f"cr3={r.get('cr3')}" if ok else err)

            ok, r, err = expect_tool(client, "get_guarded_region")
            record("get_guarded_region", ok,
                   f"region={r.get('guarded_region')} (zero if no EAC target)" if ok else err)

            # ── Memory read ────────────────────────────────────────
            ok, r, err = expect_tool(client, "read_memory",
                                     pid=target_pid, address=buffer_va_hex, size=16)
            read_ok = (ok and bytes.fromhex(r.get("hex", ""))[:4]
                       == struct.pack("<I", sentinel_int))
            record("read_memory (sentinel)", read_ok,
                   f"hex={r.get('hex','')[:32]}" if ok else err)

            ok, r, err = expect_tool(client, "dump_memory",
                                     pid=target_pid, address=buffer_va_hex, size=64)
            # xxd format shows bytes little-endian: sentinel 0xDECAFBAD -> "AD FB CA DE"
            record("dump_memory",
                   ok and isinstance(r, str) and "AD FB CA DE" in r.upper(),
                   "found sentinel bytes in dump" if ok else err)

            ok, r, err = expect_tool(client, "read_typed",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x10:X}",
                                     type_name="f32")
            record("read_typed (f32 health)",
                   ok and abs(r.get("value", 0.0) - 100.0) < 0.001,
                   f"value={r.get('value')}" if ok else err)

            ok, r, err = expect_tool(client, "read_typed",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x14:X}",
                                     type_name="i32")
            record("read_typed (i32 ammo)",
                   ok and r.get("value") == 30,
                   f"value={r.get('value')}" if ok else err)

            ok, r, err = expect_tool(client, "read_typed",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x20:X}",
                                     type_name="cstring")
            record("read_typed (cstring)",
                   ok and "DRV_MCP_TEST_STRING_v1" in str(r.get("value", "")),
                   f"value={r.get('value')!r}" if ok else err)

            ok, r, err = expect_tool(client, "read_typed",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x40:X}",
                                     type_name="wstring")
            record("read_typed (wstring)",
                   ok and "ScootwareDriverMCP" in str(r.get("value", "")),
                   f"value={r.get('value')!r}" if ok else err)

            ok, r, err = expect_tool(client, "read_typed",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x100:X}",
                                     type_name="u64")
            record("read_typed (u64 leaf)",
                   ok and r.get("value") == 0xDEADC0DEBEEFCAFE,
                   f"value=0x{r.get('value',0):X}" if ok else err)

            # ── Memory write + readback ────────────────────────────
            scratch = f"0x{buffer_va_int + 0x800:X}"
            ok, r, err = expect_tool(client, "write_memory",
                                     pid=target_pid, address=scratch,
                                     hex_data="DE AD BE EF CA FE BA BE")
            record("write_memory", ok and r.get("bytes_written") == 8,
                   f"wrote {r.get('bytes_written')} bytes" if ok else err)

            ok, r, err = expect_tool(client, "read_memory",
                                     pid=target_pid, address=scratch, size=8)
            record("write-read roundtrip",
                   ok and r.get("hex","").lower() == "deadbeefcafebabe",
                   f"readback={r.get('hex','')}" if ok else err)

            # ── scan_memory: find sentinel in buffer ───────────────
            ok, r, err = expect_tool(client, "scan_memory",
                                     pid=target_pid,
                                     start_address=buffer_va_hex,
                                     region_size=4096,
                                     pattern_hex="AD FB CA DE")
            record("scan_memory",
                   ok and r.get("match_count", 0) >= 1,
                   f"matches={r.get('matches', [])[:3]}" if ok else err)

            # ── Analysis: modules / PE / exports / imports ─────────
            ok, r, err = expect_tool(client, "list_modules", pid=target_pid)
            mods = r if ok else []
            has_ntdll = isinstance(mods, list) and any("ntdll" in m["name"].lower() for m in mods)
            record("list_modules",
                   ok and has_ntdll and len(mods) > 3,
                   f"{len(mods) if isinstance(mods,list) else '?'} modules, ntdll={has_ntdll}" if ok else err)

            ok, r, err = expect_tool(client, "parse_pe",
                                     pid=target_pid, module_name="ntdll.dll")
            ntdll_sections = r.get("sections", []) if ok else []
            has_text = any(s["name"] == ".text" for s in ntdll_sections)
            record("parse_pe (ntdll)",
                   ok and has_text and r.get("is_64bit"),
                   f"sections={len(ntdll_sections)} text={has_text}" if ok else err)

            text_section = next((s for s in ntdll_sections if s["name"] == ".text"), None)

            ok, r, err = expect_tool(client, "list_exports",
                                     pid=target_pid, module_name="ntdll.dll",
                                     name_filter="NtClose")
            export_count = r.get("shown", 0) if ok else 0
            ntclose_va = None
            if ok:
                for e in r.get("exports", []):
                    if e.get("name") == "NtClose":
                        ntclose_va = int(e["va"], 16)
                        break
            record("list_exports (NtClose filter)",
                   ok and ntclose_va is not None,
                   f"NtClose va={hex(ntclose_va) if ntclose_va else None}" if ok else err)

            ok, r, err = expect_tool(client, "list_imports",
                                     pid=target_pid, module_name="python.exe")
            imp_modules = r.get("modules", []) if ok else []
            record("list_imports (python.exe)",
                   ok and len(imp_modules) > 0,
                   f"{len(imp_modules)} import DLLs" if ok else err)

            ok, r, err = expect_tool(client, "resolve_export",
                                     pid=target_pid, module_name="ntdll.dll",
                                     function_name="NtClose")
            record("resolve_export (NtClose)",
                   ok and r.get("found") and r.get("va"),
                   f"va={r.get('va')}" if ok else err)

            # ── Disassembly of code we planted in test buffer ──────
            ok, r, err = expect_tool(client, "disassemble",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x80:X}",
                                     byte_count=16, max_instructions=8)
            insns = r.get("instructions", []) if ok else []
            mnemonics = [i["mnemonic"] for i in insns]
            record("disassemble (planted code)",
                   ok and "mov" in mnemonics and "push" in mnemonics
                   and "sub" in mnemonics and "ret" in mnemonics,
                   f"mnemonics={mnemonics}" if ok else err)

            # ── Disassemble live NtClose for stronger signal ───────
            if ntclose_va:
                ok, r, err = expect_tool(client, "disassemble",
                                         pid=target_pid, address=f"0x{ntclose_va:X}",
                                         byte_count=24, max_instructions=8)
                m = [i["mnemonic"] for i in r.get("instructions", [])] if ok else []
                record("disassemble (NtClose live)",
                       ok and "syscall" in m,
                       f"mnemonics={m}" if ok else err)

            # ── follow_pointer_chain: buffer+0x08 dereferences to buffer+0x100, leaf u64
            ok, r, err = expect_tool(client, "follow_pointer_chain",
                                     pid=target_pid, base=buffer_va_hex,
                                     offsets=[0x8, 0x0])
            expect_final = f"0x{buffer_va_int + 0x100:X}"
            record("follow_pointer_chain",
                   ok and r.get("final_address", "").upper() == expect_final.upper(),
                   f"final={r.get('final_address')} expected={expect_final}" if ok else err)

            # ── search_strings: find planted strings ───────────────
            ok, r, err = expect_tool(client, "search_strings",
                                     pid=target_pid,
                                     start_address=buffer_va_hex,
                                     region_size=4096,
                                     min_length=6)
            matches = r.get("matches", []) if ok else []
            found_ascii = any("DRV_MCP_TEST_STRING_v1" in m["text"] for m in matches)
            found_wide  = any("ScootwareDriverMCP"     in m["text"] for m in matches)
            record("search_strings",
                   ok and found_ascii and found_wide,
                   f"ascii={found_ascii} wide={found_wide} total={len(matches)}" if ok else err)

            # ── watch_memory: write changes to a watched region ────
            print("[*] watch_memory: launching a writer thread...", flush=True)
            import threading
            def writer():
                time.sleep(0.4)
                for i in range(3):
                    expect_tool(client, "write_memory",
                                pid=target_pid,
                                address=f"0x{buffer_va_int + 0x900:X}",
                                hex_data=f"{(i+1):02X}" + "00 00 00")
                    time.sleep(0.4)
            # We can't reliably call the MCP from a thread (single stdio). Do
            # it inline instead: snapshot, single write, watch sees 1 event.
            ok, r, err = expect_tool(client, "watch_memory",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x900:X}",
                                     size=8, duration_seconds=0.3,
                                     poll_interval_ms=30)
            # Without a writer this just confirms watch returns cleanly
            record("watch_memory (no writer)",
                   ok and r.get("poll_count", 0) >= 2,
                   f"polls={r.get('poll_count')} events={r.get('event_count')}" if ok else err)

            # watch_memory with concurrent writes: the harness can't share
            # the MCP stdio across threads, so launch a tiny external
            # writer that pokes the target's memory directly via ctypes.
            # The test_target buffer is RWX in our test_target process —
            # any process can map a file with the same physical pages? No,
            # but we CAN just use VirtualProtect... easier: have the
            # test_target itself rotate a byte in a background thread when
            # we set a flag.
            #
            # Simplest portable approach: write a value via the MCP, then
            # immediately watch with a poll long enough to catch a
            # follow-up MCP write — but we can't interleave them on one
            # stdio. Instead use a side Python process that does
            # WriteProcessMemory on the target. test_target's buffer is
            # RWX in test_target's address space; we need PROCESS_VM_WRITE
            # access. That opens a handle on the target, which is fine
            # because the TARGET is our test harness — not anti-cheat.
            import threading, ctypes
            poker_done = threading.Event()
            def poker():
                # Open the test_target process and write a few bytes
                PROCESS_VM_WRITE = 0x0020
                PROCESS_VM_OPERATION = 0x0008
                h = ctypes.windll.kernel32.OpenProcess(
                    PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, target_pid)
                if not h:
                    return
                try:
                    time.sleep(0.1)  # let watch start
                    target_addr = buffer_va_int + 0x900
                    for v in (0xAA, 0xBB, 0xCC):
                        b = ctypes.c_ubyte(v)
                        n = ctypes.c_size_t(0)
                        ctypes.windll.kernel32.WriteProcessMemory(
                            h, ctypes.c_void_p(target_addr),
                            ctypes.byref(b), 1, ctypes.byref(n))
                        time.sleep(0.12)
                finally:
                    ctypes.windll.kernel32.CloseHandle(h)
                    poker_done.set()
            tpoker = threading.Thread(target=poker, daemon=True)
            tpoker.start()
            ok, r, err = expect_tool(client, "watch_memory",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0x900:X}",
                                     size=1, duration_seconds=0.6,
                                     poll_interval_ms=20)
            tpoker.join(timeout=2)
            record("watch_memory (with writer)",
                   ok and r.get("event_count", 0) >= 1,
                   f"events={r.get('event_count')} polls={r.get('poll_count')}" if ok else err)

            # ── patch_code / restore_patch ─────────────────────────
            ok, r, err = expect_tool(client, "patch_code",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0xA00:X}",
                                     hex_data="DE AD BE EF",
                                     name="t_patch1")
            record("patch_code", ok and r.get("size") == 4,
                   f"orig={r.get('original')} patched={r.get('patched')}" if ok else err)

            ok, r, err = expect_tool(client, "list_patches")
            record("list_patches", ok and any(p["name"] == "t_patch1" for p in r),
                   f"{len(r)} patches" if ok else err)

            ok, r, err = expect_tool(client, "restore_patch", name="t_patch1")
            record("restore_patch", ok and r.get("restored"), str(r)[:120] if ok else err)

            # ── nop_code + restore_all_patches ─────────────────────
            ok, r, err = expect_tool(client, "nop_code",
                                     pid=target_pid,
                                     address=f"0x{buffer_va_int + 0xB00:X}",
                                     size=8, name="t_nop1")
            record("nop_code", ok and r.get("size") == 8,
                   f"patched={r.get('patched')}" if ok else err)

            ok, r, err = expect_tool(client, "restore_all_patches")
            record("restore_all_patches",
                   ok and r.get("count", 0) >= 1,
                   f"count={r.get('count')}" if ok else err)

            # ── probe_memory_map ───────────────────────────────────
            ok, r, err = expect_tool(client, "probe_memory_map",
                                     pid=target_pid,
                                     start=buffer_va_hex,
                                     end=f"0x{buffer_va_int + buffer_size + 0x10000:X}",
                                     step=4096, max_probes=300)
            record("probe_memory_map",
                   ok and r.get("total_mapped_bytes", 0) >= buffer_size // 2,
                   f"mapped_bytes={r.get('total_mapped_bytes')} ranges={r.get('range_count')}" if ok else err)

            # ── Value scanning + filter ────────────────────────────
            ok, r, err = expect_tool(client, "value_scan_new",
                                     pid=target_pid, value=100.0,
                                     type_name="f32",
                                     region_start=buffer_va_hex,
                                     region_size=4096)
            scan_id = r.get("scan_id") if ok else None
            record("value_scan_new (health=100.0)",
                   ok and r.get("candidate_count", 0) >= 1,
                   f"id={scan_id} candidates={r.get('candidate_count')}" if ok else err)

            # Change the health to 75.0, filter, expect 1 candidate
            if scan_id:
                ok2, _, _ = expect_tool(client, "write_memory",
                                        pid=target_pid,
                                        address=f"0x{buffer_va_int + 0x10:X}",
                                        hex_data=struct.pack("<f", 75.0).hex())
                ok, r, err = expect_tool(client, "value_scan_filter",
                                         scan_id=scan_id, op="eq", value=75.0)
                record("value_scan_filter (eq 75.0)",
                       ok and r.get("candidate_count", 0) == 1,
                       f"remain={r.get('candidate_count')}" if ok else err)

                ok, r, err = expect_tool(client, "value_scan_list", scan_id=scan_id)
                cands = r.get("candidates", []) if ok else []
                final_addr = int(cands[0]["address"], 16) if cands else None
                record("value_scan_list",
                       ok and final_addr == buffer_va_int + 0x10,
                       f"addr={hex(final_addr) if final_addr else None}" if ok else err)

                ok, r, err = expect_tool(client, "value_scan_all")
                record("value_scan_all", ok and len(r) >= 1,
                       f"scans={len(r) if ok else '?'}" if ok else err)

                ok, r, err = expect_tool(client, "value_scan_delete", scan_id=scan_id)
                record("value_scan_delete", ok and r.get("deleted"),
                       str(r) if ok else err)

            # ── find_pointers_to: buffer+0x08 holds pointer to buffer+0x100
            ok, r, err = expect_tool(client, "find_pointers_to",
                                     pid=target_pid,
                                     scan_start=buffer_va_hex,
                                     scan_size=4096,
                                     target_va=f"0x{buffer_va_int + 0x100:X}",
                                     max_results=8)
            hits = r.get("matches", []) if ok else []
            expected = f"0x{buffer_va_int + 0x8:X}"
            found = any(h["address"].upper() == expected.upper() for h in hits)
            record("find_pointers_to",
                   ok and found,
                   f"found at {expected}? {found} matches={len(hits)}" if ok else err)

            # ── Snapshot / diff ────────────────────────────────────
            ok, r, err = expect_tool(client, "snapshot_save", label="snap1",
                                     pid=target_pid, address=buffer_va_hex,
                                     size=4096)
            record("snapshot_save",
                   ok and r.get("size") == 4096,
                   f"label={r.get('label')}" if ok else err)

            # Mutate a byte, diff vs live
            expect_tool(client, "write_memory",
                        pid=target_pid, address=f"0x{buffer_va_int + 0xC00:X}",
                        hex_data="FF FF FF FF")
            ok, r, err = expect_tool(client, "snapshot_diff_live", label="snap1")
            record("snapshot_diff_live",
                   ok and r.get("diff_count", 0) >= 1,
                   f"diff_count={r.get('diff_count')}" if ok else err)

            # Save snap2 (mutated), diff with snap1
            ok, _, _ = expect_tool(client, "snapshot_save", label="snap2",
                                   pid=target_pid, address=buffer_va_hex,
                                   size=4096)
            ok, r, err = expect_tool(client, "snapshot_diff",
                                     label_a="snap1", label_b="snap2")
            record("snapshot_diff",
                   ok and r.get("diff_count", 0) >= 1,
                   f"diff_count={r.get('diff_count')}" if ok else err)

            ok, r, err = expect_tool(client, "snapshot_list")
            record("snapshot_list",
                   ok and len(r) >= 2,
                   f"snapshots={[s['label'] for s in r] if ok else err}")

            expect_tool(client, "snapshot_delete", label="snap1")
            expect_tool(client, "snapshot_delete", label="snap2")

            # ── find_xrefs: scan a small section of ntdll text for refs ─
            # Pick the data directory (export RVA target) as a stable ref target
            if ntclose_va and text_section:
                text_va  = int(text_section["va"], 16)
                # Search just 16 KiB of .text for any RIP-rel ref to NtClose
                # (NtClose is referenced by KiUserExceptionDispatcher and
                # other places; if no hit, this is informational not failure)
                ok, r, err = expect_tool(client, "find_xrefs",
                                         pid=target_pid,
                                         target_va=f"0x{ntclose_va:X}",
                                         scan_start=f"0x{text_va:X}",
                                         scan_size=64 * 1024,
                                         max_results=4)
                record("find_xrefs (NtClose in ntdll head .text)",
                       ok,
                       f"hits={r.get('match_count')}" if ok else err)

            # ── list_threads ───────────────────────────────────────
            ok, r, err = expect_tool(client, "list_threads", pid=target_pid)
            record("list_threads",
                   ok and r.get("found") and r.get("thread_count", 0) >= 1
                   and r.get("image_name", "").lower().startswith("python"),
                   f"image={r.get('image_name')} threads={r.get('thread_count')}" if ok else err)

            # ── Process suspension via spin-patch ──────────────────
            # Write EB FE into the buffer's code region, verify list_frozen,
            # then unfreeze and confirm the original bytes are restored.
            freeze_va = f"0x{buffer_va_int + 0x80:X}"  # our planted code
            ok, r, err = expect_tool(client, "freeze_at_va",
                                     pid=target_pid, address=freeze_va,
                                     length=2, note="function_test")
            patched_ok = ok and r.get("patched", "").startswith("ebfe")
            orig_bytes_hex = r.get("original", "")
            record("freeze_at_va",
                   patched_ok,
                   f"orig={orig_bytes_hex[:8]} patched={r.get('patched','')[:8]}" if ok else err)

            # Verify the bytes actually changed in target memory
            ok, r, err = expect_tool(client, "read_memory",
                                     pid=target_pid, address=freeze_va, size=2)
            record("verify spin-patch in memory",
                   ok and r.get("hex", "").lower() == "ebfe",
                   f"actual={r.get('hex','')}" if ok else err)

            ok, r, err = expect_tool(client, "list_frozen")
            record("list_frozen",
                   ok and any(f["address"].upper() == freeze_va.upper() for f in r),
                   f"frozen={[(f['pid'],f['address']) for f in r]}" if ok else err)

            ok, r, err = expect_tool(client, "unfreeze",
                                     pid=target_pid, address=freeze_va)
            record("unfreeze (specific va)",
                   ok and len(r) == 1,
                   f"restored {len(r)} freezes" if ok else err)

            # Verify the restore
            ok, r, err = expect_tool(client, "read_memory",
                                     pid=target_pid, address=freeze_va, size=2)
            record("verify restore in memory",
                   ok and r.get("hex", "").lower() == orig_bytes_hex.lower()[:4],
                   f"after={r.get('hex','')} expected={orig_bytes_hex[:4]}" if ok else err)

            # Freeze + unfreeze_all
            expect_tool(client, "freeze_at_va", pid=target_pid,
                        address=freeze_va, length=2)
            ok, r, err = expect_tool(client, "unfreeze_all")
            record("unfreeze_all", ok and r.get("count", 0) >= 1,
                   f"count={r.get('count')}" if ok else err)

        finally:
            print("[*] Terminating test_target...", flush=True)
            try:
                tgt_proc.terminate(); tgt_proc.wait(timeout=3)
            except Exception:
                tgt_proc.kill()

    finally:
        # Don't shutdown the driver — user has it loaded.
        client.stop()

    # Summary
    print("\n" + "=" * 70, flush=True)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = len(RESULTS) - passed
    print(f"FINAL: {passed} pass / {failed} fail / {len(RESULTS)} total", flush=True)
    if failed:
        print("Failures:")
        for name, ok, detail in RESULTS:
            if not ok:
                print(f"  - {name}: {detail}")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
