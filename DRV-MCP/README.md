# drv-mcp — Scootware Driver MCP Server

An [MCP](https://modelcontextprotocol.io) server that exposes the
Scootware CR3 kernel driver to an AI agent (Claude Code, Claude Desktop,
etc.) for **debugging and dynamic analysis**: enumerate processes, read
process memory through the CR3 bypass, dump regions, scan for patterns,
and write memory for hot-patching.

## How it works

The driver discovers a single usermode process named `scootware.exe`
that contains the `IPC_MAGIC` value, then read/writes that process's
shared-memory IPC buffer. We satisfy the contract from Python by:

1. Creating a named Win32 file mapping sized `IPC_TOTAL_SIZE`.
2. Spawning a tiny C helper (`helper/scootware.exe`) that opens the
   same mapping and maps a view into its own address space. That makes
   the IPC pages visible to the driver as soon as it scans the helper.
3. Issuing commands from Python by writing into our view of the same
   mapping and waiting for the driver's response.

```
┌─────────────────┐  stdio JSON-RPC   ┌──────────────────────────────┐
│  Claude Code    │ ────────────────► │  drv_mcp Python MCP server   │
└─────────────────┘                   └──────────────┬───────────────┘
                                                     │ Win32 file mapping
                                                     ▼
                                       ┌─────────────────────────┐
                                       │  scootware.exe (helper) │  ← driver scans
                                       └────────────┬────────────┘    EPROCESS for
                                                    │ same physical    this name
                                                    │ pages, IPC_MAGIC
                                                    ▼
                                       ┌─────────────────────────┐
                                       │  drv.sys kernel driver  │
                                       └─────────────────────────┘
```

## Setup

1. Build the kernel driver (`FINAL-DRV/build.bat`) and load `drv.sys`
   however you normally do — KDU, manual mapping, test-signing service,
   etc. The MCP doesn't manage driver loading.
2. From this directory, run:

   ```cmd
   install.bat
   ```

   It builds the helper with `cl.exe`, installs `mcp` from PyPI, and
   registers the server with the Claude CLI.

3. If `install.bat` couldn't find the `claude` CLI, add the entry to
   `%USERPROFILE%\.claude.json` yourself:

   ```json
   {
     "mcpServers": {
       "scootware-driver": {
         "type": "stdio",
         "command": "python",
         "args": ["-m", "drv_mcp"],
         "cwd": "C:\\Users\\you\\path\\to\\Driver\\DRV-MCP"
       }
     }
   }
   ```

## Coexistence with the ImGui control center

The driver only attaches to one process called `scootware.exe`. The MCP
will **terminate any existing `scootware.exe`** on startup (e.g. your
`IPC-Interface/scootware.exe` ImGui control center) so its helper can
take that slot. Close the GUI before opening an MCP session if you care
about a graceful shutdown.

To change this, set `SessionConfig.kill_existing = False` in
`drv_mcp/server.py`.

## Tools

### Session

| Tool | Purpose |
| --- | --- |
| `driver_status` | Helper PID, IPC VA, driver PING result. |
| `wait_for_driver` | Block until the driver responds to PING. |
| `driver_shutdown` | Send `CMD_SHUTDOWN`, unload the driver, close session. |

### Process discovery & introspection

| Tool | Purpose |
| --- | --- |
| `list_processes` | Toolhelp32 enumeration with optional name filter. |
| `find_pid` | Find a PID by name (local enum or driver-side). |
| `get_base_address` | Main module base of a target process. |
| `get_peb` | PEB address (target's VA). |
| `get_module_base` | Module load base by name (e.g. `"ntdll.dll"`). |
| `resolve_dtb` | CR3 / DTB for a process. |
| `get_guarded_region` | EAC `TnoC` big-pool guarded region. |

### Memory R/W

| Tool | Purpose |
| --- | --- |
| `read_memory` | Read bytes; returns hex + ASCII. |
| `dump_memory` | xxd-style hex+ASCII dump (up to 64 KiB). |
| `read_typed` | Read a primitive (u8/u16/u32/u64/i32/i64/f32/f64/cstring/wstring/ptr). |
| `write_memory` | Write bytes (destructive — double-check the VA). |
| `scan_memory` | Pattern scan with `??` wildcards in a VA range. |

### Dynamic analysis (debugger-class without debug APIs)

These tools give you debugger-like reach **without ever touching the
Windows debug surface**. No `DebugActiveProcess`, no `DbgUiRemoteBreakin`,
no `NtCreateDebugObject`, no hardware debug registers, no TF flag, no
page guards, no `SetWindowsHookEx`, no handle opening on the target.
Every observation goes through the CR3 R/W primitive; every mutation
goes through `write_memory`. If the CR3 R/W is clean, these are clean.

| Tool | Purpose |
| --- | --- |
| `list_modules` | Walk PEB→Ldr for every loaded DLL (name, base, size, entry). |
| `list_threads` | Enumerate threads via `NtQuerySystemInformation` (no handle). |
| `parse_pe` | DOS+NT header + section table for any loaded module. |
| `list_exports` | Walk export directory; supports name filter. |
| `list_imports` | Walk import descriptors; shows resolved IAT entries (spot hooks). |
| `resolve_export` | `GetProcAddress` equivalent — by module + function name. |
| `disassemble` | Capstone x86/x64 disassembly of N bytes at a VA. |
| `follow_pointer_chain` | Cheat-Engine style `base + offsets` with dereferences. |
| `search_strings` | Find ASCII + UTF-16LE printable strings in a VA range. |
| `watch_memory` | Poll a region for changes (data-breakpoint replacement). |
| `find_xrefs` | Find callers / RIP-relative references to a VA. |
| `patch_code` | Write bytes + record undo entry under a name. |
| `nop_code` | Convenience: NOP N bytes + record undo. |
| `restore_patch` / `list_patches` / `restore_all_patches` | Patch lifecycle. |
| `probe_memory_map` | Heuristic memory map via sparse-page probing. |

### Stealth process suspension (spin-patch)

| Tool | Purpose |
| --- | --- |
| `freeze_at_va` | Patch `EB FE` (JMP $-2, 2-byte infinite loop) at a VA. |
| `unfreeze` | Restore one freeze (or all for a PID). |
| `unfreeze_all` | Restore every active freeze. |
| `list_frozen` | Show every active freeze. |

Why this beats `SuspendThread`/`NtSuspendProcess`:

- **No handle** opened on the target (no `PROCESS_SUSPEND_RESUME`).
- **`WaitReason` stays normal** — threads aren't waiting, they're
  running the JMP instruction. AC code that polls for `WrSuspended` /
  `Suspended` will see nothing.
- **`SuspendCount` stays 0** — no kernel-managed suspend state to detect.
- **Seamless restore** — x86 cache coherency (MESI snoops the L1
  instruction cache) makes the executing core re-fetch from the new
  bytes immediately. The thread continues from the same RIP into the
  restored instruction.

⚠️ Pick the target VA carefully:

- **Always patch inside the target's own modules** (e.g. the game's
  main `.exe` `.text`). NEVER patch shared system DLLs (`ntdll`,
  `kernel32`, `user32`) — those physical pages are COW-shared via
  KnownDlls and writing through the CR3 pipe corrupts every process
  that shares them.
- A function that the main thread hits every frame freezes only the
  main thread. A function that every worker calls (rare) would freeze
  more. Use `list_threads` to identify the busy thread by `state` and
  `user_time_us`.

### Pointer-offset hunting (Cheat-Engine class)

| Tool | Purpose |
| --- | --- |
| `value_scan_new` | Start a typed scan (u8…f64) for a known value in a region. |
| `value_scan_filter` | Narrow the candidate set by re-reading + comparing. |
| `value_scan_list` | Show current candidates + last-seen values. |
| `value_scan_delete` / `value_scan_all` | Scan lifecycle. |
| `find_pointers_to` | Find every 8-byte aligned pointer in a region matching a target VA (with optional tolerance). |
| `snapshot_save` | Capture a labelled byte snapshot of a region. |
| `snapshot_diff_live` | Diff a snapshot against current memory. |
| `snapshot_diff` | Diff two snapshots against each other. |
| `snapshot_list` / `snapshot_delete` | Snapshot store lifecycle. |

**`value_scan_filter` operators**: `eq`, `ne`, `gt`, `lt`, `range`,
`changed`, `unchanged`, `increased`, `decreased`.

The hunt workflow for finding a static pointer chain to a dynamic value
(e.g. "where does the game store my health?"):

1. Find the heap range: `probe_memory_map(pid, 0x10000000000, 0x20000000000, step=0x100000)`.
2. Initial scan: `value_scan_new(pid, value=100.0, type='f32', region_start=heap, region_size=heap_size)`.
3. Take damage; health is now 75: `value_scan_filter(scan_id, 'eq', 75.0)`.
4. Heal up; health is now 100: `value_scan_filter(scan_id, 'eq', 100.0)`.
5. Repeat until one survivor → that's the leaf VA, call it `L`.
6. Walk back: `find_pointers_to(pid, heap, heap_size, L)` → list of
   addresses `A` holding pointers to `L`.
7. For each `A`, repeat `find_pointers_to(pid, heap, heap_size, A)` to
   find addresses `B` pointing to `A`. Stop when an address `X` falls
   inside a module's `.data`/`.rdata` (check via `parse_pe` sections).
8. The chain is `module_base + (X - module_base) → ... → L`.

All address parameters accept either an integer or a hex string
(`"0x7ff8aabb1234"`). The `use_cr3` flag (default `True`) routes
reads/writes through the CR3 physical-memory pipeline, bypassing
EAC's MmCopyVirtualMemory hooks; set it to `False` for the
conventional path when you don't care about anti-cheat detection.

## Examples

In a Claude Code conversation after the server is registered:

```
"Find notepad.exe and dump its main module's first 256 bytes."
```

Under the hood the agent calls:

1. `find_pid(process_name="notepad.exe")` → `{"pid": 12345, ...}`
2. `get_base_address(pid=12345)` → `{"base_address": "0x7FF7AABB0000", ...}`
3. `dump_memory(pid=12345, address="0x7FF7AABB0000", size=256)` → formatted hex dump

```
"Resolve CR3 for the EAC-protected client and grep its .text for the
pattern '48 8B 05 ?? ?? ?? ?? 48 85 C0'."
```

1. `find_pid(process_name="client.exe")`
2. `resolve_dtb(pid=...)`
3. `parse_pe(pid=..., module_name="client.exe")` — gives `.text` RVA + size
4. `scan_memory(pid=..., start_address=..., region_size=...,
                pattern_hex="48 8B 05 ?? ?? ?? ?? 48 85 C0")`

```
"Find every place in client.exe that calls NtAllocateVirtualMemory and
NOP out the first one for 30 seconds."
```

1. `resolve_export(pid, "ntdll.dll", "NtAllocateVirtualMemory")` → target VA
2. `parse_pe(pid, module_name="client.exe")` → `.text` range
3. `disassemble(pid, .text_va, .text_size)` and search for `call <target>`
   (or scan_memory for `E8 ?? ?? ?? ??` + relative-offset arithmetic)
4. `nop_code(pid, call_va, 5, name="alloc_block")`
5. `watch_memory(pid, some_state_addr, 8, duration_seconds=30)`
6. `restore_patch("alloc_block")`

```
"What hooks are installed on the IAT of client.exe? Compare bound_va
against the source DLL's image range."
```

1. `list_imports(pid, module_name="client.exe")`
2. For each function, check whether `bound_va` falls inside the source
   module's base..base+size (use `list_modules` to get bounds). Anything
   that doesn't is a redirected import — i.e., a hook.

```
"Track changes to player health (a 4-byte float) for 10 seconds."
```

1. `follow_pointer_chain(pid, base=GameModuleBase,
                          offsets=[0x340A8B0, 0x18, 0x40])` → health addr
2. `watch_memory(pid, health_addr, 4, duration_seconds=10,
                  poll_interval_ms=20)` → timeline of changes

```
"Freeze the game's main thread without it knowing, scan memory for a
specific health value, and resume."
```

1. `list_threads(pid)` → identify the busy thread (state=Running, high
   user_time_us). Its `start_address` is in the game's module.
2. `list_modules(pid)` → resolve which module that start_address is in.
3. `parse_pe(pid, module_name="game.exe")` → find `.text` range.
4. `disassemble(pid, address=<some hot function>, byte_count=...)` to
   pick a stable freeze point (e.g. function prologue).
5. `freeze_at_va(pid, address=<chosen VA>, note="for health scan")`.
6. `value_scan_new(pid, value=100.0, type_name="f32",
                    region_start=heap_start, region_size=heap_size)`.
7. `unfreeze(pid)` to resume the game.
8. Trigger damage; re-`freeze_at_va`; `value_scan_filter(scan_id, "eq", 75.0)`.
9. Repeat until one candidate survives → leaf address `L`.

```
"Find a static pointer chain from the main module's .data to that
health address L."
```

1. `find_pointers_to(pid, heap_start, heap_size, target_va=L)` → list of
   addresses `A1, A2, ...` that hold pointers to `L`.
2. For each `A`, `find_pointers_to(pid, ..., target_va=A)` → addresses `B`.
3. Stop expanding when a result address falls inside the main module's
   `.data`/`.rdata` sections (cross-reference with `parse_pe`).
4. The pointer chain is `module.data + (B - module.data) → A → L`.

```
"Who calls NtAllocateVirtualMemory in this process?"
```

1. `resolve_export(pid, "ntdll.dll", "NtAllocateVirtualMemory")` → target VA.
2. `list_modules(pid)` to pick the suspect module.
3. `parse_pe(pid, module_base=…)` → its `.text` range.
4. `find_xrefs(pid, target_va=…, scan_start=.text_va, scan_size=.text_size)`
   → every call/jmp/RIP-relative reference.

## File layout

```
DRV-MCP/
├── drv_mcp/
│   ├── __init__.py
│   ├── __main__.py       # python -m drv_mcp
│   ├── server.py         # FastMCP server + 47 tool definitions
│   ├── session.py        # Helper-process + shared-memory lifecycle
│   ├── driver.py         # IPC arming protocol + command wrappers
│   ├── analysis.py       # ModuleWalker, PatchRegistry, MemoryWatcher, …
│   ├── hunting.py        # ValueScanner, PointerHunter, SnapshotStore, XrefFinder
│   ├── suspend.py        # ProcessFreezer (spin-patch suspend)
│   ├── threads.py        # NtQuerySystemInformation thread enum
│   ├── pe.py             # PE header / export / import parser
│   ├── disasm.py         # Capstone x86/x64 wrapper
│   ├── ipc.py            # ctypes mirror of shared_memory_ipc.h
│   └── win32.py          # Thin Win32 ctypes shims
├── helper/
│   ├── scootware_helper.c # Tiny C program — image name "scootware.exe"
│   ├── build.bat          # Build with cl.exe / VS 2022
│   └── scootware.exe      # (built artifact)
├── install.bat
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Stealth notes

The analysis tools are deliberately built to **not** trip standard
anti-cheat fingerprints. What we never do:

- Open a handle on the target (`OpenProcess` with any access)
- Call `DebugActiveProcess`, `WaitForDebugEvent`, `DbgUiRemoteBreakin`
- Create a debug object (`NtCreateDebugObject`)
- Touch hardware debug registers (`DR0`–`DR7`)
- Set the trap flag (`TF`) in EFLAGS / per-thread CONTEXT
- Install page guards (`PAGE_GUARD`) or VEH/SEH hooks in target
- Use `SetWindowsHookEx`, `SetThreadContext`, `GetThreadContext`
- Issue `NtQueryInformationProcess(ProcessDebugPort/DebugObjectHandle)`
  against the target

What we do:
- `read_memory` / `write_memory` through the driver's CR3+physical pipe
- Local syscalls that don't reference the target by handle (Toolhelp32
  for process enum, `GetModuleHandleW` only in our own process)

Detection surface = whatever the underlying CR3 R/W exposes. If the
driver is clean, the MCP is clean.

## Troubleshooting

- **`driver_attached` is `false` after `wait_for_driver`** — the kernel
  driver isn't loaded or didn't bind to scootware.exe. Reload `drv.sys`
  and re-run any tool to re-trigger session bring-up.
- **`Helper exited immediately with code 2`** — the helper couldn't
  open the file mapping. Usually means another `scootware.exe` instance
  raced ahead with an incompatible mapping name; set
  `SessionConfig.kill_existing=True` or close the other process.
- **All tool calls hit `STATUS_IPC_ERROR`** — the driver thinks the
  process you targeted is invalid, or the EPROCESS pointer got
  invalidated. Re-resolve the PID with `find_pid` and try again.
- **`READ_MEMORY timed out`** — the driver's worker is stuck (possibly
  attached to a dead process). Call `driver_shutdown` to force a
  re-establishment, then reload `drv.sys`.

## Extending

To add a new driver command (e.g. HWID spoofing or DLL injection
support):

1. Add the `CMD_*` constant and any per-command struct to
   `drv_mcp/ipc.py` (keep the layout in sync with the kernel header).
2. Add a wrapper method to `DriverClient` in `drv_mcp/driver.py`.
3. Add an `@mcp.tool()` function in `drv_mcp/server.py`.
