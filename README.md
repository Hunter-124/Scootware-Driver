# OVERVIEW

A kernel-mode read/write primitive driver base implementing CR3 register manipulation for interacting with physical memory directly and doing the virtual -> physical address translations. included as well is also a stack spoofing bypass that make it look like we are calling windows functions both documented and undocumented), from within ntoskrnl.exe, hal.dll, and other common windows binaries. this can easily be defeated though since most anticheat programs will see that the runtime has been tampered with and if they fully unwind the stack they can still see our driver. this driver is designed for anti debugging and built to withstanding dynamic analysis reverse engineering attempts.

---
#**Disclaimer***
there's a lot of broken stuff in here, but the read primatives should be undetected on be/eac/ricochet but im not sure about writes. untested and likely not working on any other platform besides windows 10 22h2 19045. its on you to disable hvci, secure boot, and use a patchguard bypass, as well as a driver loader/mapping method of your choice.

## Project Structure

```
Scootware-Driver/
├── FINAL-DRV/              Kernel-mode driver (driver.sys)
│   ├── driver.cpp          Main driver entry point, IOCTL dispatch,
│   │                       CR3 R/W primitives, PT injector,
│   │                       mouse implementation, thread spoofing,
│   │                       HWID spoofer, DLL injector, stealth pool alloc
│   ├── CR3.h               CR3 manipulation structures (PML4/PDE/PTE bitfields)
│   ├── communication.hpp   IOCTL protocol and shared IPC structures
│   ├── defines.h / definitions.hpp  Constants, offsets, macros
│   ├── device_profile.cpp  HWID spoofer (device-profile-level spoofing)
│   ├── device_profile.hpp
│   ├── mouse.cpp / mouse.hpp  Mouse input via MouClass/MouHID device extension scanning
│   ├── private_pool.h      Stealth-aware pool allocation (randomized tags)
│   ├── kdebug.h            Compiles-to-nothing logging macro (Release builds)
│   ├── kcfg_patch.h        KCFG bitmap layout probe and bit-flip helper
│   ├── thread_ctx.h        Thread context manipulation utilities
│   ├── syscall_stack_ctx.h Direct syscall + stack spoofing context
│   ├── driver.inf          Driver installation INF
│   ├── driver.vcxproj      Visual Studio driver project
│   ├── driver.slnx         Solution file
│   ├── build.bat           Build script (requires WDK)
│   └── README.md           Driver-specific documentation
│
├── DRV-MCP/                Model Context Protocol (MCP) server
│   ├── drv_mcp/            Python MCP tool implementations
│   │   ├── server.py       FastMCP server with 47+ tools
│   │   ├── driver.py       IPC arming protocol + command wrappers
│   │   ├── session.py      Helper-process + shared-memory lifecycle
│   │   ├── analysis.py     ModuleWalker, PatchRegistry, MemoryWatcher, ...
│   │   ├── hunting.py      ValueScanner, PointerHunter, SnapshotStore, XrefFinder
│   │   ├── suspend.py      ProcessFreezer (spin-patch suspend, no handle required)
│   │   ├── threads.py      NtQuerySystemInformation thread enumeration
│   │   ├── pe.py           PE header / export / import parser
│   │   ├── disasm.py       Capstone x86/x64 disassembly wrapper
│   │   ├── ipc.py          ctypes mirror of shared_memory_ipc.h
│   │   └── win32.py        Thin Win32 ctypes shims
│   ├── helper/             C helper (scootware_helper.cpp) + build.bat
│   │   └── build.bat       Builds helper with cl.exe (VS 2022)
│   ├── install.bat         Installs drv-mcp as an MCP server for Claude Code
│   ├── pyproject.toml      Python package metadata (mcp, capstone deps)
│   ├── requirements.txt
│   └── README.md           Full MCP tool documentation
│
├── IPC-Interface/          Usermode IPC interface and GUI tool
│   ├── CMakeLists.txt      CMake build configuration
│   ├── build.bat           Build script
│   ├── scootware.exe       ImGui-based GUI control center
│   ├── imgui.ini           ImGui configuration
│   ├── imgui-master/       ImGui library source (bundled)
│   ├── build/              Build output directory
│   └── ipc_speed_test.cpp  IPC throughput benchmark utility
│
├── LICENSE                 AGPL v3 (see below)
├── .mcp.json               MCP server registration for Claude Code
└── README.md               This file
```

---

## Architecture Overview

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        usermode (Ring 3)                           │
│                                                                     │
│  ┌──────────────┐   ┌──────────────────────┐   ┌────────────────┐  │
│  │  scootware.exe │   │  DRV-MCP (Python)    │   │ IPC Speed Test │  │
│  │  (ImGui GUI)   │   │  (MCP server for AI) │   │  (benchmark)   │  │
│  └──────┬───────┘   └──────────┬───────────┘   └───────┬────────┘  │
│         │                      │                         │           │
│         │   Shared Memory      │  stdio JSON-RPC        │           │
│         │   IPC (IPC_MAGIC)    │  via MCP protocol      │           │
│         ▼                      ▼                         ▼           │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                    drv.sys (Kernel, Ring 0)                   │  │
│  │                                                               │  │
│  │  ┌─────────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │  IOCTL Dispatch  │  │  Stealth Pool │  │  PT Injector    │  │  │
│  │  │  (driver.cpp)    │  │  Allocation   │  │  (known unstable)│  │  │
│  │  └────────┬────────┘  └──────────────┘  └─────────────────┘  │  │
│  │           │                                                    │  │
│  │  ┌────────▼─────────────────────────────────────────────────┐  │  │
│  │  │          CR3 Bypass + Physical Memory Primitives         │  │  │
│  │  │  • MmCopyMemory (physical)                               │  │  │
│  │  │  • MmMapIoSpaceEx                                        │  │  │
│  │  │  • CR3 swap / direct CR3 R/W via physical translation   │  │  │
│  │  │  • MmPfnDatabase walking for _MMPFN validation          │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  │  │
│  │  │  Mouse Input    │  │  HWID Spoofer  │  │  Thread Spoof  │  │  │
│  │  │  (MouClass ext  │  │  (device_profile│  │  (code-cave    │  │  │
│  │  │   scanning)     │  │   + registry)   │  │   BSOD-prone)  │  │  │
│  │  └────────────────┘  └────────────────┘  └────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Location | Purpose | Status |
|---|---|---|---|
| CR3 Decryption / DTB Bypass | `FINAL-DRV/driver.cpp` | Resolves target process CR3 via `_MMPFN` walking and self-referenced PTE scanning; supports KPTI-aware translation | Functional |
| Physical Memory R/W | `FINAL-DRV/driver.cpp` | `MmCopyMemory` + `MmMapIoSpaceEx` for raw physical read/write; CR3 swap path for EAC-bypassed access | Functional |
| PT Injector | `FINAL-DRV/driver.cpp` | Direct page-table manipulation to map physical memory into target CR3 | ⚠️ Unstable — known BSOD risk |
| Mouse Input | `FINAL-DRV/mouse.cpp` | Resolves MouClass/MouHID drivers via `ObReferenceObjectByName` + device extension scanning | ⚠️ Well-known detection method |
| Thread Spoofing | `FINAL-DRV/driver.cpp` | Code-cave–based ENDBR64 patch + KCFG bit-flip to spoof `ETHREAD.Win32StartAddress` | ⚠️ BSOD on bare metal |
| Process Hiding | `FINAL-DRV/driver.cpp` | PPL-targeted stealth pool allocation + pool-tag obfuscation | Functional (limited) |
| HWID Spoofer | `FINAL-DRV/device_profile.cpp` | Device-profile-level spoofing via registry writes + service callback resolution | Functional |
| MCP Server | `DRV-MCP/` | Python MCP server exposing driver to AI agents for debugging and dynamic analysis | Functional |
| IPC GUI | `IPC-Interface/` | ImGui-based usermode control center (`scootware.exe`) with shared-memory protocol | Functional |

### IPC Protocol

Usermode ↔ kernel communication uses a shared-memory IPC buffer identified by `IPC_MAGIC` (`0xCDA1F2B5C8E2AE13ULL` — a high-entropy 64-bit value with all bytes outside printable ASCII range, defeating naïve string scanners). The protocol supports multi-slot concurrent operations (up to 16 slots, 4 KiB each) with commands for memory read/write, DTB resolution, PEB/module enumeration, mouse input, DLL injection, HWID spoofing, and stealth diagnostics.

---

## Build Prerequisites

### Required Tools

| Tool | Version | Notes |
|---|---|---|
| **Visual Studio** | 2022 (17.x) | Desktop development with C++ workload |
| **Windows Driver Kit (WDK)** | Matching VS version (10.0.xxxx) | Must match Windows SDK version |
| **Windows SDK** | 10.0.xxxx | Bundled with WDK installation |
| **Python** | ≥ 3.10 | Required for DRV-MCP server |

### Building the Driver

1. Open `FINAL-DRV/driver.slnx` in Visual Studio (2022)
2. Select **Release | x64** configuration
3. Build the `driver` project — outputs `driver.sys` to `FINAL-DRV/x64/Release/`
4. Or use the batch script:
   ```cmd
   FINAL-DRV\build.bat
   ```
   This also copies `driver.sys` to the repo `BIN\` directory as both `driver.sys` and `drv.sys`.

### Building the MCP Server

```cmd
DRV-MCP\install.bat
```

This builds the C helper (`scootware_helper.cpp`), installs the Python package from PyPI, and registers the MCP server with Claude Code. Manual registration is also supported by editing `%USERPROFILE%\.claude.json`.

### Building the IPC GUI

```cmd
IPC-Interface\build.bat
```

Requires CMake and a compatible C++ compiler. Uses the bundled ImGui library.

---

## Usage Guidance

### For Reverse Engineering / Research

1. **Build and load** the kernel driver (`drv.sys`) on a test VM or isolated bare-metal system with DSE/PatchGuard disabled (e.g., via EfiGuard compat module).
2. **Run** `scootware.exe` (the ImGui GUI) from `IPC-Interface/` to establish a driver session and interact with the CR3 R/W primitives.
3. **For AI-assisted analysis**, use the DRV-MCP server with Claude Code or Claude Desktop. The MCP exposes 47+ tools for process discovery, memory R/W, dynamic analysis (disassembly, pointer hunting, snapshot diffing, stealth process suspension), and patch management — all operating through the CR3 physical-memory pipe without touching Windows debug APIs.
4. **See `DRV-MCP/README.md`** for full tool documentation and usage examples.

### For Educational Purposes

This codebase is intended to help you understand:
- How CR3-based isolation works and how it can be bypassed
- Physical memory manipulation via `MmCopyMemory` and `MmMapIoSpaceEx`
- PEB/TEB/EPROCESS structure traversal for process introspection
- Kernel pool allocation hiding (stealth pool tags)
- Direct syscall and stack-spoofing techniques
- Code-cave patching and KCFG bypass mechanics
- Mouse driver internals and device extension structures

---

## Disclaimer

**Game cheating is a violation of terms of service.**

Using this driver (or any kernel-mode memory manipulation tool) in online games:

- Violates the terms of service of virtually all online games (including but not limited to EAC-protected titles).
- May result in **permanent hardware bans** (HWID bans), account suspensions, or other enforcement actions.
- Exposes users to legal risk, as game publishers actively pursue legal action against cheat developers and distributors.

The maintainers of this project are not responsible for any consequences arising from misuse of this software. All features are provided for educational research in authorized, isolated environments only.

---

## Attribution

- **Mouse input implementation** in `FINAL-DRV/mouse.cpp` references the [norsefire](https://github.com/nbqofficial/norsefire) project for the `ObReferenceObjectByName` + MouClass/MouHID device extension scanning technique.
- **CR3 decryption / DTB bypass** techniques leverage documented Windows kernel structures (`_MMPFN`, `KDDEBUGGER_DATA64`, PML4/PDE/PTE bitfields) as published in the Windows internals community and `ntinternals` documentation.
- **Stealth pool allocation** (`private_pool.h`) uses randomized pool tags and kernel API resolution to avoid detection via `SystemBigPoolInformation` queries.
- **DRV-MCP** (`drv_mcp/server.py`) uses the [Model Context Protocol](https://modelcontextprotocol.io) (MCP) framework and the `mcp` Python package for AI-agent integration.
- **Capstone** disassembly engine (`drv_mcp/disasm.py`) is used for x86/x64 disassembly in the MCP analysis tools.

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See the bundled `LICENSE` file for the full license text. Key terms:

- **Source code must be made available** to any user who interacts with this software over a network.
- **Copyleft**: modifications and derivative works must also be licensed under AGPL v3.
- **No warranty**: the software is provided "as is" without any warranty of any kind.

> If you are redistributing or offering this software as a service, you must comply with the AGPL's network-copyleft provisions, including providing access to the complete corresponding source code.

---

## ⚠️ Known Issues

This project contains several features with known stability or detection problems. Be aware before relying on any of them.

### Page-Table (PT) Injector

The PT injector has **known stability issues**. It operates by directly manipulating page-table structures to map physical memory into a target's CR3 context. This is inherently fragile — any race condition, incorrect PTE/PDE permission bit, or unexpected page-table state can trigger a kernel panic (BSOD). It is not yet suitable for production or reliability-sensitive workloads.

### Mouse Input Implementation

The mouse input feature uses `ObReferenceObjectByName` to resolve `\Driver\MouClass` and `\Driver\MouHID` driver objects, then walks device extensions to locate the mouse service callback and device object. This is a **well-known anti-cheat detection surface**. EAC and similar systems scan for these exact patterns (device extension pointer chasing on MouClass/MouHID) and flag any kernel module that performs them. Use of this method will be detected by modern anti-cheat scanners.

### Thread Spoofing

Thread spoofing (code-cave–based start-address spoofing via `ETHREAD.Win32StartAddress`) is **known to BSOD on bare metal** hardware. The cave scanner, KCFG bitmap validation, and ENDBR64-prefix patching interact badly with real hardware firmware/UEFI environments, especially when combined with EfiGuard-style compat modules. The feature works reliably in VMs with a kernel debugger attached, but on bare metal it produces `KMODE_EXCEPTION_NOT_HANDLED (0x1E)` with no bugcheck arguments or minidump on some configurations. See `FINAL-DRV/THREAD_SPOOF_HANDOFF.md` for the full debugging history.

---

*Built for the reverse engineering and game hacking learning community. Use responsibly and ethically.*
