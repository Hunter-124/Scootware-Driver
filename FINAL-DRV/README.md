# Kernel-Mode Read/Write driver base

**Educational Project Only**

Kernel-Mode Read/Write driver base featuring a custom CR3 decryption / directory table base bypass designed to work against modern anticheats such as Easy Anti-Cheat (EAC).

> ⚠️ Important: This project is strictly for educational and reverse engineering purposes only. Using kernel drivers for memory manipulation in online games may violate game terms of service and can result in permanent hardware bans or account suspensions. Use responsibly and only in controlled/test environments

---
### Features

- Full kernel-mode Read/Write primitive using physical memory access
- Custom CR3 decryption / Directory Table Base bypass (works on Windows 10/11)
- Process base address retrieval
- Guarded region (BigPool) finder for "TnoC" allocations
- Supports both standard and obfuscated EAC-protected processes
- Clean dispatch routines with strong security cookie
- Minimal and stable code base
- Proper driver unload and resource cleanup
- Built with latest Windows Driver Kit patterns

### Technical Overview

- Pure kernel-mode driver (`driver.cpp`)
- Uses **MmCopyMemory** (physical) + **MmMapIoSpaceEx** for safe read/write
- Advanced CR3 decryption via `_MMPFN` walking and self-referenced PTE scanning
- Leverages `KDDEBUGGER_DATA64` extraction from crash dump header for `MmPfnDatabase`
- Dynamic PTE/PDE/PPE/PXE base resolution
- `ZwQuerySystemInformation(SystemBigPoolInformation)` for guarded region detection
- IOCTL-based communication layer (`communication.hpp`)
- Strong security check (`0x83b5b69`) to prevent unauthorized access
- Supports Windows 1803 up to latest 22H2 builds (with fallback)

Made with ❤️ for the **reverse engineering and game hacking learning community**.
