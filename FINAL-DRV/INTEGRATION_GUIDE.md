//
// INTEGRATION_GUIDE.md
// ────────────────────────────────────────────────────────────────────────────
// How to integrate the two stealth modules into the existing CR3-IPC driver.
//
// Files created:
//   thread_spoof.h          — Code-cave thread start address spoofing (Task A)
//   syscall_stack_spoof.h   — Direct syscall + stack spoofing (Task B)
//
// ────────────────────────────────────────────────────────────────────────────
//
// STEP 1: In driver.cpp, add these includes near the top (after "hwid_spoofer.hpp"):
//
//   #include "thread_spoof.h"
//   #include "syscall_stack_spoof.h"
//
// STEP 2: In driver.cpp DriverEntry, replace the PsCreateSystemThread calls
//         (around line 3210-3230) with CodeCave::CreateSpoofedSystemThread.
//
//   OLD (detectable):
//     PsCreateSystemThread(&hDiscovery, THREAD_ALL_ACCESS, NULL, NULL, NULL,
//                          ipc_discovery_thread, NULL);
//     ...
//     PsCreateSystemThread(&hWorker, THREAD_ALL_ACCESS, NULL, NULL, NULL,
//                          ipc_worker_thread, (PVOID)(ULONG_PTR)i);
//
//   NEW (stealth):
//     CodeCave::CreateSpoofedSystemThread(&hDiscovery, THREAD_ALL_ACCESS,
//                          NULL, NULL, NULL,
//                          (PVOID)ipc_discovery_thread, NULL);
//     ...
//     CodeCave::CreateSpoofedSystemThread(&hWorker, THREAD_ALL_ACCESS,
//                          NULL, NULL, NULL,
//                          (PVOID)ipc_worker_thread, (PVOID)(ULONG_PTR)i);
//
//   Note: The function signatures are identical except the 6th parameter takes
//   PVOID instead of PKSTART_ROUTINE (the internal cast handles it).
//
// STEP 3: In manual_mapper.h, replace the ZwFreeVirtualMemory call in
//         ManualMapper::MapDllIntoProcess (around line 350) with the spoofed variant:
//
//   OLD:
//     ZwFreeVirtualMemory(NtCurrentProcess(), &pBase, &FreeSz, MEM_RELEASE);
//
//   NEW:
//     SpoofedNtFreeVirtualMemory(NtCurrentProcess(), &pBase, &FreeSz, MEM_RELEASE);
//
//   Also replace the ZwFreeVirtualMemory in ManualMapper::UnmapDll:
//
//   OLD:
//     ZwFreeVirtualMemory(NtCurrentProcess(), &MappedVa, &FreeSz, MEM_RELEASE);
//
//   NEW:
//     SpoofedNtFreeVirtualMemory(NtCurrentProcess(), &MappedVa, &FreeSz, MEM_RELEASE);
//
// STEP 4: For any other calls from the mapper that reference ntoskrnl (e.g.,
//         ZwAllocateVirtualMemory in MapDllIntoProcess), optionally wrap with
//         SpoofedSysCall<decltype(ZwAllocateVirtualMemory)>:
//
//     Status = SpoofedSysCall<decltype(ZwAllocateVirtualMemory)>(
//         ZwAllocateVirtualMemory,
//         NtCurrentProcess(), &pBase, 0, &AllocSz,
//         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//
//   This is OPTIONAL — ZwAllocateVirtualMemory is a one-time call and its
//   stack frame is transient. The critical frame is the mapper's body itself.
//
// ────────────────────────────────────────────────────────────────────────────
//
// COMPILATION NOTES:
//
// 1. The naked function SpoofCallThunk requires MSVC (/naked attribute).
//    If compiling with Clang/GCC, the #if defined(_MSC_VER) guards will
//    fall back to ZwFreeVirtualMemory (detectable but functional).
//
// 2. The inline assembly block in SpoofedNtFreeVirtualMemory uses __asm { }.
//    For x64 MSVC, inline assembly is NOT supported by default. You MUST
//    either:
//      a) Compile as a separate .asm file with MASM (ml64.exe) and link it, OR
//      b) Use a separate naked-function .c file with the thunk, OR
//      c) Use the MSVC intrinsic __writegsqword approach (preferred for
//         driver compilation — inline asm is banned in x64 MSVC!)
//
//    RECOMMENDED APPROACH (no inline asm):
//    Use the SpoofedSysCall<FnType> template which calls through the naked
//    C function SpoofCallThunk. Define SpoofCallThunk in a .asm file:
//
//    ;; spoof_thunk.asm
//    .CODE
//    EXTERN g_SpoofedTarget:QWORD
//    EXTERN g_SpoofedGadget:QWORD
//    SpoofCallThunk PROC
//        pop rax
//        mov r10, g_SpoofedTarget
//        push g_SpoofedGadget
//        push rax
//        jmp r10
//    SpoofCallThunk ENDP
//    END
//
//    Then compile with: ml64 /c spoof_thunk.asm
//    And link spoof_thunk.obj with the driver.
//
// 3. The SpoofedNtFreeVirtualMemory inline function uses __asm which won't
//    compile on x64 MSVC. Use the SpoofedSysCall template instead:
//
//    auto pfnFree = (PFN_NtFreeVirtualMemorySyscall)
//                   MmGetSystemRoutineAddress(&fnName);
//    return SpoofedSysCall<PFN_NtFreeVirtualMemorySyscall>(
//        pfnFree, ProcessHandle, BaseAddress, RegionSize, FreeType);
//
// ────────────────────────────────────────────────────────────────────────────
//
// SECURITY NOTES:
//
// 1. The code cave patch is applied via physical::write_physical which uses
//    MmMapIoSpaceEx. While this is a documented API, creating IoSpace mappings
//    on kernel .text pages may be flagged by advanced PatchGuard heuristics.
//    The alternative (MDL-based write) is equally detectable.
//
//    For maximum stealth, consider writing to the physical page via the
//    PFN database directly (swap PTE to mark the page writable, write, swap
//    back). This is more complex but evades MmMapIoSpaceEx detection.
//
// 2. The ret-gadget address is resolved once and cached. If ntoskrnl is
//    updated (hot-patch), the gadget may move. In practice, kernel modules
//    are never hot-patched on production systems.
//
// 3. The SSN for NtFreeVirtualMemory is cached statically after first use.
//    Windows updates that change the SSN will not be picked up until reboot.
//    The dynamic resolver (reading ntdll's stub) handles this for fresh boots.
//
// ────────────────────────────────────────────────────────────────────────────
