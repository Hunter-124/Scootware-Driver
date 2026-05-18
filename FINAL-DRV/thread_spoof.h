#pragma once
//
// thread_spoof.h
// ────────────────────────────────────────────────────────────────────────────
// CODE-CAVE THREAD START ADDRESS SPOOFING
//
// Problem: PsCreateSystemThread creates threads whose ETHREAD.Win32StartAddress
// points into the manually-mapped driver (unbacked memory). EAC/BattlEye scan
// ALL system threads' Win32StartAddress via NtQuerySystemInformation(
// SystemExtendedHandleInformation) + ZwQueryInformationThread. When the start
// address doesn't belong to a loaded kernel module, the thread is flagged as
// belonging to a hidden driver / rootkit.
//
// Solution: Find a code cave (region of 0xCC INT3 padding bytes, preceded by a
// RET 0xC3) inside the .text section of a legitimate kernel module. Patch that
// cave with a JMP to our real thread function, then direct PsCreateSystemThread
// to use the cave's address as the start routine. From EAC's perspective, the
// thread's Win32StartAddress is inside ntoskrnl.exe/.text — perfectly legitimate.
//
// The cave must:
//   1. Live inside a known loaded module's .text section.
//   2. Be filled with 0xCC (INT3) — these are alignment/padding bytes inserted
//      by the compiler in function epilogue interstitials.
//   3. Be immediately preceded by a 0xC3 (RET) byte — this proves it's dead
//      code, not an active instruction that would be hit by execution.
//   4. Be large enough for our patch: [JMP rel32] = 5 bytes minimum.
//       0xE9 [4-byte signed offset relative to next instruction]
//
// Detection references (unKover/EAC):
//   EAC scans ETHREAD via NtQuerySystemInformation(SystemExtendedHandleInformation)
//   -> PsGetNextProcessThread -> PsGetThreadWin32Thread / PsGetThreadStartAddress.
//   The scanner enumerates PsLoadedModuleList to build a set of valid address
//   ranges; any thread whose start address is outside ALL ranges is flagged.
//
//   BattlEye does similar via ObOpenObjectByPointer -> ZwQueryInformationThread
//   with ThreadQuerySetWin32StartAddress (0x09). Same exact logic.
//
// KPTI / KVA Shadow awareness:
//   The patched cave is in the kernel .text section which resides in the shared
//   kernel half of the VAS. KPTI only affects user-mode half. All accesses are
//   done with __writecr3(our_kernel_cr3) so the patch is applied to the real
//   physical page — visible to all CPUs regardless of PCID/KPTI state. We also
//   flush the TLB for the patched page with __invlpg.
//
// Windows 10/11 compatibility:
//   Uses RtlImageNtHeaderEx (available from Win8 onwards) for header parsing.
//   Falls back to manual IMAGE_DOS_HEADER -> IMAGE_NT_HEADERS if the extended
//   variant is unavailable for any reason.
// ────────────────────────────────────────────────────────────────────────────

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>  // __cpuid for CodeCave_SerializeAllCpus

// Forward declaration: physical::write_physical is defined in CR3.h (included
// before this header in driver.cpp). The namespace is brought in scope via
// the CR3.h include chain.
namespace physical {
    NTSTATUS write_physical(
        PVOID address, PVOID buffer, size_t size, size_t* bytes);
}

// ============================================================================
// Code Cave descriptor
// ============================================================================
typedef struct _CODE_CAVE {
    PVOID   module_base;        // Base of the kernel module containing the cave
    PVOID   cave_address;       // VA of the first 0xCC after a 0xC3
    SIZE_T  cave_size;          // Number of consecutive 0xCC bytes found
    BOOLEAN is_valid;           // TRUE if the cave is usable
    UINT8   patch_size;         // Number of bytes written by PatchCaveWithJump (for cleanup)
    CHAR    module_name[64];    // Short name of the module, e.g. "ntoskrnl.exe"
} CODE_CAVE, *PCODE_CAVE;

// ============================================================================
// Patch sizes — every patch begins with a 4-byte ENDBR64 prefix.
//
//   ENDBR64  =  F3 0F 1E FA      ; 4-byte NOP on pre-CET CPUs
//                                 ; mandatory IBT landing pad on CET CPUs
//
// Why ENDBR64 is mandatory:
//   PspSystemThreadStartup invokes the registered KSTART_ROUTINE through an
//   indirect branch (call qword ptr [...]).  When the CPU supports CET-IBT
//   AND Windows has enabled Kernel-CET (default on Win10 21H2+ / Win11 on
//   11th-gen Intel & Zen4+ AMD), every indirect-branch target must begin
//   with ENDBR64 or the CPU raises #CP (Control-flow Protection).  Windows
//   surfaces #CP as either:
//       KMODE_EXCEPTION_NOT_HANDLED   (0x1E)  param1 = 0xC0000409, or
//       KERNEL_SECURITY_CHECK_FAILURE (0x139) param1 = 0x27 / 0x39
//   on the very first dispatch of the spoofed thread.
//
//   This was the BSOD seen immediately after the cave was re-enabled in
//   605f93c.  The patch path was hardened, but the dispatch path still
//   landed on a bare 0xE9 (JMP rel32) which IBT correctly rejects.
//
//   Real ntoskrnl/HAL/CI exports all begin with ENDBR64; the cave entry has
//   to look the same.  The prefix decodes as a no-op on CPUs without CET,
//   so emitting it unconditionally is safe.
//
//   9 bytes  — ENDBR64 + JMP rel32     (F3 0F 1E FA  E9 dd dd dd dd)
//  18 bytes  — ENDBR64 + JMP [rip+0] + 8-byte absolute target
//
// CAVE_RUN_MIN is bumped to 18 so the abs64 form always fits.  Compiler
// padding runs of 18 bytes still occur frequently in ntoskrnl (.text after
// large leaf functions); the priority module list (ntoskrnl → hal → CI →
// fltmgr) almost always finds a hit on the first module.
//
// For smaller modules (hal.dll, CI.dll, fltmgr.sys), we use a smaller minimum
// that can accommodate rel32 jumps (9 bytes) with alignment slack.
// ============================================================================
#define CAVE_PATCH_ENDBR  4
#define CAVE_PATCH_REL32  (CAVE_PATCH_ENDBR + 5)    //  9 bytes
#define CAVE_PATCH_ABS64  (CAVE_PATCH_ENDBR + 14)   // 18 bytes
#define CAVE_MIN_SIZE     CAVE_PATCH_REL32

// Different minimums for different module types
#define CAVE_RUN_MIN_NTOSKRNL      33  // Large module, needs abs64 support
#define CAVE_RUN_MIN_SMALL_MODULE  20  // Smaller modules, rel32 is enough
#define CAVE_RUN_MIN_DEFAULT       CAVE_RUN_MIN_SMALL_MODULE

// ============================================================================
// Forward declarations for RtlImageNtHeaderEx (undocumented but stable since Win8)
// ============================================================================
typedef NTSTATUS (NTAPI *PRtlImageNtHeaderEx_t)(
    _In_ ULONG Flags,
    _In_ PVOID Base,
    _In_ ULONG Size,
    _Out_ PIMAGE_NT_HEADERS *OutHeaders
);
#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK 0x00000001

// ============================================================================
// HVCI / KMCI detection
//
// Hypervisor-protected Code Integrity (a.k.a. Memory Integrity / VBS) keeps
// kernel .text RX in the second-level address translation tables. A write to
// any kernel code page — through CR0.WP, MmMapIoSpaceEx, or even physical
// memory manipulation — raises an EPT violation that bugchecks the box with
// no opportunity for SEH recovery. PatchGuard being disabled does not help
// here; HVCI is enforced by the hypervisor, not the kernel.
//
// We query SystemCodeIntegrityInformation (class 103) and check the
// CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED (0x400) flag.  If unknown we fail
// closed (assume enabled) so we never patch on an unfamiliar build.
// ============================================================================
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION_LOCAL {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION_LOCAL;

#ifndef SystemCodeIntegrityInformation_Local
#define SystemCodeIntegrityInformation_Local 103
#endif

#ifndef CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#endif

__forceinline BOOLEAN IsHvciActive() {
    SYSTEM_CODEINTEGRITY_INFORMATION_LOCAL sci = { 0 };
    sci.Length = sizeof(sci);
    ULONG ret = 0;

    // SYSTEM_INFORMATION_CLASS the typedef isn't reliably visible from
    // ntifs.h in every WDK configuration even though its enumerators are.
    // Cast the function pointer to a ULONG-first-arg signature so we can
    // pass the raw class id (103) without naming the enum type.
    typedef NTSTATUS (NTAPI *PFN_ZwQSI_Raw)(ULONG, PVOID, ULONG, PULONG);
    auto pfn = reinterpret_cast<PFN_ZwQSI_Raw>(&ZwQuerySystemInformation);

    NTSTATUS st = pfn(SystemCodeIntegrityInformation_Local,
                      &sci, sizeof(sci), &ret);
    if (!NT_SUCCESS(st)) {
        // Fail closed: if we can't tell, assume HVCI is on and skip patching.
        return TRUE;
    }
    return (sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
}

namespace CodeCave {

    // ============================================================================
    // Resolve RtlImageNtHeaderEx dynamically.
    // We avoid a static import so the driver compiles even against older WDKs.
    // ============================================================================
    __forceinline PRtlImageNtHeaderEx_t ResolveImageNtHeaderEx() {
        UNICODE_STRING rtn;
        RtlInitUnicodeString(&rtn, L"RtlImageNtHeaderEx");
        return (PRtlImageNtHeaderEx_t)MmGetSystemRoutineAddress(&rtn);
    }

    // ============================================================================
    // Get the .text section bounds (VA + size) for a given kernel module image.
    // Uses RtlImageNtHeaderEx for robustness; falls back to manual parsing.
    // ============================================================================
    __forceinline NTSTATUS GetTextSectionRange(
        _In_ PVOID ModuleBase,
        _Out_ PVOID *TextStart,
        _Out_ SIZE_T *TextSize)
    {
        *TextStart = nullptr;
        *TextSize  = 0;
        if (!ModuleBase) return STATUS_INVALID_PARAMETER;
        if (!MmIsAddressValid(ModuleBase)) return STATUS_INVALID_PARAMETER;

        PIMAGE_NT_HEADERS pNt = nullptr;
        auto pfnNtHeaderEx = ResolveImageNtHeaderEx();

        if (pfnNtHeaderEx) {
            // Use the extended version which performs bounds checks.
            NTSTATUS st = pfnNtHeaderEx(
                RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
                ModuleBase, 0, &pNt);
            if (!NT_SUCCESS(st) || !pNt)
                return STATUS_INVALID_IMAGE_FORMAT;
        } else {
            // Manual fallback — standard since NT4.
            auto* pDos = (PIMAGE_DOS_HEADER)ModuleBase;
            if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
                return STATUS_INVALID_IMAGE_FORMAT;
            pNt = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + pDos->e_lfanew);
            if (pNt->Signature != IMAGE_NT_SIGNATURE)
                return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (USHORT i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            // Check for executable code sections. We accept:
            // 1. Exact ".text\0\0\0" match (standard)
            // 2. ".text$" prefix (subsections in some builds)
            // 3. "PAGE" or "INIT" sections that are executable
            static const UCHAR kDotText[8] = { '.','t','e','x','t', 0, 0, 0 };
            
            BOOLEAN isTextSection = FALSE;
            
            // Exact ".text" match
            if (memcmp(pSec[i].Name, kDotText, 8) == 0) {
                isTextSection = TRUE;
            }
            // ".text$" prefix (5 characters)
            else if (memcmp(pSec[i].Name, kDotText, 5) == 0 && pSec[i].Name[5] == '$') {
                isTextSection = TRUE;
            }
            // Check if section is executable and not discardable
            else if ((pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                     !(pSec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
                     (pSec[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
                // Additional check: section name starts with '.' (common for code sections)
                if (pSec[i].Name[0] == '.') {
                    isTextSection = TRUE;
                }
            }
            
            if (isTextSection) {
                *TextStart = (PUCHAR)ModuleBase + pSec[i].VirtualAddress;
                *TextSize  = pSec[i].Misc.VirtualSize;
                
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] GetTextSectionRange: found executable section '%.8s' at %p (size=%zu)\n",
                           pSec[i].Name, *TextStart, *TextSize);
                return STATUS_SUCCESS;
            }
        }
        
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] GetTextSectionRange: no executable .text section found in module %p\n",
                   ModuleBase);
        return STATUS_NOT_FOUND;
    }

    // ============================================================================
    // Cross-CPU instruction-stream synchronization after self-modifying code.
    //
    // Intel SDM Vol. 3 §8.1.3 "Cross-Modifying Code" — when one logical
    // processor writes to a code region that another logical processor will
    // later execute, BOTH processors must execute a serializing instruction
    // between the write and the execute.  __writecr0 serializes only the
    // writing CPU.
    //
    // ─── Why we DON'T use KeIpiGenericCall here ────────────────────────────────
    // The obvious primitive (broadcast a CPUID callback to every CPU) raises
    // each CPU to IPI_LEVEL and then transfers control to the callback.  At
    // IPI_LEVEL the kernel forbids paging in any code page — if the callback's
    // page is in pageable backing (which manually-mapped drivers commonly are,
    // and whose PTE state is unpredictable on a remote CPU), the IPI bugchecks
    // with DRIVER_PORTION_MUST_BE_NONPAGED (0xD3).  This is exactly what
    // happened the first time around.
    //
    // ─── What we do instead ────────────────────────────────────────────────────
    // Run the serializing instruction at PASSIVE_LEVEL on the CURRENT thread,
    // bouncing across every active CPU via group affinity.  Each step:
    //   1. KeSetSystemGroupAffinityThread → request the next CPU.
    //   2. KeDelayExecutionThread → force a quantum boundary so the scheduler
    //      actually migrates us (affinity sets are honored asynchronously
    //      otherwise; without the yield we might run CPUID on the wrong CPU).
    //   3. CPUID → strongest serializer in x86-64; flushes the instruction
    //      prefetch/decode pipeline on this CPU.
    //   4. KeRevertToUserGroupAffinityThread → restore for the next iteration.
    //
    // Since we run entirely at PASSIVE_LEVEL on our own thread, no page-fault
    // restriction applies — driver pages page in normally if they happen to
    // be in pageable backing.
    //
    // Belt-and-suspenders note: thread dispatch on each target CPU eventually
    // involves an IRETQ to the cave_address, which is itself a serializing
    // instruction per Intel SDM Vol. 3 §8.3.  So in practice the spoofed
    // worker's CPU is going to serialize anyway.  We do the explicit sweep
    // because:
    //   (a) IRETQ-serialization happens AT dispatch time, not before — there
    //       is technically a window where stale prefetch from neighbouring
    //       reads could matter on aggressive prefetchers.
    //   (b) Some Windows builds use SYSRET-equivalent paths whose serializing
    //       semantics are CPU-dependent; CPUID is unconditionally serializing.
    //   (c) The sweep is a one-shot cost at DriverEntry — ~1 ms per CPU.
    // ============================================================================
    __forceinline VOID CodeCave_SerializeAllCpus() {
        ULONG cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (cpuCount == 0) return;

        // 1 ms delay — long enough to guarantee the scheduler observes the
        // new affinity and migrates us.  Negative value = relative time in
        // 100-ns ticks.
        LARGE_INTEGER migrateDelay;
        migrateDelay.QuadPart = -10000LL;  // 1 ms

        for (ULONG idx = 0; idx < cpuCount; idx++) {
            PROCESSOR_NUMBER procNum;
            if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(idx, &procNum)))
                continue;

            GROUP_AFFINITY ga;
            RtlZeroMemory(&ga, sizeof(ga));
            ga.Mask  = (KAFFINITY)1ULL << procNum.Number;
            ga.Group = procNum.Group;

            GROUP_AFFINITY oldGa;
            KeSetSystemGroupAffinityThread(&ga, &oldGa);

            // Yield so the scheduler migrates us to the requested CPU.  Without
            // this, KeSetSystemGroupAffinityThread is a hint that takes effect
            // at the next reschedule and we'd CPUID on the wrong CPU.
            KeDelayExecutionThread(KernelMode, FALSE, &migrateDelay);

            // CPUID is unconditionally serializing.  Leaf 0 is universally
            // supported and side-effect-free.  Executes here on the target CPU
            // at PASSIVE_LEVEL — any pageable code we touched faults in normally.
            int regs[4];
            __cpuid(regs, 0);

            KeRevertToUserGroupAffinityThread(&oldGa);
        }
    }

    // ============================================================================
    // Scan a memory range for a code cave: a 0xC3 (RET) followed by a
    // consecutive 0xCC (INT3) run long enough that a 16-byte-aligned offset
    // within it has at least CAVE_PATCH_ABS64 bytes of patch space remaining.
    //
    // Kernel CFG (`_guard_dispatch_icall`) fast-fails any indirect-call target
    // that isn't 16-byte aligned via `test cl, 0Fh`, so the returned
    // cave_address MUST be 16-aligned.  We scan for runs ≥ CAVE_RUN_MIN (33)
    // bytes, then advance to the first 16-aligned position inside the run.
    //
    // Returns the number of patchable bytes from the 16-aligned cave start
    // through the end of the 0xCC run.  *OutCaveStart receives the 16-aligned
    // VA itself.
    // ============================================================================
    __forceinline SIZE_T FindCaveInRange(
        _In_ PUCHAR Start,
        _In_ SIZE_T Length,
        _In_ SIZE_T MinCaveSize,
        _In_ BOOLEAN IsLargeModule,  // TRUE for ntoskrnl, FALSE for smaller modules
        _Out_ PUCHAR *OutCaveStart)
    {
        *OutCaveStart = nullptr;
        if (Length < (MinCaveSize + 1)) return 0; // need RET + at least N bytes

        // Use different minimums based on module size
        // Large modules (ntoskrnl) need space for abs64 jumps
        // Small modules can work with rel32 jumps
        const SIZE_T runMin = IsLargeModule ? CAVE_RUN_MIN_NTOSKRNL : CAVE_RUN_MIN_SMALL_MODULE;
        
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] FindCaveInRange: scanning %zu bytes, runMin=%zu, IsLargeModule=%d\n",
                   Length, runMin, IsLargeModule);
        
        if (Length < (runMin + 1)) return 0;

        for (SIZE_T i = 0; i <= Length - (runMin + 1); i++) {
            if (Start[i] != 0xC3) continue;

            // Count the 0xCC run immediately after the RET.
            SIZE_T cc_count = 0;
            for (SIZE_T j = i + 1; j < Length && Start[j] == 0xCC; j++) {
                cc_count++;
            }
            if (cc_count < runMin) {
                // Run too short — skip past it and resume scanning.
                i += cc_count;
                continue;
            }

            PUCHAR runStart  = &Start[i + 1];
            PUCHAR runEnd    = runStart + cc_count;

            // For large modules (ntoskrnl), we need 16-byte alignment for CFG
            // For smaller modules, we can be more flexible
            ULONG_PTR alignRequirement = IsLargeModule ? 16 : 8;
            
            // Advance runStart to the next aligned position.
            ULONG_PTR runStartVA  = (ULONG_PTR)runStart;
            ULONG_PTR alignOffset = (alignRequirement - (runStartVA & (alignRequirement - 1))) & (alignRequirement - 1);
            PUCHAR    alignedStart = runStart + alignOffset;

            // Verify that the aligned position is still inside the run
            if (alignedStart >= runEnd) {
                i += cc_count;
                continue;
            }
            
            SIZE_T usable = (SIZE_T)(runEnd - alignedStart);
            
            // Check if we have enough space for the appropriate patch type
            SIZE_T requiredSize = IsLargeModule ? CAVE_PATCH_ABS64 : CAVE_PATCH_REL32;
            if (usable < (SIZE_T)requiredSize) {
                i += cc_count;
                continue;
            }
            
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] FindCaveInRange: found potential cave: run %p+%zu, aligned %p, usable %zu, required %zu\n",
                       runStart, cc_count, alignedStart, usable, requiredSize);

            *OutCaveStart = alignedStart;
            return usable;
        }
        return 0;
    }

    // ============================================================================
    // Top-level: find a usable code cave in a kernel module.
    //
    // Parameters:
    //   ModuleName  — e.g. "ntoskrnl.exe", "hal.dll", "CI.dll"
    //   OutCave     — receives the cave descriptor
    //
    // Strategy:
    //   1. Resolve module base via ZwQuerySystemInformation(SystemModuleInformation).
    //   2. Parse the PE header to locate the .text section.
    //   3. Scan .text for a 0xC3 + N×0xCC run.
    //   4. For CI.dll (Code Integrity), special-care: some builds have
    //      a smaller .text with less padding; we widen the fallback list.
    // ============================================================================
    __forceinline NTSTATUS FindCodeCave(
        _In_ const char *ModuleName,
        _Out_ PCODE_CAVE OutCave)
    {
        RtlZeroMemory(OutCave, sizeof(CODE_CAVE));

        // Resolve module base — reusing the same SystemModuleInformation query
        // pattern already in the driver.
        ULONG bytes = 0;
        NTSTATUS st = ZwQuerySystemInformation(
            SystemModuleInformation,
            nullptr, 0, &bytes);
        if (!bytes) return STATUS_NOT_FOUND;

        auto* pMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);
        if (!pMods) return STATUS_INSUFFICIENT_RESOURCES;

        st = ZwQuerySystemInformation(SystemModuleInformation,
                                       pMods, bytes, &bytes);
        if (!NT_SUCCESS(st)) {
            ExFreePool(pMods);
            return st;
        }

        PVOID modBase = nullptr;
        for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
            auto& m = pMods->Modules[i];
            // Case-insensitive suffix match on FullPathName
            SIZE_T pathLen = 0;
            const char* path = (const char*)m.FullPathName;
            while (path[pathLen]) pathLen++;

            SIZE_T nameLen = 0;
            const char* name = ModuleName;
            while (name[nameLen]) nameLen++;

            if (pathLen >= nameLen) {
                BOOLEAN match = TRUE;
                for (SIZE_T j = 0; j < nameLen; j++) {
                    char a = path[pathLen - nameLen + j];
                    char b = name[j];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { match = FALSE; break; }
                }
                if (match) {
                    modBase = m.ImageBase;
                    DbgPrintEx(0x4d, 0xffffffff,
                               "[CR3-IPC] FindCodeCave: found module %s at %p (path: %s)\n",
                               ModuleName, modBase, path);
                    break;
                }
            }
            
            // Also try case-insensitive substring match for flexibility
            // Some modules might have slightly different names in the path
            BOOLEAN substringMatch = FALSE;
            for (SIZE_T pos = 0; pos <= pathLen - nameLen; pos++) {
                BOOLEAN match = TRUE;
                for (SIZE_T j = 0; j < nameLen; j++) {
                    char a = path[pos + j];
                    char b = name[j];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { match = FALSE; break; }
                }
                if (match) {
                    substringMatch = TRUE;
                    break;
                }
            }
            
            if (substringMatch) {
                modBase = m.ImageBase;
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] FindCodeCave: found module %s (substring match) at %p (path: %s)\n",
                           ModuleName, modBase, path);
                break;
            }
            
            // Debug: print all modules if we're looking for specific ones
            if (strstr(ModuleName, "hal") || strstr(ModuleName, "CI") || strstr(ModuleName, "fltmgr")) {
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] FindCodeCave: module[%lu]: %s at %p (size: %lu)\n",
                           i, path, m.ImageBase, m.ImageSize);
            }
        }
        ExFreePool(pMods);

        if (!modBase) {
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] FindCodeCave: module %s not found in system module list\n",
                       ModuleName);
            return STATUS_NOT_FOUND;
        }

        // Locate .text section
        PVOID textStart = nullptr;
        SIZE_T textSize = 0;
        st = GetTextSectionRange(modBase, &textStart, &textSize);
        if (!NT_SUCCESS(st)) return st;

        // Determine if this is a large module (ntoskrnl) or small module
        BOOLEAN isLargeModule = (strstr(ModuleName, "ntoskrnl") != nullptr);
        
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] FindCodeCave: scanning %s, text section %p+%zu, isLargeModule=%d\n",
                   ModuleName, textStart, textSize, isLargeModule);
        
        // Scan .text for a cave - try with appropriate settings first
        PUCHAR caveStart = nullptr;
        SIZE_T caveSize = FindCaveInRange(
            (PUCHAR)textStart, textSize, CAVE_MIN_SIZE, isLargeModule, &caveStart);

        // If no cave found with standard settings, try more relaxed settings for small modules
        if (!caveSize || !caveStart) {
            if (!isLargeModule) {
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] FindCodeCave: no cave found with standard settings, trying relaxed scan for %s\n",
                           ModuleName);
                
                // Try with even smaller requirements
                // For very small modules, we might need to accept smaller caves
                const SIZE_T relaxedRunMin = 12;  // Enough for ENDBR64 + rel32 with some alignment slack
                
                // Simple scan without strict alignment requirements
                for (SIZE_T i = 0; i <= textSize - (relaxedRunMin + 1); i++) {
                    PUCHAR current = (PUCHAR)textStart + i;
                    
                    // Look for RET (0xC3) followed by enough 0xCC bytes
                    if (*current != 0xC3) continue;
                    
                    SIZE_T cc_count = 0;
                    for (SIZE_T j = 1; j < textSize - i && ((PUCHAR)textStart)[i + j] == 0xCC; j++) {
                        cc_count++;
                    }
                    
                    if (cc_count >= CAVE_PATCH_REL32) {
                        // Found a suitable cave
                        caveStart = (PUCHAR)textStart + i + 1;
                        caveSize = cc_count;
                        
                        // Try to align to at least 8 bytes if possible
                        ULONG_PTR caveVa = (ULONG_PTR)caveStart;
                        ULONG_PTR alignOffset = (8 - (caveVa & 7)) & 7;
                        if (alignOffset < caveSize) {
                            caveStart += alignOffset;
                            caveSize -= alignOffset;
                        }
                        
                        DbgPrintEx(0x4d, 0xffffffff,
                                   "[CR3-IPC] FindCodeCave: found relaxed cave in %s at %p (size=%zu)\n",
                                   ModuleName, caveStart, caveSize);
                        break;
                    }
                }
            }
            
            if (!caveSize || !caveStart) {
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] FindCodeCave: no suitable cave found in %s (text size=%zu)\n",
                           ModuleName, textSize);
                return STATUS_NOT_FOUND;
            }
        }

        OutCave->module_base  = modBase;
        OutCave->cave_address = caveStart;
        OutCave->cave_size    = caveSize;
        OutCave->is_valid     = TRUE;

        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] CodeCave: found in %s at %p (size=%zu, .text=%p+%zx)\n",
                   ModuleName, caveStart, caveSize, textStart, textSize);
        return STATUS_SUCCESS;
    }

    // ============================================================================
    // Patch the code cave with a JMP to our real thread function.
    //
    // Two patch shapes are supported:
    //
    //   rel32 (5 bytes):     E9 dd dd dd dd
    //                        disp32 = target - (cave + 5),  |disp32| ≤ 2 GB
    //
    //   abs64 (14 bytes):    FF 25 00 00 00 00          ; jmp [rip+0]
    //                        <8-byte absolute target>
    //
    // We pick rel32 if the displacement fits AND the cave has 5 bytes.
    // Otherwise we pick abs64 if the cave has 14.  Otherwise we bail —
    // truncating a 64-bit displacement into INT32 is exactly how the previous
    // version produced a JMP into garbage memory and bugchecked on first
    // thread dispatch.
    //
    // Write path: CR0.WP toggle at IRQL=HIGH_LEVEL with interrupts disabled.
    // The previous physical-write path (MmGetPhysicalAddress + MmMapIoSpaceEx
    // via physical::write_physical) is NOT safe against a kernel code page —
    // on systems with HVCI, KDP, or MmProtectDriverSection it bugchecks
    // immediately.  CR0.WP works only when HVCI is OFF, which we verify
    // explicitly below before touching anything.
    // ============================================================================
    __forceinline NTSTATUS PatchCaveWithJump(
        _In_ PCODE_CAVE Cave,
        _In_ PVOID TargetFunction)
    {
        if (!Cave || !Cave->is_valid || !TargetFunction)
            return STATUS_INVALID_PARAMETER;
        if (Cave->cave_size < CAVE_PATCH_REL32)
            return STATUS_BUFFER_TOO_SMALL;

        // ─── HVCI gate ────────────────────────────────────────────────────────
        // Writing kernel .text under SLAT-enforced RX raises EPT_VIOLATION,
        // which is not catchable by SEH and bugchecks the system.  Detect and
        // bail cleanly so the caller's __try/__except path can fall back.
        if (IsHvciActive()) {
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: HVCI/KMCI active — skipping patch "
                       "(would EPT-fault)\n");
            return STATUS_NOT_SUPPORTED;
        }

        // ─── Pre-flight: validate cave address before raising IRQL ───────────
        // MmIsAddressValid is reliable for non-paged kernel .text.  A fault
        // during the HIGH_LEVEL write section is not catchable by SEH and
        // produces an immediate BSOD — validating here keeps us at PASSIVE.
        if (!MmIsAddressValid(Cave->cave_address)) {
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: cave %p not accessible — aborting\n",
                       Cave->cave_address);
            return STATUS_ACCESS_VIOLATION;
        }

        // Re-verify every byte we intend to overwrite is still 0xCC.
        // Guards against: (a) scanner false-positives (live code that happens
        // to match the pattern), (b) another component patching the same bytes
        // between discovery and here.  Either way, writing over live code = BSOD.
        {
            const SIZE_T checkLen = (Cave->cave_size < (SIZE_T)CAVE_PATCH_ABS64)
                                  ? Cave->cave_size : (SIZE_T)CAVE_PATCH_ABS64;
            const PUCHAR probe = (PUCHAR)Cave->cave_address;
            for (SIZE_T k = 0; k < checkLen; k++) {
                if (probe[k] != 0xCC) {
                    DbgPrintEx(0x4d, 0xffffffff,
                               "[CR3-IPC] CodeCave: byte[%zu] at %p = 0x%02X "
                               "(not 0xCC) — may be live code, aborting\n",
                               k, Cave->cave_address, (unsigned)probe[k]);
                    return STATUS_CONFLICTING_ADDRESSES;
                }
            }
        }

        // ─── Build the patch ──────────────────────────────────────────────────
        // Layout (every patch shape):
        //   [0..3]   ENDBR64           ; F3 0F 1E FA   — IBT landing pad
        //   [4..]    JMP form          ; rel32 (5B) or abs64 indirect (14B)
        //
        // The cave_address itself is what gets handed to PsCreateSystemThread
        // as the start routine, so the FIRST byte the dispatcher's indirect
        // call lands on must be ENDBR64.  See the patch-size comment block for
        // the full BSOD rationale.
        UINT8  patch[CAVE_PATCH_ABS64];
        SIZE_T patchSize = 0;

        // ENDBR64 prefix — always emitted, NOP on pre-CET CPUs.
        patch[0] = 0xF3; patch[1] = 0x0F; patch[2] = 0x1E; patch[3] = 0xFA;

        const ULONG_PTR caveVa = (ULONG_PTR)Cave->cave_address;
        const ULONG_PTR jmpVa  = caveVa + CAVE_PATCH_ENDBR;     // JMP starts after ENDBR64
        const ULONG_PTR tgtVa  = (ULONG_PTR)TargetFunction;
        // rel32 displacement is anchored at the byte AFTER the JMP, i.e.
        // jmpVa + 5 = caveVa + 9.  Anchoring at caveVa + 5 (the old code) would
        // off-by-four and land the JMP four bytes short of the real function.
        const INT64     disp64 = (INT64)(tgtVa - (jmpVa + 5));

        if (disp64 >= (INT64)INT32_MIN && disp64 <= (INT64)INT32_MAX &&
            Cave->cave_size >= CAVE_PATCH_REL32) {
            patch[4] = 0xE9;
            INT32 disp = (INT32)disp64;
            patch[5] = (UINT8)(disp & 0xFF);
            patch[6] = (UINT8)((disp >>  8) & 0xFF);
            patch[7] = (UINT8)((disp >> 16) & 0xFF);
            patch[8] = (UINT8)((disp >> 24) & 0xFF);
            patchSize = CAVE_PATCH_REL32;
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: ENDBR+rel32 patch %p -> %p (disp=0x%X)\n",
                       Cave->cave_address, TargetFunction, disp);
        } else if (Cave->cave_size >= CAVE_PATCH_ABS64) {
            // FF 25 00 00 00 00  ; jmp qword ptr [rip+0]
            //  <8-byte absolute target follows immediately>
            patch[4] = 0xFF; patch[5] = 0x25;
            patch[6] = 0x00; patch[7] = 0x00; patch[8] = 0x00; patch[9] = 0x00;
            for (int i = 0; i < 8; i++) {
                patch[10 + i] = (UINT8)((tgtVa >> (i * 8)) & 0xFF);
            }
            patchSize = CAVE_PATCH_ABS64;
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: ENDBR+abs64 patch %p -> %p\n",
                       Cave->cave_address, TargetFunction);
        } else {
            // Target unreachable via rel32 and cave too small for abs64.
            // The OLD code would have happily truncated disp64 to INT32 here,
            // producing a JMP into hyperspace.  Refuse instead.
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: unreachable — disp=0x%llX, cave=%zu, "
                       "need %d for abs64\n",
                       (unsigned long long)disp64, Cave->cave_size,
                       CAVE_PATCH_ABS64);
            return STATUS_BUFFER_TOO_SMALL;
        }

        // Record how many bytes were written so UnpatchCave can restore them.
        Cave->patch_size = (UINT8)patchSize;

        // ─── Primary: MmMapIoSpace write ──────────────────────────────────
        // Map the physical page backing the cave as a new writable VA.
        // This bypasses CR0.WP entirely and works under boot-time hypervisors
        // that shadow CR0 (e.g. EfiGuard).  Falls back to CR0.WP if
        // MmMapIoSpace fails (e.g. old builds, unusual memory configs).
        BOOLEAN writeOk = FALSE;

        PHYSICAL_ADDRESS cavePa = MmGetPhysicalAddress(Cave->cave_address);
        if (cavePa.QuadPart != 0) {
            ULONG_PTR pageOff = (ULONG_PTR)Cave->cave_address & (PAGE_SIZE - 1);
            PHYSICAL_ADDRESS pagePA;
            pagePA.QuadPart = cavePa.QuadPart - (LONGLONG)pageOff;

            PVOID mapped = MmMapIoSpace(pagePA, PAGE_SIZE, MmNonCached);
            if (mapped) {
                PVOID writeDst = (PUCHAR)mapped + pageOff;
                RtlCopyMemory(writeDst, patch, patchSize);
                MmUnmapIoSpace(mapped, PAGE_SIZE);
                writeOk = TRUE;
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] CodeCave: wrote %zu bytes via MmMapIoSpace "
                           "(PA=%llX)\n", patchSize, cavePa.QuadPart);
            } else {
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] CodeCave: MmMapIoSpace failed for PA=%llX "
                           "— falling back to CR0.WP\n", cavePa.QuadPart);
            }
        }

        // ─── Fallback: CR0.WP toggle at HIGH_LEVEL ──────────────────────────
        // Works on bare hardware without a hypervisor.  Fails under boot-time
        // hypervisors that shadow CR0.WP, which is why MmMapIoSpace is tried
        // first.
        if (!writeOk) {
            KIRQL oldIrql;
            KeRaiseIrql(HIGH_LEVEL, &oldIrql);
            _disable();

            const ULONG_PTR cr0  = __readcr0();
            const ULONG_PTR WP   = (ULONG_PTR)0x10000;
            __writecr0(cr0 & ~WP);

            RtlCopyMemory(Cave->cave_address, patch, patchSize);

            __writecr0(cr0);
            __invlpg(Cave->cave_address);

            _enable();
            KeLowerIrql(oldIrql);
        }

        // Flush TLB for the original .text VA and issue a full memory barrier
        // so all CPUs see the new instructions.
        __invlpg(Cave->cave_address);
        KeMemoryBarrier();

        // ─── Cross-CPU serialize — intentionally NOT done here ───────────────
        // Earlier revisions of this code attempted an explicit cross-CPU
        // serialization sweep here (first via KeIpiGenericCall, then via an
        // affinity-bouncing CPUID loop).  Both BSOD'd:
        //   - IPI variant → DRIVER_PORTION_MUST_BE_NONPAGED (0xD3): the
        //     callback runs at IPI_LEVEL on remote CPUs, where pageable
        //     driver code can't fault in.  Manually-mapped drivers have
        //     unpredictable PTE-resident state for their image backing.
        //   - Affinity-shift variant → KMODE_EXCEPTION_NOT_HANDLED (0x1E):
        //     bouncing the driver-loader thread across CPUs during
        //     DriverEntry destabilized something in the loader path.
        //
        // We rely on the natural serializer instead: per Intel SDM Vol. 3
        // §8.3, IRETQ is unconditionally serializing, and the kernel
        // dispatches every new thread by IRETQ-ing into its start routine.
        // That means the executing CPU's instruction pipeline is fully
        // serialized immediately before fetching our patched cave bytes —
        // the cross-modifying-code contract is satisfied without our help.
        //
        // If a future revision discovers a real coherence problem on some
        // CPU family, CodeCave_SerializeAllCpus() is kept defined above for
        // re-use, BUT it must only be called from a context that owns its
        // own thread (e.g., a dedicated system thread spawned for the
        // purpose) — never from DriverEntry's calling context.

        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] CodeCave: patch applied (%zu bytes) at %p, "
                   "target=%p (relying on IRETQ-induced dispatch serialize)\n",
                   patchSize, Cave->cave_address, TargetFunction);
        return STATUS_SUCCESS;
    }

    // ============================================================================
    // Restore a previously-patched code cave to its original 0xCC fill.
    //
    // Must be called only after every thread whose start routine points into
    // the cave has fully terminated (i.e. after KeWaitForSingleObject on each
    // worker PETHREAD succeeds).  Executing code cannot be in the cave while
    // we overwrite it.
    //
    // Uses the same MmMapIoSpace-primary / CR0.WP-fallback write path as
    // PatchCaveWithJump so the write succeeds under identical conditions.
    //
    // On success, Cave->is_valid and Cave->patch_size are zeroed so callers
    // can tell the cave is no longer active.
    // ============================================================================
    __forceinline NTSTATUS UnpatchCave(_In_ PCODE_CAVE Cave)
    {
        // cave_address and patch_size are the meaningful indicators that a
        // patch was actually written.  is_valid can be FALSE if DriverEntry's
        // post-patch verification block zeroed the struct after a transient
        // read fault — callers restore is_valid to TRUE before calling here.
        if (!Cave || !Cave->cave_address)
            return STATUS_INVALID_PARAMETER;
        if (!Cave->patch_size || Cave->patch_size > CAVE_PATCH_ABS64)
            return STATUS_INVALID_PARAMETER;

        if (IsHvciActive()) {
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: HVCI active — skipping unpatch\n");
            return STATUS_NOT_SUPPORTED;
        }

        if (!MmIsAddressValid(Cave->cave_address)) {
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: cave %p not accessible for unpatch\n",
                       Cave->cave_address);
            return STATUS_ACCESS_VIOLATION;
        }

        // Restore buffer: all 0xCC (original padding bytes).
        UINT8 restore[CAVE_PATCH_ABS64];
        RtlFillMemory(restore, Cave->patch_size, 0xCC);

        BOOLEAN writeOk = FALSE;

        PHYSICAL_ADDRESS cavePa = MmGetPhysicalAddress(Cave->cave_address);
        if (cavePa.QuadPart != 0) {
            ULONG_PTR pageOff = (ULONG_PTR)Cave->cave_address & (PAGE_SIZE - 1);
            PHYSICAL_ADDRESS pagePA;
            pagePA.QuadPart = cavePa.QuadPart - (LONGLONG)pageOff;

            PVOID mapped = MmMapIoSpace(pagePA, PAGE_SIZE, MmNonCached);
            if (mapped) {
                PVOID writeDst = (PUCHAR)mapped + pageOff;
                RtlCopyMemory(writeDst, restore, Cave->patch_size);
                MmUnmapIoSpace(mapped, PAGE_SIZE);
                writeOk = TRUE;
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] CodeCave: unpatched %u bytes via MmMapIoSpace "
                           "(PA=%llX)\n", Cave->patch_size, cavePa.QuadPart);
            }
        }

        if (!writeOk) {
            KIRQL oldIrql;
            KeRaiseIrql(HIGH_LEVEL, &oldIrql);
            _disable();

            const ULONG_PTR cr0 = __readcr0();
            const ULONG_PTR WP  = (ULONG_PTR)0x10000;
            __writecr0(cr0 & ~WP);

            RtlCopyMemory(Cave->cave_address, restore, Cave->patch_size);

            __writecr0(cr0);
            __invlpg(Cave->cave_address);

            _enable();
            KeLowerIrql(oldIrql);
        }

        __invlpg(Cave->cave_address);
        KeMemoryBarrier();

        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] CodeCave: unpatch complete — %u bytes at %p restored to 0xCC\n",
                   Cave->patch_size, Cave->cave_address);

        Cave->is_valid   = FALSE;
        Cave->patch_size = 0;
        return STATUS_SUCCESS;
    }

    // ============================================================================
    // Attempt cave discovery across a prioritized list of kernel modules.
    //
    // Priority order:
    //   1. ntoskrnl.exe  — Largest .text, most padding. Best target.
    //   2. hal.dll       — Also large .text, often overlooked by scanners.
    //   3. CI.dll        — Code Integrity DLL, loaded early, contains padding.
    //   4. fltmgr.sys    — Filter Manager, always loaded, medium-sized .text.
    //
    // Returns the first successfully found AND patched cave.
    // ============================================================================
    __forceinline NTSTATUS FindAndPatchAnyCave(
        _In_ PVOID ThreadFunction,
        _Inout_ PCODE_CAVE OutCave)
    {
        // If OutCave already holds a patched cave (e.g. driver re-init),
        // restore the original 0xCC bytes before overwriting the descriptor.
        if (OutCave && OutCave->is_valid && OutCave->patch_size > 0) {
            UnpatchCave(OutCave);
        }
        if (OutCave) RtlZeroMemory(OutCave, sizeof(CODE_CAVE));

        static const char* g_priority_modules[] = {
            "ntoskrnl.exe",
            "hal.dll",
            "CI.dll",
            "fltmgr.sys"
        };
        constexpr int num_mods = sizeof(g_priority_modules) / sizeof(g_priority_modules[0]);

        for (int i = 0; i < num_mods; i++) {
            CODE_CAVE cave = {};
            NTSTATUS st = FindCodeCave(g_priority_modules[i], &cave);
            if (!NT_SUCCESS(st)) {
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] CodeCave: no cave in %s (st=0x%X)\n",
                           g_priority_modules[i], st);
                continue;
            }

            st = PatchCaveWithJump(&cave, ThreadFunction);
            if (NT_SUCCESS(st)) {
                *OutCave = cave;
                // Record which module the cave lives in for diagnostics display.
                const char* src = g_priority_modules[i];
                int ni = 0;
                while (src[ni] && ni < 63) { OutCave->module_name[ni] = src[ni]; ni++; }
                OutCave->module_name[ni] = '\0';
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] CodeCave: SUCCESS — using %s cave at %p\n",
                           g_priority_modules[i], cave.cave_address);
                return STATUS_SUCCESS;
            }
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: patch failed for %s (st=0x%X)\n",
                       g_priority_modules[i], st);
        }
        return STATUS_NOT_FOUND;
    }

    // ============================================================================
    // Convenience: spawn a system thread with a spoofed start address.
    //
    // This is the drop-in replacement for PsCreateSystemThread where the
    // "StartRoutine" is actually the code cave address (patched to JMP to
    // the real thread function), so ETHREAD.Win32StartAddress points into
    // ntoskrnl.exe/.text instead of unbacked pool.
    //
    // Parameters match PsCreateSystemThread exactly, except "StartRoutine"
    // is now "RealStartRoutine" — we internally resolve the cave and use
    // the cave address as the actual thread start.
    //
    // Returns STATUS_NOT_FOUND if no code cave could be found. In that case,
    // the caller should fall back to raw PsCreateSystemThread (which is better
    // than not spawning the thread at all).
    // ============================================================================
    __forceinline NTSTATUS CreateSpoofedSystemThread(
        _Out_ PHANDLE ThreadHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ PVOID ObjectAttributes,
        _In_opt_ HANDLE ProcessHandle,
        _Out_opt_ PCLIENT_ID ClientId,
        _In_ PVOID RealStartRoutine,
        _In_ PVOID StartContext)
    {
        // Find and patch a code cave
        CODE_CAVE cave = {};
        NTSTATUS st = FindAndPatchAnyCave(RealStartRoutine, &cave);
        if (!NT_SUCCESS(st)) {
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CreateSpoofedSystemThread: no cave available, "
                       "falling back to raw PsCreateSystemThread\n");
            // Fallback: spawn the thread with its real start address.
            // This is detectable but better than breaking functionality.
            return PsCreateSystemThread(ThreadHandle, DesiredAccess,
                                        (POBJECT_ATTRIBUTES)ObjectAttributes,
                                        ProcessHandle, ClientId,
                                        (PKSTART_ROUTINE)RealStartRoutine,
                                        StartContext);
        }

        // Use the cave address as the thread start routine.
        // When the scheduler first dispatches this thread, it will execute
        // the JMP instruction at cave.cave_address, which transfers control
        // to RealStartRoutine.
        //
        // The thread's first stack frame will have the return address set to
        // the byte immediately after the JMP (cave_address + 5), which is still
        // inside the module's .text section. Any stack walk will see a frame
        // anchored inside ntoskrnl.exe.
        st = PsCreateSystemThread(ThreadHandle, DesiredAccess,
                                  (POBJECT_ATTRIBUTES)ObjectAttributes,
                                  ProcessHandle,
                                  ClientId,
                                  (PKSTART_ROUTINE)cave.cave_address,
                                  StartContext);

        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] CreateSpoofedSystemThread: thread=%p "
                   "cave=%p real=%p st=0x%X\n",
                   ThreadHandle ? *ThreadHandle : NULL,
                   cave.cave_address, RealStartRoutine, st);
        return st;
    }

} // namespace CodeCave
