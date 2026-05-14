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
    CHAR    module_name[64];    // Short name of the module, e.g. "ntoskrnl.exe"
} CODE_CAVE, *PCODE_CAVE;

// ============================================================================
// Patch sizes:
//   5 bytes  — JMP rel32  (E9 dd dd dd dd)         used when |disp| <= 2 GB
//  14 bytes  — JMP [rip+0] + 8-byte absolute       used otherwise
//
// Scanner requires at least RUN_MIN consecutive 0xCC bytes to qualify a cave.
// Compiler-emitted INT3 padding is typically 8–15 bytes; demanding RUN_MIN=14
// rejects the vast majority of "0xC3 followed by an immediate that happens to
// be 0xCC" false positives that would otherwise have us patching live code.
// ============================================================================
#define CAVE_PATCH_REL32  5
#define CAVE_PATCH_ABS64  14
#define CAVE_MIN_SIZE     CAVE_PATCH_REL32
#define CAVE_RUN_MIN      14

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
            // .text section is always the first section in kernel modules,
            // but we check by name for safety.
            if (memcmp(pSec[i].Name, ".text", 5) == 0) {
                *TextStart = (PUCHAR)ModuleBase + pSec[i].VirtualAddress;
                *TextSize  = pSec[i].Misc.VirtualSize;
                return STATUS_SUCCESS;
            }
        }
        return STATUS_NOT_FOUND;
    }

    // ============================================================================
    // Scan a memory range for a code cave: a 0xC3 (RET) immediately followed by
    // at least `min_cave_bytes` of consecutive 0xCC (INT3).
    //
    // Returns the number of valid 0xCC bytes starting at (pRet + 1).
    // Set *out_cave_start to the first 0xCC after the RET.
    // ============================================================================
    __forceinline SIZE_T FindCaveInRange(
        _In_ PUCHAR Start,
        _In_ SIZE_T Length,
        _In_ SIZE_T MinCaveSize,
        _Out_ PUCHAR *OutCaveStart)
    {
        *OutCaveStart = nullptr;
        if (Length < (MinCaveSize + 1)) return 0; // need RET + at least N bytes

        // Require RUN_MIN consecutive 0xCC bytes to qualify — short runs
        // (1–4 bytes) can be immediates inside a real instruction, and
        // patching one of those replaces live code → BSOD on next dispatch.
        const SIZE_T runMin = (MinCaveSize > CAVE_RUN_MIN) ? MinCaveSize : CAVE_RUN_MIN;
        if (Length < (runMin + 1)) return 0;

        for (SIZE_T i = 0; i <= Length - (runMin + 1); i++) {
            if (Start[i] != 0xC3) continue;

            SIZE_T cc_count = 0;
            for (SIZE_T j = i + 1; j < Length && Start[j] == 0xCC; j++) {
                cc_count++;
            }
            if (cc_count >= runMin) {
                *OutCaveStart = &Start[i + 1];
                return cc_count;
            }
            // Resume scanning past the 0xCC run we just walked.
            i += cc_count;
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
                    break;
                }
            }
        }
        ExFreePool(pMods);

        if (!modBase) return STATUS_NOT_FOUND;

        // Locate .text section
        PVOID textStart = nullptr;
        SIZE_T textSize = 0;
        st = GetTextSectionRange(modBase, &textStart, &textSize);
        if (!NT_SUCCESS(st)) return st;

        // Scan .text for a cave
        PUCHAR caveStart = nullptr;
        SIZE_T caveSize = FindCaveInRange(
            (PUCHAR)textStart, textSize, CAVE_MIN_SIZE, &caveStart);

        if (!caveSize || !caveStart) return STATUS_NOT_FOUND;

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
        UINT8  patch[CAVE_PATCH_ABS64];
        SIZE_T patchSize = 0;

        const ULONG_PTR caveVa = (ULONG_PTR)Cave->cave_address;
        const ULONG_PTR tgtVa  = (ULONG_PTR)TargetFunction;
        const INT64     disp64 = (INT64)(tgtVa - (caveVa + 5));

        if (disp64 >= (INT64)INT32_MIN && disp64 <= (INT64)INT32_MAX &&
            Cave->cave_size >= CAVE_PATCH_REL32) {
            patch[0] = 0xE9;
            INT32 disp = (INT32)disp64;
            patch[1] = (UINT8)(disp & 0xFF);
            patch[2] = (UINT8)((disp >>  8) & 0xFF);
            patch[3] = (UINT8)((disp >> 16) & 0xFF);
            patch[4] = (UINT8)((disp >> 24) & 0xFF);
            patchSize = CAVE_PATCH_REL32;
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: rel32 patch %p -> %p (disp=0x%X)\n",
                       Cave->cave_address, TargetFunction, disp);
        } else if (Cave->cave_size >= CAVE_PATCH_ABS64) {
            // FF 25 00 00 00 00  ; jmp qword ptr [rip+0]
            patch[0] = 0xFF; patch[1] = 0x25;
            patch[2] = 0x00; patch[3] = 0x00; patch[4] = 0x00; patch[5] = 0x00;
            for (int i = 0; i < 8; i++) {
                patch[6 + i] = (UINT8)((tgtVa >> (i * 8)) & 0xFF);
            }
            patchSize = CAVE_PATCH_ABS64;
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] CodeCave: abs64 patch %p -> %p\n",
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

        // ─── Write at HIGH_LEVEL with WP cleared, interrupts off ─────────────
        // High IRQL keeps the scheduler off our back; _disable() blocks
        // maskable interrupts so no other code on this CPU runs while WP is
        // clear.  __writecr0 itself is a serializing instruction, which both
        // commits the WP change and flushes the prefetch queue.
        KIRQL oldIrql;
        KeRaiseIrql(HIGH_LEVEL, &oldIrql);
        _disable();

        const ULONG_PTR cr0  = __readcr0();
        const ULONG_PTR WP   = (ULONG_PTR)0x10000;   // CR0.WP = bit 16
        __writecr0(cr0 & ~WP);

        // RtlCopyMemory is a __movsb-style copy — non-paged, IRQL-agnostic,
        // and our destination is locked into kernel .text.
        RtlCopyMemory(Cave->cave_address, patch, patchSize);

        __writecr0(cr0);

        // Invalidate the TLB entry for the cave VA on this CPU.  __writecr0
        // serializes the pipeline (flushes prefetch/decode) but does NOT flush
        // TLB entries.  __invlpg is safe at HIGH_LEVEL — it is a single
        // serializing privileged instruction with no side effects.
        __invlpg(Cave->cave_address);

        _enable();
        KeLowerIrql(oldIrql);
        KeMemoryBarrier();

        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] CodeCave: patch applied (%zu bytes)\n", patchSize);
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
        _Out_ PCODE_CAVE OutCave)
    {
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
