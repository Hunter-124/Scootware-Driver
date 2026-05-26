#pragma once
//
// kcfg_patch.h
// ────────────────────────────────────────────────────────────────────────────
// KERNEL CONTROL-FLOW GUARD (KCFG) BITMAP-BIT PATCHING
//
// Marks a specific kernel-mode VA as a valid indirect-call target by setting
// the corresponding bit in nt!KiCfgBitMap.  Used to make our code-cave entry
// inside ntoskrnl.exe .text pass PspSystemThreadStartup's CFG-guarded
// indirect call.
//
// ─── Background ─────────────────────────────────────────────────────────────
// ntoskrnl.exe is compiled with /guard:cf, so every indirect call from kernel
// code goes through a thunk:
//     call    [nt!_guard_check_icall_fptr]   ; validate the target
//     call    rax                             ; the actual indirect call
//
// _guard_check_icall_fptr points to nt!_guard_dispatch_icall (real check) or
// nt!_guard_check_icall_nop (no-op, when KCFG is disabled — e.g. when a
// kernel debugger is attached).  When a debugger is NOT attached and
// EfiGuard / similar bootkits leave KCFG alone, the real check runs and any
// target that isn't in nt!KiCfgBitMap fast-fails the system.
//
// Function-entry addresses are pre-populated in the bitmap by the loader
// (from each module's IMAGE_LOAD_CONFIG_DIRECTORY guard-CF function table).
// Inter-function 0xCC padding regions — where our code cave lives — are
// not.  Hence the BSOD.
//
// ─── Bitmap layout (Win10 17763+ / Win11) ───────────────────────────────────
//   1 bit per 16 bytes of kernel code  →  16-byte granularity
//   byte_offset = address >> 7      (i.e. (addr / 16) / 8)
//   bit_in_byte = (address >> 4) & 7
//   bitmap[byte_offset] & (1 << bit_in_byte) == 1  →  valid call target
//
// The bitmap is a flat byte array referenced by nt!KiCfgBitMapBase, which
// is itself an RIP-relative load in the first few instructions of
// _guard_dispatch_icall.  Resolving the base is therefore:
//   1. Find nt!_guard_check_icall_fptr in ntoskrnl's export table.
//   2. Read it → address of _guard_dispatch_icall.
//   3. Pattern-scan _guard_dispatch_icall for the first
//        mov reg, qword ptr [rip+disp32]
//      instruction — that disp32 resolves to &KiCfgBitMapBase.
//   4. Read *KiCfgBitMapBase → the bitmap byte-array base.
//
// ─── Alignment requirement ──────────────────────────────────────────────────
// _guard_dispatch_icall's prologue does `test cl, 0Fh` and fast-fails any
// non-16-byte-aligned target.  Setting the bit is necessary but not
// sufficient — the call target itself must also be 16-byte aligned.  The
// cave scanner in thread_spoof.h has been updated to skip to the first
// 16-aligned offset within each 0xCC run; CAVE_RUN_MIN was bumped to 33 to
// guarantee at least 18 bytes of patch space after alignment in the worst
// case.
//
// ─── HVCI gate ──────────────────────────────────────────────────────────────
// The bitmap byte sits in kernel R/W .data.  On HVCI-enabled systems, even
// data pages can be SLAT-protected from kernel-mode writes.  The user runs
// the EfiGuard compatibility module which disables HVCI, but we re-verify
// to fail closed if the assumption ever breaks.
//
// ─── Layout validation ─────────────────────────────────────────────────────
// Before flipping any bit, the helper reads the bitmap bit for a known
// CFG-valid address (nt!PsCreateSystemThread).  If that bit is NOT set, our
// layout assumption is wrong and we abort rather than corrupt arbitrary
// kernel memory.
// ────────────────────────────────────────────────────────────────────────────

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include "kdebug.h"  // KIPC_LOG — compiles to no-op in Release

// Forward declaration — defined in driver.cpp; brings in the system module
// base by case-insensitive name match.
PVOID GetSystemModuleBase(const char *module_name);

// IsHvciActive is provided by thread_spoof.h (as a __forceinline).  This
// header MUST be included AFTER thread_spoof.h in the translation unit so
// the inline body is visible at the call site below.

namespace KcfgPatch {

    // ============================================================================
    // Generic PE export resolver.  Walks ntoskrnl's export table looking for a
    // name match.  Returns the resolved VA (function or data symbol).
    // ============================================================================
    __forceinline PVOID FindExport(_In_ PVOID modBase, _In_ const char* name) {
        if (!modBase || !MmIsAddressValid(modBase) || !name) return nullptr;

        auto* pDos = (PIMAGE_DOS_HEADER)modBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto* pNt = (PIMAGE_NT_HEADERS)((PUCHAR)modBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        auto& expDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDir.VirtualAddress || !expDir.Size) return nullptr;

        auto* pExport = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)modBase + expDir.VirtualAddress);
        auto* names   = (PULONG)((PUCHAR)modBase + pExport->AddressOfNames);
        auto* ords    = (PUSHORT)((PUCHAR)modBase + pExport->AddressOfNameOrdinals);
        auto* funcs   = (PULONG)((PUCHAR)modBase + pExport->AddressOfFunctions);

        for (ULONG i = 0; i < pExport->NumberOfNames; i++) {
            const char* fnName = (const char*)((PUCHAR)modBase + names[i]);
            if (strcmp(fnName, name) == 0) {
                return (PVOID)((PUCHAR)modBase + funcs[ords[i]]);
            }
        }
        return nullptr;
    }

    // ============================================================================
    // Resolve GuardCFCheckFunctionPointer from the PE Load Config Directory.
    //
    // On many Windows 10/11 builds, _guard_check_icall_fptr is NOT in the
    // export table — it's an internal data symbol whose VA is stored in
    // IMAGE_LOAD_CONFIG_DIRECTORY64.GuardCFCheckFunctionPointer (offset 0x70).
    // This is the authoritative source; the export table is a fallback.
    // ============================================================================
    __forceinline PVOID FindGuardCFCheckFPtrViaLoadConfig(_In_ PVOID modBase) {
        if (!modBase || !MmIsAddressValid(modBase)) return nullptr;

        auto* pDos = (PIMAGE_DOS_HEADER)modBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto* pNt = (PIMAGE_NT_HEADERS)((PUCHAR)modBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        auto& lcDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (!lcDir.VirtualAddress || !lcDir.Size) return nullptr;

        PUCHAR pLC = (PUCHAR)modBase + lcDir.VirtualAddress;
        if (!MmIsAddressValid(pLC)) return nullptr;

        ULONG lcSize = *(PULONG)pLC;
        // GuardCFCheckFunctionPointer is at offset 0x70 in the 64-bit load
        // config — need at least 0x78 bytes to cover it.
        if (lcSize < 0x78) return nullptr;

        if (!MmIsAddressValid(pLC + 0x70)) return nullptr;
        ULONGLONG guardCFCheckFPtr = *(PULONGLONG)(pLC + 0x70);
        if (!guardCFCheckFPtr) return nullptr;

        PVOID fptrLoc = (PVOID)(ULONG_PTR)guardCFCheckFPtr;
        if (!MmIsAddressValid(fptrLoc)) return nullptr;

        return fptrLoc;
    }

    // ============================================================================
    // Pattern-decode the first
    //     mov reg, qword ptr [rip + disp32]
    // instruction in _guard_dispatch_icall.  That instruction loads the
    // KiCfgBitMapBase pointer.  Return the address of KiCfgBitMapBase
    // (a PVOID* in ntoskrnl's data).
    //
    // Encodings handled:
    //     48 8B 05 dd dd dd dd   mov rax, [rip+disp32]
    //     48 8B 0D dd dd dd dd   mov rcx, [rip+disp32]
    //     48 8B 15 dd dd dd dd   mov rdx, [rip+disp32]
    //     48 8B 1D dd dd dd dd   mov rbx, [rip+disp32]
    //     48 8B 25 dd dd dd dd   mov rsp, [rip+disp32]   (unlikely but handled)
    //     48 8B 2D dd dd dd dd   mov rbp, [rip+disp32]
    //     48 8B 35 dd dd dd dd   mov rsi, [rip+disp32]
    //     48 8B 3D dd dd dd dd   mov rdi, [rip+disp32]
    //     4C 8B 05 dd dd dd dd   mov r8, [rip+disp32]
    //     ... and r9..r15 with REX.R set
    //
    // All share the pattern: REX.W (48 or 4C/4D/4E/4F) + 8B + modrm with
    // mod=00 rm=101 (which means [rip+disp32]) → low 3 bits of modrm == 5,
    // high 2 bits == 0  →  (modrm & 0xC7) == 0x05.
    // ============================================================================
    __forceinline PVOID* DecodeBitmapBaseRef(_In_ PUCHAR dispatchFunc) {
        if (!dispatchFunc || !MmIsAddressValid(dispatchFunc)) return nullptr;

        // Scan the first 96 bytes — the bitmap base load is always near the
        // start of _guard_dispatch_icall (it's the very first thing after
        // the alignment fast-fail branch).
        constexpr SIZE_T scanLen = 96;
        for (SIZE_T i = 0; i + 7 <= scanLen; i++) {
            UCHAR rex = dispatchFunc[i];
            UCHAR op  = dispatchFunc[i + 1];
            UCHAR modrm = dispatchFunc[i + 2];

            // REX prefix must have W=1 (bit 3 set).  Accept 48 (base), 4C
            // (REX.R for r8..r15 destination), 4D, 4E, 4F.
            if ((rex & 0xF8) != 0x48) continue;
            if (op != 0x8B) continue;
            // mod=00, rm=101  →  [rip + disp32]
            if ((modrm & 0xC7) != 0x05) continue;

            INT32 disp = *(PINT32)(dispatchFunc + i + 3);
            PUCHAR target = dispatchFunc + i + 7 + disp;
            if (MmIsAddressValid(target)) {
                return (PVOID*)target;
            }
        }
        return nullptr;
    }

    // ============================================================================
    // Resolved KCFG state.
    // ============================================================================
    typedef struct _CFG_RESOLVE {
        PVOID*  bitmap_base_loc;  // Address of KiCfgBitMapBase (PVOID* in .data)
        PUCHAR  bitmap_base;      // *bitmap_base_loc — the bitmap byte array
        PVOID   fptr_loc;         // Address of _guard_check_icall_fptr
        PVOID   fptr_value;       // Current value: real check or _nop
        PVOID   nop_func;         // Address of _guard_check_icall_nop (NULL if not exported)
        BOOLEAN kcfg_active;      // TRUE = real check is in use
        BOOLEAN valid;            // TRUE = full resolution succeeded
    } CFG_RESOLVE;

    // ============================================================================
    // One-shot CFG state resolution.  Caches via static so repeated calls are
    // free.  Safe at PASSIVE_LEVEL.
    // ============================================================================
    // Namespace-level cache so ResetResolveCache() can reach it.
    // selectany avoids multiple-definition errors if this header is ever
    // included from more than one TU.
    __declspec(selectany) CFG_RESOLVE g_cfg_cached = {};
    __declspec(selectany) BOOLEAN     g_cfg_resolved = FALSE;

    __forceinline void ResetResolveCache() {
        g_cfg_resolved = FALSE;
        RtlZeroMemory(&g_cfg_cached, sizeof(g_cfg_cached));
    }

    __forceinline CFG_RESOLVE Resolve() {
        if (g_cfg_resolved) return g_cfg_cached;

        CFG_RESOLVE info = {};

        PVOID ntosBase = GetSystemModuleBase("ntoskrnl.exe");
        if (!ntosBase) {
            g_cfg_cached = info; g_cfg_resolved = TRUE; return info;
        }

        // Primary: PE Load Config Directory — authoritative on all Win10/11
        // builds.  GuardCFCheckFunctionPointer (offset 0x70) holds the VA of
        // the function pointer that the CFG thunk calls through.
        PVOID fptrLoc = FindGuardCFCheckFPtrViaLoadConfig(ntosBase);
        KIPC_LOG(
                   "[CR3-IPC] KcfgPatch: LoadConfig lookup → fptrLoc=%p\n", fptrLoc);

        // Fallback: export table — older builds or unusual link configs.
        if (!fptrLoc) {
            fptrLoc = FindExport(ntosBase, "_guard_check_icall_fptr");
            if (!fptrLoc) fptrLoc = FindExport(ntosBase, "__guard_check_icall_fptr");
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: export fallback → fptrLoc=%p\n", fptrLoc);
        }

        if (!fptrLoc || !MmIsAddressValid(fptrLoc)) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: _guard_check_icall_fptr not found "
                       "— KCFG inactive on this build\n");
            info.valid = TRUE;
            info.kcfg_active = FALSE;
            g_cfg_cached = info; g_cfg_resolved = TRUE; return info;
        }
        info.fptr_loc = fptrLoc;
        info.fptr_value = *(PVOID*)fptrLoc;

        if (!info.fptr_value || !MmIsAddressValid(info.fptr_value)) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: fptr_value=%p invalid — KCFG inactive\n",
                       info.fptr_value);
            info.valid = TRUE;
            info.kcfg_active = FALSE;
            g_cfg_cached = info; g_cfg_resolved = TRUE; return info;
        }

        // Determine if fptr_value is the NOP stub or the real dispatch.
        // _guard_check_icall_nop is rarely exported, so probing the function
        // prologue is the primary detection method.
        //
        // NOP variant patterns:
        //   C3                    → ret
        //   F3 C3                 → rep ret (AMD retpoline-safe)
        //   48 8B C1 C3           → mov rax, rcx; ret (return target as-is)
        BOOLEAN isNop = FALSE;
        __try {
            PUCHAR fn = (PUCHAR)info.fptr_value;
            if (MmIsAddressValid(fn) && MmIsAddressValid(fn + 3)) {
                if (fn[0] == 0xC3 ||
                    (fn[0] == 0xF3 && fn[1] == 0xC3) ||
                    (fn[0] == 0x48 && fn[1] == 0x8B &&
                     fn[2] == 0xC1 && fn[3] == 0xC3)) {
                    isNop = TRUE;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (isNop) {
            info.nop_func = info.fptr_value;
            info.kcfg_active = FALSE;
            info.valid = TRUE;
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: fptr prologue is NOP — KCFG inactive\n");
            g_cfg_cached = info; g_cfg_resolved = TRUE; return info;
        }

        // Fallback: export-table NOP lookup (works on older builds).
        info.nop_func = FindExport(ntosBase, "_guard_check_icall_nop");
        if (!info.nop_func) info.nop_func = FindExport(ntosBase, "__guard_check_icall_nop");
        if (info.nop_func && info.fptr_value == info.nop_func) {
            info.kcfg_active = FALSE;
            info.valid = TRUE;
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: fptr == _nop export — KCFG inactive\n");
            g_cfg_cached = info; g_cfg_resolved = TRUE; return info;
        }

        // fptr_value is the real _guard_dispatch_icall — resolve bitmap.
        info.kcfg_active = TRUE;

        info.bitmap_base_loc = DecodeBitmapBaseRef((PUCHAR)info.fptr_value);
        if (!info.bitmap_base_loc) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: could not pattern-decode KiCfgBitMapBase "
                       "from _guard_dispatch_icall at %p\n", info.fptr_value);
            g_cfg_cached = info; g_cfg_resolved = TRUE; return info;
        }

        info.bitmap_base = *(PUCHAR*)info.bitmap_base_loc;
        if (!info.bitmap_base) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: KiCfgBitMapBase is NULL — dispatch "
                       "function will pass all targets; CFG effectively off\n");
            info.kcfg_active = FALSE;
            info.valid = TRUE;
            g_cfg_cached = info; g_cfg_resolved = TRUE; return info;
        }

        info.valid = TRUE;
        KIPC_LOG(
                   "[CR3-IPC] KcfgPatch: resolved — fptr_loc=%p fptr_val=%p nop=%p "
                   "bitmap_base_loc=%p bitmap=%p active=%u\n",
                   info.fptr_loc, info.fptr_value, info.nop_func,
                   info.bitmap_base_loc, info.bitmap_base, info.kcfg_active);

        g_cfg_cached = info; g_cfg_resolved = TRUE;
        return info;
    }

    // ============================================================================
    // Compute the (byte_offset, bit_in_byte) pair for a given VA under our
    // assumed bitmap layout (1 bit per 16 bytes of code).
    // ============================================================================
    __forceinline void ComputeBitPos(_In_ ULONG_PTR addr,
                                     _Out_ ULONG_PTR* byteOffset,
                                     _Out_ ULONG* bitInByte) {
        ULONG_PTR bitIdx = addr >> 4;   // 16-byte granularity
        *byteOffset = bitIdx >> 3;      // (addr / 16) / 8
        *bitInByte  = (ULONG)(bitIdx & 7);
    }

    // ============================================================================
    // Read the bitmap bit for a given address.  Returns -1 on access failure,
    // 0 if clear, 1 if set.
    // ============================================================================
    __forceinline int ReadBit(_In_ PUCHAR bitmapBase, _In_ ULONG_PTR addr) {
        ULONG_PTR byteOffset;
        ULONG bitInByte;
        ComputeBitPos(addr, &byteOffset, &bitInByte);

        PUCHAR byteAddr = bitmapBase + byteOffset;
        if (!MmIsAddressValid(byteAddr)) return -1;
        return (*byteAddr & (1u << bitInByte)) ? 1 : 0;
    }

    // ============================================================================
    // Validate the layout assumption by reading the bit for a known
    // CFG-valid export.  We use PsCreateSystemThread — always exported,
    // always a legitimate indirect-call target.  If its bit reads as 0 our
    // layout is wrong and we MUST refuse to write (else we'd corrupt
    // unrelated kernel memory).
    // ============================================================================
    __forceinline BOOLEAN ValidateLayout(_In_ PUCHAR bitmapBase) {
        PVOID ntosBase = GetSystemModuleBase("ntoskrnl.exe");
        if (!ntosBase) return FALSE;

        // Probe a few well-known CFG-valid exports.  At least one must be set.
        // We accept partial match: if any of these reads as set, layout is
        // confirmed.  We don't require all because a build might have
        // renamed/inlined one of them.
        static const char* kProbes[] = {
            "PsCreateSystemThread",
            "ExAllocatePool2",
            "KeQueryActiveProcessorCountEx",
            "MmGetSystemRoutineAddress",
        };
        constexpr int kNumProbes = sizeof(kProbes) / sizeof(kProbes[0]);

        for (int i = 0; i < kNumProbes; i++) {
            PVOID exp = FindExport(ntosBase, kProbes[i]);
            if (!exp) continue;
            int bit = ReadBit(bitmapBase, (ULONG_PTR)exp);
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: layout probe %s @ %p → bit=%d\n",
                       kProbes[i], exp, bit);
            if (bit == 1) return TRUE;
        }
        return FALSE;
    }

    // ============================================================================
    // Set the bitmap bit for `address`, making it a valid indirect-call target.
    //
    // Requirements (checked):
    //   - address is 16-byte aligned (CFG fast-fails otherwise even with bit set).
    //   - HVCI is off.
    //   - Bitmap is resolvable and layout passes validation.
    //
    // Returns:
    //   STATUS_SUCCESS         — bit set (or already set, or KCFG inactive).
    //   STATUS_INVALID_PARAMETER — address misaligned.
    //   STATUS_NOT_SUPPORTED   — HVCI on, or layout unrecognised.
    //   STATUS_NOT_FOUND       — bitmap couldn't be resolved.
    // ============================================================================
    __forceinline NTSTATUS MarkValidCallTarget(_In_ PVOID address) {
        if (!address) return STATUS_INVALID_PARAMETER;

        if (((ULONG_PTR)address & 0xF) != 0) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: %p not 16-byte aligned — CFG will "
                       "fast-fail before bitmap check; refusing to set bit\n", address);
            return STATUS_INVALID_PARAMETER;
        }

        // HVCI gate.  Writing to .data is permitted by CR0.WP toggle only when
        // SLAT isn't enforcing it from above the kernel.
        if (IsHvciActive()) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: HVCI active — skipping bitmap write "
                       "(would EPT-fault)\n");
            return STATUS_NOT_SUPPORTED;
        }

        CFG_RESOLVE info = Resolve();
        if (!info.valid) return STATUS_NOT_FOUND;
        if (!info.kcfg_active) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: KCFG inactive — no bit flip needed for %p\n",
                       address);
            return STATUS_SUCCESS;
        }
        if (!info.bitmap_base) return STATUS_NOT_FOUND;

        // Layout sanity check — if a known-valid export doesn't read as set,
        // our shift/granularity assumption is wrong on this build.  Bail
        // before we set a bit somewhere arbitrary.
        if (!ValidateLayout(info.bitmap_base)) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: layout validation failed — bitmap "
                       "shift/granularity differs on this build; aborting\n");
            return STATUS_NOT_SUPPORTED;
        }

        // Compute bit position.
        ULONG_PTR byteOffset;
        ULONG bitInByte;
        ComputeBitPos((ULONG_PTR)address, &byteOffset, &bitInByte);
        PUCHAR byteAddr = info.bitmap_base + byteOffset;

        if (!MmIsAddressValid(byteAddr)) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: bitmap byte %p not accessible for addr %p\n",
                       byteAddr, address);
            return STATUS_ACCESS_VIOLATION;
        }

        UCHAR mask = (UCHAR)(1u << bitInByte);
        if (*byteAddr & mask) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: bit already set for %p (byte %p, bit %u)\n",
                       address, byteAddr, bitInByte);
            return STATUS_SUCCESS;
        }

        // The bitmap is in ntoskrnl .data (R/W).  Try direct atomic write
        // first — this works on most systems.  Fall back to MmMapIoSpace
        // then CR0.WP for hardened configurations.
        BOOLEAN bitSet = FALSE;

        // Attempt 1: direct InterlockedOr8 (bitmap .data is normally RW).
        __try {
            InterlockedOr8((CHAR*)byteAddr, (CHAR)mask);
            bitSet = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KIPC_LOG(
                       "[CR3-IPC] KcfgPatch: direct write faulted (0x%X) — "
                       "trying MmMapIoSpace\n", GetExceptionCode());
        }

        // Attempt 2: MmMapIoSpace — remap the physical page as writable.
        if (!bitSet) {
            PHYSICAL_ADDRESS bitmapPa = MmGetPhysicalAddress(byteAddr);
            if (bitmapPa.QuadPart != 0) {
                ULONG_PTR pageOff = (ULONG_PTR)byteAddr & (PAGE_SIZE - 1);
                PHYSICAL_ADDRESS pagePA;
                pagePA.QuadPart = bitmapPa.QuadPart - (LONGLONG)pageOff;
                PVOID mapped = MmMapIoSpace(pagePA, PAGE_SIZE, MmNonCached);
                if (mapped) {
                    InterlockedOr8((CHAR*)((PUCHAR)mapped + pageOff), (CHAR)mask);
                    MmUnmapIoSpace(mapped, PAGE_SIZE);
                    bitSet = TRUE;
                }
            }
        }

        // Attempt 3: CR0.WP at HIGH_LEVEL (last resort).
        if (!bitSet) {
            KIRQL oldIrql;
            KeRaiseIrql(HIGH_LEVEL, &oldIrql);
            _disable();

            const ULONG_PTR cr0 = __readcr0();
            const ULONG_PTR WP  = (ULONG_PTR)0x10000;
            __writecr0(cr0 & ~WP);

            InterlockedOr8((CHAR*)byteAddr, (CHAR)mask);

            __writecr0(cr0);
            __invlpg(byteAddr);

            _enable();
            KeLowerIrql(oldIrql);
        }
        KeMemoryBarrier();

        KIPC_LOG(
                   "[CR3-IPC] KcfgPatch: marked %p as CFG-valid (byte %p bit %u → %02X)\n",
                   address, byteAddr, bitInByte, (unsigned)*byteAddr);
        return STATUS_SUCCESS;
    }

} // namespace KcfgPatch
