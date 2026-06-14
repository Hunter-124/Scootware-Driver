#pragma once

// Minimal kernel headers — no FINAL-DRV-specific includes
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include "../kdebug.h"  // KIPC_LOG — compiles to no-op in Release

// Injector type definitions and globals namespace
#include "def/globals.hpp"

// physical::init() declaration
#include "mem/phys.hpp"

// Forward declaration: populated by FINAL-DRV's pml4 subsystem before this is called.
// Allows us to copy the already-scanned PFN database pointer instead of re-scanning.
namespace pml4 { extern uintptr_t g_mmonp_MmPfnDatabase; }

#pragma warning(push)
#pragma warning(disable : 4055)  // type cast: data pointer to function pointer
#pragma warning(disable : 4152)  // nonstandard extension: function/data pointer conversion
#pragma warning(disable : 4191)  // unsafe conversion between function pointer types

// ─────────────────────────────────────────────────────────────────────────────
// File-private helpers (anonymous namespace — not visible outside this TU)
// ─────────────────────────────────────────────────────────────────────────────
namespace {

// Scan every IMAGE_SCN_CNT_CODE section of the PE image at ntos_base for the
// given byte pattern.  Tokens separated by spaces; '?' or '??' = wildcard byte.
// Returns a pointer to the first matching byte, or nullptr on failure.
static PVOID inj_scan_pattern(PVOID ntos_base, const char* pat_str) {
    if (!ntos_base || !pat_str) return nullptr;

    // ── Parse pattern string into byte array + mask ───────────────────────
    UINT8  pat[256]  = {};
    bool   mask[256] = {};
    SIZE_T plen      = 0;

    for (const char* p = pat_str; *p && plen < 256;) {
        // skip whitespace
        while (*p == ' ') ++p;
        if (!*p) break;

        if (*p == '?') {
            mask[plen] = false;
            pat[plen]  = 0;
            ++plen;
            ++p;
            if (*p == '?') ++p;  // consume optional second '?'
        } else {
            UINT8 b = 0;
            for (int nibble = 0; nibble < 2 && *p && *p != ' ' && *p != '?'; ++nibble, ++p) {
                b = (UINT8)(b << 4);
                if      (*p >= '0' && *p <= '9') b |= (UINT8)(*p - '0');
                else if (*p >= 'A' && *p <= 'F') b |= (UINT8)(*p - 'A' + 10);
                else if (*p >= 'a' && *p <= 'f') b |= (UINT8)(*p - 'a' + 10);
            }
            pat[plen]  = b;
            mask[plen] = true;
            ++plen;
        }
    }
    if (!plen) return nullptr;

    // ── Validate PE headers ───────────────────────────────────────────────
    auto* dos = (PIMAGE_DOS_HEADER)ntos_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (PIMAGE_NT_HEADERS64)((UINT8*)ntos_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // ── Walk code sections ────────────────────────────────────────────────
    auto* secs = IMAGE_FIRST_SECTION(nt);
    for (USHORT si = 0; si < nt->FileHeader.NumberOfSections; ++si) {
        if (!(secs[si].Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        auto*  base = (UINT8*)ntos_base + secs[si].VirtualAddress;
        SIZE_T size = secs[si].Misc.VirtualSize;
        if (size < plen) continue;

        for (SIZE_T i = 0; i + plen <= size; ++i) {
            bool found = true;
            for (SIZE_T j = 0; j < plen; ++j) {
                if (mask[j] && base[i + j] != pat[j]) { found = false; break; }
            }
            if (found) return base + i;
        }
    }
    return nullptr;
}

// Thin wrapper: call the WDK-exported MmGetSystemRoutineAddress directly.
// Used before globals::mm_get_system_routine_address is populated.
static PVOID inj_resolve(const wchar_t* name) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, name);
    return MmGetSystemRoutineAddress(&us);
}

// Scan one named PE section (e.g. ".text", "PAGE", "PAGELK") for `pat_str`.
// Returns a pointer to the first matching byte, or nullptr.  Modeled after
// kdmapper's FindPatternInSectionAtKernel — required because some functions
// (MmFreeIndependentPages, MmSetPageProtection, PiDDB*) live in non-`.text`
// sections and a global pattern scan can false-match equivalent prologues in
// unrelated sections.
static PVOID inj_scan_pattern_in_section(PVOID ntos_base,
                                         const char* section_name,
                                         const char* pat_str) {
    if (!ntos_base || !section_name || !pat_str) return nullptr;

    // Parse pattern (same parser as inj_scan_pattern above).
    UINT8  pat[256]  = {};
    bool   mask[256] = {};
    SIZE_T plen      = 0;
    for (const char* p = pat_str; *p && plen < 256;) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (*p == '?') {
            mask[plen] = false; pat[plen] = 0; ++plen; ++p;
            if (*p == '?') ++p;
        } else {
            UINT8 b = 0;
            for (int n = 0; n < 2 && *p && *p != ' ' && *p != '?'; ++n, ++p) {
                b = (UINT8)(b << 4);
                if      (*p >= '0' && *p <= '9') b |= (UINT8)(*p - '0');
                else if (*p >= 'A' && *p <= 'F') b |= (UINT8)(*p - 'A' + 10);
                else if (*p >= 'a' && *p <= 'f') b |= (UINT8)(*p - 'a' + 10);
            }
            pat[plen] = b; mask[plen] = true; ++plen;
        }
    }
    if (!plen) return nullptr;

    auto* dos = (PIMAGE_DOS_HEADER)ntos_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (PIMAGE_NT_HEADERS64)((UINT8*)ntos_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // Section names in the PE header are not null-terminated when full.
    // Compare up to IMAGE_SIZEOF_SHORT_NAME (8) bytes.
    auto name_eq = [](const char* a, const char* b) -> bool {
        for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; ++i) {
            char ca = a[i], cb = b[i];
            if (ca != cb) return false;
            if (ca == '\0') return true;
        }
        return true;
    };

    auto* secs = IMAGE_FIRST_SECTION(nt);
    for (USHORT si = 0; si < nt->FileHeader.NumberOfSections; ++si) {
        if (!name_eq((const char*)secs[si].Name, section_name)) continue;
        auto*  base = (UINT8*)ntos_base + secs[si].VirtualAddress;
        SIZE_T size = secs[si].Misc.VirtualSize;
        if (size < plen) continue;
        for (SIZE_T i = 0; i + plen <= size; ++i) {
            bool found = true;
            for (SIZE_T j = 0; j < plen; ++j) {
                if (mask[j] && base[i + j] != pat[j]) { found = false; break; }
            }
            if (found) return base + i;
        }
    }
    return nullptr;
}

// Manual export-table walker.  Some KDU-mapped images can't reliably reach
// MmGetSystemRoutineAddress (or it returns NULL for routines that are in
// fact exported).  This function walks ntoskrnl's IMAGE_EXPORT_DIRECTORY by
// hand, exactly the way kdmapper's GetKernelModuleExport does it, and is
// independent of any kernel-API resolve.  Returns nullptr if the name isn't
// present or resolves to a forwarder.
static PVOID inj_get_export(PVOID module_base, const char* name) {
    if (!module_base || !name) return nullptr;
    auto* dos = (PIMAGE_DOS_HEADER)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (PIMAGE_NT_HEADERS64)((UINT8*)module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    ULONG exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva || !exp_size) return nullptr;

    auto* exp   = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)module_base + exp_rva);
    auto* names = (ULONG*)  ((UINT8*)module_base + exp->AddressOfNames);
    auto* ords  = (USHORT*) ((UINT8*)module_base + exp->AddressOfNameOrdinals);
    auto* funcs = (ULONG*)  ((UINT8*)module_base + exp->AddressOfFunctions);

    for (ULONG i = 0; i < exp->NumberOfNames; ++i) {
        const char* fn_name = (const char*)((UINT8*)module_base + names[i]);
        // Inline strcmp — we can't depend on globals::strncmp here, it may
        // not be resolved yet.
        bool match = true;
        for (ULONG j = 0; ; ++j) {
            char a = fn_name[j];
            char b = name[j];
            if (a != b) { match = false; break; }
            if (a == '\0') break;
        }
        if (!match) continue;

        USHORT ord = ords[i];
        if (ord >= exp->NumberOfFunctions) return nullptr;
        ULONG fn_rva = funcs[ord];
        if (!fn_rva) return nullptr;
        // Forwarded exports point into the export directory itself; we don't
        // try to follow forwarders.  Return nullptr so the caller can fall
        // back to pattern scan.
        if (fn_rva >= exp_rva && fn_rva < exp_rva + exp_size) return nullptr;
        return (PVOID)((UINT8*)module_base + fn_rva);
    }
    return nullptr;
}

// Scan a section iteratively, yielding every match.  Calls `cb(hit, ctx)` for
// each.  Stops when the callback returns true (match accepted).  Returns the
// accepted hit, or nullptr.  Used to find NtCreateThreadEx by walking every
// generic-looking syscall prologue and validating each via a follow-up scan
// for the `mov rax, gs:[0x188]` syscall self-pointer load.
static PVOID inj_scan_pattern_in_section_iter(
    PVOID ntos_base, const char* section_name, const char* pat_str,
    bool (*accept)(UINT8* hit, SIZE_T remaining, void* ctx), void* ctx) {
    if (!ntos_base || !section_name || !pat_str || !accept) return nullptr;

    UINT8  pat[256]  = {};
    bool   mask[256] = {};
    SIZE_T plen      = 0;
    for (const char* p = pat_str; *p && plen < 256;) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (*p == '?') {
            mask[plen] = false; pat[plen] = 0; ++plen; ++p;
            if (*p == '?') ++p;
        } else {
            UINT8 b = 0;
            for (int n = 0; n < 2 && *p && *p != ' ' && *p != '?'; ++n, ++p) {
                b = (UINT8)(b << 4);
                if      (*p >= '0' && *p <= '9') b |= (UINT8)(*p - '0');
                else if (*p >= 'A' && *p <= 'F') b |= (UINT8)(*p - 'A' + 10);
                else if (*p >= 'a' && *p <= 'f') b |= (UINT8)(*p - 'a' + 10);
            }
            pat[plen] = b; mask[plen] = true; ++plen;
        }
    }
    if (!plen) return nullptr;

    auto* dos = (PIMAGE_DOS_HEADER)ntos_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (PIMAGE_NT_HEADERS64)((UINT8*)ntos_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto name_eq = [](const char* a, const char* b) -> bool {
        for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; ++i) {
            char ca = a[i], cb = b[i];
            if (ca != cb) return false;
            if (ca == '\0') return true;
        }
        return true;
    };

    auto* secs = IMAGE_FIRST_SECTION(nt);
    for (USHORT si = 0; si < nt->FileHeader.NumberOfSections; ++si) {
        if (!name_eq((const char*)secs[si].Name, section_name)) continue;
        auto*  base = (UINT8*)ntos_base + secs[si].VirtualAddress;
        SIZE_T size = secs[si].Misc.VirtualSize;
        if (size < plen) continue;
        for (SIZE_T i = 0; i + plen <= size; ++i) {
            bool found = true;
            for (SIZE_T j = 0; j < plen; ++j) {
                if (mask[j] && base[i + j] != pat[j]) { found = false; break; }
            }
            if (!found) continue;
            if (accept(base + i, size - i, ctx)) return base + i;
        }
    }
    return nullptr;
}

// NtCreateThreadEx validator: a generic 11-arg syscall prologue match is
// only acceptable if the function reads gs:[0x188] (KPCR.CurrentThread)
// somewhere in its first ~512 bytes — that's the hallmark of a syscall
// service routine and is absent from non-syscall helpers (FsRtl*, Cc*, etc.)
// that share the same prologue.  We log every candidate so the user can
// `ln` each address in WinDbg if the validator still misses.
static bool inj_accept_nt_create_thread_ex(UINT8* hit, SIZE_T remaining, void* ctx) {
    static const UINT8 gs_read_rax[] = {
        // mov rax, gs:[0x188]
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00
    };
    static const UINT8 gs_read_rcx[] = {
        // mov rcx, gs:[0x188]  (some builds load into rcx instead)
        0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00
    };
    static const UINT8 gs_read_rdx[] = {
        // mov rdx, gs:[0x188]
        0x65, 0x48, 0x8B, 0x14, 0x25, 0x88, 0x01, 0x00, 0x00
    };

    // ctx, when non-null, is a counter we increment so the caller can log
    // every candidate that *didn't* validate, for offline analysis.
    int* candidate_count = (int*)ctx;
    if (candidate_count) ++*candidate_count;

    KIPC_LOG(
               "[INJECTOR] NtCreateThreadEx candidate at %p — validating...\n",
               (PVOID)hit);

    // Widen the search to 0x200 bytes (some builds defer the gs read past
    // earlier validation code).
    SIZE_T scan_len = remaining > 0x200 ? 0x200 : remaining;

    auto match_at = [&](const UINT8* pat, SIZE_T plen) -> SIZE_T {
        for (SIZE_T k = 0; k + plen <= scan_len; ++k) {
            bool ok = true;
            for (SIZE_T m = 0; m < plen; ++m) {
                if (hit[k + m] != pat[m]) { ok = false; break; }
            }
            if (ok) return k;
        }
        return (SIZE_T)-1;
    };

    SIZE_T off = match_at(gs_read_rax, sizeof(gs_read_rax));
    if (off == (SIZE_T)-1) off = match_at(gs_read_rcx, sizeof(gs_read_rcx));
    if (off == (SIZE_T)-1) off = match_at(gs_read_rdx, sizeof(gs_read_rdx));

    if (off != (SIZE_T)-1) {
        KIPC_LOG(
                   "[INJECTOR] candidate at %p ACCEPTED (gs[188h] at +0x%llx)\n",
                   (PVOID)hit, (unsigned long long)off);
        return true;
    }

    KIPC_LOG(
               "[INJECTOR] candidate at %p REJECTED (no gs[188h] in first "
               "0x%llx bytes)\n",
               (PVOID)hit, (unsigned long long)scan_len);
    return false;
}

// Resolve a RIP-relative instruction operand.
//   instr            = address of the instruction we just located
//   offset_offset    = byte offset within the instruction at which the disp32 lives
//                      (e.g. 1 for `E8 dd`, 3 for `48 8B 0D dd`)
//   instruction_size = total length of the instruction (5 for `E8 dd`,
//                      6 for `FF 15 dd`, 7 for `48 8B 0D dd`, ...)
// Returns the absolute target address.  Modeled on kdmapper's
// ResolveRelativeAddress.
static PVOID inj_resolve_rel(PVOID instr, ULONG offset_offset, ULONG instruction_size) {
    if (!instr) return nullptr;
    LONG disp = *(LONG*)((UINT8*)instr + offset_offset);
    return (PVOID)((UINT8*)instr + instruction_size + disp);
}

// RtlCopyMemory / RtlFillMemory / RtlCompareMemory are macros in the WDK —
// they cannot be cast directly to function pointers.  These thunks provide
// addressable wrappers with the signatures expected by function_types::.
static void* __cdecl inj_memcpy_thunk(void* dst, const void* src, size_t n) {
    RtlCopyMemory(dst, src, n);
    return dst;
}
static void* __cdecl inj_memset_thunk(void* dst, int c, size_t n) {
    RtlFillMemory(dst, n, (UCHAR)(unsigned int)c);
    return dst;
}
static int __cdecl inj_memcmp_thunk(const void* a, const void* b, size_t n) {
    SIZE_T matched = RtlCompareMemory(a, b, n);
    return (matched == n) ? 0 : 1;
}

}  // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
//  injector_init_globals
//
//  Populates every globals:: function pointer and data field required by the
//  PT-injector code copied into FINAL-DRV/injector/.  Call once from
//  DriverEntry or the post-handoff init path, after FINAL-DRV's pml4 subsystem
//  has populated pml4::g_mmonp_MmPfnDatabase.
//
//  ntos_base_addr  –  base VA of ntoskrnl.exe (from GetSystemModuleBase or
//                     equivalent).  Must not be NULL.
//
//  Returns STATUS_SUCCESS on full success.
//  Returns STATUS_UNSUCCESSFUL if either mm_allocate_independent_pages_ex or
//  mi_get_pte_address could not be resolved — both are required by
//  allocate_between_modules / allocate_at_non_present_pml4e.
//  Returns STATUS_INVALID_PARAMETER if ntos_base_addr is NULL.
// ─────────────────────────────────────────────────────────────────────────────
inline NTSTATUS injector_init_globals(PVOID ntos_base_addr) {
    // ── Guard against double-init ─────────────────────────────────────────
    if (globals::initialized) return STATUS_SUCCESS;

    if (!ntos_base_addr) {
        KIPC_LOG(
                   "[INJECTOR] injector_init_globals: NULL ntos_base_addr\n");
        return STATUS_INVALID_PARAMETER;
    }

    // ── Set dbg_print first so log() works immediately ────────────────────
    // DbgPrint matches dbg_print_t: ULONG(__cdecl*)(PCCH, ...)
    globals::dbg_print = (function_types::dbg_print_t)DbgPrint;

    // ─────────────────────────────────────────────────────────────────────
    // (a)  Public exports resolved via MmGetSystemRoutineAddress
    // ─────────────────────────────────────────────────────────────────────

// Helper macro: resolve a named export and log a warning if absent.
// Non-critical symbols use this; critical ones are checked explicitly below.
#define INJ_RESOLVE(field, wname, ftype)                                             \
    globals::field = (ftype)inj_resolve(wname);                                      \
    if (!globals::field)                                                              \
        KIPC_LOG(                        \
                   "[INJECTOR] WARNING: " #wname " not found\n");

    // Mm — memory management exports
    INJ_RESOLVE(mm_get_physical_address,        L"MmGetPhysicalAddress",
                function_types::mm_get_physical_address_t)
    INJ_RESOLVE(mm_allocate_contiguous_memory,  L"MmAllocateContiguousMemory",
                function_types::mm_allocate_contiguous_memory_t)
    INJ_RESOLVE(mm_free_contiguous_memory,      L"MmFreeContiguousMemory",
                function_types::mm_free_contiguous_memory_t)
    INJ_RESOLVE(mm_copy_memory,                 L"MmCopyMemory",
                function_types::mm_copy_memory_t)
    INJ_RESOLVE(mm_get_virtual_for_physical,    L"MmGetVirtualForPhysical",
                function_types::mm_get_virtual_for_physical_t)
    INJ_RESOLVE(mm_copy_virtual_memory,         L"MmCopyVirtualMemory",
                function_types::mm_copy_virtual_memory_t)
    INJ_RESOLVE(mm_is_address_valid,            L"MmIsAddressValid",
                function_types::mm_is_address_valid_t)
    INJ_RESOLVE(mm_get_system_routine_address,  L"MmGetSystemRoutineAddress",
                function_types::mm_get_system_routine_address_t)
    INJ_RESOLVE(mm_get_physical_memory_ranges,  L"MmGetPhysicalMemoryRanges",
                function_types::mm_get_physical_memory_ranges_t)
    INJ_RESOLVE(mm_mark_physical_memory_as_bad, L"MmMarkPhysicalMemoryAsBad",
                function_types::mm_mark_physical_memory_as_bad_t)

    // MmAllocateSecureKernelPages — absent on older builds; non-critical
    globals::mm_allocate_secure_kernel_pages =
        (function_types::mm_allocate_secure_kernel_pages_t)inj_resolve(L"MmAllocateSecureKernelPages");

    // MmUserProbeAddress — data export: MmGetSystemRoutineAddress returns
    // &MmUserProbeAddress (a PVOID*).  Dereference to obtain the actual probe
    // address value, then store it so code comparing against it works without
    // a further dereference.
    {
        PVOID* p = (PVOID*)inj_resolve(L"MmUserProbeAddress");
        if (p)
            globals::mm_user_probe_address =
                (function_types::mm_user_probe_address_t)(uintptr_t)*p;
        else
            KIPC_LOG(
                       "[INJECTOR] WARNING: MmUserProbeAddress not found\n");
    }

    // Ps — process/thread management exports
    INJ_RESOLVE(ps_lookup_process_by_process_id,
                L"PsLookupProcessByProcessId",
                function_types::ps_lookup_process_by_process_id_t)
    INJ_RESOLVE(ps_lookup_thread_by_thread_id,
                L"PsLookupThreadByThreadId",
                function_types::ps_lookup_thread_by_thread_id_t)
    INJ_RESOLVE(ps_get_process_exit_status,
                L"PsGetProcessExitStatus",
                function_types::ps_get_process_exit_status_t)
    INJ_RESOLVE(ps_acquire_process_exit_synchronization,
                L"PsAcquireProcessExitSynchronization",
                function_types::ps_acquire_process_exit_synchronization_t)
    INJ_RESOLVE(ps_release_process_exit_synchronization,
                L"PsReleaseProcessExitSynchronization",
                function_types::ps_release_process_exit_synchronization_t)
    INJ_RESOLVE(ps_get_process_peb,
                L"PsGetProcessPeb",
                function_types::ps_get_process_peb_t)
    INJ_RESOLVE(ps_get_process_image_file_name,
                L"PsGetProcessImageFileName",
                function_types::ps_get_process_image_file_name_t)
    INJ_RESOLVE(ps_get_next_process_thread,
                L"PsGetNextProcessThread",
                function_types::ps_get_next_process_thread_t)
    INJ_RESOLVE(ps_suspend_thread,
                L"PsSuspendThread",
                function_types::ps_suspend_thread_t)
    INJ_RESOLVE(ps_resume_thread,
                L"PsResumeThread",
                function_types::ps_suspend_thread_t)
    INJ_RESOLVE(ps_get_current_thread_id,
                L"PsGetCurrentThreadId",
                function_types::ps_get_current_thread_id_t)
    INJ_RESOLVE(ps_set_create_thread_notify_routine,
                L"PsSetCreateThreadNotifyRoutine",
                function_types::ps_set_create_thread_notify_routine_t)

    // CAUTION — do NOT call ps_set_create_process_notify_routine_ex from a
    // KDU-mapped driver.  PatchGuard scans the callback array and will
    // BSOD (CRITICAL_STRUCTURE_CORRUPTION 0x109) if the registered address
    // does not belong to a loaded module.  The hyperspace code path
    // (ALLOC_AT_HYPERSPACE) uses this routine and is therefore disabled.
    globals::ps_set_create_process_notify_routine_ex =
        (function_types::ps_set_create_process_notify_routine_ex_t)
        inj_resolve(L"PsSetCreateProcessNotifyRoutineEx");

    // PsQueryThreadStartAddress — may be absent on some builds; non-critical
    globals::ps_query_thread_start_address =
        (function_types::ps_query_thread_start_address_t)
        inj_resolve(L"PsQueryThreadStartAddress");

    // Io / Ob / Ex
    INJ_RESOLVE(io_get_current_process,  L"IoGetCurrentProcess",
                function_types::io_get_current_process_t)
    INJ_RESOLVE(obf_dereference_object,  L"ObfDereferenceObject",
                function_types::obf_dereference_object_t)
    INJ_RESOLVE(ex_allocate_pool2,       L"ExAllocatePool2",
                function_types::ex_allocate_pool2_t)
    INJ_RESOLVE(ex_free_pool_with_tag,   L"ExFreePoolWithTag",
                function_types::ex_free_pool_with_tag_t)
    INJ_RESOLVE(ex_get_previous_mode,    L"ExGetPreviousMode",
                function_types::ex_get_previous_mode_t)

    // Ke — kernel executive exports
    INJ_RESOLVE(ke_raise_irql_to_dpc_level, L"KeRaiseIrqlToDpcLevel",
                function_types::ke_raise_irql_to_dpc_level_t)
    INJ_RESOLVE(ke_lower_irql,              L"KeLowerIrql",
                function_types::ke_lower_irql_t)
    INJ_RESOLVE(ke_query_system_time_precise, L"KeQuerySystemTimePrecise",
                function_types::ke_query_system_time_precise_t)
    INJ_RESOLVE(ke_initialize_apc,          L"KeInitializeApc",
                function_types::ke_initialize_apc_t)
    INJ_RESOLVE(ke_insert_queue_apc,        L"KeInsertQueueApc",
                function_types::ke_insert_queue_apc_t)
    INJ_RESOLVE(ke_alert_thread,            L"KeAlertThread",
                function_types::ke_alert_thread_t)
    INJ_RESOLVE(ke_delay_execution_thread,  L"KeDelayExecutionThread",
                function_types::ke_delay_execution_thread_t)

    // KeUserModeCallback — may be absent; non-critical
    globals::ke_usermode_callback =
        (function_types::ke_usermode_callback_t)inj_resolve(L"KeUserModeCallback");

    // Rtl — runtime library exports
    INJ_RESOLVE(rtl_init_ansi_string,           L"RtlInitAnsiString",
                function_types::rtl_init_ansi_string_t)
    INJ_RESOLVE(rtl_init_unicode_string,        L"RtlInitUnicodeString",
                function_types::rtl_init_unicode_string_t)
    INJ_RESOLVE(rtl_ansi_string_to_unicode_string, L"RtlAnsiStringToUnicodeString",
                function_types::rtl_ansi_string_to_unicode_string_t)
    INJ_RESOLVE(rtl_compare_unicode_string,     L"RtlCompareUnicodeString",
                function_types::rtl_compare_unicode_string_t)
    INJ_RESOLVE(rtl_free_unicode_string,        L"RtlFreeUnicodeString",
                function_types::rtl_free_unicode_string_t)
    INJ_RESOLVE(rtl_get_version,                L"RtlGetVersion",
                function_types::rtl_get_version_t)
    // RtlCreateUserThread is NOT actually exported by ntoskrnl on most Windows
    // builds — it lives in ntdll.dll.  The resolve below will warn (NULL) but
    // we keep the line so the global stays known.  All real inject paths use
    // nt_create_thread_ex instead.
    INJ_RESOLVE(rtl_create_user_thread,         L"RtlCreateUserThread",
                function_types::rtl_create_user_thread_t)

    // ────────────────────────────────────────────────────────────────────
    // NtCreateThreadEx — needed to spawn the user-mode thread that runs
    // the shellcode.  Resolution chain:
    //
    //   1. MmGetSystemRoutineAddress(L"NtCreateThreadEx")
    //   2. MmGetSystemRoutineAddress(L"ZwCreateThreadEx")
    //   3. Manual ntoskrnl export-table walk for "NtCreateThreadEx"
    //   4. Manual ntoskrnl export-table walk for "ZwCreateThreadEx"
    //   5. Pattern scan of NtCreateThreadEx's function prologue in .text
    //
    // (3) and (4) exist because some KDU-mapped loaders interfere with the
    // import resolution path that MmGetSystemRoutineAddress depends on, and
    // we've observed (1) and (2) both returning NULL on Win10 19041 even
    // though the exports do exist in ntoskrnl.exe.  Walking the export
    // table by hand bypasses that entirely.
    //
    // Either NtCreateThreadEx or ZwCreateThreadEx is fine — Zw* is a thin
    // wrapper that sets PreviousMode = KernelMode before tail-calling
    // Nt* (or routing through KiSystemServiceCopyEnd on newer builds).
    // Since we pass kernel-built OBJECT_ATTRIBUTES with OBJ_KERNEL_HANDLE,
    // either path is correct for our usage.
    // ────────────────────────────────────────────────────────────────────
    globals::nt_create_thread_ex =
        (function_types::nt_create_thread_ex_t)inj_resolve(L"NtCreateThreadEx");
    const char* nt_create_thread_ex_source = "MmGetSystemRoutineAddress(NtCreateThreadEx)";

    if (!globals::nt_create_thread_ex) {
        globals::nt_create_thread_ex =
            (function_types::nt_create_thread_ex_t)inj_resolve(L"ZwCreateThreadEx");
        if (globals::nt_create_thread_ex)
            nt_create_thread_ex_source = "MmGetSystemRoutineAddress(ZwCreateThreadEx)";
    }
    if (!globals::nt_create_thread_ex) {
        globals::nt_create_thread_ex =
            (function_types::nt_create_thread_ex_t)
                inj_get_export(ntos_base_addr, "NtCreateThreadEx");
        if (globals::nt_create_thread_ex)
            nt_create_thread_ex_source = "manual export walk (NtCreateThreadEx)";
    }
    if (!globals::nt_create_thread_ex) {
        globals::nt_create_thread_ex =
            (function_types::nt_create_thread_ex_t)
                inj_get_export(ntos_base_addr, "ZwCreateThreadEx");
        if (globals::nt_create_thread_ex)
            nt_create_thread_ex_source = "manual export walk (ZwCreateThreadEx)";
    }
    if (!globals::nt_create_thread_ex) {
        // Ground-truth prologue from WinDbg `u nt!NtCreateThreadEx L20` on
        // Windows 10 22H2 (build 19045) — see WinDbg dump above.
        //
        // Try two scans:
        //   (1) Section-restricted to `.text`
        //   (2) All code sections (in case the kernel actually puts this
        //       function in another code section like KVASCODE or PAGE)
        //
        // Both should match the same address; if (1) misses but (2) hits,
        // the section name on this kernel isn't ".text".  Diagnostic output
        // is emitted so the user can tell which scan worked.
        const char* nt_ctx_pattern =
            "40 55 53 56 57 41 54 41 55 41 56 41 57"
            " 48 81 EC ? ? ? ?"
            " 48 8D 6C 24 ?"
            " 48 8B 05 ? ? ? ?"
            " 48 33 C5"
            " 48 89 85 ? ? ? ?"
            " 4D 8B F9"
            " 4C 89 45 ?"
            " 89 55 ?"
            " 48 8B F1";

        PVOID hit = inj_scan_pattern_in_section(
            ntos_base_addr, ".text", nt_ctx_pattern);
        if (hit) {
            globals::nt_create_thread_ex =
                (function_types::nt_create_thread_ex_t)hit;
            nt_create_thread_ex_source =
                "11-push /GS+arg-save pattern (.text)";
        } else {
            // Fall back to scanning every IMAGE_SCN_CNT_CODE section.
            KIPC_LOG(
                       "[INJECTOR] NtCreateThreadEx: .text section scan "
                       "missed — trying every code section\n");
            hit = inj_scan_pattern(ntos_base_addr, nt_ctx_pattern);
            if (hit) {
                globals::nt_create_thread_ex =
                    (function_types::nt_create_thread_ex_t)hit;
                nt_create_thread_ex_source =
                    "11-push /GS+arg-save pattern (any CODE section)";
            }
        }

        if (!globals::nt_create_thread_ex) {
            KIPC_LOG(
                       "[INJECTOR] NtCreateThreadEx: BOTH section-restricted "
                       "and all-CODE scans missed — printing PE section "
                       "layout for diagnosis\n");
            // Dump every section so we can see what the kernel actually has.
            auto* dos2 = (PIMAGE_DOS_HEADER)ntos_base_addr;
            if (dos2->e_magic == IMAGE_DOS_SIGNATURE) {
                auto* nt2 = (PIMAGE_NT_HEADERS64)
                    ((UINT8*)ntos_base_addr + dos2->e_lfanew);
                if (nt2->Signature == IMAGE_NT_SIGNATURE) {
                    auto* secs2 = IMAGE_FIRST_SECTION(nt2);
                    for (USHORT si = 0; si < nt2->FileHeader.NumberOfSections; ++si) {
                        char name_buf[9] = {};
                        for (int n = 0; n < 8; ++n) name_buf[n] = secs2[si].Name[n];
                        KIPC_LOG(
                                   "[INJECTOR]   section[%u] name='%s' VA=+0x%X "
                                   "size=0x%X chars=0x%X\n",
                                   (unsigned)si, name_buf,
                                   (unsigned)secs2[si].VirtualAddress,
                                   (unsigned)secs2[si].Misc.VirtualSize,
                                   (unsigned)secs2[si].Characteristics);
                    }
                }
            }
        }
    }

    if (globals::nt_create_thread_ex) {
        KIPC_LOG(
                   "[INJECTOR] nt_create_thread_ex = %p (resolved via %s)\n",
                   (PVOID)globals::nt_create_thread_ex,
                   nt_create_thread_ex_source);
    } else {
        KIPC_LOG(
                   "[INJECTOR] WARNING: NtCreateThreadEx unresolved (export "
                   "lookups via MmGetSystemRoutineAddress and manual walk, "
                   "plus prologue pattern, all failed) — inject path will "
                   "be rejected\n");
    }

    // Zw / Nt
    INJ_RESOLVE(zw_open_process,              L"ZwOpenProcess",
                function_types::zw_open_process_t)
    INJ_RESOLVE(zw_close,                     L"ZwClose",
                function_types::zw_close_t)
    INJ_RESOLVE(zw_wait_for_single_object,    L"ZwWaitForSingleObject",
                function_types::zw_wait_for_single_object_t)
    INJ_RESOLVE(zw_query_information_process, L"ZwQueryInformationProcess",
                function_types::zw_query_information_process_t)
    INJ_RESOLVE(nt_alert_resume_thread,       L"NtAlertResumeThread",
                function_types::nt_alert_resume_thread_t)

    // ZwResumeThread — replaces PsResumeThread (which is not exported on
    // Win10 22H2 / 19045 and most newer builds).  Handle-based, decrements
    // the thread's suspend count.  See injector_execute_dll for the call
    // site that uses this instead of the old PETHREAD-based PsResumeThread.
    globals::zw_resume_thread = (function_types::zw_resume_thread_t)
        inj_resolve(L"ZwResumeThread");
    if (!globals::zw_resume_thread) {
        // Fall back to manual export-table walk, then a NtResumeThread alias.
        globals::zw_resume_thread = (function_types::zw_resume_thread_t)
            inj_get_export(ntos_base_addr, "ZwResumeThread");
    }
    if (!globals::zw_resume_thread) {
        globals::zw_resume_thread = (function_types::zw_resume_thread_t)
            inj_resolve(L"NtResumeThread");
    }
    if (!globals::zw_resume_thread) {
        globals::zw_resume_thread = (function_types::zw_resume_thread_t)
            inj_get_export(ntos_base_addr, "NtResumeThread");
    }
    KIPC_LOG(
               "[INJECTOR] zw_resume_thread = %p\n",
               (PVOID)globals::zw_resume_thread);

#undef INJ_RESOLVE

    // ─────────────────────────────────────────────────────────────────────
    // (b)  CRT-like function pointers
    // ─────────────────────────────────────────────────────────────────────

    // RtlCopyMemory/RtlFillMemory/RtlCompareMemory are macros — use thunks.
    globals::memcpy = inj_memcpy_thunk;
    globals::memset = inj_memset_thunk;
    globals::memcmp = inj_memcmp_thunk;

    // snprintf / swprintf_s — resolve Rtl formatted-print variants; non-critical
    globals::snprintf   = (function_types::snprintf_t)  inj_resolve(L"RtlStringCbPrintfA");
    globals::swprintf_s = (function_types::swprintf_s_t)inj_resolve(L"RtlStringCbPrintfW");

    // strlen / strncmp / _wcsicmp — exported from ntoskrnl on Win10 20H2+
    // (UCRT is statically linked into ntoskrnl on modern builds).
    globals::strlen   = (function_types::strlen_t)  inj_resolve(L"strlen");
    globals::strncmp  = (function_types::strncmp_t) inj_resolve(L"strncmp");
    globals::_wcsicmp = (function_types::_wcsicmp_t)inj_resolve(L"_wcsicmp");

    // rand / srand — not used by the injection paths exercised from FINAL-DRV
    globals::rand  = nullptr;
    globals::srand = nullptr;

    // ─────────────────────────────────────────────────────────────────────
    // (c)  Private / undocumented functions — pattern scan ntoskrnl .text
    // ─────────────────────────────────────────────────────────────────────

// Helper macro: scan for a byte pattern, assign, warn on failure.
#define INJ_SCAN(field, pattern_str, ftype, sym_name)                        \
    globals::field = (ftype)inj_scan_pattern(ntos_base_addr, pattern_str);   \
    if (!globals::field)                                                       \
        KIPC_LOG(                 \
                   "[INJECTOR] WARNING: pattern scan failed for " sym_name "\n");

// Like INJ_SCAN but tries pat2 before warning.  pat1 = Win10 22H2 (19045),
// pat2 = fallback for Win11 22H2-24H2 and other builds.
#define INJ_SCAN2(field, pat1, pat2, ftype, sym_name)                          \
    globals::field = (ftype)inj_scan_pattern(ntos_base_addr, pat1);            \
    if (!globals::field)                                                         \
        globals::field = (ftype)inj_scan_pattern(ntos_base_addr, pat2);         \
    if (!globals::field)                                                          \
        KIPC_LOG(                            \
                   "[INJECTOR] WARNING: pattern scan failed for " sym_name "\n");

    INJ_SCAN(ke_flush_single_tb,
             "4C 8B DC 53 56 57 41 54 41 55 41 56 41 57 48 81 EC",
             function_types::ke_flush_single_tb_t,
             "KeFlushSingleTb")

    INJ_SCAN2(ke_flush_entire_tb,
              // Win10 22H2 (19045): RSP-frame style, BA 03 literal
              "48 8B C4 48 89 58 08 48 89 68 10 57 48 83 EC 30 BA 03 00 00 00",
              // Win11 22H2-24H2 fallback
              "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 0F B6 F1",
              function_types::ke_flush_entire_tb_t,
              "KeFlushEntireTb")

    INJ_SCAN(ke_invalidate_all_caches,
             "48 83 EC 28 65 48 8B 04 25 88 01 00 00",
             function_types::ke_invalidate_all_caches_t,
             "KeInvalidateAllCaches")

    // ────────────────────────────────────────────────────────────────────
    // MmAllocateIndependentPagesEx — modeled on kdmapper/intel_driver.cpp
    // (line 527+).  Strategy:
    //
    //   1. Try exports first (`MmAllocateIndependentPagesEx`, then
    //      `MmAllocateIndependentPages`).  Some KDU-mapped images have the
    //      ntoskrnl export table fully resolvable; some don't.
    //
    //   2. Fall back to a CALL-SITE pattern inside KeAllocateInterrupt that
    //      reliably points at a CALL to MmAllocateIndependentPagesEx on every
    //      build from Win10 1803 to Win11 24H2:
    //
    //        41 8B D6 B9 00 10 00 00 E8 ?? ?? ?? ?? 48 8B D8
    //        ^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^ ^^^^^^^^
    //        mov edx,r14d / mov ecx,0x1000 / call X / mov rbx,rax
    //
    //      Skip 8 bytes to land on the `E8 ?? ?? ?? ??` (CALL), then resolve
    //      the disp32 (offset 1, instruction size 5) to get the target VA.
    //
    //   The old prologue-only pattern false-matched CcPerfLogWorkItemEnqueue
    //   and BSOD'd; call-site resolution is immune to that class of false
    //   match.
    // ────────────────────────────────────────────────────────────────────
    globals::mm_allocate_independent_pages_ex =
        (function_types::mm_allocate_independent_pages_ex_t)
            inj_resolve(L"MmAllocateIndependentPagesEx");
    if (!globals::mm_allocate_independent_pages_ex) {
        globals::mm_allocate_independent_pages_ex =
            (function_types::mm_allocate_independent_pages_ex_t)
                inj_resolve(L"MmAllocateIndependentPages");
    }
    if (!globals::mm_allocate_independent_pages_ex) {
        PVOID hit = inj_scan_pattern_in_section(
            ntos_base_addr, ".text",
            "41 8B D6 B9 00 10 00 00 E8 ? ? ? ? 48 8B D8");
        if (hit) {
            PVOID call_site = (PVOID)((UINT8*)hit + 8);  // step to the E8 disp32
            globals::mm_allocate_independent_pages_ex =
                (function_types::mm_allocate_independent_pages_ex_t)
                    inj_resolve_rel(call_site, 1, 5);
            if (globals::mm_allocate_independent_pages_ex) {
                KIPC_LOG(
                           "[INJECTOR] MmAllocateIndependentPagesEx: exports "
                           "absent, resolved via KeAllocateInterrupt call-site "
                           "= %p\n",
                           (PVOID)globals::mm_allocate_independent_pages_ex);
            }
        }
    }
    if (!globals::mm_allocate_independent_pages_ex) {
        KIPC_LOG(
                   "[INJECTOR] WARNING: MmAllocateIndependentPagesEx "
                   "unresolved (export + KeAllocateInterrupt call-site both "
                   "failed) — falling back to MmAllocateContiguousMemory\n");
    }

    INJ_SCAN(mm_set_page_protection,
             "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 41 8B F8 48 8B F2",
             function_types::mm_set_page_protection_t,
             "MmSetPageProtection")

    // ────────────────────────────────────────────────────────────────────
    // MmFreeIndependentPages — same call-site approach as the allocate
    // routine, also modeled on kdmapper/intel_driver.cpp.  Two patterns
    // cover Win10 (PAGE section, edx=0x6000 literal load) and Win11 (edx
    // loaded RIP-relative from a global).  Both end with a CALL to
    // MmFreeIndependentPages followed by `lea rcx,[rbx±??]`.
    // ────────────────────────────────────────────────────────────────────
    globals::mm_free_independent_pages =
        (function_types::mm_free_independent_pages)
            inj_resolve(L"MmFreeIndependentPages");
    if (!globals::mm_free_independent_pages) {
        // Win10 pattern: BA 00 60 00 00 / 48 8B CB / E8 ?? ?? ?? ?? / 48 8D 8B ??
        PVOID hit = inj_scan_pattern_in_section(
            ntos_base_addr, "PAGE",
            "BA 00 60 00 00 48 8B CB E8 ? ? ? ? 48 8D 8B 00 F0 FF FF");
        ULONG skip = 0;
        if (hit) {
            skip = 8;  // step to the E8 disp32
        } else {
            // Win11 pattern: 8B 15 ?? ?? ?? ?? / 48 8B CB / E8 ?? ?? ?? ?? / 48 8D 8B
            hit = inj_scan_pattern_in_section(
                ntos_base_addr, "PAGE",
                "8B 15 ? ? ? ? 48 8B CB E8 ? ? ? ? 48 8D 8B");
            if (hit) skip = 9;
        }
        if (hit) {
            PVOID call_site = (PVOID)((UINT8*)hit + skip);
            globals::mm_free_independent_pages =
                (function_types::mm_free_independent_pages)
                    inj_resolve_rel(call_site, 1, 5);
            if (globals::mm_free_independent_pages) {
                KIPC_LOG(
                           "[INJECTOR] MmFreeIndependentPages: export absent, "
                           "resolved via call-site = %p\n",
                           (PVOID)globals::mm_free_independent_pages);
            }
        }
    }
    if (!globals::mm_free_independent_pages) {
        KIPC_LOG(
                   "[INJECTOR] WARNING: MmFreeIndependentPages unresolved — "
                   "matching free path will fall through to "
                   "MmFreeContiguousMemory\n");
    }

    // MiGetPteAddress — the pattern matches the start of the function body.
    // After finding the pattern the function pointer points directly to the
    // matched instruction sequence, which IS the start of MiGetPteAddress.
    INJ_SCAN(mi_get_pte_address,
             "48 C1 E9 09 48 B8 F8 FF FF FF 7F 00 00 00 48 23 C8 48 B8",
             function_types::mi_get_pte_address_t,
             "MiGetPteAddress")

    // MiGetPdeAddress — try the export first (present on some builds), then
    // fall back to a pattern that matches the analogous PDE-shift sequence
    // (SAR RCX,12h instead of 9h for the PTE variant).
    globals::mi_get_pde_address =
        (function_types::mi_get_pde_address_t)inj_resolve(L"MiGetPdeAddress");
    if (!globals::mi_get_pde_address) {
        // Win10 22H2 (19045): SAR+AND+MOV-imm sequence
        globals::mi_get_pde_address =
            (function_types::mi_get_pde_address_t)inj_scan_pattern(
                ntos_base_addr,
                "48 C1 E9 12 81 E1 F8 FF FF 3F 48 B8");
    }
    if (!globals::mi_get_pde_address) {
        // Win11 22H2-24H2 fallback: SAR+MOV-imm (no AND masking step)
        globals::mi_get_pde_address =
            (function_types::mi_get_pde_address_t)inj_scan_pattern(
                ntos_base_addr,
                "48 C1 E9 12 48 B8 ? ? ? ? ? ? ? ? 48 23 C8 48 B8");
    }
    if (!globals::mi_get_pde_address)
        KIPC_LOG(
                   "[INJECTOR] WARNING: MiGetPdeAddress not found (export + pattern)\n");

    INJ_SCAN(mi_reserve_ptes,
             "48 89 5C 24 08 57 48 83 EC 20 8B DA 48 8B F9 E8",
             function_types::mi_reserve_ptes_t,
             "MiReservePtes")

    INJ_SCAN2(mi_flush_entire_tb_due_to_attribute_change,
              // Win10 22H2 (19045): sub rsp,E8h + stack cookie prolog
              "48 81 EC E8 00 00 00 48 8B 05 ? ? ? ? 48 33 C4",
              // Win11 22H2-24H2 fallback
              "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55"
              " 41 56 41 57 48 83 EC 40 45 33 FF",
              function_types::mi_flush_entire_tb_due_to_attribute_change_t,
              "MiFlushEntireTbDueToAttributeChange")

    INJ_SCAN(mi_flush_cache_range,
             "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 49 8B E9",
             function_types::mi_flush_cache_range_t,
             "MiFlushCacheRange")

    INJ_SCAN(mi_get_page_table_pfn_buddy_raw,
             "48 89 5C 24 08 48 89 7C 24 10 41 55 48 83 EC 50 45 8B E9",
             function_types::mi_get_page_table_pfn_buddy_raw_t,
             "MiGetPageTablePfnBuddyRaw")

    INJ_SCAN2(mi_set_page_table_pfn_buddy,
              // Win10 22H2 (19045): saves rdx→rsi, rcx→rdi
              "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F2 48 8B F9",
              // Win11 22H2-24H2 fallback
              "48 89 5C 24 08 57 48 83 EC 20 48 8B 1A 48 8B F9 48 85 DB 74 ? 48 8B CB",
              function_types::mi_set_page_table_pfn_buddy_t,
              "MiSetPageTablePfnBuddy")

    INJ_SCAN2(mi_lock_page_table_page,
              // Win10 22H2 (19045): 8-reg push chain, xor r15d/r15d, mov r12d,edx
              "40 53 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 28 45 33 FF 44 8B E2 48 8B D9",
              // Win11 22H2-24H2 fallback
              "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 44 8B 41 08 48 8B F1",
              function_types::mi_lock_page_table_page_t,
              "MiLockPageTablePage")

    INJ_SCAN2(mi_allocate_large_zero_pages,
              // Win10 22H2 (19045): push chain + lea rbp,[rsp-7]
              "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 F9 48 81 EC D8 00 00 00",
              // Win11 22H2-24H2 fallback
              "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55"
              " 41 56 41 57 48 83 EC 40 4D 8B E1",
              function_types::mi_allocate_large_zero_pages_t,
              "MiAllocateLargeZeroPages")

    INJ_SCAN2(mi_create_decay_pfn,
              // Win10 22H2 (19045): 3-reg save + lea rcx,[rip+?] + call + mov rdi,rax
              "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B F8",
              // Win11 22H2-24H2 fallback
              "40 53 48 83 EC 20 48 8B 59 08 48 8B D1 33 C9 E8",
              function_types::mi_create_decay_pfn_t,
              "MiCreateDecayPfn")

    INJ_SCAN(mi_get_vm_access_logging_partition,
             "48 83 EC 28 65 48 8B 04 25 88 01 00 00 48 8B 80 ? ? ? ?"
             " 48 85 C0 74 ? 48 8B C8 E8",
             function_types::mi_get_vm_access_logging_partition_t,
             "MiGetVmAccessLoggingPartition")

    INJ_SCAN2(mi_remove_physical_memory,
              // Win10 22H2 (19045): mov rax,rsp home-arg style
              "48 8B C4 48 89 58 08 44 89 40 18 48 89 50 10 55 56 57 41 54"
              " 41 55 41 56 41 57 48 8D 68",
              // Win11 22H2-24H2 fallback
              "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55"
              " 41 56 41 57 48 83 EC 60 0F B7 52 06",
              function_types::mi_remove_physical_memory_t,
              "MiRemovePhysicalMemory")

    INJ_SCAN(mi_get_ultra_page,
             "4C 8B DC 49 89 5B 08 49 89 73 10 49 89 7B 18 55 41 54 41 55"
             " 41 56 41 57 48 8D AB",
             function_types::mi_get_ultra_page_t,
             "MiGetUltraPage")

#undef INJ_SCAN
#undef INJ_SCAN2

    // PspExitThread — pattern scan only (never exported)
    {
        PVOID p = inj_scan_pattern(ntos_base_addr,
                                   "40 55 53 56 57 41 56 48 8D AC 24");
        if (p)
            globals::psp_exit_thread = (uintptr_t)p;
        else
            KIPC_LOG(
                       "[INJECTOR] WARNING: PspExitThread pattern not found\n");
    }

    // KiProcessListHead — not required for the injection paths used from
    // FINAL-DRV; set NULL and let callers handle absence gracefully.
    globals::ki_process_list_head = nullptr;

    // ─────────────────────────────────────────────────────────────────────
    // (d)  Symbol / data globals
    // ─────────────────────────────────────────────────────────────────────

    globals::ntos_base = (uintptr_t)ntos_base_addr;

    // mm_pfn_db: mem.cpp dereferences this as *mm_pfn_db to get the PFN array base,
    // so it must hold &MmPfnDatabase (the address of the kernel global), NOT its value.
    // pml4::g_mmonp_MmPfnDatabase follows the same convention (it is &MmPfnDatabase).
    // When no pml4 subsystem is present, inj_resolve returns &MmPfnDatabase directly —
    // do NOT dereference it before storing.
    globals::mm_pfn_db = pml4::g_mmonp_MmPfnDatabase;
    if (!globals::mm_pfn_db) {
        PVOID* pfn_ptr = (PVOID*)inj_resolve(L"MmPfnDatabase");
        if (pfn_ptr)
            globals::mm_pfn_db = (uintptr_t)pfn_ptr;  // store &MmPfnDatabase, not MmPfnDatabase
    }
    // MmPfnDatabase was removed from the ntoskrnl export table on hardened Win10 22H2
    // builds.  Fall back to the manual export walk first, then scan the body of
    // MmGetVirtualForPhysical (which IS exported) for the first RIP-relative 64-bit
    // load — on every observed Win10/11 build this is the load of MmPfnDatabase.
    if (!globals::mm_pfn_db) {
        PVOID* pfn_ptr = (PVOID*)inj_get_export(ntos_base_addr, "MmPfnDatabase");
        if (pfn_ptr)
            globals::mm_pfn_db = (uintptr_t)pfn_ptr;
    }
    if (!globals::mm_pfn_db && globals::mm_get_virtual_for_physical) {
        auto* fn = reinterpret_cast<UINT8*>(globals::mm_get_virtual_for_physical);
        for (int i = 0; i < 0x80 - 6; ++i) {
            // REX.W + MOV reg, [RIP+disp32]: 48 8B {05,0D,15,1D,...} disp32
            if (fn[i] == 0x48 && fn[i + 1] == 0x8B &&
                (fn[i + 2] & 0xC7) == 0x05) {
                PVOID target = inj_resolve_rel(&fn[i], 3, 7);
                if ((uintptr_t)target > 0xFFFF800000000000ULL) {
                    uintptr_t candidate = *(uintptr_t*)target;
                    // PFN database sits in the range ffffe... on Win10/11
                    if (candidate >= 0xFFFFE00000000000ULL &&
                        candidate <  0xFFFFF00000000000ULL) {
                        globals::mm_pfn_db = (uintptr_t)target;
                        KIPC_LOG(
                                   "[INJECTOR] MmPfnDatabase: resolved via "
                                   "MmGetVirtualForPhysical body scan = %p "
                                   "(value=%p)\n",
                                   target, (PVOID)candidate);
                        break;
                    }
                }
            }
        }
    }
    if (!globals::mm_pfn_db)
        KIPC_LOG(
                   "[INJECTOR] WARNING: MmPfnDatabase not found\n");

    // ps_loaded_module_list: MmGetSystemRoutineAddress returns the address of
    // the PsLoadedModuleList LIST_ENTRY exported from ntoskrnl.
    {
        PVOID p = inj_resolve(L"PsLoadedModuleList");
        if (p)
            globals::ps_loaded_module_list = (uintptr_t)p;
        else
            KIPC_LOG(
                       "[INJECTOR] WARNING: PsLoadedModuleList not found\n");
    }

    // build_version: read from RtlGetVersion
    if (globals::rtl_get_version) {
        RTL_OSVERSIONINFOW osvi = {};
        osvi.dwOSVersionInfoSize = sizeof(osvi);
        globals::rtl_get_version(&osvi);
        globals::build_version = osvi.dwBuildNumber;
        KIPC_LOG(
                   "[INJECTOR] build_version = %lu\n", globals::build_version);
    }

    // mm_highest_physical_page / mm_lowest_physical_page — required before any
    // physical r/w: is_pfn_valid() gates every read_physical_address call and
    // physical::init() does NOT populate these. Try two sources in order:
    //   1. ntoskrnl data exports MmHighestPhysicalPage / MmLowestPhysicalPage
    //   2. Walk MmGetPhysicalMemoryRanges to find the true extents
    {
        uintptr_t* p = (uintptr_t*)inj_resolve(L"MmHighestPhysicalPage");
        if (p) globals::mm_highest_physical_page = *p;

        p = (uintptr_t*)inj_resolve(L"MmLowestPhysicalPage");
        if (p) globals::mm_lowest_physical_page = *p;

        // Fallback: walk MmGetPhysicalMemoryRanges if either value is still 0.
        // This handles builds where the exports are absent or return 0.
        if (!globals::mm_highest_physical_page && globals::mm_get_physical_memory_ranges) {
            PPHYSICAL_MEMORY_RANGE ranges = globals::mm_get_physical_memory_ranges();
            if (ranges) {
                for (PPHYSICAL_MEMORY_RANGE r = ranges; r->NumberOfBytes.QuadPart; ++r) {
                    uintptr_t lo = (uintptr_t)(r->BaseAddress.QuadPart >> PAGE_SHIFT);
                    uintptr_t hi = (uintptr_t)((r->BaseAddress.QuadPart +
                                                r->NumberOfBytes.QuadPart - 1) >> PAGE_SHIFT);
                    if (!globals::mm_lowest_physical_page || lo < globals::mm_lowest_physical_page)
                        globals::mm_lowest_physical_page = lo;
                    if (hi > globals::mm_highest_physical_page)
                        globals::mm_highest_physical_page = hi;
                }
                ExFreePool(ranges);
            }
        }

        KIPC_LOG(
                   "[INJECTOR] physical page range: pfn 0x%llx - 0x%llx\n",
                   (unsigned long long)globals::mm_lowest_physical_page,
                   (unsigned long long)globals::mm_highest_physical_page);
    }

    // Known-good EPROCESS/KPROCESS structural offsets for Win10/11 (19041–26100).
    // These are only consumed by the hyperspace path, which is disabled, so
    // stale values cause no harm on future builds.
    globals::active_process_links       = 0x448;
    globals::_eprocess_thread_list_head = 0x5E0;
    globals::_kprocess_thread_list_head = 0x30;

    // ─────────────────────────────────────────────────────────────────────
    // (e)  HYPERSPACE DISABLED
    //
    // The hyperspace feature (ALLOC_AT_HYPERSPACE) requires calling
    // PsSetCreateProcessNotifyRoutineEx to register a per-process callback.
    // That callback's address must belong to a loaded module; a KDU-mapped
    // driver has no valid module backing.  PatchGuard validates the callback
    // array and will raise CRITICAL_STRUCTURE_CORRUPTION (bug-check 0x109)
    // on any mismatch.  Do NOT call any hyperspace:: functions or select
    // ALLOC_AT_HYPERSPACE from FINAL-DRV.
    // ─────────────────────────────────────────────────────────────────────
    globals::ctx.initialized = false;

    // ─────────────────────────────────────────────────────────────────────
    // (f)  physical::init()
    //
    // Sets up the single-page "hyperspace" physical-memory window used by
    // the standard alloc modes.  Failure is non-fatal: the physical read/write
    // primitives required by allocate_between_modules and
    // allocate_at_non_present_pml4e still work via translate_linear_address.
    // ─────────────────────────────────────────────────────────────────────
    {
        NTSTATUS phys_st = physical::init();
        if (!NT_SUCCESS(phys_st))
            KIPC_LOG(
                       "[INJECTOR] WARNING: physical::init() failed: 0x%08X"
                       " — contiguous-window alloc unavailable\n", phys_st);
        // Do NOT return failure here; standard alloc modes remain operational.
    }

    // ─────────────────────────────────────────────────────────────────────
    // (g)  Mark initialized, then verify critical pointers
    // ─────────────────────────────────────────────────────────────────────
    globals::initialized = true;

    // mm_allocate_independent_pages_ex is allowed to be NULL — mem.cpp
    // transparently falls back to MmAllocateContiguousMemory in that case.
    // The remaining two are non-negotiable for any inject codepath.
    if (!globals::mi_get_pte_address || !globals::nt_create_thread_ex) {
        KIPC_LOG(
                   "[INJECTOR] FATAL: critical pointers missing —"
                   " mi_get_pte_address=%p  nt_create_thread_ex=%p"
                   "  (mm_allocate_independent_pages_ex=%p — NULL is OK,"
                   " contiguous-memory fallback in mem.cpp)\n",
                   (PVOID)(uintptr_t)globals::mi_get_pte_address,
                   (PVOID)(uintptr_t)globals::nt_create_thread_ex,
                   (PVOID)(uintptr_t)globals::mm_allocate_independent_pages_ex);
        globals::initialized = false;
        return STATUS_UNSUCCESSFUL;
    }

    KIPC_LOG(
               "[INJECTOR] critical pointers:"
               " mm_allocate_independent_pages_ex=%p"
               "  mm_free_independent_pages=%p"
               "  mm_allocate_contiguous_memory=%p"
               "  mm_free_contiguous_memory=%p\n",
               (PVOID)(uintptr_t)globals::mm_allocate_independent_pages_ex,
               (PVOID)(uintptr_t)globals::mm_free_independent_pages,
               (PVOID)(uintptr_t)globals::mm_allocate_contiguous_memory,
               (PVOID)(uintptr_t)globals::mm_free_contiguous_memory);

    KIPC_LOG(
               "[INJECTOR] injector_init_globals: OK"
               " (build=%lu  pfn_db=0x%llx)\n",
               globals::build_version,
               (unsigned long long)globals::mm_pfn_db);

    return STATUS_SUCCESS;
}

#pragma warning(pop)
