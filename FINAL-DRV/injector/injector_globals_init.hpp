#pragma once

// Minimal kernel headers — no FINAL-DRV-specific includes
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,                        \
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
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
    INJ_RESOLVE(rtl_create_user_thread,         L"RtlCreateUserThread",
                function_types::rtl_create_user_thread_t)

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,                 \
                   "[INJECTOR] WARNING: pattern scan failed for " sym_name "\n");

    INJ_SCAN(ke_flush_single_tb,
             "4C 8B DC 53 56 57 41 54 41 55 41 56 41 57 48 81 EC",
             function_types::ke_flush_single_tb_t,
             "KeFlushSingleTb")

    INJ_SCAN(ke_flush_entire_tb,
             "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 0F B6 F1",
             function_types::ke_flush_entire_tb_t,
             "KeFlushEntireTb")

    INJ_SCAN(ke_invalidate_all_caches,
             "48 83 EC 28 65 48 8B 04 25 88 01 00 00",
             function_types::ke_invalidate_all_caches_t,
             "KeInvalidateAllCaches")

    INJ_SCAN(mm_allocate_independent_pages_ex,
             "48 89 5C 24 ? 48 89 74 24 ? 55 57 41 56 48 8B EC 48 83 EC 60",
             function_types::mm_allocate_independent_pages_ex_t,
             "MmAllocateIndependentPages")

    INJ_SCAN(mm_set_page_protection,
             "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 41 8B F8 48 8B F2",
             function_types::mm_set_page_protection_t,
             "MmSetPageProtection")

    INJ_SCAN(mm_free_independent_pages,
             "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B FA 48 8B D9 E8",
             function_types::mm_free_independent_pages,
             "MmFreeIndependentPages")

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
        globals::mi_get_pde_address =
            (function_types::mi_get_pde_address_t)inj_scan_pattern(
                ntos_base_addr,
                "48 C1 E9 12 48 B8 ? ? ? ? ? ? ? ? 48 23 C8 48 B8");
    }
    if (!globals::mi_get_pde_address)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[INJECTOR] WARNING: MiGetPdeAddress not found (export + pattern)\n");

    INJ_SCAN(mi_reserve_ptes,
             "48 89 5C 24 08 57 48 83 EC 20 8B DA 48 8B F9 E8",
             function_types::mi_reserve_ptes_t,
             "MiReservePtes")

    INJ_SCAN(mi_flush_entire_tb_due_to_attribute_change,
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

    INJ_SCAN(mi_set_page_table_pfn_buddy,
             "48 89 5C 24 08 57 48 83 EC 20 48 8B 1A 48 8B F9 48 85 DB 74 ? 48 8B CB",
             function_types::mi_set_page_table_pfn_buddy_t,
             "MiSetPageTablePfnBuddy")

    INJ_SCAN(mi_lock_page_table_page,
             "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 44 8B 41 08 48 8B F1",
             function_types::mi_lock_page_table_page_t,
             "MiLockPageTablePage")

    INJ_SCAN(mi_allocate_large_zero_pages,
             "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55"
             " 41 56 41 57 48 83 EC 40 4D 8B E1",
             function_types::mi_allocate_large_zero_pages_t,
             "MiAllocateLargeZeroPages")

    INJ_SCAN(mi_create_decay_pfn,
             "40 53 48 83 EC 20 48 8B 59 08 48 8B D1 33 C9 E8",
             function_types::mi_create_decay_pfn_t,
             "MiCreateDecayPfn")

    INJ_SCAN(mi_get_vm_access_logging_partition,
             "48 83 EC 28 65 48 8B 04 25 88 01 00 00 48 8B 80 ? ? ? ?"
             " 48 85 C0 74 ? 48 8B C8 E8",
             function_types::mi_get_vm_access_logging_partition_t,
             "MiGetVmAccessLoggingPartition")

    INJ_SCAN(mi_remove_physical_memory,
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

    // PspExitThread — pattern scan only (never exported)
    {
        PVOID p = inj_scan_pattern(ntos_base_addr,
                                   "40 55 53 56 57 41 56 48 8D AC 24");
        if (p)
            globals::psp_exit_thread = (uintptr_t)p;
        else
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[INJECTOR] WARNING: PspExitThread pattern not found\n");
    }

    // KiProcessListHead — not required for the injection paths used from
    // FINAL-DRV; set NULL and let callers handle absence gracefully.
    globals::ki_process_list_head = nullptr;

    // ─────────────────────────────────────────────────────────────────────
    // (d)  Symbol / data globals
    // ─────────────────────────────────────────────────────────────────────

    globals::ntos_base = (uintptr_t)ntos_base_addr;

    // mm_pfn_db: use pml4 subsystem's value if already populated (avoids rescan).
    // When FINAL-DRV has no pml4 subsystem (g_mmonp_MmPfnDatabase == 0), fall back
    // to MmGetSystemRoutineAddress — MmPfnDatabase IS in ntoskrnl's export table on
    // all supported Windows versions and MmGetSystemRoutineAddress returns its address.
    globals::mm_pfn_db = pml4::g_mmonp_MmPfnDatabase;
    if (!globals::mm_pfn_db) {
        PVOID* pfn_ptr = (PVOID*)inj_resolve(L"MmPfnDatabase");
        if (pfn_ptr)
            globals::mm_pfn_db = (uintptr_t)*pfn_ptr;
    }

    // ps_loaded_module_list: MmGetSystemRoutineAddress returns the address of
    // the PsLoadedModuleList LIST_ENTRY exported from ntoskrnl.
    {
        PVOID p = inj_resolve(L"PsLoadedModuleList");
        if (p)
            globals::ps_loaded_module_list = (uintptr_t)p;
        else
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[INJECTOR] WARNING: PsLoadedModuleList not found\n");
    }

    // build_version: read from RtlGetVersion
    if (globals::rtl_get_version) {
        RTL_OSVERSIONINFOW osvi = {};
        osvi.dwOSVersionInfoSize = sizeof(osvi);
        globals::rtl_get_version(&osvi);
        globals::build_version = osvi.dwBuildNumber;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[INJECTOR] build_version = %lu\n", globals::build_version);
    }

    // mm_highest_physical_page / mm_lowest_physical_page — populated by
    // physical::init() below; leave at 0 until then.

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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[INJECTOR] WARNING: physical::init() failed: 0x%08X"
                       " — contiguous-window alloc unavailable\n", phys_st);
        // Do NOT return failure here; standard alloc modes remain operational.
    }

    // ─────────────────────────────────────────────────────────────────────
    // (g)  Mark initialized, then verify critical pointers
    // ─────────────────────────────────────────────────────────────────────
    globals::initialized = true;

    // Both of these are exercised on every allocation call.  If either is
    // absent the driver will null-deref on the first inject attempt.
    if (!globals::mm_allocate_independent_pages_ex || !globals::mi_get_pte_address) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[INJECTOR] FATAL: critical pointers missing —"
                   " mm_allocate_independent_pages_ex=%p  mi_get_pte_address=%p\n",
                   (PVOID)(uintptr_t)globals::mm_allocate_independent_pages_ex,
                   (PVOID)(uintptr_t)globals::mi_get_pte_address);
        globals::initialized = false;
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[INJECTOR] injector_init_globals: OK"
               " (build=%lu  pfn_db=0x%llx)\n",
               globals::build_version,
               (unsigned long long)globals::mm_pfn_db);

    return STATUS_SUCCESS;
}

#pragma warning(pop)
