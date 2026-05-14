#pragma once
#include <ntdef.h>
#include <ntifs.h>

// Alloc mode constants (mirrors PT-injector def/request.hpp alloc_mode enum)
#define INJ_ALLOC_INSIDE_MAIN_MODULE     0
#define INJ_ALLOC_BETWEEN_LEGIT_MODULES  1
#define INJ_ALLOC_AT_LOW_ADDRESS         2
#define INJ_ALLOC_AT_HIGH_ADDRESS        3
// INJ_ALLOC_AT_HYPERSPACE (4) is disabled for KDU-mapped drivers — do not use

// Initialize the PT-injector globals. Call once from DriverEntry.
// ntos_base: base address of ntoskrnl.exe (use GetSystemModuleBase("ntoskrnl")).
NTSTATUS injector_init(PVOID ntos_base);

// Allocate memory in a target process using the specified stealth mode.
// out_remote_base receives the VA in the target process's address space.
NTSTATUS injector_stealth_alloc(
    UINT32  local_pid,
    UINT32  target_pid,
    SIZE_T  size,
    UINT32  alloc_mode,       // one of INJ_ALLOC_* constants
    PVOID*  out_remote_base);

// Write a mapped DLL's sections into the target process.
// remote_base:     VA in target as returned by injector_stealth_alloc.
// local_dll_buf:   kernel-mode buffer containing the raw DLL image.
// dll_size:        size of local_dll_buf.
// out_entry_offset:[out] RVA of DLL entry point (AddressOfEntryPoint).
NTSTATUS injector_map_dll_sections(
    UINT32  target_pid,
    PVOID   remote_base,
    PVOID   local_dll_buf,
    SIZE_T  dll_size,
    ULONG*  out_entry_offset);

// Execute the DLL entry point in the target process via RtlCreateUserThread.
// remote_base:          VA in target (same pointer from stealth_alloc).
// entry_offset:         RVA of entry point (from injector_map_dll_sections).
// shellcode_alloc_mode: alloc mode for the small shellcode stub page.
NTSTATUS injector_execute_dll(
    UINT32  local_pid,
    UINT32  target_pid,
    PVOID   remote_base,
    ULONG   entry_offset,
    UINT32  shellcode_alloc_mode);
