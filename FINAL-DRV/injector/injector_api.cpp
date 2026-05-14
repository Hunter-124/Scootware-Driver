// injector_api.cpp
//
// Thin implementation layer that bridges FINAL-DRV's C-like driver code to the
// PT-injector C++ subsystem.  This TU must NOT include any FINAL-DRV-specific
// headers (no CR3.h, no driver.cpp internals).

#include "injector_api.hpp"
#include "injector_globals_init.hpp"  // injector_init_globals + pml4 fwd decl
#include "def/globals.hpp"
#include "def/def.hpp"
#include "mem/mem.hpp"
#include "mem/phys.hpp"
#include "utils/raii.hpp"

// ─────────────────────────────────────────────────────────────────────────────
// pml4::g_mmonp_MmPfnDatabase definition
//
// injector_globals_init.hpp forward-declares this as extern to allow FINAL-DRV's
// own pml4 subsystem to pre-populate it.  FINAL-DRV has no pml4 subsystem, so we
// own the definition here; it starts at 0 and injector_init_globals() fills it in
// via pattern scan when it is 0.
// ─────────────────────────────────────────────────────────────────────────────
namespace pml4 { uintptr_t g_mmonp_MmPfnDatabase = 0; }

// ─────────────────────────────────────────────────────────────────────────────
// Cross-process memory helpers (option b — MmCopyVirtualMemory via globals)
// ─────────────────────────────────────────────────────────────────────────────

// Write size bytes from kernel buffer src_buf to dest_va in a target process.
static NTSTATUS inj_write_process(UINT32 target_pid, PVOID dest_va,
                                  PVOID src_buf, SIZE_T size) {
    PEPROCESS proc = nullptr;
    NTSTATUS st = globals::ps_lookup_process_by_process_id(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &proc);
    if (!NT_SUCCESS(st)) return st;

    SIZE_T copied = 0;
    st = globals::mm_copy_virtual_memory(
        globals::io_get_current_process(), src_buf,
        proc, dest_va,
        size, KernelMode, &copied);

    globals::obf_dereference_object(proc);
    return (NT_SUCCESS(st) && copied == size) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// Read size bytes from src_va in target_proc into kernel buffer dst_buf.
static NTSTATUS inj_read_target(PEPROCESS target_proc, PVOID src_va,
                                PVOID dst_buf, SIZE_T size) {
    SIZE_T copied = 0;
    NTSTATUS st = globals::mm_copy_virtual_memory(
        target_proc, src_va,
        globals::io_get_current_process(), dst_buf,
        size, KernelMode, &copied);
    return (NT_SUCCESS(st) && copied == size) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// ─────────────────────────────────────────────────────────────────────────────
// IAT resolution helpers
// ─────────────────────────────────────────────────────────────────────────────

// Find the base address of a DLL loaded in the target process's address space
// by walking the PEB InLoadOrderModuleList via cross-process reads.
// dll_name_ansi: short base name, e.g. "ntdll.dll" — case-insensitive.
static PVOID inj_find_module_in_target(PEPROCESS target_proc,
                                       const char* dll_name_ansi) {
    // PsGetProcessPeb returns a VA inside the target's address space.
    PPEB peb_va = globals::ps_get_process_peb(target_proc);
    if (!peb_va) return nullptr;

    // Read Ldr pointer from PEB (at a fixed offset of 0x18 on all x64 Windows).
    PPEB_LDR_DATA ldr_ptr = nullptr;
    if (!NT_SUCCESS(inj_read_target(target_proc,
            reinterpret_cast<PUCHAR>(peb_va) + 0x18,
            &ldr_ptr, sizeof(ldr_ptr))))
        return nullptr;
    if (!ldr_ptr) return nullptr;

    // Read InLoadOrderModuleList head (at ldr_ptr->InLoadOrderModuleList).
    LIST_ENTRY list_head;
    PUCHAR lml_va = reinterpret_cast<PUCHAR>(ldr_ptr) +
                    offsetof(PEB_LDR_DATA, InLoadOrderModuleList);
    if (!NT_SUCCESS(inj_read_target(target_proc, lml_va,
                                    &list_head, sizeof(list_head))))
        return nullptr;

    LIST_ENTRY* head_va = reinterpret_cast<LIST_ENTRY*>(lml_va);
    LIST_ENTRY* cur_va  = list_head.Flink;

    // Compute the ansi name length once
    SIZE_T ansi_len = 0;
    while (dll_name_ansi[ansi_len]) ++ansi_len;

    for (ULONG guard = 0; cur_va && cur_va != head_va && guard < 512; ++guard) {
        // LDR_DATA_TABLE_ENTRY starts at InLoadOrderLinks
        LDR_DATA_TABLE_ENTRY entry = {};
        PUCHAR entry_va = reinterpret_cast<PUCHAR>(cur_va) -
                          offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!NT_SUCCESS(inj_read_target(target_proc, entry_va,
                                        &entry, sizeof(entry))))
            break;

        if (entry.BaseDllName.Length && entry.BaseDllName.Buffer) {
            USHORT buf_bytes = min(entry.BaseDllName.Length,
                                   static_cast<USHORT>(260 * sizeof(WCHAR)));
            WCHAR wname[261] = {};
            inj_read_target(target_proc, entry.BaseDllName.Buffer,
                            wname, buf_bytes);

            SIZE_T wlen = buf_bytes / sizeof(WCHAR);
            bool match = (wlen == ansi_len);
            for (SIZE_T i = 0; i < ansi_len && match; ++i) {
                wchar_t wc = wname[i];
                char    ac = dll_name_ansi[i];
                if (wc >= L'A' && wc <= L'Z') wc += 32;
                if (ac >= 'A' && ac <= 'Z')   ac += 32;
                if (static_cast<wchar_t>(ac) != wc) match = false;
            }
            if (match && entry.DllBase) return entry.DllBase;
        }

        cur_va = entry.InLoadOrderLinks.Flink;
    }
    return nullptr;
}

// Find an exported function by name in a DLL resident in target_proc's VA space.
static PVOID inj_find_export_in_target(PEPROCESS target_proc,
                                       PVOID dll_base_va,
                                       const char* fn_name) {
    IMAGE_DOS_HEADER dos = {};
    if (!NT_SUCCESS(inj_read_target(target_proc, dll_base_va, &dos, sizeof(dos))))
        return nullptr;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS64 nt = {};
    if (!NT_SUCCESS(inj_read_target(target_proc,
            reinterpret_cast<PUCHAR>(dll_base_va) + dos.e_lfanew,
            &nt, sizeof(nt))))
        return nullptr;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& exp_dir_entry = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir_entry.VirtualAddress) return nullptr;

    IMAGE_EXPORT_DIRECTORY exp_dir = {};
    if (!NT_SUCCESS(inj_read_target(target_proc,
            reinterpret_cast<PUCHAR>(dll_base_va) + exp_dir_entry.VirtualAddress,
            &exp_dir, sizeof(exp_dir))))
        return nullptr;

    if (!exp_dir.NumberOfNames || !exp_dir.NumberOfFunctions) return nullptr;

    // Heap-allocate the three export arrays.
    SIZE_T names_sz = exp_dir.NumberOfNames    * sizeof(ULONG);
    SIZE_T ords_sz  = exp_dir.NumberOfNames    * sizeof(USHORT);
    SIZE_T funcs_sz = exp_dir.NumberOfFunctions * sizeof(ULONG);

    auto* name_rvas = static_cast<ULONG*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, names_sz, 'INRv'));
    auto* ordinals  = static_cast<USHORT*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, ords_sz,  'IORd'));
    auto* func_rvas = static_cast<ULONG*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, funcs_sz, 'IFRv'));

    PVOID result = nullptr;

    if (!name_rvas || !ordinals || !func_rvas) goto out;

    if (!NT_SUCCESS(inj_read_target(target_proc,
            reinterpret_cast<PUCHAR>(dll_base_va) + exp_dir.AddressOfNames,
            name_rvas, names_sz)))
        goto out;
    if (!NT_SUCCESS(inj_read_target(target_proc,
            reinterpret_cast<PUCHAR>(dll_base_va) + exp_dir.AddressOfNameOrdinals,
            ordinals, ords_sz)))
        goto out;
    if (!NT_SUCCESS(inj_read_target(target_proc,
            reinterpret_cast<PUCHAR>(dll_base_va) + exp_dir.AddressOfFunctions,
            func_rvas, funcs_sz)))
        goto out;

    for (ULONG i = 0; i < exp_dir.NumberOfNames; ++i) {
        char name_buf[256] = {};
        inj_read_target(target_proc,
                        reinterpret_cast<PUCHAR>(dll_base_va) + name_rvas[i],
                        name_buf, sizeof(name_buf) - 1);

        bool match = true;
        for (int j = 0; ; ++j) {
            if (name_buf[j] != fn_name[j]) { match = false; break; }
            if (!name_buf[j]) break;
        }
        if (match) {
            ULONG rva = func_rvas[ordinals[i]];
            if (rva) {
                // Skip forwarded exports (RVA inside export directory)
                if (rva >= exp_dir_entry.VirtualAddress &&
                    rva <  exp_dir_entry.VirtualAddress + exp_dir_entry.Size)
                    break;
                result = reinterpret_cast<PUCHAR>(dll_base_va) + rva;
            }
            break;
        }
    }

out:
    if (name_rvas) ExFreePoolWithTag(name_rvas, 'INRv');
    if (ordinals)  ExFreePoolWithTag(ordinals,  'IORd');
    if (func_rvas) ExFreePoolWithTag(func_rvas, 'IFRv');
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API implementation
// ─────────────────────────────────────────────────────────────────────────────

NTSTATUS injector_init(PVOID ntos_base) {
    return injector_init_globals(ntos_base);
}

NTSTATUS injector_stealth_alloc(UINT32  local_pid,
                                UINT32  target_pid,
                                SIZE_T  size,
                                UINT32  alloc_mode,
                                PVOID*  out_remote_base) {
    if (!out_remote_base) return STATUS_INVALID_PARAMETER;
    *out_remote_base = nullptr;

    void* addr = nullptr;
    switch (alloc_mode) {
        case INJ_ALLOC_INSIDE_MAIN_MODULE:
            addr = mem::hijack_null_pfn(local_pid, target_pid, size);
            break;
        case INJ_ALLOC_BETWEEN_LEGIT_MODULES:
            addr = mem::allocate_between_modules(local_pid, target_pid, size);
            break;
        case INJ_ALLOC_AT_LOW_ADDRESS:
            addr = mem::allocate_at_non_present_pml4e(
                local_pid, target_pid, size,
                memory_type::NORMAL_PAGE,
                static_cast<bool>(memory_space::USER_MODE));
            break;
        case INJ_ALLOC_AT_HIGH_ADDRESS:
            addr = mem::allocate_at_non_present_pml4e(
                local_pid, target_pid, size,
                memory_type::NORMAL_PAGE,
                static_cast<bool>(memory_space::KERNEL_MODE));
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    if (!addr) return STATUS_UNSUCCESSFUL;
    *out_remote_base = addr;
    return STATUS_SUCCESS;
}

NTSTATUS injector_map_dll_sections(UINT32  target_pid,
                                   PVOID   remote_base,
                                   PVOID   local_dll_buf,
                                   SIZE_T  dll_size,
                                   ULONG*  out_entry_offset) {
    if (!remote_base || !local_dll_buf || !dll_size || !out_entry_offset)
        return STATUS_INVALID_PARAMETER;

    // ── Validate PE ───────────────────────────────────────────────────────
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(local_dll_buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        reinterpret_cast<PUCHAR>(local_dll_buf) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return STATUS_NOT_SUPPORTED;

    // ── Apply base relocations into local_dll_buf ─────────────────────────
    auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir.VirtualAddress && reloc_dir.Size) {
        ULONG_PTR delta = reinterpret_cast<ULONG_PTR>(remote_base) -
                          nt->OptionalHeader.ImageBase;
        if (delta != 0) {
            auto* blk = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<PUCHAR>(local_dll_buf) + reloc_dir.VirtualAddress);
            auto* blk_end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<PUCHAR>(local_dll_buf) + reloc_dir.VirtualAddress +
                reloc_dir.Size);

            while (blk < blk_end && blk->VirtualAddress && blk->SizeOfBlock) {
                ULONG count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                              sizeof(USHORT);
                auto* entry = reinterpret_cast<PUSHORT>(
                    reinterpret_cast<PUCHAR>(blk) + sizeof(IMAGE_BASE_RELOCATION));

                for (ULONG i = 0; i < count; ++i) {
                    if ((entry[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        ULONG offset = entry[i] & 0xFFF;
                        auto* patch = reinterpret_cast<PULONG_PTR>(
                            reinterpret_cast<PUCHAR>(local_dll_buf) +
                            blk->VirtualAddress + offset);
                        *patch += delta;
                    }
                }
                blk = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                    reinterpret_cast<PUCHAR>(blk) + blk->SizeOfBlock);
            }
        }
    }

    // ── Resolve imports and patch IAT in local_dll_buf ────────────────────
    auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress && import_dir.Size) {
        PEPROCESS target_proc = nullptr;
        NTSTATUS lookup_st = globals::ps_lookup_process_by_process_id(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)),
            &target_proc);

        if (NT_SUCCESS(lookup_st) && target_proc) {
            auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                reinterpret_cast<PUCHAR>(local_dll_buf) + import_dir.VirtualAddress);

            while (desc->Name) {
                const char* dll_name = reinterpret_cast<const char*>(
                    reinterpret_cast<PUCHAR>(local_dll_buf) + desc->Name);

                PVOID mod_base = inj_find_module_in_target(target_proc, dll_name);
                if (!mod_base) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[INJECTOR] injector_map_dll_sections: %s not"
                               " found in target PEB\n", dll_name);
                    ++desc;
                    continue;
                }

                // Prefer OriginalFirstThunk (hint names); fall back to FirstThunk
                auto* orig_thunk = desc->OriginalFirstThunk
                    ? reinterpret_cast<PIMAGE_THUNK_DATA64>(
                          reinterpret_cast<PUCHAR>(local_dll_buf) +
                          desc->OriginalFirstThunk)
                    : reinterpret_cast<PIMAGE_THUNK_DATA64>(
                          reinterpret_cast<PUCHAR>(local_dll_buf) +
                          desc->FirstThunk);

                auto* iat_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
                    reinterpret_cast<PUCHAR>(local_dll_buf) + desc->FirstThunk);

                while (orig_thunk->u1.AddressOfData) {
                    PVOID fn_va = nullptr;

                    if (IMAGE_SNAP_BY_ORDINAL64(orig_thunk->u1.Ordinal)) {
                        // Import by ordinal — find via ordinal in export table
                        USHORT ordinal = static_cast<USHORT>(
                            IMAGE_ORDINAL64(orig_thunk->u1.Ordinal));

                        // Read export directory to resolve by ordinal
                        IMAGE_DOS_HEADER mod_dos = {};
                        IMAGE_NT_HEADERS64 mod_nt = {};
                        if (NT_SUCCESS(inj_read_target(target_proc, mod_base,
                                                       &mod_dos, sizeof(mod_dos))) &&
                            mod_dos.e_magic == IMAGE_DOS_SIGNATURE &&
                            NT_SUCCESS(inj_read_target(target_proc,
                                reinterpret_cast<PUCHAR>(mod_base) + mod_dos.e_lfanew,
                                &mod_nt, sizeof(mod_nt))) &&
                            mod_nt.Signature == IMAGE_NT_SIGNATURE) {

                            auto& exp_dir_entry2 =
                                mod_nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                            if (exp_dir_entry2.VirtualAddress) {
                                IMAGE_EXPORT_DIRECTORY exp_dir2 = {};
                                inj_read_target(target_proc,
                                    reinterpret_cast<PUCHAR>(mod_base) +
                                    exp_dir_entry2.VirtualAddress,
                                    &exp_dir2, sizeof(exp_dir2));

                                ULONG idx = ordinal - exp_dir2.Base;
                                if (idx < exp_dir2.NumberOfFunctions) {
                                    ULONG rva2 = 0;
                                    inj_read_target(target_proc,
                                        reinterpret_cast<PUCHAR>(mod_base) +
                                        exp_dir2.AddressOfFunctions +
                                        idx * sizeof(ULONG),
                                        &rva2, sizeof(rva2));
                                    if (rva2) fn_va =
                                        reinterpret_cast<PUCHAR>(mod_base) + rva2;
                                }
                            }
                        }
                    } else {
                        // Import by name
                        auto* by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                            reinterpret_cast<PUCHAR>(local_dll_buf) +
                            orig_thunk->u1.AddressOfData);
                        fn_va = inj_find_export_in_target(
                            target_proc, mod_base,
                            reinterpret_cast<const char*>(by_name->Name));
                    }

                    if (!fn_va)
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[INJECTOR] injector_map_dll_sections:"
                                   " unresolved import in %s\n", dll_name);

                    iat_thunk->u1.Function =
                        reinterpret_cast<ULONGLONG>(fn_va);

                    ++orig_thunk;
                    ++iat_thunk;
                }
                ++desc;
            }
            globals::obf_dereference_object(target_proc);
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[INJECTOR] injector_map_dll_sections: could not open"
                       " target pid %u for import resolution\n", target_pid);
        }
    }

    // ── Write PE header to target ─────────────────────────────────────────
    {
        NTSTATUS st = inj_write_process(target_pid, remote_base,
                                        local_dll_buf,
                                        nt->OptionalHeader.SizeOfHeaders);
        if (!NT_SUCCESS(st)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[INJECTOR] injector_map_dll_sections: header write"
                       " failed: 0x%08X\n", st);
            return st;
        }
    }

    // ── Write sections to target ──────────────────────────────────────────
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!sec[i].SizeOfRawData) continue;

        SIZE_T write_size = min(
            static_cast<SIZE_T>(sec[i].SizeOfRawData),
            static_cast<SIZE_T>(sec[i].Misc.VirtualSize));

        // Bounds-check source pointer
        if (static_cast<SIZE_T>(sec[i].PointerToRawData) + write_size > dll_size)
            continue;

        PVOID src = reinterpret_cast<PUCHAR>(local_dll_buf) + sec[i].PointerToRawData;
        PVOID dst = reinterpret_cast<PUCHAR>(remote_base)   + sec[i].VirtualAddress;

        NTSTATUS st = inj_write_process(target_pid, dst, src, write_size);
        if (!NT_SUCCESS(st))
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[INJECTOR] injector_map_dll_sections: section %hu"
                       " write failed: 0x%08X\n", i, st);
    }

    *out_entry_offset = nt->OptionalHeader.AddressOfEntryPoint;
    return STATUS_SUCCESS;
}

NTSTATUS injector_execute_dll(UINT32  local_pid,
                              UINT32  target_pid,
                              PVOID   remote_base,
                              ULONG   entry_offset,
                              UINT32  shellcode_alloc_mode) {
    if (!remote_base || !entry_offset || !target_pid)
        return STATUS_INVALID_PARAMETER;

    // ── Build shellcode in kernel buffer ──────────────────────────────────
    // Verbatim from PT-injector handle_execute_dll_via_thread_request().
    // Implements: ((DllMain_t)(remote_base + entry_offset))(remote_base, 1, NULL)
    //
    //   48 83 EC 28             sub  rsp, 28h         ; shadow space
    //   48 B9 [8 bytes]         mov  rcx, DLL_BASE    ; hinstDLL  (offset 0x06)
    //   48 B8 [8 bytes]         mov  rax, ENTRY_POINT ; call target (offset 0x10)
    //   BA 01 00 00 00          mov  edx, 1            ; DLL_PROCESS_ATTACH
    //   45 33 C0                xor  r8d, r8d          ; lpvReserved = NULL
    //   FF D0                   call rax
    //   48 83 C4 28             add  rsp, 28h
    //   C3                      ret
    std::uint8_t dll_main_shellcode[50] = {
        0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x01,
        0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3};

    const unsigned long dll_base_offset   = 0x6;
    const unsigned long entry_point_offset = 0x10;

    // Kernel-side staging buffer via RAII
    raii::kernel_memory kernel_shellcode(PAGE_SIZE);
    if (!kernel_shellcode.is_valid()) {
        log("ERROR", "failed to allocate kernel buffer for shellcode");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    globals::memcpy(kernel_shellcode.get(), dll_main_shellcode,
                    sizeof(dll_main_shellcode));

    // Patch in DLL base and entry point addresses
    *reinterpret_cast<std::uintptr_t*>(
        reinterpret_cast<std::uintptr_t>(kernel_shellcode.get()) +
        dll_base_offset) = reinterpret_cast<std::uintptr_t>(remote_base);

    *reinterpret_cast<std::uintptr_t*>(
        reinterpret_cast<std::uintptr_t>(kernel_shellcode.get()) +
        entry_point_offset) =
            reinterpret_cast<std::uintptr_t>(remote_base) + entry_offset;

    // ── Allocate remote shellcode page ────────────────────────────────────
    PVOID remote_shellcode = nullptr;
    NTSTATUS alloc_st = injector_stealth_alloc(
        local_pid, target_pid, PAGE_SIZE,
        shellcode_alloc_mode, &remote_shellcode);
    if (!NT_SUCCESS(alloc_st) || !remote_shellcode) {
        log("ERROR", "failed to allocate remote shellcode");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ── Get target EPROCESS ───────────────────────────────────────────────
    PEPROCESS target_process = nullptr;
    NTSTATUS lookup_st = globals::ps_lookup_process_by_process_id(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)),
        &target_process);
    if (!NT_SUCCESS(lookup_st)) {
        log("ERROR", "failed to get target process");
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return lookup_st;
    }
    raii::kernel_object_ref<_KPROCESS> target_ref(
        reinterpret_cast<_KPROCESS*>(target_process));

    // ── Write shellcode to target (non-hyperspace path) ───────────────────
    // globals::ctx.initialized is always FALSE (hyperspace disabled in FINAL-DRV).
    NTSTATUS write_st = physical::copy_memory(
        globals::io_get_current_process(), kernel_shellcode.get(),
        target_process, remote_shellcode,
        sizeof(dll_main_shellcode));

    if (!NT_SUCCESS(write_st)) {
        log("ERROR", "failed to write shellcode to target process");
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return write_st;
    }

    // ── Open target process handle ────────────────────────────────────────
    raii::kernel_handle process_handle;
    OBJECT_ATTRIBUTES obj_attr = {};
    CLIENT_ID process_client_id = {};
    process_client_id.UniqueProcess =
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid));
    InitializeObjectAttributes(&obj_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS open_st = globals::zw_open_process(
        process_handle.address_of(), PROCESS_ALL_ACCESS, &obj_attr,
        &process_client_id);
    if (!NT_SUCCESS(open_st)) {
        log("ERROR", "failed to open target process: 0x%X", open_st);
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return open_st;
    }

    // ── Create suspended user thread at shellcode ─────────────────────────
    raii::kernel_handle thread_handle;
    CLIENT_ID thread_client_id = {};

    NTSTATUS thread_st = globals::rtl_create_user_thread(
        process_handle.get(), NULL, TRUE, 0, 0, 0,
        remote_shellcode, NULL,
        thread_handle.address_of(), &thread_client_id);
    if (!NT_SUCCESS(thread_st)) {
        log("ERROR", "RtlCreateUserThread failed: 0x%X", thread_st);
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return thread_st;
    }

    // ── Look up ETHREAD for the new thread ───────────────────────────────
    PETHREAD thread = nullptr;
    NTSTATUS thr_lookup_st = globals::ps_lookup_thread_by_thread_id(
        thread_client_id.UniqueThread, &thread);
    if (!NT_SUCCESS(thr_lookup_st)) {
        log("ERROR", "PsLookupThreadByThreadId failed: 0x%X", thr_lookup_st);
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return thr_lookup_st;
    }
    raii::kernel_object_ref<_KTHREAD> thread_ref(thread);

    // ── Resume thread ─────────────────────────────────────────────────────
    unsigned long prev_suspend = 0;
    NTSTATUS resume_st = globals::ps_resume_thread(thread, &prev_suspend);
    if (!NT_SUCCESS(resume_st)) {
        log("ERROR", "PsResumeThread failed: 0x%X", resume_st);
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return resume_st;
    }

    // ── Wait for thread (15-second timeout) ──────────────────────────────
    if (thread_handle.is_valid()) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -150000000LL;  // 15 s in 100 ns units

        NTSTATUS wait_st = globals::zw_wait_for_single_object(
            thread_handle.get(), FALSE, &timeout);

        if (wait_st == STATUS_TIMEOUT)
            log("WARNING", "thread execution timed out after 15 seconds");
        else if (NT_SUCCESS(wait_st))
            log("INFO", "thread completed successfully");
        else
            log("ERROR", "wait failed: 0x%X", wait_st);
    }

    // ── Zero shellcode in target (best-effort cleanup) ────────────────────
    std::uint8_t zero_buffer[sizeof(dll_main_shellcode)] = {0};

    PEPROCESS cleanup_process = nullptr;
    if (globals::ps_lookup_process_by_process_id(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)),
            &cleanup_process) == STATUS_SUCCESS) {
        raii::kernel_object_ref<_KPROCESS> cleanup_ref(
            reinterpret_cast<_KPROCESS*>(cleanup_process));
        physical::copy_memory(globals::io_get_current_process(), zero_buffer,
                              cleanup_process, remote_shellcode,
                              sizeof(dll_main_shellcode));
    }

    log("INFO", "DLL execution completed for PID: %d at base: 0x%p",
        target_pid, remote_base);
    return STATUS_SUCCESS;
}
