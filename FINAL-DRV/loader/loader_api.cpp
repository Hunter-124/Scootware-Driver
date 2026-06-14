// injector_api.cpp
//
// Thin implementation layer that bridges FINAL-DRV's C-like driver code to the
// PT-injector C++ subsystem.  This TU must NOT include any FINAL-DRV-specific
// headers (no CR3.h, no driver.cpp internals).

#include "loader_api.hpp"
#include "loader_globals_init.hpp"  // injector_init_globals + pml4 fwd decl
#include "def/globals.hpp"
#include "def/def.hpp"
#include "mem/mem.hpp"
#include "mem/phys.hpp"
#include "utils/raii.hpp"
#include "../kdebug.h"        // KIPC_LOG — compiles to no-op in Release
#include "../private_pool.h" // STEALTH_POOL_ALLOC — randomized tags

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
// Cross-process memory helpers
// ─────────────────────────────────────────────────────────────────────────────
//
// IMPORTANT: there are TWO different write paths and they are NOT
// interchangeable.  The destinations the injector writes to fall into two
// categories:
//
//   (A) Pages backed by a real VAD — the existing modules of the target.
//       Reads from these (PEB walk, import resolution, ordinal lookup) go
//       through MmCopyVirtualMemory which walks the VAD tree to validate
//       the address before copying.
//
//   (B) Pages we manually mapped ourselves via write_page_tables, that have
//       NO VAD entry in the target.  Mm cannot resolve these — calling
//       MmCopyVirtualMemory on them dereferences a null/stale VAD pointer
//       deep inside the MM/Cc helpers and raises a kernel access violation
//       that we cannot unwind out of (manifests as DRIVER_OVERRAN_STACK_
//       BUFFER 0xF7 / MISSING_GSFRAME because manually-mapped drivers
//       have no registered RUNTIME_FUNCTION entries for the unwinder).
//
// All writes into category (B) MUST go through physical::write_process_memory
// (PT-injector physical-write path), which uses our own proxy PTE to
// reach the target page by PFN.  No VAD lookup, no MM bookkeeping, no Cc.

// Write size bytes from kernel buffer src_buf to dest_va in a target process.
// Use this ONLY when dest_va is VAD-backed in the target.
static NTSTATUS inj_write_process_vad(UINT32 target_pid, PVOID dest_va,
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

// Write to our own manually-mapped (VAD-less) pages in the target.
// Goes through the PT-injector physical path — bypasses MM entirely.
static NTSTATUS inj_write_process_phys(UINT32 target_pid, PVOID dest_va,
                                       PVOID src_buf, SIZE_T size) {
    PEPROCESS proc = nullptr;
    NTSTATUS st = globals::ps_lookup_process_by_process_id(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &proc);
    if (!NT_SUCCESS(st)) return st;

    st = physical::write_process_memory(proc, reinterpret_cast<uintptr_t>(dest_va),
                                        src_buf, size);

    globals::obf_dereference_object(proc);
    return st;
}

// Read size bytes from src_va in target_proc into kernel buffer dst_buf.
// Used only for reading the target's REAL (VAD-backed) module pages during
// PEB walk / import resolution.
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
        STEALTH_POOL_ALLOC(names_sz, kStealthTagIatN));
    auto* ordinals  = static_cast<USHORT*>(
        STEALTH_POOL_ALLOC(ords_sz,  kStealthTagIatO));
    auto* func_rvas = static_cast<ULONG*>(
        STEALTH_POOL_ALLOC(funcs_sz, kStealthTagIatF));

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

    // Cap the export-name walk to a generous ceiling so a corrupt
    // NumberOfNames can't make us iterate forever.  (The bound is computed
    // inline here rather than as a named local because the goto-out
    // cleanup path above would skip a local's initialization, tripping
    // C2362 on /Wall.)
    for (ULONG i = 0;
         i < (exp_dir.NumberOfNames > 65536 ? 65536u : exp_dir.NumberOfNames);
         ++i) {
        char name_buf[256] = {};
        inj_read_target(target_proc,
                        reinterpret_cast<PUCHAR>(dll_base_va) + name_rvas[i],
                        name_buf, sizeof(name_buf) - 1);

        // Bounded compare: stop at the first null in name_buf (guaranteed
        // by the {} init + size-1 read) and never read past 255 chars of
        // fn_name.  Previously this loop read fn_name[j] without any cap,
        // so a fn_name pointer that wasn't null-terminated within the
        // mapped DLL buffer could fault.
        bool match = true;
        for (int j = 0; j < (int)sizeof(name_buf); ++j) {
            char a = name_buf[j];
            char b = fn_name[j];
            if (a != b) { match = false; break; }
            if (a == '\0') break;
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
    // Frees MUST match the allocator's tag.  These buffers come from
    // STEALTH_POOL_ALLOC, which derives a per-boot randomized tag from
    // stealth_alloc::TagFor(site); using the old hardcoded 'INRv'/'IORd'/'IFRv'
    // tags here would bugcheck BAD_POOL_HEADER under Driver Verifier and
    // pollute !poolused attribution on production kernels.
    if (name_rvas) STEALTH_POOL_FREE(name_rvas, kStealthTagIatN);
    if (ordinals)  STEALTH_POOL_FREE(ordinals,  kStealthTagIatO);
    if (func_rvas) STEALTH_POOL_FREE(func_rvas, kStealthTagIatF);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API implementation
// ─────────────────────────────────────────────────────────────────────────────

NTSTATUS injector_init(PVOID ntos_base) {
    return injector_init_globals(ntos_base);
}

BOOLEAN injector_is_ready(void) {
    return globals::initialized ? TRUE : FALSE;
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
            // hijack_null_pfn replaces null-PFN PTEs inside the target's
            // existing .text section with our own physical pages.  This
            // bypasses MM's working-set accounting; on target process exit
            // MM finds PFNs it didn't charge for and bugchecks 0x21
            // (QUOTA_UNDERFLOW).  mi_lock_page_table_page is required to
            // lock the relevant page-table page before modifying entries —
            // refuse if it didn't resolve.
            if (!globals::mi_lock_page_table_page) {
                KIPC_LOG(
                           "[INJECTOR] injector_stealth_alloc: rejecting "
                           "INJ_ALLOC_INSIDE_MAIN_MODULE (mode 0) — "
                           "mi_lock_page_table_page unresolved; pattern scan "
                           "failed for this build.  Use "
                           "INJ_ALLOC_BETWEEN_LEGIT_MODULES (mode 1) instead.\n");
                return STATUS_NOT_SUPPORTED;
            }
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
                                   PVOID   file_dll_buf,
                                   SIZE_T  file_dll_size,
                                   ULONG*  out_entry_offset) {
    if (!remote_base || !file_dll_buf || !file_dll_size || !out_entry_offset)
        return STATUS_INVALID_PARAMETER;

    // ── Validate the PE from file-form bytes ──────────────────────────────
    auto* file_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(file_dll_buf);
    if (file_dos->e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    auto* file_nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        reinterpret_cast<PUCHAR>(file_dll_buf) + file_dos->e_lfanew);
    if (file_nt->Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if (file_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return STATUS_NOT_SUPPORTED;

    const ULONG image_size = file_nt->OptionalHeader.SizeOfImage;
    if (!image_size || image_size > (256u * 1024u * 1024u))
        return STATUS_INVALID_IMAGE_FORMAT;

    // ── Build a MEMORY-form staging buffer ────────────────────────────────
    // CRITICAL FIX: the rest of this function patches relocations + imports
    // at RVA offsets (`buf + reloc_dir.VirtualAddress`, `buf + FirstThunk`,
    // etc).  The user-mode helper reads the DLL via ReadFile, so what arrives
    // here is in FILE form (sections at PointerToRawData, typically 0x200-
    // aligned).  Patching at RVA offsets in file-form bytes writes deltas
    // to wrong file positions, corrupting random bytes and leaving the actual
    // section content un-relocated.  When the injected DllMain accesses any
    // global, it derefs an un-relocated pointer and AVs → target process dies.
    //
    // LoadLibrary works because the Windows loader does the file→memory
    // conversion internally.  Do the same here: copy SizeOfHeaders + each
    // section into a SizeOfImage-sized buffer at their VirtualAddress.  From
    // that point on, `local_dll_buf` is in memory form and RVAs Just Work.
    PVOID local_dll_buf = STEALTH_POOL_ALLOC(image_size, kStealthTagPayload);
    if (!local_dll_buf) return STATUS_INSUFFICIENT_RESOURCES;

    {
        SIZE_T hdr_copy = file_nt->OptionalHeader.SizeOfHeaders;
        if (hdr_copy > file_dll_size) hdr_copy = file_dll_size;
        if (hdr_copy > image_size)    hdr_copy = image_size;
        RtlCopyMemory(local_dll_buf, file_dll_buf, hdr_copy);

        auto* file_sec = IMAGE_FIRST_SECTION(file_nt);
        for (USHORT si = 0; si < file_nt->FileHeader.NumberOfSections; ++si) {
            if (!file_sec[si].SizeOfRawData) continue;
            SIZE_T copy = min(
                static_cast<SIZE_T>(file_sec[si].SizeOfRawData),
                static_cast<SIZE_T>(file_sec[si].Misc.VirtualSize
                                    ? file_sec[si].Misc.VirtualSize
                                    : file_sec[si].SizeOfRawData));
            if ((SIZE_T)file_sec[si].PointerToRawData + copy > file_dll_size) continue;
            if ((SIZE_T)file_sec[si].VirtualAddress  + copy > image_size)     continue;
            RtlCopyMemory(
                reinterpret_cast<PUCHAR>(local_dll_buf) + file_sec[si].VirtualAddress,
                reinterpret_cast<PUCHAR>(file_dll_buf) + file_sec[si].PointerToRawData,
                copy);
        }
    }

    // From this point `local_dll_buf` is memory-form and `dll_size` is the
    // virtual image size.  Re-bind dos/nt to the new buffer.
    const SIZE_T dll_size = image_size;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(local_dll_buf);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        reinterpret_cast<PUCHAR>(local_dll_buf) + dos->e_lfanew);

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
            // Bounds-check the import directory itself.  The PE loader on
            // Windows treats a too-large import dir as invalid; we do the
            // same.  Beyond that we cap the descriptor count at a sane
            // ceiling so a corrupt/poisoned import RVA cannot walk us off
            // the end of local_dll_buf into unmapped pool memory (which is
            // exactly what triggered the DbgPrintEx %s page fault we saw
            // in the 0xF7_MISSING_GSFRAME dump).
            const SIZE_T desc_max =
                (import_dir.VirtualAddress + import_dir.Size > dll_size)
                ? 0
                : import_dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

            KIPC_LOG(
                       "[INJECTOR] imports: scanning up to %llu descriptors\n",
                       (unsigned long long)desc_max);

            ULONG resolved_modules    = 0;
            ULONG unresolved_modules  = 0;
            ULONG resolved_functions  = 0;
            ULONG unresolved_functions = 0;

            auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                reinterpret_cast<PUCHAR>(local_dll_buf) + import_dir.VirtualAddress);

            for (SIZE_T desc_i = 0; desc_i < desc_max && desc[desc_i].Name; ++desc_i) {
                PIMAGE_IMPORT_DESCRIPTOR cur = &desc[desc_i];

                // Validate that desc->Name is an in-bounds RVA before we
                // dereference it as a C string.  An out-of-bounds Name
                // would let DbgPrint or our PEB-walker read into
                // arbitrary kernel pool memory — the page fault we saw
                // happened inside DbgPrintEx's internal string copy.
                if (cur->Name == 0 || cur->Name >= dll_size) {
                    KIPC_LOG(
                               "[INJECTOR] map_sections: import desc %llu has "
                               "out-of-bounds Name RVA 0x%X (dll_size=0x%X) — "
                               "skipping\n",
                               (unsigned long long)desc_i,
                               (unsigned)cur->Name, (unsigned)dll_size);
                    continue;
                }

                const char* dll_name = reinterpret_cast<const char*>(
                    reinterpret_cast<PUCHAR>(local_dll_buf) + cur->Name);

                // Make sure the name string is null-terminated within the
                // buffer — strnlen against the remaining buffer length.
                SIZE_T name_max = dll_size - cur->Name;
                SIZE_T name_len = 0;
                while (name_len < name_max && dll_name[name_len] != '\0') ++name_len;
                if (name_len == name_max) {
                    KIPC_LOG(
                               "[INJECTOR] map_sections: import desc %llu name "
                               "not null-terminated within buffer — skipping\n",
                               (unsigned long long)desc_i);
                    continue;
                }

                PVOID mod_base = inj_find_module_in_target(target_proc, dll_name);
                if (!mod_base) {
                    // dll_name is now known to be a safe null-terminated
                    // string inside local_dll_buf — printing with %s is OK.
                    KIPC_LOG(
                               "[INJECTOR] imports: %s NOT FOUND in target — "
                               "calls into this DLL will null-deref (target "
                               "must already have this dependency loaded; "
                               "use LoadLibrary first or pick a DLL that only "
                               "depends on modules already loaded by the "
                               "target)\n",
                               dll_name);
                    ++unresolved_modules;
                    continue;
                }
                KIPC_LOG(
                           "[INJECTOR] imports: %s -> %p (resolving functions)\n",
                           dll_name, mod_base);
                ++resolved_modules;

                // Bounds-check the thunk arrays.  Either thunk pointer past
                // the end of our buffer means the PE is malformed; bail on
                // this descriptor rather than dereferencing junk.
                if (!cur->FirstThunk || cur->FirstThunk >= dll_size)
                    continue;
                ULONG orig_thunk_rva = cur->OriginalFirstThunk
                    ? cur->OriginalFirstThunk
                    : cur->FirstThunk;
                if (orig_thunk_rva >= dll_size)
                    continue;

                auto* orig_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
                    reinterpret_cast<PUCHAR>(local_dll_buf) + orig_thunk_rva);
                auto* iat_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
                    reinterpret_cast<PUCHAR>(local_dll_buf) + cur->FirstThunk);

                // Cap thunk iterations at a sane ceiling.  A normal DLL has
                // tens to low-hundreds of imports per module; 4096 is well
                // above that and keeps us inside any reasonable buffer.
                ULONG max_thunks =
                    (ULONG)((dll_size - orig_thunk_rva) /
                            sizeof(IMAGE_THUNK_DATA64));
                if (max_thunks > 4096) max_thunks = 4096;

                for (ULONG t = 0; t < max_thunks && orig_thunk->u1.AddressOfData; ++t) {
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
                        // Import by name — bounds-check the IMAGE_IMPORT_BY_NAME
                        // RVA before dereferencing it.
                        ULONG by_name_rva = (ULONG)orig_thunk->u1.AddressOfData;
                        if (by_name_rva == 0 ||
                            by_name_rva + sizeof(IMAGE_IMPORT_BY_NAME) > dll_size) {
                            ++orig_thunk;
                            ++iat_thunk;
                            continue;
                        }
                        auto* by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                            reinterpret_cast<PUCHAR>(local_dll_buf) + by_name_rva);
                        // Don't print by_name->Name with %s anywhere — if it
                        // somehow isn't null-terminated within the buffer it
                        // can crash DbgPrintEx (see fix above).
                        fn_va = inj_find_export_in_target(
                            target_proc, mod_base,
                            reinterpret_cast<const char*>(by_name->Name));
                    }

                    if (fn_va) {
                        ++resolved_functions;
                    } else {
                        ++unresolved_functions;
                    }

                    iat_thunk->u1.Function =
                        reinterpret_cast<ULONGLONG>(fn_va);

                    ++orig_thunk;
                    ++iat_thunk;
                }
                // for-loop index ++desc_i is handled by the for() header.
            }
            globals::obf_dereference_object(target_proc);

            KIPC_LOG(
                       "[INJECTOR] imports: tally — modules %lu resolved / "
                       "%lu unresolved, functions %lu resolved / %lu "
                       "unresolved\n",
                       resolved_modules, unresolved_modules,
                       resolved_functions, unresolved_functions);
            if (unresolved_modules || unresolved_functions) {
                KIPC_LOG(
                           "[INJECTOR] imports: WARNING — DllMain will "
                           "very likely crash the target when it invokes "
                           "an unresolved import.  Inject a DLL whose "
                           "dependencies are already loaded in target, "
                           "or arrange to LoadLibrary them first.\n");
            }
        } else {
            KIPC_LOG(
                       "[INJECTOR] injector_map_dll_sections: could not open"
                       " target pid %u for import resolution\n", target_pid);
        }
    }

    // ── Write PE header to target (VAD-less manual-map → physical path) ───
    // remote_base was created by mem::allocate_between_modules /
    // mem::allocate_at_non_present_pml4e — those install PTEs by hand without
    // creating a VAD entry.  MmCopyVirtualMemory would page-fault inside its
    // VAD lookup; route the write through the physical proxy PTE instead.
    {
        NTSTATUS st = inj_write_process_phys(target_pid, remote_base,
                                             local_dll_buf,
                                             nt->OptionalHeader.SizeOfHeaders);
        if (!NT_SUCCESS(st)) {
            KIPC_LOG(
                       "[INJECTOR] injector_map_dll_sections: header write"
                       " failed: 0x%08X\n", st);
            // Match the STEALTH_POOL_ALLOC tag for this buffer (kStealthTagPayload).
            STEALTH_POOL_FREE(local_dll_buf, kStealthTagPayload);
            return st;
        }
    }

    // ── Write sections to target (same rationale — physical path only) ────
    // local_dll_buf is MEMORY form, so read from `local_dll_buf + VirtualAddress`
    // (NOT `+ PointerToRawData`).  Each section's relocated/IAT-patched bytes
    // are now exactly where they need to be at remote_base + VirtualAddress.
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        SIZE_T raw  = sec[i].SizeOfRawData;
        SIZE_T virt = sec[i].Misc.VirtualSize;
        SIZE_T write_size = raw < virt ? raw : virt;
        if (!write_size) continue;

        if ((SIZE_T)sec[i].VirtualAddress + write_size > dll_size) continue;
        if ((SIZE_T)sec[i].VirtualAddress + write_size <
            (SIZE_T)sec[i].VirtualAddress) continue;  // overflow guard

        PVOID src = reinterpret_cast<PUCHAR>(local_dll_buf) + sec[i].VirtualAddress;
        PVOID dst = reinterpret_cast<PUCHAR>(remote_base)   + sec[i].VirtualAddress;

        NTSTATUS st = inj_write_process_phys(target_pid, dst, src, write_size);
        if (!NT_SUCCESS(st))
            KIPC_LOG(
                       "[INJECTOR] injector_map_dll_sections: section %hu"
                       " write failed: 0x%08X\n", i, st);
    }

    *out_entry_offset = nt->OptionalHeader.AddressOfEntryPoint;
    // Match the STEALTH_POOL_ALLOC tag for this buffer (kStealthTagPayload).
    STEALTH_POOL_FREE(local_dll_buf, kStealthTagPayload);
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

    // ── Write shellcode to target via PT-injector physical path ──────────
    // remote_shellcode is a manually-mapped page (no VAD entry).  Using
    // MmCopyVirtualMemory here was a mistake — it dereferences the target's
    // VAD tree during the destination probe and page-faults on missing VAD,
    // producing DRIVER_OVERRAN_STACK_BUFFER (0xF7 / MISSING_GSFRAME) when
    // the exception can't be unwound through our manually-mapped driver
    // frames.  physical::copy_memory writes via the proxy PTE — no VAD
    // lookup, no MM helpers involved.  The proxy PTE is now serialised by
    // the spinlock added in phys.cpp, so the previous wbinvd/IPI storm is
    // also gone.
    NTSTATUS write_st = physical::copy_memory(
        globals::io_get_current_process(), kernel_shellcode.get(),
        target_process, remote_shellcode,
        sizeof(dll_main_shellcode));

    if (!NT_SUCCESS(write_st)) {
        log("ERROR", "failed to write shellcode to target: 0x%X", write_st);
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
    // RtlCreateUserThread is NOT exported by ntoskrnl on standard Windows
    // builds (it's an ntdll.dll routine).  Resolving it via
    // MmGetSystemRoutineAddress returns NULL, and calling that NULL function
    // pointer corrupts the caller's stack frame on the way back through the
    // exception unwinder — which is exactly the DRIVER_OVERRAN_STACK_BUFFER
    // 0xF7 / _report_gsfailure dump we keep hitting.
    //
    // Use NtCreateThreadEx instead.  It IS in ntoskrnl's export table and
    // is the kernel-supported way to create a user thread in another process.
    //
    // Attach to the target before the call so the TEB / stack allocations
    // land in the target's address space rather than ours.
    raii::kernel_handle thread_handle;

    if (!globals::nt_create_thread_ex) {
        log("ERROR", "nt_create_thread_ex unresolved — cannot create remote thread");
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    KAPC_STATE apc_state;
    KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(target_process), &apc_state);

    OBJECT_ATTRIBUTES thread_obj_attr = {};
    InitializeObjectAttributes(&thread_obj_attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    // Local copies of the NtCreateThreadEx CreateFlags bits (phnt header
    // conflicts with WDK includes, so we inline the numeric values).
    constexpr ULONG kThreadCreateFlagsSkipThreadAttach = 0x00000002;
    constexpr ULONG kThreadCreateFlagsHideFromDebugger = 0x00000004;

    // Note: NOT setting CREATE_SUSPENDED here.  PsResumeThread and
    // ZwResumeThread are both unresolvable on hardened Win10 22H2 builds
    // (export table strip), so we let the thread start immediately and
    // just wait on the handle below.  HideFromDebugger + SkipThreadAttach
    // are still useful — the first hides the new thread from any usermode
    // debugger attached to the target, the second skips DLL_THREAD_ATTACH
    // notifications to loaded DLLs (we're injecting one, no need to
    // disturb the others' DllMain handlers).
    NTSTATUS thread_st = globals::nt_create_thread_ex(
        thread_handle.address_of(),
        THREAD_ALL_ACCESS,
        &thread_obj_attr,
        process_handle.get(),
        remote_shellcode,
        /*Argument*/ NULL,
        /*CreateFlags*/ kThreadCreateFlagsHideFromDebugger |
                        kThreadCreateFlagsSkipThreadAttach,
        /*ZeroBits*/ 0,
        /*StackSize*/ 0,
        /*MaximumStackSize*/ 0,
        /*AttributeList*/ NULL);

    KeUnstackDetachProcess(&apc_state);

    if (!NT_SUCCESS(thread_st)) {
        log("ERROR", "NtCreateThreadEx failed: 0x%X", thread_st);
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return thread_st;
    }

    // NtCreateThreadEx doesn't fill a CLIENT_ID like RtlCreateUserThread did,
    // so we resolve the ETHREAD via the handle instead.
    PETHREAD thread = nullptr;
    NTSTATUS thr_lookup_st = ObReferenceObjectByHandle(
        thread_handle.get(), THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, reinterpret_cast<PVOID*>(&thread), NULL);
    if (!NT_SUCCESS(thr_lookup_st)) {
        log("ERROR", "ObReferenceObjectByHandle(thread) failed: 0x%X", thr_lookup_st);
        globals::mm_free_independent_pages(
            reinterpret_cast<uintptr_t>(remote_shellcode), PAGE_SIZE);
        return thr_lookup_st;
    }
    raii::kernel_object_ref<_KTHREAD> thread_ref(thread);

    // No resume step needed — we created the thread without CREATE_SUSPENDED
    // (see NtCreateThreadEx call above), so it's already running.  This
    // avoids depending on PsResumeThread / ZwResumeThread which are both
    // absent from the export table on hardened Win10 22H2 builds.

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
        // Manual-mapped destination — use the physical path (same rationale
        // as the shellcode write above; MmCopyVirtualMemory faults on VAD-less
        // pages and the fault cannot be unwound through our driver frames).
        physical::copy_memory(globals::io_get_current_process(), zero_buffer,
                              cleanup_process, remote_shellcode,
                              sizeof(dll_main_shellcode));
    }

    log("INFO", "DLL execution completed for PID: %d at base: 0x%p",
        target_pid, remote_base);
    return STATUS_SUCCESS;
}
