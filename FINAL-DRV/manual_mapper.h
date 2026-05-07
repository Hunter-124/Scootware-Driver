#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstatus.h>
#include <wdm.h>

// ─── Limits ────────────────────────────────────────────────────────────────
#define MM_MAX_DLL_SIZE (32 * 1024 * 1024)   // 32 MB sanity cap

// ─── PE typedef aliases ────────────────────────────────────────────────────
typedef IMAGE_DOS_HEADER     DOS_HEADER,  *PDOS_HEADER;
typedef IMAGE_NT_HEADERS64   NT_HEADERS,  *PNT_HEADERS;
typedef IMAGE_TLS_DIRECTORY64 TLS_DIR64,  *PTLS_DIR64;

// ─── IOCTL data passed by user-mode client ─────────────────────────────────
typedef struct _MM_DATA {
    UINT64  dwTargetProcess;    // Target PID (as 64-bit value)
    PVOID   pDllBuffer;         // User-space pointer to raw DLL bytes
    SIZE_T  dwDllSize;          // Size of raw DLL
    PVOID   pBaseAddress;       // Preferred base (NULL = OS chooses) – reserved
    NTSTATUS status;            // [out] NTSTATUS result
    PVOID   pMappedAddress;     // [out] VA in target process
} MM_DATA, *PMM_DATA;

// ─── IOCTL codes ──────────────────────────────────────────────────────────
#define IOCTL_MAP_DLL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNMAP_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_ANY_ACCESS)
// New: resolve exported function address in a mapped module
#define IOCTL_GET_EXPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Request used with IOCTL_GET_EXPORT
typedef struct _MM_EXPORT_REQUEST {
    UINT64 dwTargetProcess;    // Target PID
    PVOID  pModuleBase;         // VA of module in target process
    CHAR   szExportName[256];   // NULL-terminated export name
    NTSTATUS status;            // [out] result
    PVOID  pExportAddress;      // [out] resolved VA in target process
} MM_EXPORT_REQUEST, *PMM_EXPORT_REQUEST;

// ─── Relocation entry ─────────────────────────────────────────────────────
typedef struct _RELOC_ENTRY {
    USHORT Offset : 12;
    USHORT Type   : 4;
} RELOC_ENTRY, *PRELOC_ENTRY;

// ─── Undocumented / partially-documented kernel structures ────────────────

// PEB_LDR_DATA (enough for us)
typedef struct _PEB_LDR_DATA2 {
    ULONG     Length;
    BOOLEAN   Initialized;
    HANDLE    SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA2, *PPEB_LDR_DATA2;

// PEB overlay — Ldr is at offset 0x18 on x64 Win10+.
// Using a pad-based struct avoids conflicts with any partial PEB already
// visible from WDK headers (e.g. _PEB from ntddk.h).
typedef struct _MY_PEB {
    UCHAR          _Pad[0x18];
    PPEB_LDR_DATA2 Ldr;
} MY_PEB, *PMY_PEB;

// LDR_DATA_TABLE_ENTRY (subset)
typedef struct _LDR_DATA_TABLE_ENTRY2 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

// ─── Kernel imports ────────────────────────────────────────────────────────
// PsGetProcessPeb is undocumented — not in any public WDK header.
extern "C" {
    NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
}

// ─── Namespace ────────────────────────────────────────────────────────────
namespace ManualMapper {

    // ── PE helpers ──────────────────────────────────────────────────────────

    __forceinline PDOS_HEADER GetDosHeader(PVOID Base) {
        if (!Base) return nullptr;
        PDOS_HEADER p = (PDOS_HEADER)Base;
        return (p->e_magic == IMAGE_DOS_SIGNATURE) ? p : nullptr;
    }

    __forceinline PNT_HEADERS GetNtHeaders(PVOID Base) {
        PDOS_HEADER pDos = GetDosHeader(Base);
        if (!pDos) return nullptr;
        // Sanity-check e_lfanew before dereferencing: must be within the DOS
        // header region (>= sizeof DOS header) and not absurdly large.
        if (pDos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || pDos->e_lfanew > 0x1000)
            return nullptr;
        PNT_HEADERS pNt = (PNT_HEADERS)((UINT8*)Base + pDos->e_lfanew);
        return (pNt->Signature == IMAGE_NT_SIGNATURE) ? pNt : nullptr;
    }

    __forceinline SIZE_T GetImageSize(PVOID DllBuf) {
        PNT_HEADERS pNt = GetNtHeaders(DllBuf);
        return pNt ? pNt->OptionalHeader.SizeOfImage : 0;
    }

    // ── Section copier ─────────────────────────────────────────────────────
    __forceinline NTSTATUS CopySection(PVOID FileBuf, SIZE_T FileSize, PVOID ImageBase, PIMAGE_SECTION_HEADER pSec) {
        if (!pSec->SizeOfRawData) return STATUS_SUCCESS;

        // Guard: raw section must be fully within the source file buffer.
        if ((UINT64)pSec->PointerToRawData + pSec->SizeOfRawData > FileSize)
            return STATUS_INVALID_IMAGE_FORMAT;

        PVOID pSrc = (PVOID)((UINT8*)FileBuf   + pSec->PointerToRawData);
        PVOID pDst = (PVOID)((UINT8*)ImageBase + pSec->VirtualAddress);
        RtlCopyMemory(pDst, pSrc, pSec->SizeOfRawData);

        if (pSec->Misc.VirtualSize > pSec->SizeOfRawData) {
            RtlZeroMemory((UINT8*)pDst + pSec->SizeOfRawData,
                          pSec->Misc.VirtualSize - pSec->SizeOfRawData);
        }
        return STATUS_SUCCESS;
    }

    // ── Base relocation ────────────────────────────────────────────────────
    __forceinline NTSTATUS ProcessRelocations(PVOID ImageBase, UINT64 Delta) {
        PNT_HEADERS pNt = GetNtHeaders(ImageBase);
        if (!pNt) return STATUS_INVALID_PARAMETER;

        auto& RelocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!RelocDir.VirtualAddress || !RelocDir.Size) return STATUS_SUCCESS;

        auto* pReloc    = (PIMAGE_BASE_RELOCATION)((UINT8*)ImageBase + RelocDir.VirtualAddress);
        auto* pRelocEnd = (PIMAGE_BASE_RELOCATION)((UINT8*)ImageBase + RelocDir.VirtualAddress + RelocDir.Size);

        while (pReloc < pRelocEnd && pReloc->VirtualAddress && pReloc->SizeOfBlock) {
            ULONG Count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            auto* pEntry = (PRELOC_ENTRY)((UINT8*)pReloc + sizeof(IMAGE_BASE_RELOCATION));

            UINT64 ImageSize = pNt->OptionalHeader.SizeOfImage;
            for (ULONG i = 0; i < Count; i++) {
                UINT8* pAddr = (UINT8*)ImageBase + pReloc->VirtualAddress + pEntry[i].Offset;
                // Bounds-check: skip any entry that would write outside the mapped image.
                if ((SIZE_T)(pAddr - (UINT8*)ImageBase) + sizeof(UINT64) > ImageSize)
                    continue;
                if      (pEntry[i].Type == IMAGE_REL_BASED_DIR64)   { *(UINT64*)pAddr += Delta; }
                else if (pEntry[i].Type == IMAGE_REL_BASED_HIGHLOW) { *(UINT32*)pAddr += (UINT32)Delta; }
                else if (pEntry[i].Type == IMAGE_REL_BASED_HIGH)    { *(UINT16*)pAddr += (UINT16)((Delta >> 16) & 0xFFFF); }
                else if (pEntry[i].Type == IMAGE_REL_BASED_LOW)     { *(UINT16*)pAddr += (UINT16)(Delta & 0xFFFF); }
            }
            pReloc = (PIMAGE_BASE_RELOCATION)((UINT8*)pReloc + pReloc->SizeOfBlock);
        }
        return STATUS_SUCCESS;
    }

    // ── Find a loaded module in the current-process PEB Ldr ───────────────
    // Must be called while attached to the target process (KeStackAttachProcess).
    __forceinline PVOID FindModuleInPebLdr(PMY_PEB pPeb, const char* DllNameAnsi) {
        if (!pPeb || !pPeb->Ldr) return nullptr;

        LIST_ENTRY* pHead = &pPeb->Ldr->InLoadOrderModuleList;
        LIST_ENTRY* pCur  = pHead->Flink;

        while (pCur != pHead) {
            auto* pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY2, InLoadOrderLinks);
            pCur = pCur->Flink;

            if (!pEntry->DllBase || !pEntry->BaseDllName.Buffer) continue;

            // Compare base name case-insensitively
            UNICODE_STRING targetUs;
            ANSI_STRING    targetAs;
            RtlInitAnsiString(&targetAs, DllNameAnsi);
            if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&targetUs, &targetAs, TRUE))) continue;

            BOOLEAN match = RtlEqualUnicodeString(&pEntry->BaseDllName, &targetUs, TRUE);
            RtlFreeUnicodeString(&targetUs);

            if (match) return pEntry->DllBase;
        }
        return nullptr;
    }

    // ── Export resolver: find a function in a loaded module (in target PAS) ─
    // Must be called while attached.
    __forceinline PVOID GetExportByName(PVOID ModBase, const char* FnName) {
        PNT_HEADERS pNt = GetNtHeaders(ModBase);
        if (!pNt) return nullptr;

        auto& ExportDirEntry = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!ExportDirEntry.VirtualAddress) return nullptr;

        auto* pExport = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)ModBase + ExportDirEntry.VirtualAddress);
        auto* pNames  = (PULONG)((UINT8*)ModBase + pExport->AddressOfNames);
        auto* pOrds   = (PUSHORT)((UINT8*)ModBase + pExport->AddressOfNameOrdinals);
        auto* pFuncs  = (PULONG)((UINT8*)ModBase + pExport->AddressOfFunctions);

        for (ULONG i = 0; i < pExport->NumberOfNames; i++) {
            const char* pName = (const char*)((UINT8*)ModBase + pNames[i]);
            if (strcmp(pName, FnName) == 0) {
                return (PVOID)((UINT8*)ModBase + pFuncs[pOrds[i]]);
            }
        }
        return nullptr;
    }

    __forceinline PVOID GetExportByOrdinal(PVOID ModBase, USHORT Ordinal) {
        PNT_HEADERS pNt = GetNtHeaders(ModBase);
        if (!pNt) return nullptr;

        auto& ExportDirEntry = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!ExportDirEntry.VirtualAddress) return nullptr;

        auto* pExport = (PIMAGE_EXPORT_DIRECTORY)((UINT8*)ModBase + ExportDirEntry.VirtualAddress);
        if (!pExport->NumberOfFunctions) return nullptr;

        ULONG Idx = Ordinal - pExport->Base;
        if (Idx >= pExport->NumberOfFunctions) return nullptr;

        auto* pFuncs = (PULONG)((UINT8*)ModBase + pExport->AddressOfFunctions);
        if (!pFuncs[Idx]) return nullptr;
        return (PVOID)((UINT8*)ModBase + pFuncs[Idx]);
    }

    // ── IAT resolver (called while attached to target process) ────────────
    __forceinline NTSTATUS ResolveImports(PVOID ImageBase, PMY_PEB pPeb) {
        PNT_HEADERS pNt = GetNtHeaders(ImageBase);
        if (!pNt) return STATUS_INVALID_PARAMETER;

        auto& ImportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!ImportDir.VirtualAddress || !ImportDir.Size) return STATUS_SUCCESS;

        auto* pDesc = (PIMAGE_IMPORT_DESCRIPTOR)((UINT8*)ImageBase + ImportDir.VirtualAddress);

        while (pDesc->Name) {
            const char* pDllName = (const char*)((UINT8*)ImageBase + pDesc->Name);

            // Look up the DLL base from the target process's PEB Ldr
            PVOID pModBase = FindModuleInPebLdr(pPeb, pDllName);
            if (!pModBase) {
                // DLL not loaded in target — this shouldn't happen for system DLLs
                // but if it does, the IAT entry stays zero → crash on first call
                pDesc++;
                continue;
            }

            PIMAGE_THUNK_DATA64 pOrig = pDesc->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA64)((UINT8*)ImageBase + pDesc->OriginalFirstThunk)
                : (PIMAGE_THUNK_DATA64)((UINT8*)ImageBase + pDesc->FirstThunk);

            PIMAGE_THUNK_DATA64 pIat = (PIMAGE_THUNK_DATA64)((UINT8*)ImageBase + pDesc->FirstThunk);

            while (pOrig->u1.AddressOfData) {
                PVOID pFn = nullptr;

                if (IMAGE_SNAP_BY_ORDINAL64(pOrig->u1.Ordinal)) {
                    USHORT Ord = (USHORT)IMAGE_ORDINAL64(pOrig->u1.Ordinal);
                    pFn = GetExportByOrdinal(pModBase, Ord);
                } else {
                    auto* pByName = (PIMAGE_IMPORT_BY_NAME)((UINT8*)ImageBase + pOrig->u1.AddressOfData);
                    pFn = GetExportByName(pModBase, (const char*)pByName->Name);
                }

                pIat->u1.Function = (UINT64)pFn;
                pOrig++;
                pIat++;
            }

            pDesc++;
        }
        return STATUS_SUCCESS;
    }

    // ── Main entry: map DLL into a user process ────────────────────────────
    inline NTSTATUS MapDllIntoProcess(
        HANDLE  TargetPid,
        PVOID   DllKernelBuf,   // kernel-pool copy of the raw PE
        SIZE_T  DllSize,
        PVOID*  OutMappedVa)    // [out] VA in target process
    {
        if (!DllKernelBuf || !DllSize || !OutMappedVa) return STATUS_INVALID_PARAMETER;
        *OutMappedVa = nullptr;

        // Validate PE
        PNT_HEADERS pNt = GetNtHeaders(DllKernelBuf);
        if (!pNt) return STATUS_INVALID_IMAGE_FORMAT;
        if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return STATUS_NOT_SUPPORTED;

        SIZE_T ImageSize = pNt->OptionalHeader.SizeOfImage;
        if (!ImageSize || ImageSize > MM_MAX_DLL_SIZE) return STATUS_INVALID_IMAGE_FORMAT;

        // Get EPROCESS
        PEPROCESS pProcess = nullptr;
        NTSTATUS Status = PsLookupProcessByProcessId(TargetPid, &pProcess);
        if (!NT_SUCCESS(Status)) return Status;

        // Attach to target process address space
        KAPC_STATE apcState;
        KeStackAttachProcess(pProcess, &apcState);

        //
        // Allocate memory in the target process.
        // We try the preferred base first, then fall back to OS choice.
        //
        PVOID pBase   = (PVOID)pNt->OptionalHeader.ImageBase;
        SIZE_T AllocSz = ImageSize;

        Status = ZwAllocateVirtualMemory(
            NtCurrentProcess(), &pBase, 0, &AllocSz,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(Status)) {
            pBase  = nullptr;
            AllocSz = ImageSize;
            Status = ZwAllocateVirtualMemory(
                NtCurrentProcess(), &pBase, 0, &AllocSz,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }

        if (!NT_SUCCESS(Status)) {
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(pProcess);
            return Status;
        }

        // Copy PE headers
        RtlCopyMemory(pBase, DllKernelBuf, pNt->OptionalHeader.SizeOfHeaders);

        // Copy sections
        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (USHORT i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            CopySection(DllKernelBuf, DllSize, pBase, &pSec[i]);
        }

        // Apply relocations (using the freshly mapped copy's NT headers)
        UINT64 Delta = (UINT64)pBase - pNt->OptionalHeader.ImageBase;
        Status = ProcessRelocations(pBase, Delta);
        if (!NT_SUCCESS(Status)) {
            SIZE_T FreeSz = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &pBase, &FreeSz, MEM_RELEASE);
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(pProcess);
            return Status;
        }

        // Resolve IAT from the target process's PEB Ldr
        PMY_PEB pPeb = (PMY_PEB)PsGetProcessPeb(pProcess);
        Status = ResolveImports(pBase, pPeb);
        if (!NT_SUCCESS(Status)) {
            SIZE_T FreeSz = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &pBase, &FreeSz, MEM_RELEASE);
            KeUnstackDetachProcess(&apcState);
            ObDereferenceObject(pProcess);
            return Status;
        }

        KeUnstackDetachProcess(&apcState);

        // Mapping complete. DllMain must be called by the usermode caller
        // via CreateRemoteThread / injector stub — we return the base VA.
        ObDereferenceObject(pProcess);
        *OutMappedVa = pBase;
        return STATUS_SUCCESS;
    }

    // ── Unmap: free the allocation in the target process ──────────────────
    inline NTSTATUS UnmapDll(HANDLE TargetPid, PVOID MappedVa) {
        if (!MappedVa) return STATUS_INVALID_PARAMETER;

        PEPROCESS pProcess = nullptr;
        NTSTATUS Status = PsLookupProcessByProcessId(TargetPid, &pProcess);
        if (!NT_SUCCESS(Status)) return Status;

        KAPC_STATE apcState;
        KeStackAttachProcess(pProcess, &apcState);

        SIZE_T FreeSz = 0;
        Status = ZwFreeVirtualMemory(NtCurrentProcess(), &MappedVa, &FreeSz, MEM_RELEASE);

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(pProcess);
        return Status;
    }

} // namespace ManualMapper

