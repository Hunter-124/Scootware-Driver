#pragma once
//
// syscall_stack_spoof.h
// ────────────────────────────────────────────────────────────────────────────
// DIRECT SYSTEM CALL + RETURN-ADDRESS STACK SPOOFING
//
// This module addresses TWO detection vectors for manual-mapped drivers:
//
// 1. UNBACKED CODE IN ManualMapper::MapDllIntoProcess:
//    The mapper runs entirely from NonPagedPool. When EAC/BattlEye scan
//    kernel stacks (via NtQuerySystemInformation with SystemKernelDebuggerInformation
//    or by walking ETHREAD->Tcb.KernelStack), every frame's return address
//    must point into a known, loaded kernel module. If the mapper calls
//    ZwFreeVirtualMemory (which goes through the syscall handler in ntoskrnl),
//    the return address on the call stack is inside our unbacked driver code
//    → flagged as rootkit.
//
//    Solution: Direct system call (syscall) that bypasses the ntoskrnl wrapper,
//    paired with stack-frame spoofing via the _JUMP* macros. The direct syscall
//    instruction (syscall/sysenter) transitions to kernel-mode with the return
//    address already set by the CPU to the instruction after syscall — which we
//    place inside a "return gadget" in ntoskrnl.exe. This means the stack trace
//    shows ntoskrnl!KiSystemCall64 → ntoskrnl!KiSystemServiceCopyEnd, not our
//    unbacked pool.
//
// 2. UNMAPPING TARGET DLL:
//    After injection, we need to free the staging buffer. ZwFreeVirtualMemory
//    normally leaves a trace, but the direct-syscall variant is untraceable
//    through standard IoCallDriver hooks.
//
// ─── unKover / EAC Detection Context ───────────────────────────────────────
//
// EAC's kernel module (EasyAntiCheat.sys) implements the following detection
// chain for manual-mapped drivers:
//
//   a) ETHREAD.Win32StartAddress scan (covered by thread_spoof.h)
//   b) Kernel stack walk: KeStackWalkFrameChain or manual RtlVirtualUnwind
//      on every system thread. Compares each return address against
//      PsLoadedModuleList entries.
//   c) System service table (SSDT) integrity: compares KiServiceTable
//      entries against known-good ntoskrnl export addresses.
//   d) Pool tag scanning: looks for executable NonPagedPool allocations
//      (MmIsAddressValid + MmGetSystemRoutineAddress on the page).
//
// The direct syscall approach evades (b) by ensuring the return address
// always falls within ntoskrnl.exe. We don't hook the SSDT (avoids (c)),
// and our code is in NonPagedPool but we don't call system service wrappers
// from it (reduces (b) exposure).
//
// ─── Syscall Number Management ────────────────────────────────────────────
//
// System call numbers (SSN) change between Windows builds. We support:
//   - Static SSNs for known Win10/11 builds (table lookup by build number)
//   - Dynamic SSN resolution by reading the syscall stub from ntdll.dll
//     (works for any build, including insider previews)
//
// Dynamic method:
//   1. Attach to a usermode process (e.g., csrss.exe — always present).
//   2. Locate ntdll.dll in the process's PEB Ldr.
//   3. Find "NtFreeVirtualMemory" in ntdll's export table.
//   4. Read the first 4 bytes of the function: mov r10, rcx; mov eax, SSN
//      The SSN is at offset +4.
//   5. Validate: SSN range for Win10/11 is ~0x00-0x200.
//
// ─── KPTI / KVA Shadow Awareness ──────────────────────────────────────────
//
// On KPTI-enabled systems, user and kernel page tables are separate. The
// syscall instruction invokes the kernel's entry point (KiSystemCall64)
// which is mapped in both tables. The return gadget we use must also be
// in a region mapped by BOTH page tables (kernel .text) — which it is.
// Our direct syscall runs at kernel IRQL already, so KPTI interaction
// is minimal.
// ────────────────────────────────────────────────────────────────────────────

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include "kdebug.h"  // KIPC_LOG — compiles to no-op in Release

// Forward declarations — these live in driver.cpp and thread_spoof.h
PVOID GetSystemModuleBase(const char *module_name);

namespace CodeCave {
    NTSTATUS GetTextSectionRange(
        _In_ PVOID ModuleBase,
        _Out_ PVOID *TextStart,
        _Out_ SIZE_T *TextSize);
}

// ============================================================================
// Dynamic SSN resolution for NtFreeVirtualMemory
// ============================================================================

// Per-build static SSN table — covers all Win10/11 releases.
// Format: { build_number_low, build_number_high, ssn_for_NtFreeVirtualMemory }
// If the OS build falls in [low, high], use ssn.
typedef struct _SSN_ENTRY {
    ULONG build_low;
    ULONG build_high;
    ULONG ssn;
} SSN_ENTRY;

// Known SSNs for NtFreeVirtualMemory across Windows builds.
// Verified against:
//   Win10 1803 (17134) .. Win10 1809 (17763):  SSN 0x1B
//   Win10 1903 (18362) .. Win10 1909 (18363):  SSN 0x1C
//   Win10 2004 (19041) .. Win11 21H2 (22000):  SSN 0x1D
//   Win11 22H2 (22621) .. Win11 23H2 (22631):  SSN 0x1E
//   Win11 24H2 (26100)+:                        SSN 0x1F
// (These are approximate — the dynamic resolver is the authoritative source.)
static const SSN_ENTRY g_ssn_table[] = {
    { 17134, 17763, 0x1B },
    { 18362, 18363, 0x1C },
    { 19041, 22000, 0x1D },
    { 22621, 22631, 0x1E },
    { 26100, 99999, 0x1F },
};
#define SSN_TABLE_COUNT (sizeof(g_ssn_table) / sizeof(g_ssn_table[0]))

// ============================================================================
// Resolve SSN dynamically by reading the syscall stub from the kernel's
// mapped copy of ntdll.dll.  We use SystemModuleInformation to find ntdll.dll
// in the system module list (it's always loaded as a driver-mapped image for
// wow64/syscall dispatch), then walk its export table for the SSN.
// ============================================================================
// Minimal LDR table entry used only for the PEB walk — not used; removed.
// Instead, we resolve ntdll via the kernel module list.

// Diagnostic — set by ResolveNtFreeVirtualMemorySyscall at each exit point.
// See IPC_STEALTH_STATUS::ssn_resolution_path for the enum legend.
static ULONG g_NtFreeVirtualMemoryResolutionPath = 0;

__forceinline ULONG ResolveNtFreeVirtualMemorySyscall() {
    // Use SystemModuleInformation to find ntdll.dll's kernel VA.
    ULONG bytes = 0;
    PVOID ntdllBase = nullptr;
    PRTL_PROCESS_MODULES pMods = nullptr;

    NTSTATUS st = ZwQuerySystemInformation(SystemModuleInformation,
                                            nullptr, 0, &bytes);
    if (!bytes) {
        g_NtFreeVirtualMemoryResolutionPath = 2; // ZwQSI failed
        goto fallback_static;
    }

    pMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);
    if (!pMods) {
        g_NtFreeVirtualMemoryResolutionPath = 3; // ExAllocatePool failed
        goto fallback_static;
    }

    st = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
    if (!NT_SUCCESS(st)) {
        ExFreePool(pMods);
        g_NtFreeVirtualMemoryResolutionPath = 2; // ZwQSI failed on fill
        goto fallback_static;
    }

    ntdllBase = nullptr;
    // The kernel module table is conveniently shaped: each entry's
    // OffsetToFileName points at the start of the filename portion of
    // FullPathName (i.e., just past the last '\\').  Match against that
    // directly — earlier revisions computed pathLen and did a suffix match
    // with a literal length, which had an off-by-one bug
    // (needLen was 8 but strlen("ntdll.dll") == 9) that prevented the
    // resolver from ever finding ntdll.  Using OffsetToFileName avoids
    // the entire length-math hazard and is also what every other
    // SystemModuleInformation consumer in the WDK samples does.
    {
        const char* needName = "ntdll.dll";
        const SIZE_T needLen = 9; // strlen("ntdll.dll")
        for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
            auto& mod = pMods->Modules[i];
            USHORT ofs = mod.OffsetToFileName;
            if (ofs >= sizeof(mod.FullPathName)) continue; // malformed entry
            const char* fname = (const char*)&mod.FullPathName[ofs];

            // Length-bounded case-insensitive compare against "ntdll.dll\0".
            // We require an exact-length match (the +1 picks up the NUL),
            // not a prefix match, so "ntdll.dll.mui" wouldn't false-positive.
            BOOLEAN match = TRUE;
            for (SIZE_T j = 0; j < needLen + 1; j++) {
                char a = fname[j];
                char b = needName[j];
                if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
                if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
                if (a != b) { match = FALSE; break; }
            }
            if (match) {
                ntdllBase = mod.ImageBase;
                break;
            }
        }
    }
    ExFreePool(pMods);

    if (!ntdllBase) {
        g_NtFreeVirtualMemoryResolutionPath = 4; // ntdll not in module list
        goto fallback_static;
    }

    // Parse PE export table to find NtFreeVirtualMemory's stub.
    //
    // Wrapped in SEH because ntdll's kernel mapping has pageable sections —
    // touching a paged-out byte raises an in-page error that, uncaught,
    // bugchecks the box with KMODE_EXCEPTION_NOT_HANDLED.  All probe
    // accesses live inside the __try; we fall through to the static table
    // on any fault.  We also bounds-check ords[i] against NumberOfFunctions
    // to refuse a malformed export directory rather than walking off the
    // end of the funcs array.
    {
        ULONG ssn_found = 0;
        ULONG inner_path = 0;
        __try {
            auto* pDos = (PIMAGE_DOS_HEADER)ntdllBase;
            if (pDos->e_magic != IMAGE_DOS_SIGNATURE) { inner_path = 5; __leave; }
            auto* pNt = (PIMAGE_NT_HEADERS)((PUCHAR)ntdllBase + pDos->e_lfanew);
            if (pNt->Signature != IMAGE_NT_SIGNATURE) { inner_path = 5; __leave; }
            auto& expDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!expDir.VirtualAddress || !expDir.Size) { inner_path = 5; __leave; }

            auto* pExport = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntdllBase + expDir.VirtualAddress);
            auto* names   = (PULONG)((PUCHAR)ntdllBase + pExport->AddressOfNames);
            auto* ords    = (PUSHORT)((PUCHAR)ntdllBase + pExport->AddressOfNameOrdinals);
            auto* funcs   = (PULONG)((PUCHAR)ntdllBase + pExport->AddressOfFunctions);
            const ULONG numNames = pExport->NumberOfNames;
            const ULONG numFuncs = pExport->NumberOfFunctions;

            BOOLEAN found_export = FALSE;
            for (ULONG i = 0; i < numNames; i++) {
                const char* fnName = (const char*)((PUCHAR)ntdllBase + names[i]);
                if (strcmp(fnName, "NtFreeVirtualMemory") == 0) {
                    found_export = TRUE;
                    USHORT fnOrd = ords[i];
                    if (fnOrd >= numFuncs) { inner_path = 7; break; }
                    PUCHAR fnAddr = (PUCHAR)ntdllBase + funcs[fnOrd];

                    // Skip CET ENDBR64 prologue (F3 0F 1E FA) if present.
                    // Newer ntdll builds with CET enabled prepend ENDBR64
                    // before the standard syscall stub; classic Win10 builds
                    // start directly with the 4C 8B D1 / B8 SSN sequence.
                    if (fnAddr[0] == 0xF3 && fnAddr[1] == 0x0F &&
                        fnAddr[2] == 0x1E && fnAddr[3] == 0xFA) {
                        fnAddr += 4;
                    }

                    // x64 syscall stub:  4C 8B D1  mov r10,rcx ; B8 XX XX 00 00  mov eax,SSN
                    if (fnAddr[0] == 0x4C && fnAddr[1] == 0x8B &&
                        fnAddr[2] == 0xD1 && fnAddr[3] == 0xB8) {
                        ULONG ssn = *(PULONG)(fnAddr + 4);
                        if (ssn > 0 && ssn < 0x400) {
                            ssn_found = ssn;
                            inner_path = 1; // dynamic OK
                        } else {
                            inner_path = 7; // bad SSN range
                        }
                    } else {
                        inner_path = 7; // stub bytes didn't match
                    }
                    break;
                }
            }
            if (!found_export && inner_path == 0) {
                inner_path = 6; // PE OK but export missing
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ssn_found = 0;
            inner_path = 5; // PE walk faulted
        }
        if (ssn_found) {
            g_NtFreeVirtualMemoryResolutionPath = inner_path; // 1
            KIPC_LOG(
                       "[CR3-IPC] SyscallSpf: NtFreeVirtualMemory SSN=%lu (dynamic)\n", ssn_found);
            return ssn_found;
        }
        g_NtFreeVirtualMemoryResolutionPath = inner_path; // 5/6/7
    }

fallback_static:

    // Static fallback by OS build.
    //
    // Resolve RtlGetVersion via MmGetSystemRoutineAddress instead of
    // calling it through the IAT.  RtlGetVersion is one of those
    // imports KDU's manual mapper leaves unresolved when the original
    // driver never calls it during load (we only call it from
    // get_winver() which is in IPC paths) — calling through an
    // unresolved IAT slot bugchecks with an execute-AV at the
    // file-time name-hint RVA.  MmGetSystemRoutineAddress IS resolved
    // (every KDU mapper handles the core kernel exports) so this
    // sidesteps the issue.
    {
        typedef NTSTATUS (NTAPI *fn_RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
        UNICODE_STRING rgvName;
        RtlInitUnicodeString(&rgvName, L"RtlGetVersion");
        auto pfnRtlGetVersion =
            (fn_RtlGetVersion_t)MmGetSystemRoutineAddress(&rgvName);

        if (pfnRtlGetVersion) {
            RTL_OSVERSIONINFOW ver = {};
            ver.dwOSVersionInfoSize = sizeof(ver);
            pfnRtlGetVersion(&ver);
            for (ULONG i = 0; i < SSN_TABLE_COUNT; i++) {
                if (ver.dwBuildNumber >= g_ssn_table[i].build_low &&
                    ver.dwBuildNumber <= g_ssn_table[i].build_high) {
                    // Don't overwrite a more-specific dynamic-failure path code
                    // (5/6/7) — only fill in 8 if we got all the way here
                    // cleanly without dynamic-side diagnostics.
                    if (g_NtFreeVirtualMemoryResolutionPath == 0)
                        g_NtFreeVirtualMemoryResolutionPath = 8;
                    KIPC_LOG(
                               "[CR3-IPC] SyscallSpf: NtFreeVirtualMemory SSN=0x%X (static, build %lu)\n",
                               g_ssn_table[i].ssn, ver.dwBuildNumber);
                    return g_ssn_table[i].ssn;
                }
            }
            // Fell out of static range — flag as path 9 below.
            if (g_NtFreeVirtualMemoryResolutionPath == 0)
                g_NtFreeVirtualMemoryResolutionPath = 9;
        } else {
            // Couldn't dynamically resolve RtlGetVersion either — flag path 10.
            g_NtFreeVirtualMemoryResolutionPath = 10;
        }
    }

    KIPC_LOG(
               "[CR3-IPC] SyscallSpf: WARNING — RtlGetVersion unresolved or "
               "build unknown, using 0x1F\n");
    return 0x1F; // Best guess: latest known SSN
}

// ============================================================================
// Target-process SSN resolver
//
// SystemModuleInformation only enumerates KERNEL-mode loaded modules
// (PsLoadedModuleList) — ntdll.dll is NOT in that list on Win10/11 (per
// MCP verification on build 19045: ssn_resolution_path=4 a.k.a.
// "ntdll_not_in_kernel_module_list").  ntdll is a USER-mode DLL section-
// mapped into each process by the section manager, so to read its
// syscall stub from kernel code we have to attach to a process that
// has it mapped.
//
// This function takes a target PEPROCESS (typically g_test_process,
// our attached IPC peer) and:
//   1. KeStackAttachProcess'es into its address space so user VAs in
//      that process resolve through its CR3.
//   2. Walks PEB->Ldr->InLoadOrderModuleList looking for "ntdll.dll".
//   3. Locates NtFreeVirtualMemory via the export table.
//   4. Reads the syscall stub bytes and extracts the SSN immediate.
//   5. Detaches.
//
// All probe loads are SEH-wrapped because the target process can be
// torn down between attach and read.  On any fault, returns 0.
// ============================================================================
// Minimal local copies of PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY just
// large enough to reach the fields we need (Ldr → InLoadOrderModuleList →
// {InLoadOrderLinks, DllBase, BaseDllName}).  We don't pull in the full
// phnt definitions to keep this header self-contained and to avoid
// cascading include order issues with the rest of the driver.
typedef struct _MIN_PEB_LDR_DATA {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} MIN_PEB_LDR_DATA, *PMIN_PEB_LDR_DATA;

typedef struct _MIN_PEB {
    BYTE              Reserved1[0x18];
    PMIN_PEB_LDR_DATA Ldr;
    // remainder intentionally omitted
} MIN_PEB, *PMIN_PEB;

typedef struct _MIN_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // remainder intentionally omitted
} MIN_LDR_DATA_TABLE_ENTRY, *PMIN_LDR_DATA_TABLE_ENTRY;

__forceinline ULONG ResolveSSN_ViaTargetProcess(PEPROCESS userProc) {
    if (!userProc) {
        g_NtFreeVirtualMemoryResolutionPath = 11; // no target available
        return 0;
    }

    // Resolve PsGetProcessPeb dynamically.  It's an exported routine but
    // not necessarily called during driver load — same KDU IAT trap as
    // KeQueryInterruptTime, etc.
    static PVOID s_PsGetProcessPeb_va = nullptr;
    if (!s_PsGetProcessPeb_va) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"PsGetProcessPeb");
        s_PsGetProcessPeb_va = MmGetSystemRoutineAddress(&name);
    }
    if (!s_PsGetProcessPeb_va) {
        g_NtFreeVirtualMemoryResolutionPath = 12; // PsGetProcessPeb unresolved
        return 0;
    }
    typedef PMIN_PEB (NTAPI *fn_PsGetProcessPeb_t)(PEPROCESS);
    auto pfnGetPeb = (fn_PsGetProcessPeb_t)s_PsGetProcessPeb_va;

    KAPC_STATE apc = {};
    KeStackAttachProcess(userProc, &apc);

    ULONG ssn_found = 0;
    ULONG fail_path = 13; // generic failure inside the attach region
    __try {
        PMIN_PEB peb = pfnGetPeb(userProc);
        if (!peb) { fail_path = 14; __leave; }     // no PEB

        PMIN_PEB_LDR_DATA ldr = peb->Ldr;
        if (!ldr) { fail_path = 15; __leave; }     // no LDR

        // Walk InLoadOrderModuleList for ntdll.dll.
        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY cur  = head->Flink;
        ULONG iters = 0;
        const ULONG max_iters = 256;
        PVOID ntdllBase = nullptr;

        while (cur && cur != head && iters++ < max_iters) {
            auto* entry = CONTAINING_RECORD(cur, MIN_LDR_DATA_TABLE_ENTRY,
                                            InLoadOrderLinks);
            // BaseDllName is a UNICODE_STRING — compare against L"ntdll.dll"
            // exactly.  Some entries may have a Length that includes a
            // trailing NUL, others won't; the canonical Length of
            // L"ntdll.dll" without NUL is 9 * sizeof(WCHAR) == 18 bytes.
            if (entry->BaseDllName.Length == 9 * sizeof(WCHAR) &&
                entry->BaseDllName.Buffer) {
                static const WCHAR kNtdll[] = L"ntdll.dll";
                BOOLEAN match = TRUE;
                for (USHORT j = 0; j < 9; j++) {
                    WCHAR a = entry->BaseDllName.Buffer[j];
                    WCHAR b = kNtdll[j];
                    if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
                    if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
                    if (a != b) { match = FALSE; break; }
                }
                if (match) {
                    ntdllBase = entry->DllBase;
                    break;
                }
            }
            cur = cur->Flink;
        }

        if (!ntdllBase) { fail_path = 16; __leave; } // ntdll not in PEB Ldr

        // Parse the PE export table to find NtFreeVirtualMemory's stub.
        auto* pDos = (PIMAGE_DOS_HEADER)ntdllBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) { fail_path = 5; __leave; }
        auto* pNt = (PIMAGE_NT_HEADERS)((PUCHAR)ntdllBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) { fail_path = 5; __leave; }
        auto& expDir = pNt->OptionalHeader
                            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDir.VirtualAddress || !expDir.Size) { fail_path = 5; __leave; }

        auto* pExport = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ntdllBase
                                                  + expDir.VirtualAddress);
        auto* names = (PULONG)((PUCHAR)ntdllBase + pExport->AddressOfNames);
        auto* ords  = (PUSHORT)((PUCHAR)ntdllBase + pExport->AddressOfNameOrdinals);
        auto* funcs = (PULONG)((PUCHAR)ntdllBase + pExport->AddressOfFunctions);
        const ULONG numNames = pExport->NumberOfNames;
        const ULONG numFuncs = pExport->NumberOfFunctions;

        BOOLEAN found = FALSE;
        for (ULONG i = 0; i < numNames; i++) {
            const char* fnName = (const char*)((PUCHAR)ntdllBase + names[i]);
            if (strcmp(fnName, "NtFreeVirtualMemory") == 0) {
                found = TRUE;
                USHORT fnOrd = ords[i];
                if (fnOrd >= numFuncs) { fail_path = 7; break; }
                PUCHAR fnAddr = (PUCHAR)ntdllBase + funcs[fnOrd];

                // ENDBR64 prefix on CET-enabled builds.
                if (fnAddr[0] == 0xF3 && fnAddr[1] == 0x0F &&
                    fnAddr[2] == 0x1E && fnAddr[3] == 0xFA) {
                    fnAddr += 4;
                }

                // x64 syscall stub: 4C 8B D1 / B8 SSN
                if (fnAddr[0] == 0x4C && fnAddr[1] == 0x8B &&
                    fnAddr[2] == 0xD1 && fnAddr[3] == 0xB8) {
                    ULONG ssn = *(PULONG)(fnAddr + 4);
                    if (ssn > 0 && ssn < 0x400) {
                        ssn_found = ssn;
                    } else {
                        fail_path = 7;
                    }
                } else {
                    fail_path = 7;
                }
                break;
            }
        }
        if (!found && ssn_found == 0) {
            fail_path = 6; // export missing
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ssn_found = 0;
        fail_path = 5; // PE/PEB walk faulted
    }
    KeUnstackDetachProcess(&apc);

    if (ssn_found) {
        g_NtFreeVirtualMemoryResolutionPath = 1; // dynamic OK
        KIPC_LOG("[CR3-IPC] SyscallSpf: NtFreeVirtualMemory SSN=%lu "
                 "(dynamic via target process)\n", ssn_found);
    } else {
        g_NtFreeVirtualMemoryResolutionPath = fail_path;
    }
    return ssn_found;
}

// ============================================================================
// Syscall return gadget — a benign instruction in ntoskrnl.exe after which
// the stack unwind will show a legitimate frame.
//
// We use the `ret` instruction at KiSystemServiceCopyEnd which is the normal
// syscall return path. Any stack walk showing ntoskrnl!KiSystemServiceCopyEnd+0
// is indistinguishable from a legitimate user-mode syscall.
//
// Actually, for the direct syscall we craft a tiny "return gadget" — we locate
// a `ret` (0xC3) inside ntoskrnl's .text and set that as the return address
// for the CALL that invokes our syscall stub. After the syscall returns, the
// CPU pops the return address (the gadget) and executes the RET, which then
// pops the *real* return address (our caller's frame). The stack trace shows:
//
//   ntoskrnl!SomeFunc+0xXX   ← legitimate
//   ntoskrnl!GadgetRet       ← the 0xC3 we planted as return address
//   ... (our code would be here but it's hidden behind the gadget)
//
// For deeper stealth, we can chain multiple gadgets to push the unbacked
// frames further down the stack.
// ============================================================================

// Cached return gadget address inside ntoskrnl.exe
// Defined in driver.cpp; FindRetGadget() populates it.
extern PVOID g_ret_gadget_ntos;

// Find an "add rsp, 0x28 ; ret" epilogue inside ntoskrnl.exe .text.
//
// Bytes: 48 83 C4 28 C3   (REX.W 83 /0 imm8 = add rsp, imm8 ; C3 = ret)
//
// A bare 0xC3 cannot be used as the spoofed return address: when the spoofed
// callee returns into the gadget, rsp points at the 32-byte shadow window the
// callee just dirtied — its first ret would pop garbage.  The "add rsp,0x28"
// step skips both the shadow space (4 qwords) AND a single alignment qword
// reserved by SpoofCallThunk, landing rsp on the real return address.
//
// This 5-byte pattern is one of the most common epilogues in ntoskrnl —
// virtually every leaf routine that homes its register args ends this way,
// so the scan finds a hit very early.
__forceinline PVOID FindRetGadget() {
    if (g_ret_gadget_ntos) return g_ret_gadget_ntos;

    PVOID ntosBase = GetSystemModuleBase("ntoskrnl.exe");
    if (!ntosBase) return nullptr;

    PVOID textStart = nullptr;
    SIZE_T textSize = 0;
    NTSTATUS st = CodeCave::GetTextSectionRange(ntosBase, &textStart, &textSize);
    if (!NT_SUCCESS(st)) return nullptr;

    // Primary: add rsp, 0x28 ; ret    — matches SpoofCallThunk's 0x38 frame.
    static const UCHAR kPrimary[] = { 0x48, 0x83, 0xC4, 0x28, 0xC3 };

    if (textSize >= sizeof(kPrimary)) {
        const SIZE_T limit = textSize - sizeof(kPrimary);
        // Skip the first 0x1000 bytes (PE header overlap / known prologues).
        for (SIZE_T i = 0x1000; i <= limit; i++) {
            PUCHAR p = (PUCHAR)textStart + i;
            if (p[0] == kPrimary[0] && p[1] == kPrimary[1] &&
                p[2] == kPrimary[2] && p[3] == kPrimary[3] &&
                p[4] == kPrimary[4]) {
                g_ret_gadget_ntos = p;
                KIPC_LOG(
                           "[CR3-IPC] SyscallSpf: gadget 'add rsp,0x28; ret' at ntos+0x%zX (%p)\n",
                           i, p);
                return g_ret_gadget_ntos;
            }
        }
    }

    // Secondary: add rsp, 0x20 ; ret  — also valid IF SpoofCallThunk is
    // rebuilt with a 0x30 frame.  Currently unused by the thunk; we resolve
    // it only as a diagnostic so the bring-up log shows it was found.
    static const UCHAR kSecondary[] = { 0x48, 0x83, 0xC4, 0x20, 0xC3 };
    if (textSize >= sizeof(kSecondary)) {
        const SIZE_T limit = textSize - sizeof(kSecondary);
        for (SIZE_T i = 0x1000; i <= limit; i++) {
            PUCHAR p = (PUCHAR)textStart + i;
            if (p[0] == kSecondary[0] && p[1] == kSecondary[1] &&
                p[2] == kSecondary[2] && p[3] == kSecondary[3] &&
                p[4] == kSecondary[4]) {
                KIPC_LOG(
                           "[CR3-IPC] SyscallSpf: alt gadget 'add rsp,0x20; ret' at ntos+0x%zX (%p) (unused)\n",
                           i, p);
                break;
            }
        }
    }

    KIPC_LOG(
               "[CR3-IPC] SyscallSpf: FAILED to locate 'add rsp,0x28; ret' gadget in ntoskrnl .text\n");
    return nullptr;
}

// ============================================================================
// _JUMP* macros for return-address stack spoofing
//
// These macros replace standard function calls with a trampoline that pushes
// a fake return address (pointing into ntoskrnl.exe) onto the stack before
// transferring control. When the callee returns, the CPU pops the fake address
// and executes our ret-gadget, which immediately returns again to the real
// caller. The stack trace shows:
//
//   ntoskrnl!GadgetRet          ← fake return address (0xC3)
//   ntoskrnl!SomeLegitFrame      ← real caller's frame
//
// Usage:
//   Instead of:         SomeKernelFunction(args);
//   Use:                _JUMP_CALL(SomeKernelFunction)(args);
//
//   Instead of:         status = ZwFreeVirtualMemory(...);
//   Use:                status = _JUMP_CALL(NtFreeVirtualMemorySyscall)(...);
// ============================================================================

//
// _JUMP_CALL(fn): calls fn with a spoofed return address.
// The macro generates a CALL to the target function with the return address
// pushed onto the stack replaced by our gadget.
//
// The implementation uses inline assembly or a small thunk:
//   1. push real_return_address   (our code, hide this)
//   2. push gadget_address        (what the stack trace will see)
//   3. jmp target_function        (which will RET to gadget)
//   → at gadget: ret (pops real_return_address, returns to our code)
//
__forceinline ULONG_PTR GetRetGadgetOrFallback() {
    PVOID gadget = FindRetGadget();
    if (gadget) return (ULONG_PTR)gadget;

    // Absolute last-resort fallback: use KeBugCheckEx+some_offset inside ntoskrnl.
    // This is NOT ideal because KeBugCheckEx is a well-known function, but it
    // is inside ntoskrnl and will pass the module-range check.
    // Better than showing unbacked memory.
    PVOID ntosBase = GetSystemModuleBase("ntoskrnl.exe");
    if (ntosBase) {
        // Return ntoskrnl base + 0x1000 — any address inside .text will pass
        // the range check, even if it's not a real return point. Stack unwind
        // may fail gracefully (it just stops) but won't flag the frame.
        return (ULONG_PTR)ntosBase + 0x1000;
    }
    return 0;
}

// ============================================================================
// Direct syscall stub for NtFreeVirtualMemory
//
// NtFreeVirtualMemory has 4 parameters:
//   ProcessHandle  (rcx)
//   BaseAddress    (rdx)  — pointer to PVOID, receives &Base on output
//   RegionSize     (r8)   — pointer to SIZE_T
//   FreeType       (r9)   — MEM_RELEASE (0x8000) or MEM_DECOMMIT (0x4000)
//
// Returns NTSTATUS in rax.
//
// The syscall convention (x64):
//   mov r10, rcx         ; syscall clobbers rcx
//   mov eax, SSN
//   syscall
//   ret
//
// We use a naked function to control the exact instruction sequence and
// avoid any compiler-generated prologue/epilogue that would add detectable
// frames.
// ============================================================================

// Extern reference to the gadget helper.
extern "C" ULONG_PTR SpoofedRetGadget;

// This is the raw syscall body — called via the spoofed return-address thunk.
// We declare it as a function pointer so we can call through the thunk.
typedef NTSTATUS (NTAPI *PFN_NtFreeVirtualMemorySyscall)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

// ============================================================================
// Stack-spoofed call wrapper
//
// The key insight: the CPU's CALL instruction pushes the return address.
// If we manually construct the stack so the "return address" is our gadget,
// the callee's RET will go to the gadget, which RETs again to the real caller.
//
// Implementation (see spoof_thunk.asm for full rationale on frame size 0x38
// and why a bare 0xC3 gadget cannot work — Win64 shadow space + alignment):
//       pop  rax                              ; real_ret
//       mov  r10, [g_SpoofedTarget]           ; real callee
//       mov  r11, [g_SpoofedGadget]           ; ntoskrnl 'add rsp,0x28; ret'
//       sub  rsp, 38h                         ; 7-qword frame, ABI-aligned
//       mov  [rsp + 30h], rax                 ; real_ret (outside shadow)
//       mov  [rsp +  0h], r11                 ; gadget   (target's ret addr)
//       jmp  r10
//
//   At target's RET: pops gadget → gadget does add rsp,0x28; ret → pops real → us
//
//   Stack trace: target_func → ntoskrnl!gadget → (our code, hidden)
//   EAC sees:    ntoskrnl!gadget → legitimate frame inside loaded module.
//
// BUILD: Compile spoof_thunk.asm with ml64.exe and link spoof_thunk.obj.
// ============================================================================

// Naked thunk implemented in spoof_thunk.asm — declared here for linkage.
extern "C" {
    VOID SpoofCallThunk();
}

// Globals set before invoking SpoofCallThunk.
// Defined in driver.cpp; referenced by spoof_thunk.asm.
extern "C" {
    extern PVOID g_SpoofedTarget;
    extern PVOID g_SpoofedGadget;
}

// ============================================================================
// Generic stack-spoofed call wrapper for any Nt*/Zw* function
//
// Usage:
//   auto pfn = (PFN_NtFreeVirtualMemory)MmGetSystemRoutineAddress(&name);
//   status = SpoofedSysCall<decltype(pfn)>(pfn,
//       ProcessHandle, &BaseAddress, &RegionSize, MEM_RELEASE);
//
// Template parameter is the function pointer type.
// First argument is the real function pointer (must be in a loaded module).
// Remaining arguments are forwarded via registers (x64 calling convention).
// ============================================================================
template<typename FnType, typename... Args>
__forceinline auto SpoofedSysCall(FnType realFn, Args... args) -> decltype(realFn(args...)) {
    PVOID gadget = FindRetGadget();
    if (!gadget) {
        // No gadget available — fall back to direct call.
        // Detectable but functional.
        return realFn(args...);
    }

    g_SpoofedTarget = (PVOID)realFn;
    g_SpoofedGadget = gadget;

    // SpoofCallThunk is a naked function with NO c++ signature.
    // We cast it to the target function type. When "called", the CPU
    // pushes our real return address onto the stack, then jumps to the
    // thunk. The thunk swaps in the fake return address and transfers
    // to realFn. realFn RETs to the gadget, which RETs back to us.
    //
    // This ONLY works because:
    //   a) SpoofCallThunk has no stack frame (naked).
    //   b) x64 calling convention passes first 4 args in RCX,RDX,R8,R9.
    //   c) The thunk preserves all argument registers (it only uses RAX/R10).
    //   d) The cast tricks the compiler into emitting CALL thunk with args
    //      already in registers — the thunk ignores them and they flow
    //      through to realFn unchanged.
    //
    auto spoofed = reinterpret_cast<FnType>(SpoofCallThunk);
    return spoofed(args...);
}

// ============================================================================
// NtFreeVirtualMemory via direct syscall with stack spoofing
//
// This is the main entry point for unmapping a DLL from the target process
// WITHOUT leaving any call-trace into unbacked memory.
//
// Parameters: identical to ZwFreeVirtualMemory.
// Returns: NTSTATUS (the raw value from the syscall — already negated to
//          standard NTSTATUS format since syscall returns in eax and the
//          kernel's KiSystemServiceExit does the negation).
//
// NOTE: The raw syscall returns the NTSTATUS directly in eax. No negation
// needed — the kernel's syscall handler does NOT negate the return value
// for `syscall`-invoked entries (only for `int 2e` legacy).
// We return eax directly. Callers should check with NT_SUCCESS().
// ============================================================================

// Cached SSN for NtFreeVirtualMemory — resolved lazily on first use.
static ULONG g_NtFreeVirtualMemorySSN = 0;

// ============================================================================
// Full spoofed NtFreeVirtualMemory — THE function to use.
//
// This does TWO things:
//   1. Uses the direct syscall (no Zw*/Nt* wrapper → no SSDT hook can intercept)
//   2. Spoofs the return address via the thunk (stack trace shows ntoskrnl)
//
// Call this instead of ZwFreeVirtualMemory in the mapper.
// ============================================================================
__forceinline NTSTATUS SpoofedNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType)
{
    // Ensure SSN and gadget are initialized (one-time lazy init)
    if (g_NtFreeVirtualMemorySSN == 0) {
        g_NtFreeVirtualMemorySSN = ResolveNtFreeVirtualMemorySyscall();
    }

    // Ensure the ret gadget is resolved
    PVOID gadget = FindRetGadget();
    if (!gadget) {
        // No gadget available — fall back to the standard Zw call.
        // This IS detectable but is the safe fallback.
        KIPC_LOG(
                   "[CR3-IPC] SyscallSpf: no ret gadget, falling back to ZwFreeVirtualMemory\n");
        return ZwFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    }

    // ─── Execute the spoofed direct syscall ──────────────────────────────────
    // We use a small inline thunk:
    //
    // The function Epilogue we want:
    //   1. mov r10, rcx         (syscall convention)
    //   2. mov eax, SSN
    //   3. Push fake return address onto stack
    //   4. syscall              (CPU pushes rflags → rsp, then RIP → rsp,
    //                            then loads RIP from LSTAR MSR → KiSystemCall64)
    //
    // The trick: after `syscall` returns (via `sysret`), the CPU pops RIP from
    // the stack. If we pushed a fake return address BEFORE the syscall, we need
    // the real return address to be UNDER the fake one. The `syscall` instruction
    // itself pushes the real return address (the instruction after syscall) onto
    // the kernel stack, not the user stack — but we're already in kernel mode.
    //
    // Since we are ALREADY in kernel mode (the mapper runs at kernel privilege),
    // the `syscall` instruction from ring 0 is not architecturally supported
    // on all CPUs — it may #GP. Instead, we use the SYSCALL shadow stack
    // technique: we set up the kernel stack so the return address points to
    // our gadget, then call the syscall stub directly.
    //
    // The SAFEST approach for a kernel-mode caller:
    //   Use the thunk (SpoofCallThunk) to wrap ANY call, including our syscall
    //   stub, so the stack trace shows the gadget.
    //
    // For the specific case of NtFreeVirtualMemory, we do NOT need to use
    // `syscall` from ring 0 — we can just call the kernel's
    // NtFreeVirtualMemory directly via its SSDT entry. But we DO need the
    // stack spoofing.

    // ─── Stack-spoofed direct call to NtFreeVirtualMemory ──────────────────
    // We use the SpoofCallThunk mechanism described above.

    // Resolve the SSDT entry for NtFreeVirtualMemory.
    // Alternative: call the function pointer from ntdll's syscall stub but
    // that's in user space. Better: use the kernel's SSDT or just call the
    // internal NtFreeVirtualMemory which is exported from ntoskrnl.

    // Get the kernel's NtFreeVirtualMemory address.
    // ntoskrnl exports NtFreeVirtualMemory — we can resolve it dynamically.
    static PVOID s_NtFreeVirtualMemory_va = nullptr;
    if (!s_NtFreeVirtualMemory_va) {
        UNICODE_STRING fnName;
        RtlInitUnicodeString(&fnName, L"NtFreeVirtualMemory");
        s_NtFreeVirtualMemory_va = MmGetSystemRoutineAddress(&fnName);
    }

    if (!s_NtFreeVirtualMemory_va) {
        return ZwFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    }

    // Perform the spoofed call via the generic template.
    // The call goes: our code → SpoofCallThunk → NtFreeVirtualMemory
    // Stack trace:   NtFreeVirtualMemory, ntoskrnl+gadget, (our code hidden)
    auto pfnFree = (PFN_NtFreeVirtualMemorySyscall)s_NtFreeVirtualMemory_va;
    return SpoofedSysCall<PFN_NtFreeVirtualMemorySyscall>(
        pfnFree, ProcessHandle, BaseAddress, RegionSize, FreeType);
}

// ============================================================================
// Force-inline the gadget address resolution for hot-path optimization
// ============================================================================
__forceinline PVOID EnsureRetGadget() {
    if (!g_ret_gadget_ntos) {
        FindRetGadget();
    }
    return g_ret_gadget_ntos;
}

// ============================================================================
// SSN getter (force-inline for hot path)
// ============================================================================
__forceinline ULONG GetNtFreeVirtualMemorySSN() {
    if (g_NtFreeVirtualMemorySSN == 0) {
        g_NtFreeVirtualMemorySSN = ResolveNtFreeVirtualMemorySyscall();
    }
    return g_NtFreeVirtualMemorySSN;
}
