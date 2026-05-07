#include <cstdint>
#include <intrin.h>
#include <ntdef.h>
#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>

// Suppress warnings that do not affect stealth or correctness:
//   C4201 - nameless struct/union (needed for PFN/PTE bitfield layouts in CR3.h)
//   C4996 - ExAllocatePool deprecated (still works on Win10/11; ExAllocatePool2
//           requires POOL_FLAGS which can leave detectable pool tag patterns)
//   C4273 - inconsistent dll linkage (ntapi.hpp vs WDK headers declare some
//           functions with different linkage — NTKERNELAPI vs NTSYSAPI — but
//           both resolve to the same symbol at link time)
//   C4505 - unreferenced local function removed (vestigial helpers from earlier
//           versions kept for reference; linker strips them anyway)
#pragma warning(disable: 4201)
#pragma warning(disable: 4996)
#pragma warning(disable: 4273)
#pragma warning(disable: 4505)

// Core CR3 page table walking
#include "CR3.h"

// Mouse movement
#include "mouse.hpp"

// Shared IPC protocol
#include "shared_memory_ipc.h"

// DLL Manual Mapper
#include "manual_mapper.h"

// HWID Spoofer
#include "hwid_spoofer.hpp"

// ============================================================================
// Struct definitions (kept from original driver)
// ============================================================================

// ============================================================================
// Dynamic import resolution for KDU-mapped drivers
// ============================================================================
// KDU manual mappers resolve the driver's PE import table, but some mappers
// skip less-common exports.  We resolve critical functions dynamically via
// MmGetSystemRoutineAddress at init time, with static-linkage fallbacks that
// keep the extern "C" declarations as the default path.  If a dynamic resolve
// succeeds, we use the function pointer; if not, we fall back to the import-
// table symbol (which may PAGE_FAULT if unresolved — that's caught by SEH).
//
// Functions resolved this way:
//   PsGetProcessPeb              – needed by find_ipc_buffer (PEB base)
//   PsGetProcessSectionBaseAddress – fallback for image base
//   PsGetProcessImageFileName    – needed by process name matching
//   ZwQuerySystemInformation     – needed by GetSystemModuleBase / GetRetGadget
//   MmCopyVirtualMemory          – needed by find_ipc_buffer / do_read_write
// ============================================================================

typedef PUCHAR (NTAPI *fn_PsGetProcessImageFileName_t)(PEPROCESS);
typedef PVOID  (NTAPI *fn_PsGetProcessSectionBaseAddress_t)(PEPROCESS);
typedef PVOID  (NTAPI *fn_PsGetProcessPeb_t)(PEPROCESS);
typedef NTSTATUS (NTAPI *fn_ZwQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fn_MmCopyVirtualMemory_t)(
    PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

static fn_PsGetProcessImageFileName_t       g_pfnPsGetProcessImageFileName = NULL;
static fn_PsGetProcessSectionBaseAddress_t  g_pfnPsGetProcessSectionBaseAddress = NULL;
static fn_PsGetProcessPeb_t                 g_pfnPsGetProcessPeb = NULL;
static fn_ZwQuerySystemInformation_t        g_pfnZwQuerySystemInformation = NULL;
static fn_MmCopyVirtualMemory_t             g_pfnMmCopyVirtualMemory = NULL;

// Only call from DriverEntry. Resolves optional functions that some KDU
// mappers skip. Callers should still SEH-wrap any invocation of these.
static void ResolveOptionalImports() {
  UNICODE_STRING name;
  auto resolve = [&](const wchar_t* n, PVOID* out) {
    RtlInitUnicodeString(&name, n);
    *out = MmGetSystemRoutineAddress(&name);
  };
  resolve(L"PsGetProcessImageFileName",      (PVOID*)&g_pfnPsGetProcessImageFileName);
  resolve(L"PsGetProcessSectionBaseAddress", (PVOID*)&g_pfnPsGetProcessSectionBaseAddress);
  resolve(L"PsGetProcessPeb",                (PVOID*)&g_pfnPsGetProcessPeb);
  resolve(L"ZwQuerySystemInformation",       (PVOID*)&g_pfnZwQuerySystemInformation);
  resolve(L"MmCopyVirtualMemory",            (PVOID*)&g_pfnMmCopyVirtualMemory);

  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] Optional imports: PsGetProcessImageFileName=%p "
             "PsGetProcessSectionBaseAddress=%p PsGetProcessPeb=%p "
             "ZwQuerySystemInformation=%p MmCopyVirtualMemory=%p\n",
             g_pfnPsGetProcessImageFileName,
             g_pfnPsGetProcessSectionBaseAddress,
             g_pfnPsGetProcessPeb,
             g_pfnZwQuerySystemInformation,
             g_pfnMmCopyVirtualMemory);
}

// Forward declarations for linker-resolved imports.
extern "C" {
NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass,
                                        PVOID SystemInformation,
                                        ULONG SystemInformationLength,
                                        PULONG ReturnLength);
// MmCopyVirtualMemory and RtlGetVersion declared in ntapi.hpp — no duplicate
}  // extern "C"

// ── Safe wrappers — use dynamic function pointers when available ────────
// These prefer the dynamic pointer resolved by ResolveOptionalImports.
// The static-linkage fallback is the extern "C" symbol (which may PAGE_FAULT
// if KDU didn't resolve it — callers must SEH-wrap).
//
// NOTE: PsGetProcessImageFileName and PsGetProcessSectionBaseAddress are
// NOT declared here because the WDK provides inline wrappers or macros for
// them that conflict with our own forward declarations.  We use the dynamic
// pointers exclusively.
//
// EPROCESS.ImageFileName is UCHAR[15] at a fixed offset that has been
// stable since Windows Vista.  We have 3 resolution tiers:
//   1. Dynamic pointer (MmGetSystemRoutineAddress) — best, always works
//   2. Direct EPROCESS read at known offset — works even if tier 1 fails
//   3. NULL — unresolved; caller treats as "no name available"
//
// The known-good offsets for modern Windows (10/11) are:
//   Win10/11  → 0x450  (stable since 20H1, verified through 24H2)
// We scan a narrow range at init time to find the exact offset, falling
// back to 0x450 if the scan fails.  This is a last-resort fallback for
// KDU-mapped drivers where even PsGetProcessImageFileName is not resolved.
static ULONG g_image_file_name_offset = 0;

static ULONG DetectImageFileNameOffset() {
  // Scan PsInitialSystemProcess for the ImageFileName field.
  // The System process has a known name ("System" = 6 chars + null).
  // We scan the plausible offset range looking for "System\0".
  PEPROCESS sys = PsInitialSystemProcess;
  if (!sys) return 0;

  // Known offsets across Windows versions: 0x448-0x5B0 range
  for (ULONG off = 0x440; off <= 0x5B0; off += 8) {
    const char* p = (const char*)((PUCHAR)sys + off);
    // "System" — case-insensitive compare of first 6 chars, 7th is '\0' or end
    if ((p[0] == 'S' || p[0] == 's') &&
        (p[1] == 'Y' || p[1] == 'y') &&
        (p[2] == 'S' || p[2] == 's') &&
        (p[3] == 'T' || p[3] == 't') &&
        (p[4] == 'E' || p[4] == 'e') &&
        (p[5] == 'M' || p[5] == 'm') &&
        (p[6] == '\0')) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] ImageFileName offset detected: EPROCESS+0x%X\n", off);
      return off;
    }
  }
  return 0;
}

static PUCHAR SafePsGetProcessImageFileName(PEPROCESS p) {
  if (g_pfnPsGetProcessImageFileName)
    return g_pfnPsGetProcessImageFileName(p);
  // Fallback: direct EPROCESS read at detected offset
  if (g_image_file_name_offset)
    return (PUCHAR)p + g_image_file_name_offset;
  return NULL; // completely unresolved — caller handles NULL
}
static PVOID SafePsGetProcessSectionBaseAddress(PEPROCESS p) {
  if (g_pfnPsGetProcessSectionBaseAddress)
    return g_pfnPsGetProcessSectionBaseAddress(p);
  // PsGetProcessSectionBaseAddress reads EPROCESS->SectionObject->Segment->...
  // This is not trivially replicable via offset reads, so return NULL.
  // The caller in find_ipc_buffer will fall back to PEB-based image base.
  return NULL;
}
static PVOID SafePsGetProcessPeb(PEPROCESS p) {
  if (g_pfnPsGetProcessPeb)
    return g_pfnPsGetProcessPeb(p);
  return PsGetProcessPeb(p); // PsGetProcessPeb IS in the WDK headers
}

#define SystemBigPoolInformation 0x42

struct comms_t {
  std::uint32_t key;
  struct {
    void *handle;
  } window;
};

typedef struct _SYSTEM_BIGPOOL_ENTRY {
  union {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged : 1;
  };
  ULONG_PTR SizeInBytes;
  union {
    UCHAR Tag[4];
    ULONG TagUlong;
  };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
  ULONG Count;
  SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

#define code_security IPC_SECURITY_CODE
#define win_1803 17134
#define win_1809 17763
#define win_1903 18362
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19042 // Was wrong (19569), corrected
#define win_21H1 19043 // Was wrong (20180), corrected
#define win_21H2 19044
#define win_22H2 19045
#define win_11_21h2 22000
#define win_11_22h2 22621
#define win_11_23h2 22631
#define win_11_24h2 26100
//#define win_11_25h2 

#define PAGE_OFFSET_SIZE 12
// BUGFIX: the old PMASK (0xFFFFFF000, 36-bit) silently truncated any PFN
// that lived above 64 GB of physical address space. On modern Windows the
// kernel hands out high PFNs for page-table pages themselves, and even on
// 16 GB boxes pieces of PT/PD/PDP memory routinely sit above 64 GB. When
// translate_linearBE truncated a valid PFN it returned a garbage physical
// address, which the proxy-PTE write path then mapped into a kernel VA
// → PAGE_FAULT_IN_NONPAGED_AREA at DISPATCH_LEVEL. Use the architectural
// 52-bit physical-address mask (bits 12..51) everywhere we pull a PFN
// out of a PTE value.
static const UINT64 PMASK = 0x000FFFFFFFFFF000ULL;

typedef struct _rw {
  INT32 security;
  INT32 process_id;
  ULONGLONG address;
  ULONGLONG buffer;
  ULONGLONG size;
  BOOLEAN write;
  BOOLEAN EAC;
} rw, *prw;

typedef struct _dtb {
  INT32 security;
  INT32 process_id;
  bool *operation;
} dtb, *dtbl;

typedef struct _ba {
  INT32 security;
  INT32 process_id;
  ULONGLONG *address;
} ba, *pba;

typedef struct _ga {
  INT32 security;
  ULONGLONG *address;
} ga, *pga;

typedef struct _mu {
  float y;
  float x;
} mu, *mua;

// ============================================================================
// Physical memory read/write primitives — REMOVED
// ============================================================================
//
// The standalone read()/write() helpers that wrapped MmCopyMemory(PHYSICAL)
// and MmMapIoSpaceEx have been deleted from the data-plane path.  Both PG
// scans IoSpace mappings of system RAM and physical-memory copies on data
// pages can be flagged as suspicious; the MDL-based path
// (IoAllocateMdl + MmProbeAndLockPages + MmMapLockedPagesSpecifyCache)
// in read_via_proxy_pte / write_via_proxy_pte replaces them entirely for
// CR3-mode requests.
//
// One narrow PT-walk helper remains below — phys_read_pt_entry() — which is
// used ONLY by translate_linearBE() for DTB-validation page-table walks
// during do_resolve_dtb.  It does not appear on the read/write data plane.
// ============================================================================

static NTSTATUS phys_read_pt_entry(UINT64 physical_address, PVOID buffer,
                                   SIZE_T size) {
  MM_COPY_ADDRESS to_read = {0};
  to_read.PhysicalAddress.QuadPart = (LONGLONG)physical_address;
  SIZE_T bytes_read = 0;
  return MmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL,
                      &bytes_read);
}

// ============================================================================
// Direct PTE Manipulation — REMOVED
// ============================================================================
//
// All proxy-PTE state (g_proxy_page, g_proxy_pte, g_mapped_pt, the
// per-core saved PTE values, InitProxyPage, CleanupProxyPage) has been
// stripped out.  No PTE swap is performed anywhere in the driver, so the
// signature PG looks for (a writable kernel mapping of a PT page +
// transient PFN substitutions in that page) cannot be observed.
//
// The pinned-RAM / race-free behavior is provided instead by the MDL
// pipeline: MmProbeAndLockPages takes a real PFN reference, the kernel
// VA returned by MmMapLockedPagesSpecifyCache is a normal mapping (not
// IoSpace), and the page is unlocked as soon as the copy completes.
//
#if 0
#define MAX_CORES 256
PVOID g_proxy_page_raw[MAX_CORES] = {
    0}; // raw pool pointer (used for ExFreePool)
PVOID g_proxy_page[MAX_CORES] = {
    0}; // PAGE_ALIGNED virtual address inside g_proxy_page_raw
PULONG64 g_proxy_pte[MAX_CORES] = {0};
PVOID g_mapped_pt[MAX_CORES] = {0};
// Saved original PTE value for each core's proxy page, captured at
// InitProxyPage() time. write() now RESTORES this value after each
// stealth write so the proxy page's virtual address always maps back
// to its real backing PFN. Without this, the PTE left behind by the
// last write() points at an arbitrary target-process physical page —
// and when ExFreePool later touches the proxy VA during driver cleanup
// (or pool reuses the memory), it corrupts random physical memory.
// Symptoms range from PAGE_FAULT_IN_NONPAGED_AREA on unload to
// delayed, seemingly-unrelated BSODs minutes later.
ULONG64 g_proxy_pte_original[MAX_CORES] = {0};

// Mask for a 52-bit physical PFN field within a PTE / physical address.
// Architecturally, x86-64 PTEs encode the PFN in bits 12..51; bit 63 is NX.
// The legacy PMASK (0xFFFFFF000) only supports 64 GB of RAM and silently
// truncates higher PFNs — keep a wider mask for the proxy write path so
// systems with > 64 GB don't corrupt addresses.
#define PROXY_PFN_MASK 0x000FFFFFFFFFF000ULL
#define PROXY_NX_BIT (1ULL << 63)

NTSTATUS InitProxyPage() {
  // Allocate two pages per core so we can carve out a guaranteed page-aligned
  // region. ExAllocatePool only aligns to pool block granularity (16 bytes),
  // but the PTE we hijack maps an entire 4 KB virtual page.

  ULONG num_cores = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
  if (num_cores > MAX_CORES)
    num_cores = MAX_CORES;

  for (ULONG i = 0; i < num_cores; i++) {
    g_proxy_page_raw[i] = ExAllocatePool(NonPagedPool, PAGE_SIZE * 2);
    if (!g_proxy_page_raw[i])
      continue;

    g_proxy_page[i] = (PVOID)(((ULONG_PTR)g_proxy_page_raw[i] + PAGE_SIZE - 1) &
                              ~(ULONG_PTR)(PAGE_SIZE - 1));

    // Touch the aligned page so it has a real PFN before we walk its PTE.
    RtlZeroMemory(g_proxy_page[i], PAGE_SIZE);

    ULONG_PTR cr3 = __readcr3();
    cr3 &= ~0xf;

    UINT64 virtualAddress = (UINT64)g_proxy_page[i];
    UINT64 pte_idx = ((virtualAddress >> 12) & 0x1ff);
    UINT64 pt_idx = ((virtualAddress >> 21) & 0x1ff);
    UINT64 pd_idx = ((virtualAddress >> 30) & 0x1ff);
    UINT64 pdp_idx = ((virtualAddress >> 39) & 0x1ff);

    SIZE_T readsize = 0;
    UINT64 pdpe = 0;
    read(PVOID(cr3 + 8 * pdp_idx), &pdpe, sizeof(pdpe), &readsize);
    if (~pdpe & 1) {
      ExFreePool(g_proxy_page_raw[i]);
      g_proxy_page_raw[i] = NULL;
      g_proxy_page[i] = NULL;
      continue;
    }

    UINT64 pde = 0;
    read(PVOID((pdpe & PMASK) + 8 * pd_idx), &pde, sizeof(pde), &readsize);
    if (~pde & 1) {
      ExFreePool(g_proxy_page_raw[i]);
      g_proxy_page_raw[i] = NULL;
      g_proxy_page[i] = NULL;
      continue;
    }

    UINT64 pteAddr = 0;
    read(PVOID((pde & PMASK) + 8 * pt_idx), &pteAddr, sizeof(pteAddr),
         &readsize);
    if (~pteAddr & 1) {
      ExFreePool(g_proxy_page_raw[i]);
      g_proxy_page_raw[i] = NULL;
      g_proxy_page[i] = NULL;
      continue;
    }

    PHYSICAL_ADDRESS p_addr;
    p_addr.QuadPart = (LONGLONG)(pteAddr & PMASK);
    g_mapped_pt[i] = MmMapIoSpaceEx(p_addr, PAGE_SIZE, PAGE_READWRITE);

    if (!g_mapped_pt[i]) {
      ExFreePool(g_proxy_page_raw[i]);
      g_proxy_page_raw[i] = NULL;
      g_proxy_page[i] = NULL;
      continue;
    }

    g_proxy_pte[i] = (PULONG64)((PUCHAR)g_mapped_pt[i] + (pte_idx * 8));
    // Snapshot the real PTE so write() can restore it after each
    // stealth write, and so CleanupProxyPage can restore it before
    // ExFreePool touches the VA. See the block comment on
    // g_proxy_pte_original for the full rationale.
    g_proxy_pte_original[i] = *g_proxy_pte[i];
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] PTP Proxy init successful for core %lu. RawPool: %p "
               "AlignedPage: %p PTE: %p OrigPTE: 0x%llx\n",
               i, g_proxy_page_raw[i], g_proxy_page[i], g_proxy_pte[i],
               (ULONGLONG)g_proxy_pte_original[i]);
  }
  return STATUS_SUCCESS;
}

VOID CleanupProxyPage() {
  for (int i = 0; i < MAX_CORES; i++) {
    // Restore the original PTE BEFORE we unmap the PT or free the
    // pool. If the last write() left the PTE pointing at a target
    // process's PFN, pool reuse / ExFreePool poisoning via the
    // proxy VA would write into that unrelated page. This is the
    // proxy-PTE-not-restored bug that produces delayed
    // PAGE_FAULT_IN_NONPAGED_AREA long after unload.
    if (g_proxy_pte[i] && g_proxy_pte_original[i]) {
      InterlockedExchange64((LONG64 *)g_proxy_pte[i],
                            (LONG64)g_proxy_pte_original[i]);
      if (g_proxy_page[i])
        __invlpg(g_proxy_page[i]);
      g_proxy_pte_original[i] = 0;
    }

    if (g_mapped_pt[i]) {
      MmUnmapIoSpace(g_mapped_pt[i], PAGE_SIZE);
      g_mapped_pt[i] = NULL;
    }
    if (g_proxy_page_raw[i]) {
      ExFreePool(g_proxy_page_raw[i]);
      g_proxy_page_raw[i] = NULL;
      g_proxy_page[i] = NULL;
    }
    g_proxy_pte[i] = NULL;
  }
}

//
// BUGFIX (round 3): the proxy-PTE hijack approach was still crashing
// under the 4096-byte CR3 benchmark even after pinning the core,
// preserving all non-PFN bits, and fixing PMASK. The proxy trick is
// fundamentally racy with the rest of the memory manager:
//
//   * We keep one page-table page permanently writable via
//     MmMapIoSpaceEx. PatchGuard scans PT pages and can flag this
//     lifetime mapping itself, not just the transient PTE values.
//
//   * Between translate_linear() at PASSIVE and our PTE swap at
//     DISPATCH, Windows' Working-Set Trimmer can evict the target's
//     physical page. The PA we memorized is now owned by someone
//     else, and the next memcpy (running at DISPATCH_LEVEL) trashes
//     unrelated kernel memory → delayed PAGE_FAULT_IN_NONPAGED_AREA.
//
//   * DPC-level page faults are NOT SEH-recoverable. Any of the
//     above becomes an unrecoverable bugcheck, not a clean NTSTATUS.
//
//   * Probability of hitting one of those windows scales with both
//     iteration count and per-op byte count. That's exactly why the
//     4096-byte / 500-iteration sweep reliably reproduced the fault
//     while smaller sizes survived.
//
// The safe path is MmMapIoSpaceEx: a documented API that holds a
// real PFN reference for the duration of the mapping (so the
// trimmer can't move the page out from under us), runs at PASSIVE
// (so any bad access is a catchable SEH exception, not a bugcheck),
// and creates a proper kernel VA mapping that cooperates with
// PatchGuard instead of fighting it. We keep InitProxyPage /
// CleanupProxyPage in place so the proxy scratch survives for any
// future direct callers of the old path, but write() itself now
// always takes the safe route.
//
#endif // proxy-PTE block disabled — see comment above

// ============================================================================
// Windows version helper — returns KPROCESS.UserDirectoryTableBase offset
// ============================================================================

// Cached result from the dynamic scan so we only pay the scan cost once.
static ULONG g_cached_user_dir_offset = 0;

// ============================================================================
// Dynamic EPROCESS.ActiveProcessLinks offset resolver
// ============================================================================
//
// The ActiveProcessLinks LIST_ENTRY offset inside EPROCESS changed between
// Windows versions:
//   Win10 20H2 .. Win11 22H2  →  0x448
//   Win11 23H2                →  0x470
//   Win11 24H2+               →  0x4C8
//
// Instead of hardcoding version-specific offsets (which can still be wrong
// for insider / pre-release builds), we scan PsInitialSystemProcess at init
// time.  The Idle / System process has the invariant that its own
// ActiveProcessLinks.Flink == ActiveProcessLinks.Blink == the address of the
// LIST_ENTRY itself.  We scan the plausible offset range and cache the result.

static ULONG g_cached_active_process_links_offset = 0;

// Minimum and maximum EPROCESS offsets to scan for ActiveProcessLinks.
// Offsets below 0x2E0 are the process-paging structures (Pcb, PaeShell,
// SeAuditProcessCreationInfo, etc).  The known values for Win10/11 span
// 0x448 .. 0x4C8, but we widen the search to cover any future shift.
#define APL_SCAN_MIN 0x2E0
#define APL_SCAN_MAX 0x550
#define APL_SCAN_STEP sizeof(PVOID)  // 8 bytes — pointer alignment

static ULONG detect_active_process_links() {
  PEPROCESS sys = PsInitialSystemProcess;
  if (!sys)
    return 0;

  PUCHAR base = (PUCHAR)sys;

  // The Idle/System process has ActiveProcessLinks pointing to itself:
  //   base[X]   = &base[X]   (Flink == self)
  //   base[X+8] = &base[X]   (Blink == self)
  for (ULONG off = APL_SCAN_MIN; off < APL_SCAN_MAX; off += APL_SCAN_STEP) {
    PVOID flink = *(PVOID *)(base + off);
    PVOID blink = *(PVOID *)(base + off + sizeof(PVOID));
    PVOID self  = (PVOID)(base + off);

    if (flink == self && blink == self) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] detect_active_process_links: found at "
                 "EPROCESS+0x%X\n", off);
      return off;
    }
  }

  // Fallback: most common offset for modern Windows
  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] detect_active_process_links: scan failed, "
             "defaulting to 0x448\n");
  return 0x448;
}

static ULONG get_active_process_links_offset() {
  if (!g_cached_active_process_links_offset) {
    g_cached_active_process_links_offset = detect_active_process_links();
  }
  return g_cached_active_process_links_offset;
}

// Scan PsInitialSystemProcess for UserDirectoryTableBase.
// On KPTI-enabled systems the System process has UserDirectoryTableBase ==
// DirectoryTableBase (same physical CR3 is reused; System never drops to user
// mode). Returns 0 if the scan cannot find a reliable candidate.
static ULONG detect_userdirtable_dynamic() {
  PEPROCESS sys = PsInitialSystemProcess;
  if (!sys)
    return 0;

  uintptr_t kernel_dtb = *(uintptr_t *)((PUCHAR)sys + 0x28);

  // Must be page-aligned and non-zero to be a valid CR3.
  if (!kernel_dtb || (kernel_dtb & 0xFFF))
    return 0;

  // Search the range where UserDirectoryTableBase is known to live across all
  // supported Windows 10/11 builds (0x0278 .. 0x03A0 covers every known
  // version).
  for (ULONG off = 0x200; off <= 0x3C0; off += 8) {
    if (off == 0x28)
      continue; // skip the field we already know
    uintptr_t val = *(uintptr_t *)((PUCHAR)sys + off);
    if (val == kernel_dtb) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] detect_userdirtable_dynamic: found "
                 "UserDirectoryTableBase at EPROCESS+0x%X\n",
                 off);
      return off;
    }
  }
  return 0;
}

INT32 get_winver() {
  RTL_OSVERSIONINFOW ver = {0};
  RtlGetVersion(&ver);
  ULONG build = ver.dwBuildNumber;

  // ----------------------------------------------------------------
  // Range-based detection: covers every shipping Windows 10/11 build.
  // Win11 25H2 (26200+) goes through the dynamic scan first because
  // EPROCESS layout changes between feature releases may shift
  // UserDirectoryTableBase; falling back to 0x0388 if the scan fails.
  // ----------------------------------------------------------------
  if (build >= 26200) {
    if (!g_cached_user_dir_offset)
      g_cached_user_dir_offset = detect_userdirtable_dynamic();
    if (g_cached_user_dir_offset)
      return (INT32)g_cached_user_dir_offset;
    return 0x0388; // Fallback: unchanged from 24H2 if dynamic scan fails
  }
  if (build >= win_2004)
    return 0x0388; // Win10 2004/20H2/21H1/21H2/22H2, Win11 21H2/22H2/23H2/24H2
  if (build >= win_1903)
    return 0x0280; // Win10 1903, 1909
  if (build >= win_1803)
    return 0x0278; // Win10 1803, 1809

  // ----------------------------------------------------------------
  // Unknown / future build: try a one-time dynamic scan, then fall back
  // to the most-recent known offset (0x0388).
  // ----------------------------------------------------------------
  if (!g_cached_user_dir_offset)
    g_cached_user_dir_offset = detect_userdirtable_dynamic();

  if (g_cached_user_dir_offset)
    return (INT32)g_cached_user_dir_offset;

  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] get_winver: unknown build %lu, defaulting "
             "UserDirectoryTableBase offset to 0x0388\n",
             build);
  return 0x0388;
}

// ============================================================================
// Process module info (for ZwQuerySystemInformation)
// ============================================================================

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define SystemModuleInformation 11

// Stealth modules — included after SystemModuleInformation and PRTL_PROCESS_MODULES
// are defined so the code-cave scanner and syscall resolver can use them.
#include "thread_spoof.h"
#include "syscall_stack_spoof.h"

bool kernel_strstr(const char *str, const char *sub) {
  if (!str || !sub)
    return false;
  for (int i = 0; str[i]; i++) {
    int j = 0;
    while (str[i + j] && sub[j] &&
           (str[i + j] == sub[j] || (str[i + j] + 32) == sub[j] ||
            str[i + j] == (sub[j] + 32)))
      j++;
    if (!sub[j])
      return true;
  }
  return false;
}

PVOID GetSystemModuleBase(const char *module_name) {
  // Use dynamic pointer if available (resolved by ResolveOptionalImports),
  // fall back to linker-resolved import.
  fn_ZwQuerySystemInformation_t pZwQSI = g_pfnZwQuerySystemInformation
      ? g_pfnZwQuerySystemInformation
      : ZwQuerySystemInformation;

  ULONG bytes = 0;
  pZwQSI(SystemModuleInformation, 0, bytes, &bytes);
  if (!bytes)
    return NULL;

  PRTL_PROCESS_MODULES modules =
      (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);
  if (!modules)
    return NULL;

  NTSTATUS status =
      pZwQSI(SystemModuleInformation, modules, bytes, &bytes);
  if (!NT_SUCCESS(status)) {
    ExFreePool(modules);
    return NULL;
  }

  PVOID module_base = NULL;
  for (ULONG i = 0; i < modules->NumberOfModules; i++) {
    if (kernel_strstr((char *)modules->Modules[i].FullPathName, module_name)) {
      module_base = modules->Modules[i].ImageBase;
      break;
    }
  }
  ExFreePool(modules);
  return module_base;
}

// ============================================================================
// CR3 / DTB resolution (unchanged)
// ============================================================================

uintptr_t eac_cr3 = 0;
PEPROCESS saved_process = 0;

// Remember which process the cached DTB (`physical::m_stored_dtb`) belongs
// to. Without this check, two CR3-mode clients targeting different PIDs
// would silently overwrite each other's DTB and then translate addresses
// against the wrong process's page tables — best case STATUS_UNSUCCESSFUL,
// worst case a successful read/write against an unrelated process's
// memory which can absolutely BSOD if that PID turned out to be a
// protected process mid-operation.
static INT32 g_cr3_cached_pid = 0;

// TRUE when the CPU has CR4.PCIDE set (bit 17), which indicates Kernel Page
// Table Isolation (KPTI) is active. On KPTI systems, UserDirectoryTableBase
// holds a shadow page table without kernel mappings and CANNOT be safely used
// as a target for rw_via_cr3_swap (which runs kernel code under the target CR3).
// On KPTI-disabled systems (common on gaming hardware for performance)
// UserDirectoryTableBase == DirectoryTableBase, so it is safe.
static BOOLEAN g_kpti_enabled = FALSE;

// TRUE when physical::m_stored_dtb is a full kernel-mode CR3 — i.e. it maps
// both the target's user-space AND the driver's own kernel virtual addresses.
// Set by do_resolve_dtb(). When FALSE (UserDTB on a KPTI system) the CR3 swap
// is skipped and the MDL+attach fallback is used instead.
static BOOLEAN g_cr3_swap_capable = FALSE;

static BOOLEAN detect_kpti() {
  return (BOOLEAN)((__readcr4() >> 17) & 1);
}

bool is_cr3_invalid(uintptr_t cr3) { return (cr3 >> 0x38) == 0x40; }

uintptr_t get_process_cr3(PEPROCESS pprocess) {
  if (!pprocess)
    return 0;
  uintptr_t process_dirbase = *(uintptr_t *)((PUCHAR)pprocess + 0x28);
  if (process_dirbase == 0) {
    ULONG user_diroffset = get_winver();
    process_dirbase = *(uintptr_t *)((PUCHAR)pprocess + user_diroffset);
  }
  return process_dirbase;
}

// ============================================================================
// Page table translation (unchanged)
// ============================================================================

UINT64 translate_linearBE(UINT64 directoryTableBase, UINT64 virtualAddress) {
  directoryTableBase &= ~0xf;

  UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
  UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
  UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
  UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
  UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

  SIZE_T readsize = 0;
  UNREFERENCED_PARAMETER(&readsize); // passed to phys_read_pt_entry but not consumed locally
  UINT64 pdpe = 0;
  phys_read_pt_entry((UINT64)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe));
  if (~pdpe & 1)
    return 0;

  UINT64 pde = 0;
  phys_read_pt_entry((UINT64)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde));
  if (~pde & 1)
    return 0;

  /* 1GB large page, use pde's 12-34 bits */
  if (pde & 0x80)
    return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

  UINT64 pteAddr = 0;
  phys_read_pt_entry((UINT64)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr));
  if (~pteAddr & 1)
    return 0;

  /* 2MB large page */
  if (pteAddr & 0x80)
    return (pteAddr & (PMASK & ~0x1FFFFFull)) +
           (virtualAddress & ~(~0ull << 21));

  UINT64 pteValue = 0;
  phys_read_pt_entry((UINT64)((pteAddr & PMASK) + 8 * pte), &pteValue,
                     sizeof(pteValue));

  if (~pteValue & 1)
    return 0;

  virtualAddress = pteValue & PMASK;

  if (!virtualAddress)
    return 0;

  return virtualAddress + pageOffset;
}

ULONG64 find_min(INT32 g, SIZE_T f) {
  INT32 h = (INT32)f;
  ULONG64 result = 0;
  result = (((g) < (h)) ? (g) : (h));
  return result;
}

EXTERN_C int _fltused = 0;

// ============================================================================
// Core operations (adapted from original — security check removed for IPC)
// ============================================================================

// ============================================================================
// Request validation helpers
//
// These catch the cases that used to be the driver's fault: usermode can
// submit a malformed command and the driver must refuse it rather than
// bugchecking the system. Any command reaching do_read_write must pass
// all of these.
// ============================================================================

// Upper bound of user-mode canonical virtual address on x64.
// 0x7FFFFFFFFFFF = 0x00007FFF'FFFFFFFF. Anything >= 0x80000000'00000000 is
// either kernel space or non-canonical. Refuse both.
#define USER_VA_MAX 0x00007FFFFFFFFFFFULL

static BOOLEAN is_user_range(ULONGLONG addr, ULONGLONG size) {
  if (size == 0)
    return FALSE;
  if (addr == 0)
    return FALSE;
  if (addr > USER_VA_MAX)
    return FALSE;
  if (size > 0x10000000ULL)
    return FALSE; // 256 MB sanity cap
  // Overflow guard, then ensure end-1 is still user.
  ULONGLONG end_m1 = addr + size - 1;
  if (end_m1 < addr)
    return FALSE;
  if (end_m1 > USER_VA_MAX)
    return FALSE;
  return TRUE;
}

static BOOLEAN is_safe_target_pid(INT32 pid) {
  if (pid <= 0)
    return FALSE; // 0 = invalid, <0 = bogus
  if (pid == 4)
    return FALSE; // System
  return TRUE;
}

// ============================================================================
// CR3-swap single-page RW  (no KeStackAttachProcess, no KAPC_STATE trace)
//
// Trimmer-race mitigation — five-phase protocol
// -----------------------------------------------
// The fundamental stealth/safety trade-off vs. MDL:
//   MDL path  = MmProbeAndLockPages pins the PFN → RACE-FREE, but
//               KeStackAttachProcess leaves a detectable KAPC_STATE trace.
//   CR3 swap  = zero KAPC_STATE trace, but the trimmer on another core can
//               evict the target page → page fault at DISPATCH_LEVEL →
//               bugcheck (NOT memory corruption — worst case is a crash).
//
// We reduce the bugcheck risk to negligible via two PFN-database checks:
//
// Phase 3 — pre-swap: read pfninfo->u3.e1.PageLocation. A value of 6
//   (ActiveAndValid) means the page is still in a working set and the PTE
//   is still Present. If it's anything else, the trimmer has already begun
//   eviction and we bail before wasting time on the CR3 swap.
//
// Phase 5 — post-swap live PTE re-validation:
//   The PFN database field pfninfo->PteAddress holds the kernel virtual
//   address of the PTE that maps this physical page. Crucially, the kernel
//   virtual address space is SHARED across all Windows processes — after
//   __writecr3(target_cr3) ALL kernel VAs (PFN database, PT pages, driver
//   code) remain accessible because the target's kernel CR3 maps the same
//   system space as our own. So we can dereference pfninfo->PteAddress and
//   read the live PTE value the CPU hardware PT-walker would use.
//
//   If the Valid bit is 0, the trimmer has already marked the PTE
//   not-present; we restore the old CR3 and return STATUS_ACCESS_VIOLATION
//   instead of triggering a page fault.
//
//   If the Valid bit is 1, the copy runs immediately. The residual window
//   is ~5 instructions (~5-10 ns). The trimmer would need to evict the
//   page AND deliver a TLB-shootdown IPI to this core inside that window —
//   effectively impossible for actively-accessed game-process pages.
//
// Phase 3 is the cheap first filter (avoids the CR3 swap when the page is
// already gone). Phase 5 is the decisive gate right before the copy.
//
// Safety requirement: ONLY call with a kernel-mode CR3 that maps the
// driver's own kernel VAs. g_cr3_swap_capable is the gate enforced by
// do_read_write.
// ============================================================================

// PageLocation==6 means the page is in an active working set (PTE is Present).
#define MMPFN_PAGELOCATION_ACTIVE 6

static NTSTATUS rw_via_cr3_swap(UINT64 target_cr3, UINT64 va,
                                  SIZE_T offset_in_page, PVOID buffer,
                                  SIZE_T chunk, BOOLEAN is_write) {
  UINT64 page_va = va & ~0xFFFULL;

  // ── Phase 1: translate at PASSIVE_LEVEL ────────────────────────────────
  // Physical PT reads are always resident; this call cannot page-fault.
  // Capture the physical address so we can derive the PFN for phases 3 & 5.
  UINT64 pa = translate_linearBE(target_cr3, page_va);
  if (!pa)
    return STATUS_ACCESS_VIOLATION;

  UINT64 pfn = pa >> 12;

  // ── Phase 2: raise IRQL ────────────────────────────────────────────────
  // Prevents the trimmer from running on THIS core. Phase 5 handles the
  // case where it runs concurrently on another core.
  KIRQL old_irql;
  KeRaiseIrql(DISPATCH_LEVEL, &old_irql);

  // ── Phase 3: pre-swap PFN sanity check ────────────────────────────────
  // The PFN database is nonpaged — always accessible, any IRQL.
  // Skip the whole CR3 swap if the page has already left the active set.
  if (pml4::g_mmonp_MmPfnDatabase) {
    const _MMPFN* pfninfo = (const _MMPFN*)
        ((ULONG_PTR)pml4::g_mmonp_MmPfnDatabase + pfn * sizeof(_MMPFN));
    if (pfninfo->u3.e1.PageLocation != MMPFN_PAGELOCATION_ACTIVE) {
      KeLowerIrql(old_irql);
      return STATUS_ACCESS_VIOLATION;
    }
  }

  // ── Phase 4: CR3 swap ─────────────────────────────────────────────────
  // Clear PCID bits (0-11) so we do not activate a stale PCID from our own
  // context inside the target's address space.
  // Bit 63 (NOFLUSH) intentionally NOT set — full TLB flush is correct here
  // so no stale kernel TLB entries from our own CR3 pollute the target walk.
  UINT64 old_cr3 = __readcr3();
  __writecr3(target_cr3 & ~0xFFFULL);

  // ── Phase 5: live PTE re-validation under the target CR3 ──────────────
  // pfninfo->PteAddress is the kernel VA of the actual PTE for this PFN.
  // Page-table pages are nonpaged and the kernel VA space is identical
  // under the target's kernel CR3, so the dereference is safe at DISPATCH.
  // If the trimmer invalidated the PTE between Phase 1 and now, Valid == 0
  // and we bail before triggering a fault.
  if (pml4::g_mmonp_MmPfnDatabase) {
    const _MMPFN* pfninfo = (const _MMPFN*)
        ((ULONG_PTR)pml4::g_mmonp_MmPfnDatabase + pfn * sizeof(_MMPFN));
    const MMPTE* pte_va = pfninfo->PteAddress;
    // Mask the low nibble: some Windows versions encode a "swizzle" cookie in
    // the bottom bits of PteAddress. The PTE itself always starts on an 8-byte
    // boundary, so clearing bits [3:0] is always safe.
    pte_va = (const MMPTE*)((ULONG_PTR)pte_va & ~0xFULL);
    if (!pte_va || !(pte_va->u.Long & 1 /* Valid */)) {
      __writecr3(old_cr3);
      KeLowerIrql(old_irql);
      return STATUS_ACCESS_VIOLATION;
    }
  }

  // ── Phase 6: copy ─────────────────────────────────────────────────────
  // PTE is confirmed Present. Window to fault is ~5 instructions.
  if (is_write) {
    RtlCopyMemory((PUCHAR)(ULONG_PTR)(va + offset_in_page), buffer, chunk);
  } else {
    RtlCopyMemory(buffer, (PUCHAR)(ULONG_PTR)(va + offset_in_page), chunk);
  }

  // ── Phase 7: restore ──────────────────────────────────────────────────
  __writecr3(old_cr3);
  // Flush any TLB entry the copy loaded for the target VA so the restored
  // page tables cannot serve it after the CR3 switch back.
  __invlpg((PVOID)(ULONG_PTR)page_va);
  KeLowerIrql(old_irql);
  return STATUS_SUCCESS;
}

// Forward declarations — definitions live further down.  Both helpers operate
// on a single page-bounded chunk and use the MDL pipeline only (no IoSpace,
// no MmCopyMemory(PHYSICAL), no PTE swap).
static NTSTATUS write_via_proxy_pte(PEPROCESS process, UINT64 va,
                                    SIZE_T offset_in_page, PVOID buffer,
                                    SIZE_T chunk);
static NTSTATUS read_via_proxy_pte(PEPROCESS process, UINT64 va,
                                   SIZE_T offset_in_page, PVOID buffer,
                                   SIZE_T chunk);

// ============================================================================
// Expanded-stack callout — hides the MDL-fallback path from stack-walk scans.
//
// KeExpandKernelStackAndCalloutEx allocates a fresh kernel stack segment and
// invokes our callout on it.  When EAC/BE walks ETHREAD->Tcb.KernelStack, the
// frames leading to our driver live on the OLD stack segment and are NOT
// reachable via the current Tcb.StackBase/Tcb.StackLimit — they see only the
// clean chain: KeExpandKernelStackAndCalloutEx → our callout (on new stack)
// → the MDL helpers.  Since the callout entry is a legitimate ntoskrnl API
// frame, the scan sees nothing suspicious.
//
// IRQL note: KeExpandKernelStackAndCalloutEx documents that the callout
// runs at "the same IRQL as the caller" (typically PASSIVE_LEVEL for
// our IPC worker).  However, during the stack-switch handoff the IRQL
// may transiently be elevated.  We defensively KfLowerIrql to PASSIVE
// because MmProbeAndLockPages requires PASSIVE_LEVEL (≤APC_LEVEL).
//
// SEH note: The expanded-stack environment inherits the caller's SEH
// chain, but the EXCEPTION_REGISTRATION_RECORD sits on the new stack.
// We wrap the MDL helpers in __try/__except to catch any access
// violations from racing process teardown.
//
// DYNAMIC RESOLUTION: For KDU-mapped drivers, imports are resolved by the
// mapper at load time.  Some mappers do not resolve every single import,
// so we resolve KeExpandKernelStackAndCalloutEx via MmGetSystemRoutineAddress
// at init time and fall back to the direct MDL path if unavailable.
// ============================================================================

// Dynamically-resolved pointer to KeExpandKernelStackAndCalloutEx.
// Resolved once at DriverEntry via MmGetSystemRoutineAddress.
typedef NTSTATUS (NTAPI *fn_KeExpandKernelStackAndCalloutEx_t)(
    PVOID Callout, PVOID Parameter, SIZE_T Size, BOOLEAN Wait, PVOID Context);
static fn_KeExpandKernelStackAndCalloutEx_t g_pfnExpandStack = NULL;

//
// Parameter block passed by do_read_write to the expanded-stack callout.
// Must be non-paged (worker thread context guarantees this).
//
typedef struct _EXPANDED_RW_PARAMS {
    PEPROCESS   process;          // Target EPROCESS (referenced, caller releases)
    UINT64      va;               // Page-aligned start of this chunk
    SIZE_T      offset_in_page;   // Byte offset within the page
    PVOID       buffer;           // Kernel buffer for the data (non-paged)
    SIZE_T      chunk;            // Bytes to copy (≤ PAGE_SIZE, non-page-crossing)
    BOOLEAN     is_write;         // TRUE = write to target, FALSE = read
    NTSTATUS    result;           // [out] NTSTATUS from the MDL operation
} EXPANDED_RW_PARAMS, *PEXPANDED_RW_PARAMS;

//
// Size budget for KeExpandKernelStackAndCalloutEx:
//
// We request a stack expansion large enough to hold:
//   - EXCEPTION_REGISTRATION_RECORD (~0x30 bytes, plus alignment)
//   - Our EXPANDED_RW_PARAMS (already allocated in the caller's non-paged
//     pool — we only need stack space for the local pointers)
//   - The MDL helpers' worst-case stack usage:
//       KeStackAttachProcess        → ~0x80  (KAPC_STATE + locals)
//       IoAllocateMdl               → ~0xC0  (MDL struct + header)
//       MmProbeAndLockPages         → ~0x200 (probe path + PFN DB lookups)
//       MmMapLockedPagesSpecifyCache→ ~0x100
//       RtlCopyMemory               → ~0x40
//       Total MDL-path overhead     ≈ 0x500
//   - Conservative headroom         ≈ 0x200
//
// Grand total: ~0x4000 is exceedingly safe and matches common driver
// conventions for this API.  Smaller values (0x2000) also work in practice
// but 0x4000 covers future build variance.
//
#define EXPANDED_STACK_SIZE 0x4000

//
// Callout routine invoked by KeExpandKernelStackAndCalloutEx on the new stack.
// The 'Parameter' is a PEXPANDED_RW_PARAMS.
//
static VOID NTAPI ExpandedRwCallout(_In_ PVOID Parameter) {
    PEXPANDED_RW_PARAMS p = (PEXPANDED_RW_PARAMS)Parameter;
    if (!p) {
        return; // result stays uninitialised; caller treats as failure
    }

    // ── IRQL normalisation ─────────────────────────────────────────────
    // MmProbeAndLockPages requires PASSIVE_LEVEL (≤APC_LEVEL).
    // Although our caller runs at PASSIVE, the stack-switch machinery
    // may leave IRQL at APC_LEVEL.  We snapshot the current IRQL and
    // lower it unconditionally, then restore on the way out.
    KIRQL oldIrql = KeGetCurrentIrql();
    if (oldIrql > PASSIVE_LEVEL) {
        KeLowerIrql(PASSIVE_LEVEL);
    }

    // ── Dispatch to the MDL helper ─────────────────────────────────────
    __try {
        if (p->is_write) {
            p->result = write_via_proxy_pte(p->process, p->va,
                                            p->offset_in_page, p->buffer,
                                            p->chunk);
        } else {
            p->result = read_via_proxy_pte(p->process, p->va,
                                           p->offset_in_page, p->buffer,
                                           p->chunk);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        p->result = STATUS_ACCESS_VIOLATION;
    }

    // ── Restore IRQL ───────────────────────────────────────────────────
    // KeExpandKernelStackAndCalloutEx expects the callout to return at
    // the same IRQL as entry.  We restore to the original value.
    if (oldIrql > PASSIVE_LEVEL) {
        KfRaiseIrql(oldIrql);
    }
}

//
// Convenience wrapper: execute a single-page read or write through the
// expanded-stack callout.  Returns the NTSTATUS from the MDL operation.
//
// Falls back to direct MDL (no expanded stack) when:
//   - KeExpandKernelStackAndCalloutEx is not available (pre-Win10 RS2)
//   - The function pointer couldn't be resolved (KDU import issue)
//   - The expansion itself fails (low kernel stack memory)
//
__forceinline static NTSTATUS expanded_rw_wrapper(
    PEPROCESS process, UINT64 va, SIZE_T offset_in_page,
    PVOID buffer, SIZE_T chunk, BOOLEAN is_write)
{
    // If the expand-stack function was never resolved (pre-RS2 or KDU issue),
    // go straight to the direct MDL path. This preserves IPC functionality
    // at the cost of slightly reduced stealth on the fallback path.
    if (!g_pfnExpandStack) {
        NTSTATUS st;
        if (is_write) {
            st = write_via_proxy_pte(process, va, offset_in_page, buffer, chunk);
        } else {
            st = read_via_proxy_pte(process, va, offset_in_page, buffer, chunk);
        }
        return st;
    }

    EXPANDED_RW_PARAMS params;
    params.process       = process;
    params.va            = va;
    params.offset_in_page = offset_in_page;
    params.buffer        = buffer;
    params.chunk         = chunk;
    params.is_write      = is_write;
    params.result        = STATUS_UNSUCCESSFUL;

    NTSTATUS st = g_pfnExpandStack(
        ExpandedRwCallout,
        &params,
        EXPANDED_STACK_SIZE,
        TRUE,   // Wait = TRUE — block until stack expansion succeeds
        NULL    // Context (unused)
    );

    if (!NT_SUCCESS(st)) {
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] expanded_rw_wrapper: stack expansion failed "
                   "st=0x%X — falling back to direct MDL\n", st);
        // Fallback: call the MDL helpers directly without stack isolation.
        // This preserves IPC correctness when expansion is unavailable.
        if (is_write) {
            st = write_via_proxy_pte(process, va, offset_in_page, buffer, chunk);
        } else {
            st = read_via_proxy_pte(process, va, offset_in_page, buffer, chunk);
        }
        return st;
    }

    return params.result;
}

NTSTATUS do_read_write(INT32 process_id, ULONGLONG address, PVOID buffer,
                       ULONGLONG size, BOOLEAN is_write, BOOLEAN use_eac_cr3) {
  // -----------------------------------------------------------------
  // Hardened validation — refuse anything that could BSOD us.
  // -----------------------------------------------------------------
  if (!is_safe_target_pid(process_id))
    return STATUS_INVALID_PARAMETER;
  if (!buffer)
    return STATUS_INVALID_PARAMETER;
  if (!is_user_range(address, size))
    return STATUS_INVALID_PARAMETER;

  PEPROCESS process = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)process_id,
                                             &process)) ||
      !process)
    return STATUS_NOT_FOUND;

  // Reject processes that are already exiting. MmCopyVirtualMemory on a
  // torn-down target can raise in-page errors; short-circuit cleanly.
  if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
    ObDereferenceObject(process);
    return STATUS_PROCESS_IS_TERMINATING;
  }

  NTSTATUS ret;

  if (!use_eac_cr3) {
    // -------------------------------------------------------------
    // SAFE FAST PATH: MmCopyVirtualMemory.
    //
    // Previously even the non-CR3 path went through
    // translate_linearBE -> write() (proxy PTE swap). That carried
    // exactly the same core-migration / TLB-invalidate race as the
    // CR3 path and was responsible for the "throughput test BSODs"
    // observed during benchmarking. MmCopyVirtualMemory is the
    // documented kernel API for cross-process copies, handles probe
    // + lock + attach itself, and can be called safely at PASSIVE
    // from a system thread.
    //
    // We SEH-wrap regardless: a racing process exit can still cause
    // the copy to raise even after the exit-status check above.
    // -------------------------------------------------------------
    SIZE_T copied = 0;
    __try {
      if (is_write) {
        ret = MmCopyVirtualMemory(PsInitialSystemProcess, buffer, process,
                                  (PVOID)address, (SIZE_T)size, KernelMode,
                                  &copied);
      } else {
        ret =
            MmCopyVirtualMemory(process, (PVOID)address, PsInitialSystemProcess,
                                buffer, (SIZE_T)size, KernelMode, &copied);
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      ret = STATUS_ACCESS_VIOLATION;
    }

    if (NT_SUCCESS(ret) && copied != (SIZE_T)size)
      ret = STATUS_PARTIAL_COPY;

    ObDereferenceObject(process);
    return ret;
  }

  // -------------------------------------------------------------
  // CR3 path — bypasses MmCopyVirtualMemory for EAC-protected targets.
  //
  // When g_cr3_swap_capable == TRUE (kernel CR3 in physical::m_stored_dtb):
  //   rw_via_cr3_swap — swaps CR3 at DISPATCH_LEVEL, copies, restores.
  //   Zero KAPC_STATE change. No KeStackAttachProcess call.
  //
  // When g_cr3_swap_capable == FALSE (UserDTB on KPTI-enabled system):
  //   Falls back to write_via_proxy_pte / read_via_proxy_pte (MDL+attach).
  //
  // 'process' is kept alive for the MDL fallback path which needs the
  // PEPROCESS for KeStackAttachProcess. It is released at loop exit.
  // -------------------------------------------------------------
  uintptr_t process_dirbase = physical::m_stored_dtb;
  INT32 cached_pid = g_cr3_cached_pid;

  if (!process_dirbase) {
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] do_read_write: CR3 path requested but DTB not cached "
               "(call CMD_RESOLVE_DTB first)\n");
    ObDereferenceObject(process);
    return STATUS_INVALID_DEVICE_STATE;
  }

  // The cached DTB belongs to *one* process. If the caller switches
  // target without re-resolving, refuse rather than translate using
  // the wrong page tables — that would either fail (best) or succeed
  // against an unrelated process's memory (catastrophic).
  if (cached_pid != process_id) {
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] do_read_write: CR3 DTB cached for pid=%d but request "
               "is pid=%d (re-send CMD_RESOLVE_DTB)\n",
               cached_pid, process_id);
    ObDereferenceObject(process);
    return STATUS_INVALID_DEVICE_STATE;
  }

  SIZE_T remaining = (SIZE_T)size;
  UINT64 current_va = address;
  PUCHAR current_buf = (PUCHAR)buffer;

  while (remaining > 0) {
    SIZE_T offset_in_page = (SIZE_T)(current_va & 0xFFF);
    SIZE_T page_remaining = PAGE_SIZE - offset_in_page;
    SIZE_T chunk = (remaining < page_remaining) ? remaining : page_remaining;
    NTSTATUS status;

    if (g_cr3_swap_capable) {
      // ── Fast stealthy path: CR3 swap ─────────────────────────────────
      // Swaps the current CPU's CR3 to the target's kernel CR3 at
      // DISPATCH_LEVEL, copies the data, then restores the original CR3.
      // Leaves ZERO trace in KAPC_STATE — no KeStackAttachProcess call,
      // no APC_STATE change visible to PsGetCurrentProcess() checks.
      status = rw_via_cr3_swap(process_dirbase, current_va, offset_in_page,
                               current_buf, chunk, is_write);
    } else {
      // ── Fallback: MDL + attach (via expanded-stack callout) ──────────
      // Used when the stored DTB is a KPTI user-shadow CR3 (no kernel
      // mappings). KeStackAttachProcess is inherently detectable, but by
      // executing the attach + MDL pipeline on a fresh kernel stack via
      // KeExpandKernelStackAndCalloutEx, we ensure that a stack-walk scan
      // (EAC/BE walking ETHREAD->Tcb.KernelStack) sees only:
      //
      //   KeExpandKernelStackAndCalloutEx → ExpandedRwCallout → MDL helpers
      //
      // All of those frames are inside ntoskrnl.exe / our driver's new
      // stack segment.  The original stack segment (which contains the
      // IPC worker's caller chain into our unbacked driver) is no longer
      // the active Tcb.StackBase/Tcb.StackLimit and is invisible to
      // RtlVirtualUnwind.
      //
      // The callout internally lowers IRQL to PASSIVE_LEVEL before
      // invoking MmProbeAndLockPages and restores IRQL on exit.
      status = expanded_rw_wrapper(process, current_va, offset_in_page,
                                   current_buf, chunk, is_write);
    }

    if (!NT_SUCCESS(status)) {
      DbgPrintEx(
          0x4d, 0xffffffff,
          "[CR3-IPC] do_read_write FAIL: CR3 %s VA=0x%llx sz=%zu st=0x%X\n",
          is_write ? "W" : "R", current_va, chunk, status);
      ObDereferenceObject(process);
      return status;
    }

    remaining -= chunk;
    current_va += chunk;
    current_buf += chunk;
  }

  ObDereferenceObject(process);
  return STATUS_SUCCESS;
}

NTSTATUS do_get_base_address(INT32 process_id, ULONGLONG *out_address) {
  if (!process_id)
    return STATUS_UNSUCCESSFUL;

  PEPROCESS process = NULL;
  PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)process_id, &process);
  if (!process)
    return STATUS_UNSUCCESSFUL;

  ULONGLONG image_base = (ULONGLONG)SafePsGetProcessSectionBaseAddress(process);
  ObDereferenceObject(process);

  if (!image_base)
    return STATUS_UNSUCCESSFUL;

  *out_address = image_base;
  return STATUS_SUCCESS;
}

NTSTATUS do_resolve_dtb(INT32 process_id, ULONGLONG *out_dtb) {
  if (!process_id)
    return STATUS_UNSUCCESSFUL;

  PEPROCESS process = 0;
  PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)process_id, &process);
  if (!process)
    return STATUS_UNSUCCESSFUL;

  UINT64 section_base = (UINT64)SafePsGetProcessSectionBaseAddress(process);

  // Initialise the PFN database exactly once per boot. This is normally done
  // as a side-effect of dirbase_from_base_address() (Stage 3). We do it here
  // unconditionally so that rw_via_cr3_swap can use g_mmonp_MmPfnDatabase for
  // its post-swap PTE re-validation even when Stage 1 or Stage 2 succeeds and
  // the PFN scan is never reached.
  if (!pml4::g_mmonp_MmPfnDatabase)
    pml4::InitializeMmPfnDatabase();

  // Detect KPTI once per driver load.
  // On KPTI systems, UserDirectoryTableBase is a shadow CR3 (user mappings
  // only) and cannot be used in rw_via_cr3_swap which runs kernel code.
  // On KPTI-disabled systems (common on gaming hardware) both DTB fields hold
  // the same full CR3, so UserDirectoryTableBase is always safe to swap.
  static BOOLEAN kpti_checked = FALSE;
  if (!kpti_checked) {
    g_kpti_enabled = detect_kpti();
    kpti_checked   = TRUE;
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] KPTI detection: CR4.PCIDE=%d → g_kpti_enabled=%d\n",
               (int)g_kpti_enabled, (int)g_kpti_enabled);
  }

  // ── Stage 1: EPROCESS.DirectoryTableBase (offset 0x28) ─────────────────
  // This is the kernel-mode CR3. Always safe for rw_via_cr3_swap.
  uintptr_t dtb_stage1 = *(uintptr_t *)((PUCHAR)process + 0x28);
  if (dtb_stage1 && !is_cr3_invalid(dtb_stage1)) {
    UINT64 phys_check = translate_linearBE(dtb_stage1, section_base);
    if (phys_check) {
      physical::m_stored_dtb = dtb_stage1;
      g_cr3_swap_capable     = TRUE;   // kernel CR3 — full mappings guaranteed
      g_cr3_cached_pid       = process_id;
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] Stage1 DirectoryTableBase validated: 0x%llx\n",
                 dtb_stage1);
      ObDereferenceObject(process);
      *out_dtb = physical::m_stored_dtb;
      return STATUS_SUCCESS;
    }
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] Stage1 DTB 0x%llx failed translate — trying "
               "UserDirectoryTableBase\n", dtb_stage1);
  } else {
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] Stage1 DTB 0x%llx invalid/spoofed — trying "
               "UserDirectoryTableBase\n", dtb_stage1);
  }

  // ── Stage 2: EPROCESS.UserDirectoryTableBase ───────────────────────────
  // EAC often spoofs DirectoryTableBase but leaves UserDirectoryTableBase
  // untouched because the latter is read by the CPU's SWAPGS path and
  // corrupting it would kill the process. On KPTI-disabled systems this
  // field equals the real kernel CR3 — ideal. On KPTI-enabled systems it
  // is the user shadow CR3 (no kernel mappings), so we mark it as not swap-
  // capable and let rw_via_cr3_swap fall back to MDL+attach for that case.
  ULONG user_off = (ULONG)get_winver();
  if (user_off && user_off != 0x28) {
    uintptr_t dtb_stage2 = *(uintptr_t *)((PUCHAR)process + user_off);
    // Accept if non-zero, not obviously spoofed, page-aligned, and different
    // from the Stage 1 value we already failed (avoid re-testing the same CR3).
    if (dtb_stage2 && dtb_stage2 != dtb_stage1 &&
        !is_cr3_invalid(dtb_stage2) && !(dtb_stage2 & 0xFFF)) {
      UINT64 phys_check2 = translate_linearBE(dtb_stage2, section_base);
      if (phys_check2) {
        physical::m_stored_dtb = dtb_stage2;
        // Safe for CR3 swap only when KPTI is disabled (UserDTB == kernel CR3).
        g_cr3_swap_capable     = !g_kpti_enabled;
        g_cr3_cached_pid       = process_id;
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] Stage2 UserDirectoryTableBase validated: "
                   "0x%llx (swap_capable=%d)\n",
                   dtb_stage2, (int)g_cr3_swap_capable);
        ObDereferenceObject(process);
        *out_dtb = physical::m_stored_dtb;
        return STATUS_SUCCESS;
      }
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] Stage2 UserDTB 0x%llx failed translate — "
                 "falling back to PFN scan\n", dtb_stage2);
    }
  }

  // ── Stage 3: PFN scan (last resort) ────────────────────────────────────
  // Scans physical memory for the page whose PteFrame == itself — the
  // defining property of a PML4 root page — and validates it against the
  // process section base. The result is always the kernel-mode CR3.
  // The scan order is now randomised and paced (see CR3.h) to avoid a
  // detectable sequential-access spike. The result is cached in
  // physical::m_stored_dtb so subsequent calls skip this stage entirely
  // (the caller checks g_cr3_cached_pid before calling us).
  physical::m_stored_dtb =
      pml4::dirbase_from_base_address((void *)section_base);
  g_cr3_swap_capable = (physical::m_stored_dtb != 0);  // PFN scan → kernel CR3

  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] Stage3 PFN scan result: 0x%llx (swap_capable=%d)\n",
             physical::m_stored_dtb, (int)g_cr3_swap_capable);

  ObDereferenceObject(process);
  g_cr3_cached_pid = process_id;
  *out_dtb = physical::m_stored_dtb;
  return STATUS_SUCCESS;
}

NTSTATUS do_get_guarded_region(ULONGLONG *out_address) {
  ULONG infoLen = 0;
  NTSTATUS status =
      ZwQuerySystemInformation(SystemBigPoolInformation, &infoLen, 0, &infoLen);
  PSYSTEM_BIGPOOL_INFORMATION pPoolInfo = 0;

  while (status == STATUS_INFO_LENGTH_MISMATCH) {
    if (pPoolInfo)
      ExFreePool(pPoolInfo);

    pPoolInfo =
        (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, infoLen);
    if (!pPoolInfo)
      break;
    status = ZwQuerySystemInformation(SystemBigPoolInformation, pPoolInfo,
                                      infoLen, &infoLen);
  }

  if (pPoolInfo) {
    for (unsigned int i = 0; i < pPoolInfo->Count; i++) {
      SYSTEM_BIGPOOL_ENTRY *Entry = &pPoolInfo->AllocatedInfo[i];
      PVOID VirtualAddress;
      VirtualAddress = (PVOID)((uintptr_t)Entry->VirtualAddress & ~1ull);
      SIZE_T SizeInBytes = Entry->SizeInBytes;
      BOOLEAN NonPaged = Entry->NonPaged;

      if (NonPaged && SizeInBytes == 0x200000) {
        if (Entry->TagUlong == 'TnoC') {
          *out_address = (ULONGLONG)VirtualAddress;
          ExFreePool(pPoolInfo);
          return STATUS_SUCCESS;
        }
      }
    }

    ExFreePool(pPoolInfo);
  }

  return STATUS_UNSUCCESSFUL;
}

// ============================================================================
// ObReferenceObjectByName declaration (for mouse.cpp compatibility)
// ============================================================================

extern "C" {
NTSYSCALLAPI
NTSTATUS
ObReferenceObjectByName(__in PUNICODE_STRING ObjectName, __in ULONG Attributes,
                        __in_opt PACCESS_STATE AccessState,
                        __in_opt ACCESS_MASK DesiredAccess,
                        __in POBJECT_TYPE ObjectType,
                        __in KPROCESSOR_MODE AccessMode,
                        __inout_opt PVOID ParseContext, __out PVOID *Object);
}
extern "C" POBJECT_TYPE *IoDriverObjectType;
extern "C" POBJECT_TYPE *PsThreadType;

// NtQueryInformationThread — we use this instead of ZwQueryInformationThread
// because the latter may not be declared in all WDK versions.
extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength);

// ============================================================================
// IPC Thread: Process discovery + command polling
// ============================================================================

static volatile BOOLEAN g_ipc_thread_running = TRUE;
static HANDLE g_ipc_thread_handle = NULL;

// ---------------------------------------------------------------------------
// Shutdown / teardown plumbing.
//
// The driver is manually mapped (no DriverEntry / DriverUnload). When the
// loader's probe issues CMD_SHUTDOWN we need to orderly tear down:
//
//   1) Stop accepting new IPC work.
//   2) Wait for every worker that is *currently* touching the shared IPC
//      buffer to finish (otherwise MmUnmapLockedPages races the worker's
//      `mem->slots[i]` access → use-after-free → BSOD).
//   3) Only then unmap + unlock the MDL and drop the target-process ref.
//   4) After every worker + the discovery thread has fully exited, clean up
//      the per-core proxy PTE mappings and pool allocations.
//
// A rundown protects any access to g_kernel_ipc_mem / g_test_process. A
// worker acquires at the top of its loop iteration and releases at the
// bottom; the discovery thread calls ExWaitForRundownProtectionRelease +
// ExReInitializeRundownProtection around every IPC-memory teardown (both
// the mid-loop "target process died" path and the final shutdown path),
// so nobody can dereference a freed mapping or a dead EPROCESS.
//
// Thread handles are kept so the supervisor (the entry thread) can wait
// for every spawned thread to actually exit before freeing the proxy
// pages — those pages are referenced by write() which can still be on
// a worker's stack until PsTerminateSystemThread unwinds.
//
// Worker-count rationale
// ----------------------
// We used to spawn 4 workers on the theory that multi-slotted concurrent
// IPC needed multiple service threads. In practice that created two
// problems that together produced the "~32 ms floor + page-fault BSOD
// after the 1024 sweep" symptom:
//
//   1. Latency floor. Each worker hot-spins for ~65k PAUSE iterations
//      before yielding. On modern CPUs (Skylake+) PAUSE is ~140 cycles,
//      so that's ~2.3 ms of spin per worker. All 4 workers drift into
//      yielding around the same wall-clock window, and once they do,
//      the scheduler has to wait for some OTHER thread's quantum to
//      expire (~15-20 ms) before it reschedules a worker. The RTT of
//      the benchmark then converges on two full timer ticks — exactly
//      the ~32 ms observed.
//
//   2. Concurrency pressure on the same slot. The single-threaded
//      benchmark only ever arms slot 0. With 4 workers all sweeping
//      slot 0 in a loop, every arm is followed by a winner-take-all
//      CAS race; the three losing workers spin right next to the
//      winner's MmCopyVirtualMemory call, stealing cache lines out
//      from under it and preempting each other on every rundown
//      acquire/release. That's the stress pattern that lines up with
//      the page-fault bugcheck at the 1024→4096 size transition — the
//      copy path itself is fine, but the surrounding contention is
//      exactly the kind of load that makes any remaining sharp edge
//      in the slot state machine actually hit.
//
// Both go away by dropping to a single worker. The multi-thread
// throughput benchmark (opts.test_multi) is opt-in and not the mode
// the user is running, so serializing the default path is the right
// trade. If we ever need real concurrency back, revisit — but with
// a per-worker slot affinity, not 4 workers sweeping every slot.
// ---------------------------------------------------------------------------
#define IPC_WORKER_COUNT 1

static EX_RUNDOWN_REF g_ipc_rundown;
static PETHREAD g_worker_threads[IPC_WORKER_COUNT] = {NULL};
static PETHREAD g_discovery_thread = NULL;

// Code cave descriptor — populated during DriverEntry by CreateSpoofedSystemThread.
// Referenced by the CMD_STEALTH_STATUS, CMD_CAVE_INFO, and CMD_THREAD_VALIDATE handlers.
CODE_CAVE g_thread_cave = {};

// ---------------------------------------------------------------------------
// Teardown serialization.
//
// teardown_ipc_mapping_locked() can be called from the discovery thread's
// polling loop when it detects the target process has exited. The mutex
// serializes concurrent invocations if the loop fires multiple times
// before teardown completes.
//
// NOTE: PsSetCreateProcessNotifyRoutine was REMOVED. Registering a
// callback from a KDU-mapped driver exposes the callback address to
// PatchGuard's periodic validation of the PspCreateProcessNotifyRoutine
// array. Since the address doesn't belong to any loaded module,
// PatchGuard flags it as CRITICAL_STRUCTURE_CORRUPTION (0x109). The
// polling discovery thread alone (100ms cadence) is sufficient to catch
// process exit and unlock the MDL before PROCESS_HAS_LOCKED_PAGES.
// ---------------------------------------------------------------------------
static FAST_MUTEX g_teardown_mutex;

// NOTE: ExSetTimerResolution was REMOVED. Like PsSetCreateProcessNotifyRoutine,
// calling it from a KDU-mapped driver creates orphaned kernel state that
// PatchGuard can flag. The usermode benchmark already calls timeBeginPeriod(1)
// which achieves the same 1ms timer resolution from the user side.

//
// Find a process by image name by walking the EPROCESS ActiveProcessLinks list.
// Returns the EPROCESS pointer (caller must dereference), or NULL.
// SEH-wrapped: if a process exits while we're mid-traversal,
// list_entry->Flink can point at freed memory. Without SEH this
// produces a PAGE_FAULT_IN_NONPAGED_AREA bugcheck.
//
// Forward declaration needed for the new merged function
static UINT64 find_ipc_buffer(PEPROCESS process);

static PEPROCESS find_process_by_name(const char *process_name) {
  PEPROCESS current_process = PsInitialSystemProcess;
  if (!current_process)
    return NULL;

  ULONG apl_off = get_active_process_links_offset();
  if (!apl_off) return NULL;

  PEPROCESS result = NULL;

  __try {
    PLIST_ENTRY list_head =
        (PLIST_ENTRY)((PUCHAR)current_process + apl_off);
    PLIST_ENTRY list_entry = list_head->Flink;

    while (list_entry != list_head) {
      PEPROCESS process = (PEPROCESS)((PUCHAR)list_entry - apl_off);

      PUCHAR image_name = SafePsGetProcessImageFileName(process);
      if (image_name) {
        // Case-insensitive comparison
        bool match = true;
        const char *a = (const char *)image_name;
        const char *b = process_name;
        while (*a && *b) {
          char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
          char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
          if (ca != cb) {
            match = false;
            break;
          }
          a++;
          b++;
        }
        // Match if we hit end of both strings, or if image_name is truncated
        if (match && (*a == '\0' || *b == '\0')) {
          if (PsGetProcessExitStatus(process) == STATUS_PENDING) {
            ObfReferenceObject(process);
            result = process;
            break;
          }
        }
      }

      list_entry = list_entry->Flink;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] find_process_by_name: SEH caught 0x%X\n",
               GetExceptionCode());
    result = NULL;
  }

  return result;
}

//
// Iterates all processes, finds any that match our target names, and immediately
// scans them for the IPC buffer. Returns the first process that ACTUALLY has
// the IPC buffer, preventing legitimate game instances from "shadowing" the
// hollowed cheat instance.
//
static PEPROCESS find_target_process_with_ipc(UINT64* out_ipc_va) {
  PEPROCESS current_process = PsInitialSystemProcess;
  if (!current_process)
    return NULL;

  PEPROCESS result = NULL;
  UINT64     result_ipc_va = 0;
  int        result_priority = -1; // Lower index in target_names = higher priority
  *out_ipc_va = 0;

  // We check an array of target names so the generic driver can find the
  // hollowed cheat regardless of which host process the loader used.
  //
  // PRIORITY: The index in this array determines attachment priority.
  // Lower index = higher priority. scootware.exe (index 0) is always
  // preferred over scootware-loader.exe (index 1) when both have a
  // live IPC buffer. This prevents the driver from re-attaching to the
  // loader when the main EXE is present, while still allowing re-attach
  // to the loader after the main EXE exits.
  const char* target_names[] = {
      IPC_TARGET_PROCESS,           // [0] The main cheat EXE (scootware.exe) — HIGHEST PRIORITY
      "scootware-loader.exe",       // [1] Loader hosts a transient IPC during bring-up
                                    //     and again after the main EXE exits.
      "cs2.exe",                    // [2] Game host processes (same priority bracket)
      "RustClient.exe",
      "EscapeFromTarkov.exe",
      "Marvel-Win64-Shipping.exe",
      "Bodycam.exe",
      "Bodycam-Win64-Shipping.exe"
  };
  const int num_targets = sizeof(target_names) / sizeof(target_names[0]);

  ULONG apl_off = get_active_process_links_offset();
  if (!apl_off) return NULL;

  __try {
    PLIST_ENTRY list_head =
        (PLIST_ENTRY)((PUCHAR)current_process + apl_off);
    PLIST_ENTRY list_entry = list_head->Flink;

    while (list_entry != list_head) {
      PEPROCESS process = (PEPROCESS)((PUCHAR)list_entry - apl_off);

      PUCHAR image_name = SafePsGetProcessImageFileName(process);
      if (image_name) {
        int matched_priority = -1;

        // EPROCESS->ImageFileName is UCHAR[15]. The kernel does NOT
        // guarantee a null terminator within those 15 bytes for image
        // names whose basename is >= 15 chars (e.g. "scootware-loader.exe"
        // = 20 chars; truncated copy of "scootware-loade" fills all 15
        // slots with no '\0'). The previous matcher walked while *a is
        // non-zero, which read past the buffer for those names — the
        // result depended on undefined adjacent EPROCESS bytes, which
        // is exactly why the driver intermittently failed to attach to
        // the loader on the same machine across runs.
        //
        // Bounded match: never read past byte 14 of image_name. Compare
        // case-insensitively up to MIN(15, strlen(target)). Accept as a
        // hit if either:
        //   * we walked the whole target and the next byte of image_name
        //     is '\0' or we hit byte 15 (truncation), OR
        //   * the image_name (<=14 chars + '\0') equals the target as a
        //     normal C-string compare.
        const int IMAGE_FILE_NAME_MAX = 15;

        for (int i = 0; i < num_targets; i++) {
          // Short-circuit: if we already have a best candidate at a higher
          // priority than i, no point checking lower-priority names.
          if (result_priority >= 0 && i >= result_priority)
            break;

          const char *img = (const char *)image_name;
          const char *tgt = target_names[i];
          int n = 0;
          bool mismatch = false;
          while (n < IMAGE_FILE_NAME_MAX && tgt[n] != '\0') {
            char ca = img[n];
            if (ca == '\0') break;             // image_name terminated early
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
            char cb = tgt[n];
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
            if (ca != cb) { mismatch = true; break; }
            n++;
          }
          if (mismatch) continue;

          // Accept either:
          //   - target fully consumed AND image_name terminator-or-end
          //     (n == 15 covers the truncated case where bytes 0..14 of
          //      image_name match the first 15 bytes of target)
          //   - image_name terminated within bounds AND target is also
          //     done at the same point
          bool target_done = (tgt[n] == '\0');
          // Windows may null-terminate the 15-byte ImageFileName at index 14,
          // meaning a long name like "scootware-loader.exe" will only have 14
          // matching characters before hitting the '\0'. We treat n=14 + null
          // as a truncation match just like n=15.
          bool image_truncated = (n == IMAGE_FILE_NAME_MAX || (n == IMAGE_FILE_NAME_MAX - 1 && img[n] == '\0'));
          bool image_terminated = (n < IMAGE_FILE_NAME_MAX && img[n] == '\0');

          if (image_truncated || (target_done && image_terminated)) {
            matched_priority = i;
            break;
          }
        }

        if (matched_priority >= 0) {
          // Only consider this candidate if it beats our current best.
          if (result_priority < 0 || matched_priority < result_priority) {
            if (PsGetProcessExitStatus(process) == STATUS_PENDING) {
              UINT64 ipc_va = find_ipc_buffer(process);
              if (ipc_va) {
                // Release any previously-held reference before taking the new one.
                if (result) {
                  ObDereferenceObject(result);
                  result = NULL;
                  result_ipc_va = 0;
                }
                ObfReferenceObject(process);
                result           = process;
                result_ipc_va    = ipc_va;
                result_priority  = matched_priority;

                // Highest-priority target (index 0 = scootware.exe) found
                // with a live IPC buffer — no need to scan further.
                if (matched_priority == 0)
                  break;
              }
            }
          }
        }
      }

      list_entry = list_entry->Flink;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] find_target_process_with_ipc: SEH caught 0x%X during "
               "ActiveProcessLinks walk\n",
               GetExceptionCode());
    // Release any reference we may have taken before the exception.
    if (result) {
      ObDereferenceObject(result);
      result = NULL;
      result_ipc_va = 0;
    }
  }

  *out_ipc_va = result_ipc_va;
  return result;
}

//
// Read memory from a target process using its CR3 (physical read).
// Used to read the IPC buffer from the test program.
//
static NTSTATUS read_process_memory(PEPROCESS process, UINT64 virtual_address,
                                    PVOID buffer, SIZE_T size) {
  // IPC-buffer discovery read.  No more translate_linearBE → MmCopyMemory(PA)
  // here — the read goes through the same MDL pipeline as the data plane so
  // there is exactly one read mechanism in the driver.  Walking page-bounded
  // chunks lets read_via_proxy_pte stay single-page like the data-plane
  // helpers expect.
  SIZE_T remaining = size;
  UINT64 current_va = virtual_address;
  PUCHAR current_buf = (PUCHAR)buffer;

  while (remaining > 0) {
    SIZE_T offset_in_page = (SIZE_T)(current_va & 0xFFF);
    SIZE_T page_remaining = PAGE_SIZE - offset_in_page;
    SIZE_T chunk = (remaining < page_remaining) ? remaining : page_remaining;

    NTSTATUS status = read_via_proxy_pte(process, current_va, offset_in_page,
                                         current_buf, chunk);
    if (!NT_SUCCESS(status))
      return status;

    current_va += chunk;
    current_buf += chunk;
    remaining -= chunk;
  }

  return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// write_via_proxy_pte – race-free single-page physical write.
//
// Races fixed vs. the MmMapIoSpaceEx approach:
//
//   Trimmer race   – MmProbeAndLockPages increments the target PFN's share
//                    count before we inspect it.  The working-set trimmer
//                    cannot reclaim a page with a non-zero share count, so
//                    the PFN is stable for the entire duration of the copy.
//
//   Migration race – Raising IRQL to DISPATCH_LEVEL prevents the scheduler
//                    from migrating the current thread to another processor.
//                    The proxy PTE and __invlpg are therefore always executed
//                    on the core that owns g_proxy_pte[core], so no remote
//                    TLB can hold a stale mapping for the proxy VA after the
//                    invalidation.
//
//   No per-write IoSpace mapping – the only IoSpace mapping in the system is
//                    the one-time g_mapped_pt page (the PT page) created by
//                    InitProxyPage.  That constant mapping does not produce a
//                    new MAP_REGION PFN-database trace per write.
//
// Falls back to MmMapLockedPagesSpecifyCache (no IoSpace tag) when the
// proxy is not initialised for the current core.
//
// va             – user virtual address of the byte to write (may be unaligned)
// offset_in_page – va & 0xFFF
// buffer         – kernel VA of source data; must be in non-paged memory
// chunk          – bytes to copy; must not cross a page boundary
// ---------------------------------------------------------------------------
static NTSTATUS write_via_proxy_pte(PEPROCESS process, UINT64 va,
                                    SIZE_T offset_in_page, PVOID buffer,
                                    SIZE_T chunk) {
  // ---- Phase 1: Pin the target physical page (IRQL <= APC_LEVEL) ----------
  //
  // Attach to the target process so MmProbeAndLockPages probes the user VA
  // in the correct address space.  We can detach before the kernel-VA copy
  // because the MDL holds the PFN reference independently of context.
  KAPC_STATE apc_state;
  KeStackAttachProcess(process, &apc_state);

  PMDL mdl = IoAllocateMdl((PVOID)va, (ULONG)chunk, FALSE, FALSE, NULL);
  if (!mdl) {
    KeUnstackDetachProcess(&apc_state);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  NTSTATUS phase1 = STATUS_SUCCESS;
  __try {
    MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    phase1 = STATUS_ACCESS_VIOLATION;
  }

  KeUnstackDetachProcess(&apc_state);

  if (!NT_SUCCESS(phase1)) {
    IoFreeMdl(mdl);
    return phase1;
  }

  // ---- Phase 2: MmMapLockedPagesSpecifyCache → memcpy → unmap -------------
  //
  // Plain kernel VA mapping; no IoSpace tag, no PT-page hijack.
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID kmapped = MmMapLockedPagesSpecifyCache(
      mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
  if (kmapped) {
    __try {
      RtlCopyMemory((PUCHAR)kmapped + offset_in_page, buffer, chunk);
      status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      status = STATUS_ACCESS_VIOLATION;
    }
    MmUnmapLockedPages(kmapped, mdl);
  }

  MmUnlockPages(mdl);
  IoFreeMdl(mdl);
  return status;
}

// ---------------------------------------------------------------------------
// read_via_proxy_pte – race-free single-page physical read.
//
// Mirror of write_via_proxy_pte for the read direction.  Locks the target
// user page via MmProbeAndLockPages (so the trimmer cannot reclaim the
// PFN underneath us), maps it into kernel VA space with
// MmMapLockedPagesSpecifyCache, copies out the bytes, and unlocks.
//
// The function is named "via_proxy_pte" purely for symmetry with the write
// path; no PTE swap or proxy mapping is performed.
// ---------------------------------------------------------------------------
static NTSTATUS read_via_proxy_pte(PEPROCESS process, UINT64 va,
                                   SIZE_T offset_in_page, PVOID buffer,
                                   SIZE_T chunk) {
  KAPC_STATE apc_state;
  KeStackAttachProcess(process, &apc_state);

  PMDL mdl = IoAllocateMdl((PVOID)va, (ULONG)chunk, FALSE, FALSE, NULL);
  if (!mdl) {
    KeUnstackDetachProcess(&apc_state);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  NTSTATUS phase1 = STATUS_SUCCESS;
  __try {
    MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    phase1 = STATUS_ACCESS_VIOLATION;
  }

  KeUnstackDetachProcess(&apc_state);

  if (!NT_SUCCESS(phase1)) {
    IoFreeMdl(mdl);
    return phase1;
  }

  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PVOID kmapped = MmMapLockedPagesSpecifyCache(
      mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
  if (kmapped) {
    __try {
      RtlCopyMemory(buffer, (PUCHAR)kmapped + offset_in_page, chunk);
      status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      status = STATUS_ACCESS_VIOLATION;
    }
    MmUnmapLockedPages(kmapped, mdl);
  }

  MmUnlockPages(mdl);
  IoFreeMdl(mdl);
  return status;
}

//
// Write memory to a target process using its virtual address.
// Delegates to write_via_proxy_pte for each page-bounded chunk; see that
// function for the full race analysis.  No per-page IoSpace mapping is
// created (contrast with the old translate_linearBE -> write(PA) path).
//
static NTSTATUS write_process_memory(PEPROCESS process, UINT64 virtual_address,
                                     PVOID buffer, SIZE_T size) {
  SIZE_T remaining = size;
  UINT64 current_va = virtual_address;
  PUCHAR current_buf = (PUCHAR)buffer;

  while (remaining > 0) {
    SIZE_T offset_in_page = (SIZE_T)(current_va & 0xFFF);
    SIZE_T page_remaining = PAGE_SIZE - offset_in_page;
    SIZE_T chunk = (remaining < page_remaining) ? remaining : page_remaining;

    NTSTATUS status = write_via_proxy_pte(process, current_va, offset_in_page,
                                          current_buf, chunk);
    if (!NT_SUCCESS(status))
      return status;

    current_va += chunk;
    current_buf += chunk;
    remaining -= chunk;
  }

  return STATUS_SUCCESS;
}

//
// Scan the test program's memory for our magic value.
// We get the base address of the process and scan only its image memory.
//
static UINT64 find_ipc_buffer(PEPROCESS process) {
  // PEB->ImageBaseAddress (PEB+0x10) is the authoritative base for the
  // *running* image. When a process is hollowed (RunPE), the loader patches
  // PEB+0x10 to the payload's allocation base BEFORE resuming the thread,
  // but EPROCESS->SectionObject (which PsGetProcessSectionBaseAddress reads)
  // still points at the original hollow shell on disk.
  // Using PEB+0x10 means the scan targets the payload's actual pages.
  UINT64 image_base = 0;
  PVOID peb = SafePsGetProcessPeb(process);
  if (peb) {
    UINT64 peb_image_base = 0;
    SIZE_T copied = 0;
    // PEB64->ImageBaseAddress is at offset 0x10.
    NTSTATUS peb_st = MmCopyVirtualMemory(
        process, (PVOID)((UINT64)peb + 0x10),
        PsInitialSystemProcess, &peb_image_base,
        sizeof(peb_image_base), KernelMode, &copied);
    if (NT_SUCCESS(peb_st) && copied == sizeof(peb_image_base) && peb_image_base)
      image_base = peb_image_base;
  }

  // Fall back to the section base for non-hollowed (normally loaded) processes
  // where PEB->ImageBaseAddress == section base anyway.
  if (!image_base)
    image_base = (UINT64)SafePsGetProcessSectionBaseAddress(process);

  if (!image_base)
    return 0;

  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] find_ipc_buffer: scanning from image_base=0x%llx "
             "(PEB-derived=%s)\n",
             image_base, peb ? "yes" : "no");

  // Read the PE headers via MmCopyVirtualMemory — this handles demand-paged
  // pages correctly (unlike translate_linearBE which returns 0 for PTEs that
  // are not yet present).
  IMAGE_DOS_HEADER dos_header = {0};
  SIZE_T hdr_copied = 0;
  NTSTATUS hdr_st = MmCopyVirtualMemory(
      process, (PVOID)image_base,
      PsInitialSystemProcess, &dos_header,
      sizeof(dos_header), KernelMode, &hdr_copied);
  if (!NT_SUCCESS(hdr_st) || hdr_copied != sizeof(dos_header))
    return 0;

  if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  IMAGE_NT_HEADERS64 nt_headers = {0};
  hdr_st = MmCopyVirtualMemory(
      process, (PVOID)(image_base + dos_header.e_lfanew),
      PsInitialSystemProcess, &nt_headers,
      sizeof(nt_headers), KernelMode, &hdr_copied);
  if (!NT_SUCCESS(hdr_st) || hdr_copied != sizeof(nt_headers))
    return 0;

  if (nt_headers.Signature != IMAGE_NT_SIGNATURE)
    return 0;

  UINT32 size_of_image = nt_headers.OptionalHeader.SizeOfImage;

  // ── Section-table-driven scan ─────────────────────────────────────────
  //
  // The IPC buffer is a static __declspec(align(4096)) global, placed by
  // the linker in a writable data section (.data, .bss).
  //
  // For SMALL images (SizeOfImage ≤ 8 MiB): scan EVERY page.  Brute-force
  // but guaranteed to find the buffer regardless of section layout, linker
  // quirks, or merged sections.  The IPC test programs and the loader are
  // all well under 8 MiB even with static CRT + ImGui linked in.
  //
  // For LARGE images (> 8 MiB): walk the PE section table and only scan
  // writable sections.  This avoids scanning 400+ MiB of game code.
  //
  // Fallback: if section-table parsing fails, scan the last 1 MiB.
  // ──────────────────────────────────────────────────────────────────────
  const UINT64 SMALL_IMAGE_THRESHOLD = 0x800000ULL; // 8 MiB

  if (size_of_image <= SMALL_IMAGE_THRESHOLD) {
    // Small image — brute-force scan every page. Safe because the total
    // number of pages is ≤ 2048 (8 MiB / 4 KiB).
    for (UINT64 addr = image_base;
         addr + 8 <= image_base + size_of_image;
         addr += 0x1000) {
      UINT64 magic_check = 0;
      SIZE_T bytes_read = 0;
      NTSTATUS status = MmCopyVirtualMemory(
          process, (PVOID)addr,
          PsInitialSystemProcess, &magic_check,
          sizeof(magic_check), KernelMode, &bytes_read);
      if (NT_SUCCESS(status) && bytes_read == sizeof(magic_check) &&
          magic_check == IPC_MAGIC) {
        UINT32 version_check = 0;
        status = MmCopyVirtualMemory(
            process, (PVOID)(addr + 8),
            PsInitialSystemProcess, &version_check,
            sizeof(version_check), KernelMode, &bytes_read);
        if (NT_SUCCESS(status) && bytes_read == sizeof(version_check) &&
            version_check == IPC_VERSION) {
          DbgPrintEx(0x4d, 0xffffffff,
                     "[CR3-IPC] Found IPC buffer (small-image full scan) at "
                     "VA: 0x%llx (Offset: 0x%llX)\n",
                     addr, addr - image_base);
          return addr;
        }
      }
    }
    return 0; // small image scanned completely, nothing found
  }
  USHORT num_sections = nt_headers.FileHeader.NumberOfSections;
  if (num_sections > 0 && num_sections <= 128) {
    // Read section headers from the target process.
    // Section headers immediately follow the optional header.
    UINT64 sec_offset = image_base + dos_header.e_lfanew +
                        sizeof(IMAGE_NT_HEADERS64);
    IMAGE_SECTION_HEADER sec_hdr = {0};
    BOOLEAN found_writable = FALSE;

    for (USHORT i = 0; i < num_sections; i++) {
      UINT64 sec_addr = sec_offset + (UINT64)i * sizeof(IMAGE_SECTION_HEADER);
      SIZE_T sec_copied = 0;
      hdr_st = MmCopyVirtualMemory(
          process, (PVOID)sec_addr,
          PsInitialSystemProcess, &sec_hdr,
          sizeof(sec_hdr), KernelMode, &sec_copied);
      if (!NT_SUCCESS(hdr_st) || sec_copied != sizeof(sec_hdr))
        continue;

      // IPC buffer is writable — skip code (.text) and read-only sections.
      if (!(sec_hdr.Characteristics & IMAGE_SCN_MEM_WRITE))
        continue;

      found_writable = TRUE;
      UINT32 sec_va = sec_hdr.VirtualAddress;
      UINT32 sec_sz = sec_hdr.Misc.VirtualSize;
      if (sec_sz == 0)
        sec_sz = sec_hdr.SizeOfRawData;
      if (sec_sz == 0 || sec_sz > size_of_image)
        continue;

      // Clamp to SizeOfImage bounds.
      if ((UINT64)sec_va + sec_sz > size_of_image)
        sec_sz = size_of_image - sec_va;

      // Scan this section page by page.
      UINT64 sec_start = image_base + sec_va;
      UINT64 sec_end   = sec_start + sec_sz;

      for (UINT64 addr = (sec_start + 0xFFF) & ~0xFFFULL; // page-align up
           addr + 8 <= sec_end;
           addr += 0x1000) {
        UINT64 magic_check = 0;
        SIZE_T bytes_read = 0;
        NTSTATUS status = MmCopyVirtualMemory(
            process, (PVOID)addr,
            PsInitialSystemProcess, &magic_check,
            sizeof(magic_check), KernelMode, &bytes_read);
        if (NT_SUCCESS(status) && bytes_read == sizeof(magic_check) &&
            magic_check == IPC_MAGIC) {
          UINT32 version_check = 0;
          status = MmCopyVirtualMemory(
              process, (PVOID)(addr + 8),
              PsInitialSystemProcess, &version_check,
              sizeof(version_check), KernelMode, &bytes_read);
          if (NT_SUCCESS(status) && bytes_read == sizeof(version_check) &&
              version_check == IPC_VERSION) {
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] Found IPC buffer in section %u at VA: "
                       "0x%llx (Offset: 0x%llX)\n",
                       i, addr, addr - image_base);
            return addr;
          }
        }
      }
    }

    if (found_writable) {
      // Scanned all writable sections — no IPC buffer found.
      // Don't fall through to the full-scan fallback.
      return 0;
    }
  }

  // ── Fallback: scan last 256 pages (1 MiB) of image ────────────────────
  // Reached only when the section table is corrupt/unparseable or no
  // writable sections exist. Covers the .bss tail of small images.
  {
    UINT64 fallback_limit = (UINT64)size_of_image;
    UINT64 fallback_start = (fallback_limit > 0x100000ULL)
                                ? (fallback_limit - 0x100000ULL)
                                : 0;
    fallback_start = (fallback_start + 0xFFF) & ~0xFFFULL; // page-align up

    for (UINT64 addr = image_base + fallback_start;
         addr < image_base + fallback_limit;
         addr += 0x1000) {
      UINT64 magic_check = 0;
      SIZE_T bytes_read = 0;
      NTSTATUS status = MmCopyVirtualMemory(
          process, (PVOID)addr,
          PsInitialSystemProcess, &magic_check,
          sizeof(magic_check), KernelMode, &bytes_read);
      if (NT_SUCCESS(status) && bytes_read == sizeof(magic_check) &&
          magic_check == IPC_MAGIC) {
        UINT32 version_check = 0;
        status = MmCopyVirtualMemory(
            process, (PVOID)(addr + 8),
            PsInitialSystemProcess, &version_check,
            sizeof(version_check), KernelMode, &bytes_read);
        if (NT_SUCCESS(status) && bytes_read == sizeof(version_check) &&
            version_check == IPC_VERSION) {
          DbgPrintEx(0x4d, 0xffffffff,
                     "[CR3-IPC] Found IPC buffer via tail scan at VA: "
                     "0x%llx (Offset: 0x%llX)\n",
                     addr, addr - image_base);
          return addr;
        }
      }
    }
  }

  return 0;
}

//
// Process a single IPC command from the shared buffer.
//

static volatile PIPC_MEMORY g_kernel_ipc_mem = NULL;
static PMDL g_ipc_mdl = NULL;
static PEPROCESS g_test_process = NULL;

// Aligned scalar copy of the target PID. Read lock-free from the process
// exit notify callback to avoid dereferencing g_test_process (which could
// be mid-teardown on another thread). On x64, an aligned pointer-sized
// read is atomic, so a plain volatile read is sufficient.
static volatile HANDLE g_target_pid = NULL;

// Set to TRUE when the client sends CMD_SHUTDOWN.  The discovery thread
// checks this flag after tearing down a session and self-shuts-down
// instead of re-scanning for a new target.  This replaces the old
// g_ipc_ever_established one-shot logic, which was broken: the
// DriverBringup probe is also named "scootware.exe" and carries
// IPC_MAGIC, so the driver would latch onto it, establish a session,
// and then self-destruct when the probe exited — before the actual
// speed test / cheat ever had a chance to connect.
static volatile BOOLEAN g_shutdown_requested = FALSE;

// ── SpoofThunk globals (referenced by spoof_thunk.asm) ──────────────────────
// g_SpoofedTarget: The real Nt*/Zw* function pointer to call.
// g_SpoofedGadget:  A RET (0xC3) instruction inside ntoskrnl.exe .text that
//                   serves as the fake return address for stack traces.
// Both are resolved in DriverEntry after the discovery thread starts.
extern "C" {
    PVOID g_SpoofedTarget = NULL;
    PVOID g_SpoofedGadget = NULL;
}

// RET gadget in ntoskrnl.exe .text — used by syscall_stack_spoof.h and
// the stealth-status diagnostics.  Populated by FindRetGadget() at init.
PVOID g_ret_gadget_ntos = NULL;

// ── Deterministic handoff hint ───────────────────────────────────────────────
// Set by CMD_HANDOFF from the loader. The loader scans the cheat PE buffer in
// its own address space to locate IPC_MAGIC, then tells the driver exactly
// where the cheat's IPC buffer lives before calling LoaderIpc::Release().
// The discovery thread consumes these on the next teardown and establishes the
// cheat session directly without a full EPROCESS walk + page scan.
// Writes are done under g_teardown_mutex from the worker; reads are from the
// discovery thread with the mutex held or immediately after teardown.
static volatile UINT32 g_handoff_pid    = 0;   // cheat's Windows PID
static volatile UINT64 g_handoff_ipc_va = 0;   // VA of IPC_MEMORY in cheat's AS

static void process_ipc_command_slot(PIPC_MEMORY mem, int slot_idx) {
  PIPC_SLOT slot = &mem->slots[slot_idx];
  UINT32 command = slot->command;
  UINT32 target_pid = slot->process_id;

  NTSTATUS result = STATUS_UNSUCCESSFUL;
  UINT32 final_status = STATUS_IPC_ERROR;

  switch (command) {
  case CMD_READ_MEMORY: {
    UINT64 target_address = slot->cmd_data.rw.target_address;
    UINT64 buffer_size = slot->cmd_data.rw.buffer_size;
    BOOLEAN use_cr3 = (BOOLEAN)slot->cmd_data.rw.use_cr3;

    // Reject obviously-bogus sizes up front. The per-slot data
    // buffer is IPC_SLOT_DATA_SIZE; anything larger is malformed.
    if (buffer_size == 0 || buffer_size > IPC_SLOT_DATA_SIZE)
      break;

    result = do_read_write(target_pid, target_address, slot->data_buffer,
                           buffer_size, FALSE, use_cr3);
    if (NT_SUCCESS(result))
      final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_WRITE_MEMORY: {
    UINT64 target_address = slot->cmd_data.rw.target_address;
    UINT64 buffer_size = slot->cmd_data.rw.buffer_size;
    BOOLEAN use_cr3 = (BOOLEAN)slot->cmd_data.rw.use_cr3;

    if (buffer_size == 0 || buffer_size > IPC_SLOT_DATA_SIZE)
      break;

    result = do_read_write(target_pid, target_address, slot->data_buffer,
                           buffer_size, TRUE, use_cr3);
    if (NT_SUCCESS(result))
      final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_GET_BASE_ADDRESS: {
    ULONGLONG base_addr = 0;
    result = do_get_base_address(target_pid, &base_addr);
    if (NT_SUCCESS(result)) {
      slot->cmd_data.result.result = base_addr;
      final_status = STATUS_IPC_SUCCESS;
    }
    break;
  }

  case CMD_GET_PEB: {
    ULONGLONG peb_addr = 0;
    if (target_pid) {
      PEPROCESS process = NULL;
      PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)target_pid, &process);
      if (process) {
        peb_addr = (ULONGLONG)SafePsGetProcessPeb(process);
        ObDereferenceObject(process);
      }
    }
    if (peb_addr) {
      slot->cmd_data.result.result = peb_addr;
      final_status = STATUS_IPC_SUCCESS;
    }
    break;
  }

  case CMD_GET_MODULE: {
    UINT32 name_len = slot->cmd_data.module.name_len;
    if (!name_len || name_len > 256 || !target_pid) {
      slot->cmd_data.module.result = 0;
      final_status = STATUS_IPC_SUCCESS;
      break;
    }

    WCHAR mod_name[257] = {0};
    memcpy(mod_name, slot->data_buffer, name_len * sizeof(WCHAR));
    mod_name[name_len] = L'\0';

    PEPROCESS target = NULL;
    NTSTATUS lookup_status =
        PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)target_pid, &target);
    if (!NT_SUCCESS(lookup_status) || !target) {
      slot->cmd_data.module.result = 0;
      final_status = STATUS_IPC_SUCCESS;
      break;
    }

    UINT64 found_base = 0;
    auto vm_read = [&](UINT64 src_va, PVOID dst, SIZE_T sz) -> bool {
      if (!src_va || !dst || !sz)
        return false;
      SIZE_T copied = 0;
      NTSTATUS st =
          MmCopyVirtualMemory(target, (PVOID)src_va, PsInitialSystemProcess,
                              dst, sz, KernelMode, &copied);
      return NT_SUCCESS(st) && copied == sz;
    };

    UINT64 peb_addr = (UINT64)SafePsGetProcessPeb(target);
    if (peb_addr) {
      UINT64 ldr_addr = 0;
      if (vm_read(peb_addr + 0x18, &ldr_addr, sizeof(ldr_addr)) && ldr_addr) {
        UINT16 ldr_name_offset = 0x58;
        UINT16 ldr_base_offset = 0x30;
        UINT64 list_head = ldr_addr + 0x10;
        UINT64 current_entry = 0;

        if (vm_read(list_head, &current_entry, sizeof(current_entry))) {
          int safety = 0;
          while (current_entry && current_entry != list_head &&
                 safety++ < 512) {
            UINT64 dll_base = 0;
            if (!vm_read(current_entry + ldr_base_offset, &dll_base,
                         sizeof(dll_base))) {
              UINT64 next = 0;
              if (!vm_read(current_entry, &next, sizeof(next)))
                break;
              current_entry = next;
              continue;
            }

            UINT16 name_len_bytes = 0;
            UINT64 name_buf_ptr = 0;
            if (vm_read(current_entry + ldr_name_offset, &name_len_bytes,
                        sizeof(name_len_bytes)) &&
                vm_read(current_entry + ldr_name_offset + 0x08, &name_buf_ptr,
                        sizeof(name_buf_ptr))) {

              if (dll_base && name_buf_ptr && name_len_bytes > 0 &&
                  name_len_bytes <= 512) {
                WCHAR entry_name[257] = {0};
                UINT16 chars = name_len_bytes / sizeof(WCHAR);
                if (chars > 256)
                  chars = 256;

                if (vm_read(name_buf_ptr, entry_name, chars * sizeof(WCHAR))) {
                  entry_name[chars] = L'\0';
                  if (chars == name_len) {
                    bool match = true;
                    for (UINT16 i = 0; i < chars && match; i++) {
                      WCHAR a = entry_name[i], b = mod_name[i];
                      if (a >= L'A' && a <= L'Z')
                        a += 32;
                      if (b >= L'A' && b <= L'Z')
                        b += 32;
                      if (a != b)
                        match = false;
                    }
                    if (match) {
                      found_base = dll_base;
                      break;
                    }
                  }
                }
              }
            }
            UINT64 next = 0;
            if (!vm_read(current_entry, &next, sizeof(next)))
              break;
            current_entry = next;
          }
        }
      }
    }
    ObDereferenceObject(target);

    slot->cmd_data.module.result = found_base;
    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_RESOLVE_DTB: {
    ULONGLONG dtb_val = 0;
    result = do_resolve_dtb(target_pid, &dtb_val);
    if (NT_SUCCESS(result)) {
      slot->cmd_data.result.result = dtb_val;
      slot->cr3_cached = dtb_val;
      final_status = STATUS_IPC_SUCCESS;
    }
    break;
  }

  case CMD_GET_GUARDED_REGION: {
    ULONGLONG guarded_addr = 0;
    result = do_get_guarded_region(&guarded_addr);
    if (NT_SUCCESS(result)) {
      slot->cmd_data.result.result = guarded_addr;
      final_status = STATUS_IPC_SUCCESS;
    }
    break;
  }

  case CMD_MOUSE_MOVE: {
    mouse::mouse_move(slot->cmd_data.mouse.x, slot->cmd_data.mouse.y,
                      slot->cmd_data.mouse.button_flags);
    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_INJECT_DLL: {
    UINT64 target_p = slot->cmd_data.inject.target_pid;
    UINT32 dll_size = slot->cmd_data.inject.dll_size;

    if (target_p > 0 && dll_size > 0 && dll_size <= MM_MAX_DLL_SIZE) {
      PVOID kernel_dll_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, dll_size, 'LLiD');
      if (kernel_dll_buffer && g_test_process) {
        NTSTATUS read_status = read_process_memory(
            g_test_process, slot->cmd_data.inject.dll_usermode_ptr,
            kernel_dll_buffer, dll_size);
        if (NT_SUCCESS(read_status)) {
          PVOID mapped_address = NULL;
          NTSTATUS map_status = ManualMapper::MapDllIntoProcess(
              (HANDLE)(ULONG_PTR)target_p, kernel_dll_buffer, dll_size,
              &mapped_address);

          if (NT_SUCCESS(map_status)) {
            slot->cmd_data.result.result = (UINT64)mapped_address;
            final_status = STATUS_IPC_SUCCESS;
          }
        }
        ExFreePool(kernel_dll_buffer);
      }
    }
    break;
  }

  case CMD_GET_PID: {
    if (slot->cmd_data.pid.name_len > 0 && slot->cmd_data.pid.name_len < 256) {
      char proc_name[257] = {0};
      memcpy(proc_name, slot->data_buffer, slot->cmd_data.pid.name_len);
      proc_name[slot->cmd_data.pid.name_len] = '\0';

      PEPROCESS target = find_process_by_name(proc_name);
      if (target) {
        slot->cmd_data.pid.result_pid =
            (UINT32)(ULONG_PTR)PsGetProcessId(target);
        ObDereferenceObject(target);
        final_status = STATUS_IPC_SUCCESS;
      } else {
        slot->cmd_data.pid.result_pid = 0;
        final_status = STATUS_IPC_SUCCESS;
      }
    }
    break;
  }

  case CMD_ALLOCATE: {
    if (is_safe_target_pid((INT32)target_pid)) {
      PEPROCESS target = NULL;
      if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)target_pid,
                                                &target))) {
        KAPC_STATE apc_state;
        KeStackAttachProcess(target, &apc_state);

        PVOID base = (PVOID)slot->cmd_data.alloc.address;
        SIZE_T size = (SIZE_T)slot->cmd_data.alloc.size;

        NTSTATUS status = ZwAllocateVirtualMemory(
            NtCurrentProcess(), &base, 0, &size,
            slot->cmd_data.alloc.allocation_type, slot->cmd_data.alloc.protect);

        if (!NT_SUCCESS(status) && slot->cmd_data.alloc.address) {
          base = NULL;
          size = (SIZE_T)slot->cmd_data.alloc.size;
          status = ZwAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                           slot->cmd_data.alloc.allocation_type,
                                           slot->cmd_data.alloc.protect);
        }

        if (NT_SUCCESS(status) && base && size) {
          if ((slot->cmd_data.alloc.allocation_type & MEM_COMMIT) &&
              !(slot->cmd_data.alloc.protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            SIZE_T pages = (size + 0xFFF) / 0x1000;
            volatile UCHAR *p = (volatile UCHAR *)base;
            for (SIZE_T i = 0; i < pages; i++) {
              __try {
                p[i * 0x1000] = 0;
              } __except (EXCEPTION_EXECUTE_HANDLER) {
              }
            }
          }
        }

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(target);

        if (NT_SUCCESS(status)) {
          slot->cmd_data.alloc.result = (UINT64)base;
          final_status = STATUS_IPC_SUCCESS;
        }
      }
    }
    break;
  }

  case CMD_FREE: {
    if (is_safe_target_pid((INT32)target_pid)) {
      PEPROCESS target = NULL;
      if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)target_pid,
                                                &target))) {
        KAPC_STATE apc_state;
        KeStackAttachProcess(target, &apc_state);

        PVOID base = (PVOID)slot->cmd_data.free.address;
        SIZE_T size = 0;

        NTSTATUS status = ZwFreeVirtualMemory(NtCurrentProcess(), &base, &size,
                                              slot->cmd_data.free.free_type);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(target);

        if (NT_SUCCESS(status))
          final_status = STATUS_IPC_SUCCESS;
      }
    }
    break;
  }

  // ============================================================================
  // HWID Spoofer commands
  // ============================================================================

  case CMD_HWID_SAVE: {
    NTSTATUS st = HWIDSpoofer::SaveOriginal();
    if (NT_SUCCESS(st)) {
      final_status = STATUS_IPC_SUCCESS;
    }
    DbgPrintEx(0x4d, 0xffffffff, "[HWID-IPC] CMD_HWID_SAVE: status=0x%X\n", st);
    break;
  }

  case CMD_HWID_SPOOF: {
    // Auto-init: ensure originals captured before we apply spoof
    if (HWIDSpoofer::GetState() == HWID_STATE::HWID_STATE_UNINITIALIZED) { HWIDSpoofer::SaveOriginal(); }
    UINT32 components = slot->cmd_data.hwid_cmd.components;
    UINT64 seed       = slot->cmd_data.hwid_cmd.random_seed;
    if (!components) components = HWID_COMPONENT_ALL;

    NTSTATUS st = HWIDSpoofer::ApplySpoof(components, seed);
    if (NT_SUCCESS(st)) {
      final_status = STATUS_IPC_SUCCESS;
    }
    DbgPrintEx(0x4d, 0xffffffff, "[HWID-IPC] CMD_HWID_SPOOF: comp=0x%X seed=0x%llX st=0x%X\n",
               components, seed, st);
    break;
  }

  case CMD_HWID_RESTORE: {
    // Auto-init: ensure originals captured first
    if (HWIDSpoofer::GetState() == HWID_STATE::HWID_STATE_UNINITIALIZED) { HWIDSpoofer::SaveOriginal(); }
    NTSTATUS st = HWIDSpoofer::RestoreOriginals();
    if (NT_SUCCESS(st)) {
      final_status = STATUS_IPC_SUCCESS;
    }
    DbgPrintEx(0x4d, 0xffffffff, "[HWID-IPC] CMD_HWID_RESTORE: status=0x%X\n", st);
    break;
  }

  case CMD_HWID_REROLL: {
    // Auto-init: ensure originals captured before reroll
    if (HWIDSpoofer::GetState() == HWID_STATE::HWID_STATE_UNINITIALIZED) { HWIDSpoofer::SaveOriginal(); }
    UINT32 components = slot->cmd_data.hwid_cmd.components;
    if (!components) components = HWID_COMPONENT_ALL;

    NTSTATUS st = HWIDSpoofer::Reroll(components);
    if (NT_SUCCESS(st)) {
      final_status = STATUS_IPC_SUCCESS;
    }
    DbgPrintEx(0x4d, 0xffffffff, "[HWID-IPC] CMD_HWID_REROLL: comp=0x%X st=0x%X\n",
               components, st);
    break;
  }

  case CMD_HWID_STATUS: {
    // Auto-init so status returns real data even without prior SAVE cmd.
    if (HWIDSpoofer::GetState() == HWID_STATE::HWID_STATE_UNINITIALIZED) { HWIDSpoofer::SaveOriginal(); }

    slot->cmd_data.hwid_cmd.state  = (UINT32)HWIDSpoofer::GetState();
    slot->cmd_data.hwid_cmd.active = HWIDSpoofer::IsActive() ? 1 : 0;

    // Copy current HWID data into the slot's data buffer
    IPC_HWID_DATA* hwid_buf = (IPC_HWID_DATA*)slot->data_buffer;
    RtlZeroMemory(hwid_buf, sizeof(IPC_HWID_DATA));

    HWID_DATA current_hwid = {};
    if (NT_SUCCESS(HWIDSpoofer::GetCurrentData(&current_hwid))) {
      memcpy(hwid_buf->smbios_uuid,             current_hwid.smbios_uuid, 16);
      memcpy(hwid_buf->smbios_system_serial,    current_hwid.smbios_system_serial, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->smbios_baseboard_serial, current_hwid.smbios_baseboard_serial, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->smbios_chassis_serial,   current_hwid.smbios_chassis_serial, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->smbios_system_sku,       current_hwid.smbios_system_sku, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->machine_guid,            current_hwid.machine_guid, HWID_MAX_GUID_LEN);
      memcpy(hwid_buf->volume_serial,           current_hwid.volume_serial, HWID_MAX_VOLUME_LEN);
      memcpy(hwid_buf->mac_address,             current_hwid.mac_address, HWID_MAX_MAC_LEN);
      hwid_buf->timestamp          = current_hwid.timestamp;
      hwid_buf->components_present = current_hwid.components_present;
    }
    slot->cmd_data.hwid_cmd.components = hwid_buf->components_present;

    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_HWID_LOAD: {
    // Load custom HWID data from usermode buffer and apply directly
    IPC_HWID_DATA* hwid_buf = (IPC_HWID_DATA*)slot->data_buffer;
    
    // Convert IPC_HWID_DATA -> kernel HWID_DATA
    HWID_DATA loaded_hwid = {};
    memcpy(loaded_hwid.smbios_uuid,             hwid_buf->smbios_uuid, 16);
    memcpy(loaded_hwid.smbios_system_serial,    hwid_buf->smbios_system_serial, HWID_MAX_SERIAL_LEN);
    memcpy(loaded_hwid.smbios_baseboard_serial, hwid_buf->smbios_baseboard_serial, HWID_MAX_SERIAL_LEN);
    memcpy(loaded_hwid.smbios_chassis_serial,   hwid_buf->smbios_chassis_serial, HWID_MAX_SERIAL_LEN);
    memcpy(loaded_hwid.smbios_system_sku,       hwid_buf->smbios_system_sku, HWID_MAX_SERIAL_LEN);
    memcpy(loaded_hwid.machine_guid,            hwid_buf->machine_guid, HWID_MAX_GUID_LEN);
    memcpy(loaded_hwid.volume_serial,           hwid_buf->volume_serial, HWID_MAX_VOLUME_LEN);
    memcpy(loaded_hwid.mac_address,             hwid_buf->mac_address, HWID_MAX_MAC_LEN);
    loaded_hwid.timestamp          = hwid_buf->timestamp;
    loaded_hwid.components_present = hwid_buf->components_present;

    // Determine which components to apply
    UINT32 comp = slot->cmd_data.hwid_cmd.components;
    if (!comp) comp = loaded_hwid.components_present;
    if (!comp) comp = HWID_COMPONENT_ALL;

    // Save original first if not already done
    if (HWIDSpoofer::GetState() == HWID_STATE::HWID_STATE_UNINITIALIZED) {
      HWIDSpoofer::SaveOriginal();
    }

    // Apply the custom values using the new ApplyCustom API
    // This directly patches physical memory with the usermode-provided data
    // instead of generating random spoof values.
    NTSTATUS st = HWIDSpoofer::ApplyCustom(&loaded_hwid, comp);
    if (NT_SUCCESS(st)) {
      final_status = STATUS_IPC_SUCCESS;
    }
    DbgPrintEx(0x4d, 0xffffffff, "[HWID-IPC] CMD_HWID_LOAD: comp=0x%X st=0x%X\n",
               comp, st);
    break;
  }

  case CMD_HWID_GET_ORIGINAL: {
    IPC_HWID_DATA* hwid_buf = (IPC_HWID_DATA*)slot->data_buffer;
    RtlZeroMemory(hwid_buf, sizeof(IPC_HWID_DATA));

    HWID_DATA orig_hwid = {};
    if (NT_SUCCESS(HWIDSpoofer::GetOriginalData(&orig_hwid))) {
      memcpy(hwid_buf->smbios_uuid,             orig_hwid.smbios_uuid, 16);
      memcpy(hwid_buf->smbios_system_serial,    orig_hwid.smbios_system_serial, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->smbios_baseboard_serial, orig_hwid.smbios_baseboard_serial, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->smbios_chassis_serial,   orig_hwid.smbios_chassis_serial, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->smbios_system_sku,       orig_hwid.smbios_system_sku, HWID_MAX_SERIAL_LEN);
      memcpy(hwid_buf->machine_guid,            orig_hwid.machine_guid, HWID_MAX_GUID_LEN);
      memcpy(hwid_buf->volume_serial,           orig_hwid.volume_serial, HWID_MAX_VOLUME_LEN);
      memcpy(hwid_buf->mac_address,             orig_hwid.mac_address, HWID_MAX_MAC_LEN);
      hwid_buf->timestamp          = orig_hwid.timestamp;
      hwid_buf->components_present = orig_hwid.components_present;
    }

    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_PING: {
    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_SHUTDOWN: {
    // Signal that the driver should self-destruct when the current
    // session ends.  We do NOT set g_ipc_thread_running = FALSE here
    // because the worker must stay alive long enough to write the
    // STATUS_IPC_SUCCESS acknowledgement back to the slot — otherwise
    // the usermode send_command spin-wait times out and the caller
    // (e.g. the speed test's "Unload Driver" button) reports failure.
    //
    // The discovery thread checks g_shutdown_requested after every
    // session teardown and after every idle scan cycle, and exits
    // when it sees it.
    g_shutdown_requested = TRUE;
    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_HANDOFF: {
    // Loader pre-announces the cheat's PID and IPC buffer VA so the
    // driver can bypass the blind EPROCESS scan on handoff.
    //
    // Validation:
    //   * target_pid must be a live, non-privileged process
    //   * ipc_va must be in user-mode canonical range
    //
    // We do NOT try to map or probe the VA here — the cheat may not
    // have armed its IPC buffer yet (it's still in CRT init). The
    // discovery thread will perform the actual MmProbeAndLockPages
    // when it consumes this hint after the loader exits.
    UINT32 hint_pid = slot->cmd_data.handoff.target_pid;
    UINT64 hint_va  = slot->cmd_data.handoff.ipc_va;

    // Basic sanity: non-zero, user-space address, valid-looking PID.
    if (hint_pid > 4 && hint_va != 0 &&
        hint_va < 0x00007FFFFFFFFFFFull &&
        (hint_va & 0xFFF) == 0) { // must be page-aligned (IPC_MEMORY is __declspec(align(4096)))

      PEPROCESS hint_proc = NULL;
      NTSTATUS hint_st = PsLookupProcessByProcessId(
          (HANDLE)(ULONG_PTR)hint_pid, &hint_proc);

      if (NT_SUCCESS(hint_st) && hint_proc) {
        if (PsGetProcessExitStatus(hint_proc) == STATUS_PENDING) {
          // Store atomically. The discovery thread reads these after
          // tearing down the loader session (under g_teardown_mutex).
          InterlockedExchange((volatile LONG *)&g_handoff_pid, (LONG)hint_pid);
          InterlockedExchange64((LONG64 *)&g_handoff_ipc_va, (LONG64)hint_va);
          final_status = STATUS_IPC_SUCCESS;
          DbgPrintEx(0x4d, 0xffffffff,
                     "[CR3-IPC] CMD_HANDOFF: hint stored pid=%u va=0x%llx\n",
                     hint_pid, hint_va);
        } else {
          DbgPrintEx(0x4d, 0xffffffff,
                     "[CR3-IPC] CMD_HANDOFF: target pid=%u is already exiting — "
                     "ignoring hint\n", hint_pid);
        }
        ObDereferenceObject(hint_proc);
      } else {
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] CMD_HANDOFF: PsLookupProcessByProcessId(pid=%u) "
                   "failed 0x%X\n", hint_pid, hint_st);
      }
    } else {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] CMD_HANDOFF: bad params pid=%u va=0x%llx\n",
                 hint_pid, hint_va);
    }
    break;
  }

  // ─── Stealth validation / diagnostics commands ──────────────────────

  case CMD_STEALTH_STATUS: {
    // Populate full diagnostic snapshot into the slot's data buffer.
    IPC_STEALTH_STATUS* diag = (IPC_STEALTH_STATUS*)slot->data_buffer;
    RtlZeroMemory(diag, sizeof(IPC_STEALTH_STATUS));

    // ── Thread spoofing status ──────────────────────────────────────
    // CODE_CAVE is defined in thread_spoof.h; we reference the global
    // g_thread_cave set during DriverEntry after cave discovery.
    // Since thread_spoof.h hasn't been included yet, we use extern.
    extern CODE_CAVE g_thread_cave;
    diag->thread_spoof_active = g_thread_cave.is_valid ? 1 : 0;
    diag->cave_address        = (UINT64)(ULONG_PTR)g_thread_cave.cave_address;
    diag->cave_module_base    = (UINT64)(ULONG_PTR)g_thread_cave.module_base;
    diag->cave_size           = (UINT32)g_thread_cave.cave_size;
    if (g_thread_cave.cave_address && g_thread_cave.cave_size >= 5) {
      SIZE_T copySz = (g_thread_cave.cave_size < 8) ? g_thread_cave.cave_size : 8;
      memcpy(diag->cave_patch_bytes, g_thread_cave.cave_address, copySz);
    }

    // ── Stack isolation ────────────────────────────────────────────
    extern PVOID g_ret_gadget_ntos;
    diag->stack_isolation_active  = (g_ret_gadget_ntos != nullptr) ? 1 : 0;
    diag->ret_gadget_address      = (UINT64)(ULONG_PTR)g_ret_gadget_ntos;
    diag->ret_gadget_module_base  = (UINT64)(ULONG_PTR)GetSystemModuleBase("ntoskrnl.exe");
    diag->expanded_stack_size     = EXPANDED_STACK_SIZE;

    // ── KPTI / CR3 mode ───────────────────────────────────────────
    diag->kpti_enabled      = g_kpti_enabled ? 1 : 0;
    diag->cr3_swap_capable  = g_cr3_swap_capable ? 1 : 0;
    if (g_cr3_swap_capable) {
      diag->cr3_mode = 0;
    } else if (g_ret_gadget_ntos) {
      diag->cr3_mode = 2;
    } else {
      diag->cr3_mode = 1;
    }

    // ── SSN info ──────────────────────────────────────────────────
    extern ULONG g_NtFreeVirtualMemorySSN;
    diag->ntfvm_ssn           = g_NtFreeVirtualMemorySSN;
    diag->ssn_resolved_dynamic = (g_NtFreeVirtualMemorySSN > 0) ? 1 : 0;

    // ── General driver state ───────────────────────────────────────
    diag->worker_count    = IPC_WORKER_COUNT;
    diag->discovery_active = (g_discovery_thread != NULL) ? 1 : 0;
    diag->target_attached  = (saved_process != NULL) ? 1 : 0;
    diag->target_pid       = (UINT32)(saved_process ? g_cr3_cached_pid : 0);
    diag->target_cr3       = physical::m_stored_dtb;
    if (saved_process) {
      diag->target_base = (UINT64)(ULONG_PTR)SafePsGetProcessSectionBaseAddress(saved_process);
      PUCHAR pname = SafePsGetProcessImageFileName(saved_process);
      if (pname) {
        SIZE_T n = 0;
        while (n < STEALTH_MAX_NAME_LEN - 1 && pname[n]) {
          diag->target_name[n] = pname[n]; n++;
        }
      }
    }

    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_RW_CYCLE_TEST: {
    IPC_RW_CYCLE_RESULT* rwResult = (IPC_RW_CYCLE_RESULT*)slot->data_buffer;
    RtlZeroMemory(rwResult, sizeof(IPC_RW_CYCLE_RESULT));

    INT32 test_pid = (saved_process && g_cr3_cached_pid) ? g_cr3_cached_pid : 0;
    if (test_pid == 0) {
      rwResult->mode_used = 0xFF;
      final_status = STATUS_IPC_SUCCESS;
      break;
    }

    PEPROCESS targetProc = NULL;
    NTSTATUS lookupSt = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)test_pid, &targetProc);
    if (!NT_SUCCESS(lookupSt) || !targetProc) {
      rwResult->mode_used = 0xFF;
      final_status = STATUS_IPC_SUCCESS;
      break;
    }

    KAPC_STATE apcSt;
    KeStackAttachProcess(targetProc, &apcSt);
    PVOID testAddr = NULL;
    SIZE_T allocSz = PAGE_SIZE;
    NTSTATUS allocSt = ZwAllocateVirtualMemory(NtCurrentProcess(), &testAddr, 0,
                                                &allocSz, MEM_COMMIT, PAGE_READWRITE);
    KeUnstackDetachProcess(&apcSt);

    if (!NT_SUCCESS(allocSt) || !testAddr) {
      ObDereferenceObject(targetProc);
      rwResult->mode_used = 0xFF;
      final_status = STATUS_IPC_SUCCESS;
      break;
    }

    rwResult->test_address = (UINT64)(ULONG_PTR)testAddr;
    UINT64 maxTest = (UINT64)IPC_SLOT_DATA_SIZE;
    if (maxTest > (UINT64)PAGE_SIZE) maxTest = (UINT64)PAGE_SIZE;
    rwResult->test_size    = (UINT32)maxTest;

    UINT8 pattern[IPC_SLOT_DATA_SIZE];
    for (UINT32 i = 0; i < rwResult->test_size; i++)
      pattern[i] = (UINT8)(((UINT64)testAddr + i * 0x9D) & 0xFF);

    rwResult->mode_used = g_cr3_swap_capable ? 0 : (g_ret_gadget_ntos ? 1 : 2);

    // Write
    LARGE_INTEGER freq;
    KeQueryPerformanceCounter(&freq);
    NTSTATUS wSt = do_read_write(test_pid, (ULONGLONG)(ULONG_PTR)testAddr,
                                  pattern, rwResult->test_size, TRUE, TRUE);
    LARGE_INTEGER t1;
    KeQueryPerformanceCounter(&t1);
    rwResult->write_success = NT_SUCCESS(wSt) ? 1 : 0;
    rwResult->write_latency_ns = (t1.QuadPart - freq.QuadPart) * 100ULL;

    // Read
    UINT8 readback[IPC_SLOT_DATA_SIZE] = {};
    LARGE_INTEGER t2;
    KeQueryPerformanceCounter(&t2);
    NTSTATUS rSt = do_read_write(test_pid, (ULONGLONG)(ULONG_PTR)testAddr,
                                  readback, rwResult->test_size, FALSE, TRUE);
    LARGE_INTEGER t3;
    KeQueryPerformanceCounter(&t3);
    rwResult->read_success = NT_SUCCESS(rSt) ? 1 : 0;
    rwResult->read_latency_ns = (t3.QuadPart - t2.QuadPart) * 100ULL;

    rwResult->data_match = (memcmp(pattern, readback, rwResult->test_size) == 0) ? 1 : 0;
    UINT32 copyPat = (rwResult->test_size < 16) ? rwResult->test_size : 16;
    memcpy(rwResult->written_pattern, pattern, copyPat);
    memcpy(rwResult->readback_pattern, readback, copyPat);

    // Cleanup
    KeStackAttachProcess(targetProc, &apcSt);
    SIZE_T freeSz = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &testAddr, &freeSz, MEM_RELEASE);
    KeUnstackDetachProcess(&apcSt);
    ObDereferenceObject(targetProc);

    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_THREAD_VALIDATE: {
    PETHREAD curThread = PsGetCurrentThread();
    IPC_RESULT_DATA* r = (IPC_RESULT_DATA*)&slot->cmd_data.result;
    r->result = 0;

    if (!curThread) {
      final_status = STATUS_IPC_ERROR;
      break;
    }

    HANDLE hThread = NULL;
    NTSTATUS objSt = ObOpenObjectByPointer(curThread, OBJ_KERNEL_HANDLE, NULL,
                                           0x0040 /* THREAD_QUERY_INFORMATION */,
                                           *PsThreadType,
                                           KernelMode, &hThread);
    if (!NT_SUCCESS(objSt) || !hThread) {
      final_status = STATUS_IPC_ERROR;
      break;
    }

    PVOID startAddr = NULL;
    NTSTATUS infoSt = NtQueryInformationThread(hThread, (THREADINFOCLASS)9,
                                                &startAddr, sizeof(startAddr), NULL);
    ZwClose(hThread);

    if (!NT_SUCCESS(infoSt) || !startAddr) {
      final_status = STATUS_IPC_ERROR;
      break;
    }

    // Check if within a loaded module
    ULONG modBytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &modBytes);
    if (!modBytes) { final_status = STATUS_IPC_ERROR; break; }

    PRTL_PROCESS_MODULES pMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, modBytes);
    if (!pMods) { final_status = STATUS_IPC_ERROR; break; }
    ZwQuerySystemInformation(SystemModuleInformation, pMods, modBytes, &modBytes);

    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
      PUCHAR mStart = (PUCHAR)pMods->Modules[i].ImageBase;
      PUCHAR mEnd   = mStart + pMods->Modules[i].ImageSize;
      if ((PUCHAR)startAddr >= mStart && (PUCHAR)startAddr < mEnd) {
        found = TRUE; break;
      }
    }

    char* report = (char*)slot->data_buffer;
    const char* statusLine = found ? "PASS - stealth active" : "FAIL - unbacked memory!";
    const char* moduleLine = found ? "YES" : "NO (DETECTABLE!)";
    // Manual formatting — no CRT dependencies, kernel-safe.
    SIZE_T pos = 0;
    auto append = [&](const char* s) {
        while (pos < IPC_SLOT_DATA_SIZE - 1 && *s)
            report[pos++] = *s++;
        report[pos] = '\0';
    };
    auto append_hex = [&](ULONG_PTR val) {
        static const char hex[] = "0123456789ABCDEF";
        char buf[19]; // "0x" + 16 hex digits + null
        int i = 17;
        buf[18] = '\0';
        ULONG_PTR v = val;
        do { buf[i--] = hex[v & 0xF]; v >>= 4; } while (v);
        buf[i--] = 'x';
        buf[i] = '0';
        append(buf + i);
    };
    append("Win32StartAddress: ");
    append_hex((ULONG_PTR)startAddr);
    append("\nInside known module: ");
    append(moduleLine);
    append("\nSTATUS: ");
    append(statusLine);
    append("\n");
    SIZE_T endPos = (pos < IPC_SLOT_DATA_SIZE - 1) ? pos : (IPC_SLOT_DATA_SIZE - 1);
    report[endPos] = '\0';

    r->result = found ? 1 : 0;
    ExFreePool(pMods);
    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  case CMD_CAVE_INFO: {
    extern CODE_CAVE g_thread_cave;
    char* report = (char*)slot->data_buffer;
    RtlZeroMemory(report, IPC_SLOT_DATA_SIZE);
    SIZE_T pos2 = 0;
    auto a = [&](const char* s) {
        while (pos2 < IPC_SLOT_DATA_SIZE - 1 && *s) report[pos2++] = *s++;
        report[pos2] = '\0';
    };
    auto ahex = [&](ULONG_PTR val) {
        static const char h[] = "0123456789ABCDEF";
        char b[19]; int i = 17; b[18] = '\0';
        ULONG_PTR v = val;
        do { b[i--] = h[v & 0xF]; v >>= 4; } while (v);
        b[i--] = 'x'; b[i] = '0'; a(b + i);
    };
    auto abyte = [&](UINT8 byte) {
        static const char h[] = "0123456789ABCDEF";
        if (pos2 + 2 < IPC_SLOT_DATA_SIZE - 1) {
            report[pos2++] = h[byte >> 4];
            report[pos2++] = h[byte & 0xF];
            report[pos2] = '\0';
        }
    };
    if (g_thread_cave.is_valid) {
        a("Cave Found: YES\nCave Address: ");
        ahex((ULONG_PTR)g_thread_cave.cave_address);
        a("\nCave Size: ");
        { SIZE_T sz = g_thread_cave.cave_size; char tmp[21]; int j = 19; tmp[20] = '\0';
          do { tmp[j--] = (char)('0' + (sz % 10)); sz /= 10; } while (sz); a(tmp + j + 1); }
        a(" bytes\nPatch[0..4]: ");
        if (g_thread_cave.cave_size >= 1) { abyte(((PUCHAR)g_thread_cave.cave_address)[0]); a(" "); }
        if (g_thread_cave.cave_size >= 2) { abyte(((PUCHAR)g_thread_cave.cave_address)[1]); a(" "); }
        if (g_thread_cave.cave_size >= 3) { abyte(((PUCHAR)g_thread_cave.cave_address)[2]); a(" "); }
        if (g_thread_cave.cave_size >= 4) { abyte(((PUCHAR)g_thread_cave.cave_address)[3]); a(" "); }
        if (g_thread_cave.cave_size >= 5) { abyte(((PUCHAR)g_thread_cave.cave_address)[4]); }
        a("\nSTATUS: Thread start address SPOOFED\n");
    } else {
        a("Cave Found: NO\nSTATUS: Thread start address NOT spoofed!\n");
    }
    SIZE_T endPos2 = (pos2 < IPC_SLOT_DATA_SIZE - 1) ? pos2 : (IPC_SLOT_DATA_SIZE - 1);
    report[endPos2] = '\0';
    final_status = STATUS_IPC_SUCCESS;
    break;
  }

  default:
    break;
  }

  slot->command = CMD_IDLE;
  InterlockedExchange((volatile LONG *)&slot->status, (LONG)final_status);
}

// SEH wrapper for the command dispatcher. Any raise inside a slot handler
// (e.g. buggy user pointer, torn-down target mapping, MDL shredded mid-op)
// bubbles out as STATUS_IPC_ERROR on the slot instead of bugchecking.
//
// Double-SEH rationale:
//   If the slot's kernel VA itself has become invalid (the case we're
//   specifically hardening against), the inner `slot->*` writes in the
//   except handler would *also* raise. That's survivable — the nested
//   raise unwinds to the caller's (worker_sweep_once) __except — but we
//   skip the write entirely with an inner __try so we don't log twice
//   or hide the original failure behind a second exception.
static void process_ipc_command_slot_safe(PIPC_MEMORY mem, int slot_idx) {
  __try {
    process_ipc_command_slot(mem, slot_idx);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    ULONG ec = GetExceptionCode();
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] SEH: exception 0x%X in slot %d handler — reporting "
               "IPC_ERROR\n",
               ec, slot_idx);
    __try {
      PIPC_SLOT slot = &mem->slots[slot_idx];
      slot->command = CMD_IDLE;
      InterlockedExchange((volatile LONG *)&slot->status, STATUS_IPC_ERROR);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      // Slot VA is also dead. Nothing we can do here — the outer
      // worker_sweep_once wrapper will log the nested fault and
      // the next sweep will no-op because teardown will have
      // cleared the globals by then.
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] SEH: nested fault writing slot %d status — mapping "
                 "appears torn down\n",
                 slot_idx);
    }
  }
}

// Returns TRUE if the worker processed at least one slot this pass.
// The sweep holds the rundown reference for exactly one slot scan, which
// keeps teardown_ipc_mapping_locked bounded (no worker can stay inside
// the rundown longer than one R/W chunk).
//
// Why the outer SEH wrapper?
//
// The kernel VA that `mem` points at is backed by an MDL taken over
// usermode pages. In theory, ExAcquireRundownProtection + nulling the
// globals under a FastMutex means no worker can observe a torn-down
// mapping; in practice, we've seen a page-fault bugcheck during the
// size-transition stress test, and the only kernel access in that path
// that isn't otherwise SEH-wrapped is the `mem->slots[i]` sweep here
// (process_ipc_command_slot_safe wraps the inner dispatch, but the
// *outer* scan of command/status is bare). If anything ever manages to
// invalidate that mapping out from under us — a subtle rundown race,
// pool corruption elsewhere, a broken PFN — we'd prefer a STATUS_ERROR
// on the slot over a bugcheck.
//
// The cost is a single __try frame per sweep iteration (very cheap);
// the benefit is that this path can never again be the one that
// bluescreens the system during a benchmark run.
static BOOLEAN worker_sweep_once(BOOLEAN *out_had_mapping) {
  BOOLEAN processed_any = FALSE;
  *out_had_mapping = FALSE;

  if (!ExAcquireRundownProtection(&g_ipc_rundown))
    return FALSE;

  PIPC_MEMORY mem = g_kernel_ipc_mem;
  PEPROCESS proc = g_test_process;

  if (mem && proc) {
    *out_had_mapping = TRUE;
    __try {
      for (int i = 0; i < IPC_MAX_SLOTS; i++) {
        // Snapshot both fields under volatile access. If the
        // CAS succeeds we've taken ownership of the slot and
        // the inner dispatcher (itself SEH-wrapped) handles
        // everything else.
        UINT32 cmd = mem->slots[i].command;
        UINT32 st = mem->slots[i].status;

        if (cmd != CMD_IDLE && st == STATUS_IPC_IDLE) {
          if (InterlockedCompareExchange((volatile LONG *)&mem->slots[i].status,
                                         STATUS_IPC_PROCESSING,
                                         STATUS_IPC_IDLE) == STATUS_IPC_IDLE) {
            process_ipc_command_slot_safe(mem, i);
            processed_any = TRUE;
          }
        }
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      // Never bugcheck from the sweep loop. If the kernel VA
      // behind `mem` is somehow invalid right now, drop out
      // cleanly and let the next sweep re-read the globals —
      // by the time we return, teardown will have completed
      // and g_kernel_ipc_mem will be NULL, so the next sweep
      // is a no-op.
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] worker_sweep_once: SEH caught 0x%X on slot scan "
                 "(mem=%p) — aborting sweep, mapping may be torn down\n",
                 GetExceptionCode(), mem);
    }
  }

  ExReleaseRundownProtection(&g_ipc_rundown);
  return processed_any;
}

//
// Worker loop.
//
// Design evolution
// ----------------
// v1: 1 ms KeDelayExecutionThread between sweeps. Timer resolution
//     stuck at 15.625 ms under KDU, so every delay rounded to a tick
//     and the benchmark saw a 15-31 ms floor.
//
// v2: three-phase backoff (tight spin → yield → 50 ms cold). The
//     "yield" phase used KeDelayExecutionThread(0), which is
//     documented as "relinquish quantum". With multiple workers
//     competing for the same cores, yielding put the worker at the
//     end of the ready queue behind peers that were still spinning;
//     it only woke up when *their* quantum expired, ~15-20 ms later.
//     Net effect: benchmark RTT was two full ticks (~32 ms), not
//     one, because both kernel and user sides rounded to a tick.
//
// v3 (this code): pure spin while a mapping exists. No yield, no
//     timer arm. The OS scheduler will preempt us naturally when
//     our quantum expires, so other threads still run; what we
//     stop doing is *voluntarily* giving up the CPU in a way that
//     lands us behind other spinners in the ready queue. With only
//     one worker (IPC_WORKER_COUNT=1), burning one core on PAUSE
//     is the right trade for microsecond-scale IPC latency — the
//     remaining cores are free for the usermode benchmark thread
//     and everything else on the system.
//
//     The only timed sleep is the *cold* path, taken when no
//     client is connected at all. Here the 15 ms rounding cost
//     doesn't matter (nothing's waiting on us).
//
static VOID ipc_worker_thread(PVOID context) {
  ULONG tid = (ULONG)(ULONG_PTR)context;
  LARGE_INTEGER delay_cold;
  delay_cold.QuadPart = -10000LL * 50; // 50 ms

  // ---------------------------------------------------------------
  // Worker scheduling setup — priority + CPU pinning.
  //
  // Why we need both:
  //   * Priority alone (no pinning) means the scheduler may co-locate
  //     the worker on the same core as the usermode benchmark thread.
  //     Once that happens, two threads at comparable priorities
  //     ping-pong at quantum expiry — user spins its quantum (≈6 ms
  //     at `timeBeginPeriod(1)`), then the worker gets a quantum
  //     while user is off-CPU. The benchmark observes the user-spin
  //     + kernel-spin time as one latency sample, which lands at
  //     exactly the ~16 ms floor reported. This is *the* cause of
  //     "most RTTs show 16 ms" — it's one scheduler quantum, not an
  //     IPC problem at all.
  //
  //   * Pinning alone (at priority 8) can still be preempted on-core
  //     by a normal-priority system thread the dispatcher decides to
  //     schedule on our core. With affinity forcing us onto exactly
  //     one core, any same-core preemption is the full ~16 ms we're
  //     trying to eliminate. Priority 15 (highest variable-priority)
  //     stops every normal system thread from preempting us; only
  //     realtime threads (16+) and DPCs/interrupts can preempt,
  //     and those run for microseconds, not milliseconds.
  //
  // Pin target is the LAST active CPU. That's the CPU least likely
  // to be hosting the usermode benchmark thread (which typically
  // lands near CPU 0 on a fresh process), and because the userspace
  // side of the patch also explicitly pins itself to CPU 0, the
  // collision is guaranteed impossible.
  //
  // We use Ex-group APIs so this works on >64-core / multi-group
  // systems. On single-group (almost every gaming box) the group
  // index is always 0.
  // ---------------------------------------------------------------
  {
    ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (cpu_count > 0) {
      USHORT target_group = 0;
      UCHAR target_cpu = (UCHAR)(cpu_count - 1);

      // On multi-group systems, route to the last CPU of the
      // last group. We keep this simple because the benchmark
      // target is single-group.
      ULONG group_cpus = KeQueryActiveProcessorCountEx(0);
      if (group_cpus > 0) {
        target_cpu = (UCHAR)(group_cpus - 1);
        target_group = 0;
      }

      GROUP_AFFINITY ga;
      RtlZeroMemory(&ga, sizeof(ga));
      ga.Mask = (KAFFINITY)(1ULL << target_cpu);
      ga.Group = target_group;
      KeSetSystemGroupAffinityThread(&ga, NULL);

      // Priority 15: highest variable-priority level. The worker
      // can only be preempted by realtime threads (16+) and
      // DPCs/interrupts (sub-microsecond). This eliminates the
      // ~16 ms quantum-preemption spikes from normal system
      // threads landing on our pinned core. We stay below 16
      // to avoid DPC-starvation side effects.
      KeSetPriorityThread(KeGetCurrentThread(), 15);

      DbgPrintEx(
          0x4d, 0xffffffff,
          "[CR3-IPC] Worker %lu pinned to CPU %u (group %u), priority 15\n",
          tid, target_cpu, target_group);
    }
  }

  DbgPrintEx(0x4d, 0xffffffff, "[CR3-IPC] Worker thread %lu started\n", tid);

  // ---------------------------------------------------------------
  // Hot loop — batched rundown.
  //
  // The old design acquired/released ExRundownProtection on every
  // single sweep (2 interlocked ops × millions of sweeps/sec).
  // This version holds the rundown across a few spins and only
  // releases every RUNDOWN_RELEASE_INTERVAL empty sweeps so
  // teardown_ipc_mapping_locked gets a window to drain workers.
  //
  // BUGFIX: was 8192, which held the rundown for hundreds of
  // milliseconds. During that time, if the target process exited,
  // teardown_ipc_mapping_locked couldn't acquire the rundown, and
  // MmCleanProcessAddressSpace could reclaim the pages backing
  // our MDL before we released → PAGE_FAULT. Reduced to 64 so
  // teardown can drain within ~microseconds.
  // ---------------------------------------------------------------
  const ULONG RUNDOWN_RELEASE_INTERVAL = 64;

  while (g_ipc_thread_running) {
    // Try to enter the rundown. If teardown is draining, spin.
    if (!ExAcquireRundownProtection(&g_ipc_rundown)) {
      _mm_pause();
      continue;
    }

    PIPC_MEMORY mem = g_kernel_ipc_mem;
    PEPROCESS proc = g_test_process;

    if (!mem || !proc) {
      // Cold path — nobody connected.
      ExReleaseRundownProtection(&g_ipc_rundown);
      KeDelayExecutionThread(KernelMode, FALSE, &delay_cold);
      continue;
    }

    // --- inner hot spin (rundown held) ---
    ULONG empty_sweeps = 0;

    while (g_ipc_thread_running && empty_sweeps < RUNDOWN_RELEASE_INTERVAL) {
      BOOLEAN found = FALSE;

      __try {
        for (int i = 0; i < IPC_MAX_SLOTS; i++) {
          UINT32 cmd = mem->slots[i].command;
          UINT32 st = mem->slots[i].status;

          if (cmd != CMD_IDLE && st == STATUS_IPC_IDLE) {
            if (InterlockedCompareExchange(
                    (volatile LONG *)&mem->slots[i].status,
                    STATUS_IPC_PROCESSING,
                    STATUS_IPC_IDLE) == STATUS_IPC_IDLE) {
              process_ipc_command_slot_safe(mem, i);
              found = TRUE;
              break; // re-scan from slot 0
            }
          }
        }
      } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] worker %lu: SEH 0x%X on slot scan "
                   "(mem=%p) — breaking out\n",
                   tid, GetExceptionCode(), mem);
        break; // exit inner loop, release rundown
      }

      if (found) {
        empty_sweeps = 0; // reset — stay in inner loop
      } else {
        empty_sweeps++;
        _mm_pause();
      }
    }

    ExReleaseRundownProtection(&g_ipc_rundown);
  }

  DbgPrintEx(0x4d, 0xffffffff, "[CR3-IPC] Worker thread %lu exiting\n", tid);
  PsTerminateSystemThread(STATUS_SUCCESS);
}

//
// Tear down the currently-mapped IPC buffer + release the target EPROCESS
// reference. MUST be called only from the discovery thread.
//
// Safety contract:
//   * Drains the rundown first so no worker is inside a `mem->slots[i]`
//     access when we unmap.
//   * SEH-wraps the MDL primitives because the target process may have
//     already been torn down by this point; on a dead process, the page
//     manager can raise in-page errors rather than returning a status.
//   * Re-initializes the rundown so the next discovery cycle can accept
//     workers again. If we're on the final shutdown path the caller will
//     just not run another cycle, which is fine.
//
static VOID teardown_ipc_mapping_locked(const char *reason) {
  // Serialize with the process-exit callback. Both paths can race here
  // and must not interleave their rundown drain / Mm* / rundown re-init.
  ExAcquireFastMutex(&g_teardown_mutex);

  // If another caller already cleared the globals, nothing to do. This
  // is the hot path when the exit callback wins the race — the polling
  // discovery thread just observes "nothing left".
  if (!g_ipc_mdl && !g_kernel_ipc_mem && !g_test_process) {
    ExReleaseFastMutex(&g_teardown_mutex);
    return;
  }

  DbgPrintEx(0x4d, 0xffffffff, "[CR3-IPC] teardown_ipc_mapping: %s\n", reason);

  // Drain all workers from their current slot access. After this returns,
  // no new ExAcquireRundownProtection() succeeds, and every worker that
  // was mid-iteration has released its ref. Only now is it safe to
  // unmap / unlock the backing MDL.
  ExWaitForRundownProtectionRelease(&g_ipc_rundown);

  // Snapshot + clear globals BEFORE touching the underlying resources.
  // The rundown drain above already guarantees no worker can observe
  // the old values, but this also makes the "already-torn-down" early
  // return above correct for subsequent callers.
  PMDL mdl = g_ipc_mdl;
  PIPC_MEMORY mem = g_kernel_ipc_mem;
  PEPROCESS proc = g_test_process;

  g_ipc_mdl = NULL;
  g_kernel_ipc_mem = NULL;
  g_test_process = NULL;
  g_target_pid = NULL;

  // Unmap + unlock as a single atomic SEH region. If MmUnmapLockedPages
  // raises, we MUST NOT proceed to MmUnlockPages — the kernel VA is in
  // an indeterminate state and unlocking pages out from under an active
  // kernel mapping dereferences freed PFNs when the pool is later
  // reused. That path produces delayed PAGE_FAULT_IN_NONPAGED_AREA
  // bugchecks (hit precisely when some later allocation happens to
  // touch the stale VA).
  if (mdl) {
    BOOLEAN teardown_ok = FALSE;
    __try {
      if (mem)
        MmUnmapLockedPages(mem, mdl);
      MmUnlockPages(mdl);
      teardown_ok = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] teardown: exception during MmUnmap/Unlock "
                 "(mem=0x%p mdl=0x%p) — leaking MDL to avoid double-free / "
                 "stale-VA corruption\n",
                 mem, mdl);
    }

    if (teardown_ok) {
      IoFreeMdl(mdl);
    }
  }

  if (proc) {
    __try {
      ObDereferenceObject(proc);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] teardown: SEH caught 0x%X during "
                 "ObDereferenceObject(proc=%p) — leaking ref\n",
                 GetExceptionCode(), proc);
    }
  }

  // Rearm rundown so the next session's workers can enter.
  ExReInitializeRundownProtection(&g_ipc_rundown);

  ExReleaseFastMutex(&g_teardown_mutex);
}

// NOTE: process_notify_callback was REMOVED.
// See the comment at g_teardown_mutex for the full rationale.
// PsSetCreateProcessNotifyRoutine from KDU-mapped code → PatchGuard 0x109.

static VOID ipc_discovery_thread(PVOID context) {
  UNREFERENCED_PARAMETER(context);
  LARGE_INTEGER sleep_interval;

  DbgPrintEx(0x4d, 0xffffffff, "[CR3-IPC] Discovery thread started\n");

  while (g_ipc_thread_running) {
    // Is our target still alive? Run the check under the teardown
    // mutex so we don't race a concurrent teardown clearing
    // g_test_process / ObDereferenceObject'ing it out from under us.
    //
    // WITHOUT this lock, we'd do two separate volatile reads of
    // g_test_process here — the null-check, then the argument to
    // PsGetProcessExitStatus — and a teardown could run in
    // between, leaving the second read with a dangling EPROCESS.
    BOOLEAN need_teardown = FALSE;
    BOOLEAN target_alive = FALSE;

    ExAcquireFastMutex(&g_teardown_mutex);
    if (g_kernel_ipc_mem) {
      PEPROCESS tp = g_test_process;
      if (!tp || PsGetProcessExitStatus(tp) != STATUS_PENDING) {
        need_teardown = TRUE;
      } else {
        // Process is alive. Also check whether the IPC magic is still
        // valid. LoaderIpc::Release() zeros the entire buffer (magic = 0)
        // while the loader process remains alive for its auto-close window.
        // Without this check the driver would sit in the alive-poll loop
        // for the full ~5 s grace period, blocking scootware.exe from
        // claiming the driver. A burned magic == voluntary IPC handoff;
        // treat it identically to process exit so we re-scan immediately.
        __try {
          UINT64 current_magic = g_kernel_ipc_mem->magic;
          if (current_magic != IPC_MAGIC) {
            // IPC magic burned — loader called Release() for handoff.
            // Treat as a soft exit: tear down and re-scan right away.
            need_teardown = TRUE;
            DbgPrintEx(0x4d, 0xffffffff,
                       "[CR3-IPC] IPC magic burned by live process (PID %llu) "
                       "— treating as voluntary handoff\n",
                       (ULONGLONG)(ULONG_PTR)g_target_pid);
          } else {
            target_alive = TRUE;
          }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
          // If reading the magic raised, the mapping may already be torn
          // down. Schedule teardown to be safe.
          need_teardown = TRUE;
        }
      }
    }
    ExReleaseFastMutex(&g_teardown_mutex);

    if (need_teardown) {
      // teardown_ipc_mapping_locked re-acquires the same mutex;
      // that's fine (no recursion — we released above). The
      // "already torn down" early-return handles the case where
      // the notify callback beat us to it.
      teardown_ipc_mapping_locked("polling loop observed target exit or magic burned");

      // If the client explicitly asked to shut down (CMD_SHUTDOWN),
      // honour it now that the session is torn down and the target
      // has exited.  Otherwise, keep scanning — another scootware.exe
      // instance (the real cheat, a re-launch, etc.) may appear later.
      //
      // This replaced the old g_ipc_ever_established one-shot that
      // killed the driver after ANY session end.  That was broken
      // because the DriverBringup probe — which is also named
      // scootware.exe and carries IPC_MAGIC — establishes a fleeting
      // session, exits cleanly, and triggered the one-shot before
      // the actual payload ever connected.
      if (g_shutdown_requested) {
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] Session ended + CMD_SHUTDOWN was received "
                   "— initiating self-shutdown\n");
        g_ipc_thread_running = FALSE;
        break;
      }

      // ── Deterministic handoff fast-path ─────────────────────────────
      // If the loader pre-announced the cheat via CMD_HANDOFF, attempt to
      // establish that session directly instead of doing a full scan.
      // This eliminates the ≤500ms idle-scan window between loader exit
      // and driver attach to scootware.exe.
      UINT32 hint_pid = (UINT32)g_handoff_pid;
      UINT64 hint_va  = g_handoff_ipc_va;

      if (hint_pid != 0 && hint_va != 0) {
        // Consume the hint immediately so it isn't used again.
        InterlockedExchange((volatile LONG *)&g_handoff_pid,    0);
        InterlockedExchange64((LONG64 *)&g_handoff_ipc_va, 0);

        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] Handoff hint: trying direct attach to pid=%u "
                   "ipc_va=0x%llx\n", hint_pid, hint_va);

        PEPROCESS hint_proc = NULL;
        NTSTATUS hint_st = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)hint_pid, &hint_proc);

        BOOLEAN hint_established = FALSE;
        if (NT_SUCCESS(hint_st) && hint_proc) {
          if (PsGetProcessExitStatus(hint_proc) == STATUS_PENDING) {
            KAPC_STATE apc;
            KeStackAttachProcess(hint_proc, &apc);

            PMDL mdl = IoAllocateMdl((PVOID)hint_va, IPC_TOTAL_SIZE,
                                     FALSE, FALSE, NULL);
            BOOLEAN locked = FALSE;
            PIPC_MEMORY kmapped = NULL;

            if (mdl) {
              __try {
                MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
                locked = TRUE;
                kmapped = (PIPC_MEMORY)MmMapLockedPagesSpecifyCache(
                    mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
              } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] Handoff hint: MmProbeAndLockPages raised "
                           "(pid=%u va=0x%llx) — falling back to scan\n",
                           hint_pid, hint_va);
              }

              if (!kmapped) {
                if (locked) {
                  __try { MmUnlockPages(mdl); } __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
                IoFreeMdl(mdl);
                mdl = NULL;
              }
            }

            KeUnstackDetachProcess(&apc);

            if (kmapped) {
              // Verify the magic is correct — the cheat must have armed
              // its IPC buffer before the loader sent CMD_HANDOFF. If the
              // cheat is still in CRT init we see magic==0 here; fall back
              // to the normal scan in that case.
              UINT64 hint_magic = 0;
              __try { hint_magic = kmapped->magic; } __except (EXCEPTION_EXECUTE_HANDLER) {}

              if (hint_magic == IPC_MAGIC) {
                g_target_pid     = PsGetProcessId(hint_proc);
                g_kernel_ipc_mem = kmapped;
                g_ipc_mdl        = mdl;
                g_test_process   = hint_proc; // hint_proc ref consumed here
                hint_established = TRUE;
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] Handoff hint: direct attach SUCCESS "
                           "pid=%u ipc=%p\n", hint_pid, kmapped);
              } else {
                // Magic not yet armed. Unmap, release, fall through to scan.
                DbgPrintEx(0x4d, 0xffffffff,
                           "[CR3-IPC] Handoff hint: magic not ready (got 0x%llx) "
                           "— falling back to full scan\n", hint_magic);
                __try {
                  MmUnmapLockedPages(kmapped, mdl);
                  MmUnlockPages(mdl);
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
                IoFreeMdl(mdl);
              }
            }
          }

          if (!hint_established) {
            ObDereferenceObject(hint_proc);
          }
        } else {
          DbgPrintEx(0x4d, 0xffffffff,
                     "[CR3-IPC] Handoff hint: pid=%u not found (0x%X) "
                     "— falling back to full scan\n", hint_pid, hint_st);
        }

        if (hint_established) {
          // Session established via hint. Skip the normal scan entirely.
          continue;
        }
        // Fall through — hint failed, do normal scan below.
      }
      // ── End deterministic fast-path ─────────────────────────────────

      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] Session ended — re-scanning for new target\n");
      continue;
    }
    if (target_alive) {
      // If CMD_SHUTDOWN arrived while the target is still running,
      // tear down immediately and exit.  This is the "Unload Driver"
      // button path in the speed test — the user wants the driver
      // gone NOW, not after they close the window.
      if (g_shutdown_requested) {
        teardown_ipc_mapping_locked("CMD_SHUTDOWN while target still alive");
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] CMD_SHUTDOWN received — tearing down active "
                   "session and shutting down\n");
        g_ipc_thread_running = FALSE;
        break;
      }

      // Alive. Tight poll (50ms) to catch process exit quickly.
      // Without the notify callback (removed for KDU compat),
      // this is our only mechanism to detect target exit and
      // unlock pages before PROCESS_HAS_LOCKED_PAGES (0x76).
      sleep_interval.QuadPart = -10000LL * 50;
      KeDelayExecutionThread(KernelMode, FALSE, &sleep_interval);
      continue;
    }

    // Check for a pending shutdown before scanning for a new process.
    // CMD_SHUTDOWN can arrive while no session is active (e.g. the
    // speed test sends CMD_SHUTDOWN and then exits before the
    // discovery thread wakes up from its idle sleep).  Without this
    // check, the driver would sit in this loop forever.
    if (g_shutdown_requested) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] CMD_SHUTDOWN seen during idle scan "
                 "— initiating self-shutdown\n");
      g_ipc_thread_running = FALSE;
      break;
    }

    UINT64 ipc_va = 0;
    PEPROCESS test_process = find_target_process_with_ipc(&ipc_va);
    if (!test_process || !ipc_va) {
      if (test_process) {
          ObDereferenceObject(test_process);
      }
      sleep_interval.QuadPart = -10000LL * 500;
      KeDelayExecutionThread(KernelMode, FALSE, &sleep_interval);
      continue;
    }

    if (ipc_va) {
      DbgPrintEx(
          0x4d, 0xffffffff,
          "[CR3-IPC] IPC buffer found at VA: 0x%llx. Mapping to kernel...\n",
          ipc_va);

      KAPC_STATE apc;
      KeStackAttachProcess(test_process, &apc);

      PMDL mdl =
          IoAllocateMdl((PVOID)ipc_va, IPC_TOTAL_SIZE, FALSE, FALSE, NULL);
      BOOLEAN locked = FALSE;
      PIPC_MEMORY kmapped = NULL;

      if (mdl) {
        __try {
          MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
          locked = TRUE;
          kmapped = (PIPC_MEMORY)MmMapLockedPagesSpecifyCache(
              mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
          DbgPrintEx(0x4d, 0xffffffff,
                     "[CR3-IPC] MmProbeAndLockPages raised — skipping (probe "
                     "process torn down racing us)\n");
        }

        if (!kmapped) {
          // Roll back: unlock MDL if ProbeAndLock succeeded,
          // free the MDL descriptor. We do this WHILE STILL
          // ATTACHED — the MDL references pages from the
          // attached process's address space.
          if (locked) {
            __try {
              MmUnlockPages(mdl);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
          }
          IoFreeMdl(mdl);
          mdl = NULL;
        }
      }

      // CRITICAL: Detach BEFORE touching the EPROCESS ref.
      //
      // The old code called ObDereferenceObject(test_process)
      // while still attached via KeStackAttachProcess. If the
      // deref dropped the last reference, the EPROCESS was
      // freed, and KeUnstackDetachProcess then dereferenced
      // the freed apc.Process → PAGE_FAULT at APC_LEVEL →
      // unrecoverable BSOD. Detach first, deref/publish after.
      KeUnstackDetachProcess(&apc);

      if (kmapped) {
        // Publish globals. Workers gate on rundown + non-null
        // globals, so the write order is the final safety net.
        g_target_pid = PsGetProcessId(test_process);
        g_kernel_ipc_mem = kmapped;
        g_ipc_mdl = mdl;
        g_test_process = test_process;
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] IPC session established with PID %llu\n",
                   (ULONGLONG)(ULONG_PTR)g_target_pid);
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] Mapped IPC successfully at %p (pid=%llu)\n",
                   kmapped, (ULONGLONG)(ULONG_PTR)g_target_pid);
      } else {
        // Mapping failed — drop the EPROCESS reference.
        // Safe now because we already detached above.
        ObDereferenceObject(test_process);
      }
    } else {
      // This branch is technically unreachable now since find_target_process_with_ipc
      // only returns a process if ipc_va is non-zero, but we keep the sleep for safety.
      if (test_process) {
          ObDereferenceObject(test_process);
      }
      sleep_interval.QuadPart = -10000LL * 2000;
      KeDelayExecutionThread(KernelMode, FALSE, &sleep_interval);
    }
  }

  // Final teardown on shutdown: drain workers, unmap, unlock, free, deref.
  // NOTE: this is the MANDATORY synchronization point that was missing
  // before — without it the discovery thread would free the MDL while
  // worker threads were still dereferencing mem->slots[i], producing the
  // "BSOD some time after unload" behavior (the worker completed one
  // more iteration against freed kernel pages).
  if (g_kernel_ipc_mem || g_ipc_mdl || g_test_process) {
    teardown_ipc_mapping_locked("discovery thread shutting down");
  }

  DbgPrintEx(0x4d, 0xffffffff, "[CR3-IPC] Discovery thread exiting\n");
  PsTerminateSystemThread(STATUS_SUCCESS);
}

void unload_drv(PDRIVER_OBJECT drv_obj) {
  UNREFERENCED_PARAMETER(drv_obj);
  g_ipc_thread_running = FALSE;
  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] Supervisor: shutdown requested — draining threads\n");

  LARGE_INTEGER worker_deadline;
  worker_deadline.QuadPart = -10LL * 1000 * 1000 * 10; // 10s hard cap per wait

  BOOLEAN all_threads_exited = TRUE;

  for (int i = 0; i < IPC_WORKER_COUNT; i++) {
    if (g_worker_threads[i]) {
      NTSTATUS wst = KeWaitForSingleObject(g_worker_threads[i], Executive,
                                           KernelMode, FALSE, &worker_deadline);
      if (wst != STATUS_SUCCESS) {
        DbgPrintEx(0x4d, 0xffffffff,
                   "[CR3-IPC] Supervisor: worker %d wait status 0x%X (likely timeout)\n",
                   i, wst);
        all_threads_exited = FALSE;
      }
      ObDereferenceObject(g_worker_threads[i]);
      g_worker_threads[i] = NULL;
    }
  }

  if (g_discovery_thread) {
    NTSTATUS wst = KeWaitForSingleObject(g_discovery_thread, Executive,
                                         KernelMode, FALSE, &worker_deadline);
    if (wst != STATUS_SUCCESS) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] Supervisor: discovery thread wait status 0x%X (likely timeout)\n",
                 wst);
      all_threads_exited = FALSE;
    }
    ObDereferenceObject(g_discovery_thread);
    g_discovery_thread = NULL;
  }

  if (!all_threads_exited) {
    DbgPrintEx(
        0x4d, 0xffffffff,
        "[CR3-IPC] Supervisor: at least one thread didn't exit in time\n");
  }

  // Proxy-PTE state has been removed from the driver entirely; no cleanup
  // is needed here.  The MDL-based read/write helpers are self-contained
  // (each call locks → maps → copies → unmaps → unlocks within scope).
  // CleanupProxyPage();

  // Clean up HWID spoofer (restores originals if active)
  HWIDSpoofer::Cleanup();

  DbgPrintEx(0x4d, 0xffffffff, "[CR3-IPC] Supervisor: shutdown complete\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  if (DriverObject) {
      DriverObject->DriverUnload = unload_drv;
  }

  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] Driver entry called\n");

  // ── Top-level SEH: catch ANY init failure so the driver always boots ──
  // KDU-mapped drivers may have unresolved imports.  If any init step
  // PAGE_FAULTs, we log it and continue — the IPC core (discovery +
  // worker threads) must still start.  Optional features that fail
  // (expand-stack, ret-gadget, code-cave, HWID spoofer) are simply
  // disabled rather than taking down the whole driver.
  __try {

  // ── Resolve optional imports dynamically ───────────────────────────
  // Some KDU mappers skip less-common exports.  We try to resolve them
  // via MmGetSystemRoutineAddress so the IPC core can still scan for
  // targets even if the PE import table entries are missing.
  ResolveOptionalImports();

  // ── Detect EPROCESS.ImageFileName offset ────────────────────────────
  // If dynamic resolution of PsGetProcessImageFileName failed (KDU import
  // miss + MmGetSystemRoutineAddress unresolved), we read ImageFileName
  // directly from the EPROCESS structure at its known offset.
  // This is the last-resort fallback that guarantees process name matching
  // works on ANY KDU-mapped driver regardless of import resolution.
  if (!g_pfnPsGetProcessImageFileName)
    g_image_file_name_offset = DetectImageFileNameOffset();

  // ── Resolve KeExpandKernelStackAndCalloutEx dynamically ──────────────
  // For KDU-mapped drivers, imports may not all be resolved by the mapper.
  // We resolve this via MmGetSystemRoutineAddress so the expanded-stack
  // fallback works even when the import table entry is missing.
  {
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"KeExpandKernelStackAndCalloutEx");
    g_pfnExpandStack = (fn_KeExpandKernelStackAndCalloutEx_t)
        MmGetSystemRoutineAddress(&routineName);
    if (g_pfnExpandStack) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] KeExpandKernelStackAndCalloutEx resolved: %p\n",
                 g_pfnExpandStack);
    } else {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] KeExpandKernelStackAndCalloutEx NOT available — "
                 "will use direct MDL fallback (no stack isolation)\n");
    }
  }

  // ── Resolve RET gadget in ntoskrnl.exe .text for spoof thunk ──────
  // Uses FindRetGadget() from syscall_stack_spoof.h which scans ntoskrnl's
  // .text section for a 0xC3 (RET) followed by 0xCC (INT3 padding).
  // This serves as the fake return address that stack unwinders see
  // when the SpoofCallThunk is used for syscall dispatch.
  // SEH-wrapped: scanning .text is read-only and safe, but guard against
  // edge cases on VBS/HVCI systems.
  {
    PVOID retGadget = NULL;
    __try {
      retGadget = FindRetGadget();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] FindRetGadget raised exception 0x%X — "
                 "spoof thunk disabled\n", GetExceptionCode());
      retGadget = NULL;
    }
    if (retGadget) {
      g_SpoofedGadget = retGadget;
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] SpoofThunk RET gadget: %p\n", retGadget);
    } else {
      g_SpoofedGadget = NULL;
      g_ret_gadget_ntos = NULL;
    }
  }

  // ── Code cave thread-spoofing ──────────────────────────────────────
  // DISABLED by default — MmMapIoSpaceEx-based physical writes to kernel
  // .text pages can PAGE_FAULT on VBS/HVCI/Secured-core systems where
  // RAM-backed physical addresses reject IoSpace mappings.
  //
  // To re-enable, define CR3_IPC_ENABLE_CAVE_SPOOF before building.
  // The RET-gadget based return-address spoofing (FindRetGadget above)
  // and KeExpandKernelStackAndCalloutEx stack isolation provide sufficient
  // stealth without the code-cave start-address spoof.
#if defined(CR3_IPC_ENABLE_CAVE_SPOOF)
  __try {
    CodeCave::FindAndPatchAnyCave((PVOID)ipc_worker_thread, &g_thread_cave);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] CodeCave: discovery/patch raised exception 0x%X — "
               "thread spoofing disabled\n", GetExceptionCode());
    RtlZeroMemory(&g_thread_cave, sizeof(g_thread_cave));
  }
#else
  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] CodeCave: disabled (CR3_IPC_ENABLE_CAVE_SPOOF not "
             "defined). RET-gadget + expanded-stack isolation in use.\n");
#endif

  // Initialize HWID spoofer module
  __try {
    HWIDSpoofer::Initialize();
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] HWIDSpoofer::Initialize raised exception 0x%X — "
               "HWID spoofer disabled\n", GetExceptionCode());
  }

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    // Catastrophic init failure — log and continue to thread creation.
    // The IPC core must still start even if every optional feature died.
    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] FATAL: DriverEntry init raised exception 0x%X "
               "— attempting to start IPC core anyway\n",
               GetExceptionCode());
    g_pfnExpandStack  = NULL;
    g_SpoofedGadget   = NULL;
    g_ret_gadget_ntos = NULL;
  }

  ExInitializeRundownProtection(&g_ipc_rundown);
  ExInitializeFastMutex(&g_teardown_mutex);

  g_ipc_thread_running = TRUE;

  HANDLE hDiscovery = NULL;
  NTSTATUS status =
      PsCreateSystemThread(&hDiscovery, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                           ipc_discovery_thread, NULL);
  if (NT_SUCCESS(status)) {
    if (!NT_SUCCESS(ObReferenceObjectByHandle(
            hDiscovery, THREAD_ALL_ACCESS, NULL, KernelMode,
            (PVOID *)&g_discovery_thread, NULL))) {
      g_discovery_thread = NULL;
    }
    ZwClose(hDiscovery);
  }

  for (int i = 0; i < IPC_WORKER_COUNT; i++) {
    HANDLE hWorker = NULL;
    // Use the code-cave address as the thread start routine if available.
    // EAC/BE scanning ETHREAD.Win32StartAddress will see a legitimate
    // ntoskrnl.exe .text address instead of our unbacked pool code.
    PVOID startRoutine = (PVOID)ipc_worker_thread;
    if (g_thread_cave.is_valid && g_thread_cave.cave_address) {
      startRoutine = g_thread_cave.cave_address;
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] Worker %d using spoofed start address %p "
                 "(cave in %p)\n",
                 i, startRoutine, g_thread_cave.module_base);
    }
    status = PsCreateSystemThread(&hWorker, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                  (PKSTART_ROUTINE)startRoutine,
                                  (PVOID)(ULONG_PTR)i);
    if (NT_SUCCESS(status)) {
      PETHREAD thread_obj = NULL;
      if (NT_SUCCESS(ObReferenceObjectByHandle(hWorker, THREAD_ALL_ACCESS, NULL,
                                               KernelMode, (PVOID *)&thread_obj,
                                               NULL))) {
        g_worker_threads[i] = thread_obj;
      }
      ZwClose(hWorker);
    } else {
      DbgPrintEx(0x4d, 0xffffffff,
                 "[CR3-IPC] Worker %d creation failed st=0x%X — falling back "
                 "to plain start address\n", i, status);
      // Fallback: try again with the real function address in case the
      // cave patch was somehow invalid (e.g., CI.dll integrity check).
      status = PsCreateSystemThread(&hWorker, THREAD_ALL_ACCESS, NULL, NULL,
                                    NULL, ipc_worker_thread,
                                    (PVOID)(ULONG_PTR)i);
      if (NT_SUCCESS(status)) {
        PETHREAD thread_obj = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(hWorker, THREAD_ALL_ACCESS,
                                                 NULL, KernelMode,
                                                 (PVOID *)&thread_obj, NULL))) {
          g_worker_threads[i] = thread_obj;
        }
        ZwClose(hWorker);
      }
    }
  }

  DbgPrintEx(0x4d, 0xffffffff,
             "[CR3-IPC] Driver initialized successfully. Waiting for %s...\n",
             IPC_TARGET_PROCESS);

  // ---------------------------------------------------------------------------
  // V1 shellcode supervisor wait.
  //
  // KDU_SHELLCODE_V1 calls DriverEntry as a PKSTART_ROUTINE (DriverObject ==
  // NULL) and fires the ReadyEvent *before* this thread runs, so the mapper
  // has already exited by the time we reach here.  That means it is safe —
  // and necessary — to block until every driver thread has exited.
  //
  // Why necessary: the V1 shellcode never frees the NonPagedPool allocation
  // that contains the driver code.  If the loader re-maps the driver (or a
  // KDU tool explicitly calls ExFreePool on rawExAlloc) while the worker or
  // discovery thread is still executing from those pages, the result is
  // guaranteed corruption / BSOD.  By blocking here we ensure the pool pages
  // are "dead" (no thread executing from them) before any external tool can
  // safely free them.
  //
  // V3 shellcode (DriverObject != NULL) calls DriverEntry synchronously and
  // fires ReadyEvent only after we return, so we must NOT block on that path.
  // Cleanup on V3 is handled by unload_drv (registered as DriverUnload above).
  // ---------------------------------------------------------------------------
  if (!DriverObject) {
    // Save thread references to stack locals before blocking.  After the
    // waits complete the pool could theoretically have been freed by an
    // external tool; reading globals from freed pool is safe for NonPagedPool
    // (physical pages still present) but we minimise the window by using
    // locals and clearing the globals now while the pool is definitely live.
    PETHREAD localDiscovery = g_discovery_thread;
    PETHREAD localWorkers[IPC_WORKER_COUNT] = {};
    for (int i = 0; i < IPC_WORKER_COUNT; i++) {
      localWorkers[i] = g_worker_threads[i];
      g_worker_threads[i] = NULL;
    }
    g_discovery_thread = NULL;

    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] Supervisor (V1): blocking until all threads exit\n");

    // Worker threads first — they depend on the discovery thread's teardown
    // having cleared g_kernel_ipc_mem before they fully drain, but we can
    // start their waits in parallel.
    for (int i = 0; i < IPC_WORKER_COUNT; i++) {
      if (localWorkers[i]) {
        KeWaitForSingleObject(localWorkers[i], Executive, KernelMode, FALSE,
                              NULL); // no timeout — wait indefinitely
        ObDereferenceObject(localWorkers[i]);
      }
    }
    if (localDiscovery) {
      KeWaitForSingleObject(localDiscovery, Executive, KernelMode, FALSE,
                            NULL);
      ObDereferenceObject(localDiscovery);
    }

    // Proxy-PTE state has been removed; nothing to tear down here.
    // CleanupProxyPage();

    DbgPrintEx(0x4d, 0xffffffff,
               "[CR3-IPC] Supervisor (V1): all threads exited — pool safe to "
               "free\n");
  }

  return STATUS_SUCCESS;
}
