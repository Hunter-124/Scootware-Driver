//
// hwid_spoofer.cpp
// HWID obfuscation / spoofing module — implementation.
//
// All patching uses physical memory access (MmMapIoSpaceEx) — NO code hooks,
// safe for KDU-mapped drivers without PatchGuard triggers.
//

#pragma warning(disable: 4996)  // ExAllocatePoolWithTag deprecated — still safe on Win10/11
#pragma warning(disable: 4505)  // unreferenced helpers kept for reference
#include "hwid_spoofer.hpp"
#include <stddef.h> // For offsetof
#include "kdebug.h"  // KIPC_LOG — compiles to no-op in Release

#ifdef _KERNEL_MODE

// min() helper (not always available in kernel mode)
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

// Safe string copy for kernel mode
static inline void hwid_strncpy(char* dest, const char* src, size_t max_len) {
    if (!dest || !src || !max_len) return;
    size_t i = 0;
    while (i < max_len - 1 && src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

// ============================================================================
// Internal helpers — kernel imports
// ============================================================================

extern "C" {
    // ZwQuerySystemInformation is often missing from ntifs.h, so we declare it with correct linkage.
    NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
        ULONG SystemInformationClass, PVOID SystemInformation,
        ULONG SystemInformationLength, PULONG ReturnLength);
}

// ZwOpenKey, ZwQueryValueKey, ZwClose and MmGetPhysicalMemoryRanges 
// are already declared in wdm.h / ntddk.h / ntifs.h.

// SystemInformationClass values we need
#define SystemFirmwareTableInformation 76

// ExAllocatePool2 support (Windows 11 / WDK 10.0.22621+)
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64
#endif

// ============================================================================
// Pool allocation wrapper — safe for Windows 10 and 11
// ============================================================================
//
// ExAllocatePool2 is only available on Windows 11 / WDK 10.0.22621+.
// On older Windows 10 builds, calling it directly will cause an unresolved
// import bugcheck.  This wrapper tries ExAllocatePool2 first via dynamic
// resolution; if unavailable, it falls back to ExAllocatePoolWithTag.
//
// The corresponding free function uses ExFreePoolWithTag so the pool tag
// is always tracked correctly regardless of which path allocated the memory.
//
// NOTE: ExFreePoolWithTag is safe to call on memory allocated by either
// ExAllocatePool2 (which internally tags allocations) or ExAllocatePoolWithTag.

// Function pointer for ExAllocatePool2 (dynamically resolved)
typedef PVOID(NTAPI* fn_ExAllocatePool2)(ULONG64 Flags, SIZE_T Size, ULONG Tag);
static fn_ExAllocatePool2 g_ExAllocatePool2 = NULL;
static BOOLEAN g_ExAllocatePool2_resolved = FALSE;

static PVOID hwid_allocate_pool(SIZE_T Size, ULONG Tag) {
    if (!g_ExAllocatePool2_resolved) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        g_ExAllocatePool2 = (fn_ExAllocatePool2)
            MmGetSystemRoutineAddress(&routineName);
        g_ExAllocatePool2_resolved = TRUE;
    }

    if (g_ExAllocatePool2) {
        return g_ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, Tag);
    }

    // Fallback for Windows 10 and older
    return ExAllocatePoolWithTag(NonPagedPool, Size, Tag);
}

static VOID hwid_free_pool(PVOID Ptr, ULONG Tag) {
    if (Ptr) {
        ExFreePoolWithTag(Ptr, Tag);
    }
}

// SYSTEM_FIRMWARE_TABLE_INFORMATION is already defined in ntddk.h, but we 
// sometimes need a local definition if the header only forward-declares it.
// We use a unique name to avoid redefinition errors (C2011).
typedef struct _HWID_FIRMWARE_TABLE_INFORMATION {
    ULONG   ProviderSignature;
    ULONG   Action;
    ULONG   TableID;
    ULONG   TableBufferLength;
    UCHAR   TableBuffer[1];
} HWID_FIRMWARE_TABLE_INFORMATION, *PHWID_FIRMWARE_TABLE_INFORMATION;

// SMBIOS signatures
#define FIRMWARE_TABLE_PROVIDER_RSMB  0x52534D42  // 'RSMB' — Raw SMBIOS
#define SMBIOS_ENTRY_POINT_ANCHOR     0x5F534D5F  // '_SM_'  (legacy)
#define SMBIOS_ENTRY_POINT_ANCHOR_V3  0x5F534D33  // '_SM3_' (SMBIOS 3.0)

// ============================================================================
// Raw SMBIOS structures (for parsing physical table)
// ============================================================================

#pragma pack(push, 1)

// Legacy SMBIOS Entry Point Structure (32-bit)
typedef struct _SMBIOS_EPS {
    UCHAR   Anchor[4];         // "_SM_"
    UCHAR   Checksum;
    UCHAR   EntryPointLength;
    UCHAR   MajorVersion;
    UCHAR   MinorVersion;
    USHORT  MaxStructureSize;
    UCHAR   EntryPointRevision;
    UCHAR   FormattedArea[5];
    UCHAR   IntermediateAnchor[5]; // "_DMI_"
    UCHAR   IntermediateChecksum;
    USHORT  TableLength;
    ULONG   TableAddress;      // Physical address of SMBIOS table
    USHORT  StructureCount;
    UCHAR   BcdRevision;
} SMBIOS_EPS, *PSMBIOS_EPS;

// SMBIOS 3.0 Entry Point Structure (64-bit)
typedef struct _SMBIOS3_EPS {
    UCHAR   Anchor[5];         // "_SM3_"
    UCHAR   Checksum;
    UCHAR   EntryPointLength;
    UCHAR   MajorVersion;
    UCHAR   MinorVersion;
    UCHAR   Docrev;
    UCHAR   EntryPointRevision;
    UCHAR   Reserved;
    ULONG   TableMaximumSize;
    ULONGLONG TableAddress;    // 64-bit physical address
} SMBIOS3_EPS, *PSMBIOS3_EPS;

// Generic SMBIOS structure header
typedef struct _SMBIOS_HEADER {
    UCHAR   Type;
    UCHAR   Length;
    USHORT  Handle;
} SMBIOS_HEADER, *PSMBIOS_HEADER;

// SMBIOS Type 1: System Information
typedef struct _SMBIOS_TYPE1 {
    UCHAR   Type;
    UCHAR   Length;
    USHORT  Handle;
    UCHAR   Manufacturer;
    UCHAR   ProductName;
    UCHAR   Version;
    UCHAR   SerialNumber;      // String index
    UCHAR   Uuid[16];          // Raw 16-byte UUID (present if Length >= 0x19)
    UCHAR   WakeupType;
    UCHAR   SkuNumber;         // String index
    UCHAR   Family;
} SMBIOS_TYPE1, *PSMBIOS_TYPE1;

// SMBIOS Type 2: Baseboard (Motherboard)
typedef struct _SMBIOS_TYPE2 {
    UCHAR   Type;
    UCHAR   Length;
    USHORT  Handle;
    UCHAR   Manufacturer;
    UCHAR   Product;
    UCHAR   Version;
    UCHAR   SerialNumber;      // String index
    UCHAR   AssetTag;
    UCHAR   FeatureFlags;
    UCHAR   LocationInChassis;
    USHORT  ChassisHandle;
    UCHAR   BoardType;
    UCHAR   NumberOfObjectHandles;
    // Object handles follow...
} SMBIOS_TYPE2, *PSMBIOS_TYPE2;

// SMBIOS Type 3: Chassis
typedef struct _SMBIOS_TYPE3 {
    UCHAR   Type;
    UCHAR   Length;
    USHORT  Handle;
    UCHAR   Manufacturer;
    UCHAR   TypeFlags;
    UCHAR   Version;
    UCHAR   SerialNumber;      // String index
    UCHAR   AssetTagNumber;
    UCHAR   BootupState;
    UCHAR   PowerSupplyState;
    UCHAR   ThermalState;
    UCHAR   SecurityStatus;
    ULONG   OemDefined;
    UCHAR   Height;
    UCHAR   NumberOfPowerCords;
    UCHAR   ContainedElementCount;
    UCHAR   ContainedElementRecordLength;
    // Contained elements follow...
} SMBIOS_TYPE3, *PSMBIOS_TYPE3;

#pragma pack(pop)

// ============================================================================
// Internal module state
// ============================================================================

static HWID_DATA      g_original_hwid = {};   // Saved original values
static HWID_DATA      g_spoofed_hwid  = {};   // Currently applied spoof values
static HWID_STATE     g_hwid_state    = HWID_STATE::HWID_STATE_UNINITIALIZED;

// g_spoof_active uses a volatile CHAR with InterlockedCompareExchange8 for
// atomicity.  0 = FALSE, 1 = TRUE. The volatile qualifier ensures the
// compiler never elides a load even when the variable appears read-only
// to local analysis (as in hwid_is_spoof_active).
static volatile CHAR g_spoof_active = 0;

// FAST_MUTEX serializes all state-machine operations (SaveOriginal,
// ApplySpoof, RestoreOriginals, Reroll, ApplyCustom, Cleanup, Initialize).
// These functions are mutually exclusive so backups, physical mappings,
// and registry writes can never race.
static FAST_MUTEX     g_hwid_lock;

static inline BOOLEAN hwid_is_spoof_active() {
    return (BOOLEAN)(g_spoof_active != 0);
}

// Atomically set g_spoof_active = TRUE. Returns the previous value.
static inline BOOLEAN hwid_set_spoof_active() {
    CHAR prev = InterlockedExchange8(&g_spoof_active, 1);
    return (prev != 0);
}

// Atomically clear g_spoof_active = FALSE. Returns the previous value.
static inline BOOLEAN hwid_clear_spoof_active() {
    CHAR prev = InterlockedExchange8(&g_spoof_active, 0);
    return (prev != 0);
}

// Backups of patched physical pages (for restore)
#define HWID_MAX_PHYSICAL_BACKUPS 8
static struct {
    PVOID    physical_address;
    PVOID    original_bytes;
    SIZE_T   backup_size;
    BOOLEAN  in_use;
} g_physical_backups[HWID_MAX_PHYSICAL_BACKUPS] = {};
static LONG g_backup_count = 0;

// SMBIOS physical patching is done with a map-while-patched-then-unmap
// strategy — no long-lived mapping to firmware memory.  Backups are stored
// in pool memory so hwid_restore_all_backups() can restore without a live
// MmMapIoSpace mapping.

// SMBIOS table content cache (from reliable API query).
// Used as a signature to FIND the physical table location for patching.
static struct {
    BOOLEAN valid;
    PUCHAR  data;
    ULONG   length;
} g_smbios_content_cache = {};

// ============================================================================
// Internal: Simple PRNG (xorshift128+) for generating spoofed values
// ============================================================================

static UINT64 g_xs_state[2] = { 0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL };

static UINT64 xs128p_next() {
    UINT64 s1 = g_xs_state[0];
    UINT64 s0 = g_xs_state[1];
    g_xs_state[0] = s0;
    s1 ^= (s1 << 23);
    s1 ^= (s1 >> 17);
    s1 ^= s0;
    s1 ^= (s0 >> 26);
    g_xs_state[1] = s1;
    return s0 + s1;
}

static void xs128p_seed(UINT64 seed) {
    // Splitmix64 to initialize state
    UINT64 z = seed + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    g_xs_state[0] = z;
    
    z = z + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    g_xs_state[1] = z;
}

// ============================================================================
// Internal: Check if a physical address falls within actual RAM ranges
// ============================================================================

static BOOLEAN hwid_is_ram_address(UINT64 phys_addr, SIZE_T size) {
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return FALSE;

    BOOLEAN found = FALSE;
    UINT64 end_addr = phys_addr + size;

    for (PPHYSICAL_MEMORY_RANGE r = ranges; r->BaseAddress.QuadPart || r->NumberOfBytes.QuadPart; r++) {
        UINT64 range_start = r->BaseAddress.QuadPart;
        UINT64 range_end   = range_start + r->NumberOfBytes.QuadPart;

        // Check if [phys_addr, phys_addr+size) overlaps with this RAM range
        if (phys_addr < range_end && end_addr > range_start) {
            found = TRUE;
            break;
        }
    }

    ExFreePool(ranges);
    return found;
}

// ============================================================================
// Internal: Validate SMBIOS EPS checksums
// ============================================================================
//
// Legacy SMBIOS 2.x EPS (_SM_): checksum is at offset 5, covers the first
// EntryPointLength bytes of the structure. The sum of all bytes in the EPS
// (including the checksum byte itself) must be 0 (mod 256).
//
// SMBIOS 3.0 EPS (_SM3_): checksum is at offset 5, covers the first
// EntryPointLength bytes of the structure. Same additive checksum rule.

static BOOLEAN smbios_validate_eps_checksum(PUCHAR eps_buf, UCHAR entry_point_length) {
    if (!eps_buf || entry_point_length < 16) return FALSE;

    UCHAR sum = 0;
    for (UCHAR i = 0; i < entry_point_length; i++) {
        sum += eps_buf[i];
    }
    return (sum == 0);
}

// ============================================================================
// Internal: Verify SMBIOS table address + size is within a valid RAM range
// ============================================================================

static BOOLEAN smbios_validate_table_in_ram(UINT64 table_phys, SIZE_T table_size) {
    if (!table_phys || !table_size) return FALSE;
    if (table_size > 0x100000) return FALSE; // Sanity: SMBIOS table never > 1 MB

    // The table must be fully contained within a single RAM range
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return FALSE;

    BOOLEAN valid = FALSE;
    UINT64 end_addr = table_phys + table_size;

    for (PPHYSICAL_MEMORY_RANGE r = ranges; r->BaseAddress.QuadPart || r->NumberOfBytes.QuadPart; r++) {
        UINT64 range_start = r->BaseAddress.QuadPart;
        UINT64 range_end   = range_start + r->NumberOfBytes.QuadPart;

        // The entire [table_phys, table_phys+table_size) must be inside this range
        if (table_phys >= range_start && end_addr <= range_end) {
            valid = TRUE;
            break;
        }
    }

    ExFreePool(ranges);
    return valid;
}

// ============================================================================
// Internal: Physical memory read/write using MmMapIoSpaceEx
// ============================================================================

static NTSTATUS hwid_phys_read(UINT64 phys_addr, PVOID buffer, SIZE_T size) {
    if (!phys_addr || !buffer || !size) return STATUS_INVALID_PARAMETER;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(phys_addr & ~0xFFFull);
    SIZE_T offset = (SIZE_T)(phys_addr & 0xFFF);
    SIZE_T map_size = ((offset + size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    // Use PAGE_READONLY for MMIO/device memory to avoid hardware bus errors.
    // Only use PAGE_READWRITE when the target is confirmed to be actual RAM.
    ULONG page_flags = PAGE_READONLY;
    if (hwid_is_ram_address(phys_addr, size)) {
        page_flags = PAGE_READWRITE;
    }

    PVOID mapped = MmMapIoSpaceEx(pa, map_size, page_flags);
    if (!mapped) return STATUS_UNSUCCESSFUL;

    __try {
        memcpy(buffer, (PUCHAR)mapped + offset, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(mapped, map_size);
        return STATUS_ACCESS_VIOLATION;
    }

    MmUnmapIoSpace(mapped, map_size);
    return STATUS_SUCCESS;
}

static NTSTATUS hwid_phys_write(UINT64 phys_addr, PVOID buffer, SIZE_T size) {
    if (!phys_addr || !buffer || !size) return STATUS_INVALID_PARAMETER;

    // Never write to MMIO/device memory — only actual RAM is safe for writes.
    if (!hwid_is_ram_address(phys_addr, size)) {
        KIPC_LOG(
            "[HWID] Rejecting write to non-RAM physical address 0x%llX (size %zu)\n",
            phys_addr, size);
        return STATUS_ACCESS_DENIED;
    }

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(phys_addr & ~0xFFFull);
    SIZE_T offset = (SIZE_T)(phys_addr & 0xFFF);
    SIZE_T map_size = ((offset + size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

    PVOID mapped = MmMapIoSpaceEx(pa, map_size, PAGE_READWRITE);
    if (!mapped) return STATUS_UNSUCCESSFUL;

    __try {
        memcpy((PUCHAR)mapped + offset, buffer, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(mapped, map_size);
        return STATUS_ACCESS_VIOLATION;
    }

    MmUnmapIoSpace(mapped, map_size);
    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: Backup a physical memory region before patching
// ============================================================================

static NTSTATUS hwid_backup_physical(UINT64 phys_addr, SIZE_T size) {
    LONG idx = InterlockedIncrement(&g_backup_count) - 1;
    if (idx >= HWID_MAX_PHYSICAL_BACKUPS) {
        InterlockedDecrement(&g_backup_count);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_physical_backups[idx].original_bytes = hwid_allocate_pool(size, 'DIWH');
    if (!g_physical_backups[idx].original_bytes) {
        InterlockedDecrement(&g_backup_count);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS st = hwid_phys_read(phys_addr, g_physical_backups[idx].original_bytes, size);
    if (!NT_SUCCESS(st)) {
        hwid_free_pool(g_physical_backups[idx].original_bytes, 'DIWH');
        g_physical_backups[idx].original_bytes = NULL;
        InterlockedDecrement(&g_backup_count);
        return st;
    }

    g_physical_backups[idx].physical_address = (PVOID)(ULONG_PTR)phys_addr;
    g_physical_backups[idx].backup_size = size;
    g_physical_backups[idx].in_use = TRUE;

    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: Restore all backed-up physical regions
// ============================================================================

static VOID hwid_restore_all_backups() {
    for (LONG i = 0; i < HWID_MAX_PHYSICAL_BACKUPS; i++) {
        if (g_physical_backups[i].in_use && g_physical_backups[i].original_bytes) {
            hwid_phys_write(
                (UINT64)(ULONG_PTR)g_physical_backups[i].physical_address,
                g_physical_backups[i].original_bytes,
                g_physical_backups[i].backup_size);
            hwid_free_pool(g_physical_backups[i].original_bytes, 'DIWH');
            g_physical_backups[i].original_bytes = NULL;
            g_physical_backups[i].in_use = FALSE;
            g_physical_backups[i].backup_size = 0;
            g_physical_backups[i].physical_address = NULL;
        }
    }
    g_backup_count = 0;

    // NOTE: smbios_patch_hwid() does NOT hold a long-lived mapping, so there
    // is no live MmMapIoSpace to unmap here.  All restore is done via
    // hwid_phys_write() which maps, writes, and unmaps per-page internally.

    // Free SMBIOS content cache
    if (g_smbios_content_cache.data) {
        hwid_free_pool(g_smbios_content_cache.data, 'SBMC');
        g_smbios_content_cache.data = NULL;
    }
    g_smbios_content_cache.valid  = FALSE;
    g_smbios_content_cache.length = 0;
}

// ============================================================================
// Internal: SMBIOS string lookup helper
// ============================================================================

static PCHAR smbios_get_string(PUCHAR table_base, SIZE_T table_size, UCHAR string_index) {
    if (string_index == 0) return NULL;
    if (!table_base || !table_size) return NULL;

    // Strings are at the end of the formatted portion.
    // First, find the end of the formatted structure.
    PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)table_base;
    PUCHAR strings_start = table_base + hdr->Length;
    PUCHAR table_end = table_base + table_size;

    // Compute remaining bytes from string start
    if (strings_start >= table_end) return NULL;
    PUCHAR pos = strings_start;
    SIZE_T remaining = (SIZE_T)(table_end - strings_start);

    UCHAR idx = 1;

    while (idx < string_index && remaining > 0) {
        // Skip this string (until null terminator or end of buffer)
        while (remaining > 0 && *pos != 0) {
            pos++;
            remaining--;
        }
        if (remaining == 0) return NULL; // ran off the end
        pos++;      // skip the null terminator
        remaining--;
        if (remaining == 0) return NULL; // no room for next char
        if (*pos == 0) break; // double null = end of strings
        idx++;
    }

    if (idx != string_index || remaining == 0 || *pos == 0) return NULL;
    return (PCHAR)pos;
}

// ============================================================================
// Internal: Read raw SMBIOS table via Windows API (reliable on all UEFI systems)
// ============================================================================

static NTSTATUS smbios_query_raw_table(PUCHAR* out_buffer, PULONG out_length) {
    if (!out_buffer || !out_length) return STATUS_INVALID_PARAMETER;
    *out_buffer = NULL;
    *out_length = 0;

    NTSTATUS st;
    PUCHAR buf = NULL;
    ULONG table_len = 0;
    ULONG buf_size = 0;
    ULONG alloc_size = 0;

    // Step 1: query required buffer size
    ZwQuerySystemInformation((ULONG)SystemFirmwareTableInformation,
                             NULL, 0, &buf_size);
    if (!buf_size) {
        KIPC_LOG( "[HWID] smbios_query_raw_table: system returned 0 size\n");
        return STATUS_NOT_FOUND;
    }

    // Add 8 KB headroom for the table buffer — some UEFI boards give
    // us buf_size == sizeof(HWID_FIRMWARE_TABLE_INFORMATION) exactly
    // and then fail on the real query because there isn't enough room
    // for the table data.
    alloc_size = buf_size + 0x2000;
    buf = (PUCHAR)hwid_allocate_pool(alloc_size, 'BIWS');
    if (!buf) {
        st = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    RtlZeroMemory(buf, alloc_size);
    { // extra scope so fw doesn't skip over goto
    PHWID_FIRMWARE_TABLE_INFORMATION fw = (PHWID_FIRMWARE_TABLE_INFORMATION)buf;
    fw->ProviderSignature = FIRMWARE_TABLE_PROVIDER_RSMB;  // 'RSMB' = Raw SMBIOS
    // Action = 1 = SystemFirmwareTable_Get (returns table data).
    // Action = 0 = SystemFirmwareTable_Enumerate (returns table-ID list, NOT the data) —
    // setting it to 0 was the previous extraction bug.
    fw->Action = 1;
    fw->TableID = 0;
    fw->TableBufferLength = alloc_size - (ULONG)offsetof(HWID_FIRMWARE_TABLE_INFORMATION, TableBuffer);

    st = ZwQuerySystemInformation((ULONG)SystemFirmwareTableInformation,
                                  buf, alloc_size, &buf_size);

    // The call may succeed with table data following the fixed header.
    // Minimum valid: header + at least 1 structure byte
    if (!NT_SUCCESS(st) || buf_size <= sizeof(HWID_FIRMWARE_TABLE_INFORMATION)) {
        KIPC_LOG(
                   "[HWID] smbios_query_raw_table: ZwQuerySystemInformation failed 0x%X, "
                   "buf_size=%lu\n", st, buf_size);
        st = NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;
        goto cleanup;
    }

    table_len = buf_size - (ULONG)offsetof(HWID_FIRMWARE_TABLE_INFORMATION, TableBuffer);
    if (table_len < 4) {
        st = STATUS_NOT_FOUND;
        goto cleanup;
    }

    *out_buffer = buf;
    *out_length = table_len;
    buf = NULL; // ownership transferred to caller
    st = STATUS_SUCCESS;
    } // end extra scope for fw

cleanup:
    if (buf) {
        hwid_free_pool(buf, 'BIWS');
    }
    return st;
}

// ============================================================================
// Internal: Resolve nt!WmipSMBiosTablePhysicalAddress / nt!WmipSMBiosTableLength
// via byte-pattern scan of ntoskrnl.exe.
//
// These two globals point at Windows's own pool copy of the SMBIOS table —
// the buffer every consumer of EnumSystemFirmwareTables ultimately reads.
// Patching it is what makes spoof values stick (and patching that exact
// physical page is also safe — it's regular pool, not firmware-mapped).
//
// The byte signatures live inside nt!WmipFindSMBiosStructure and have been
// stable from Win10 22H2 (19045) through Win11 25H2.
// ============================================================================

// RTL_PROCESS_MODULES is declared in driver.cpp — redeclare locally so this
// translation unit doesn't pull driver.cpp in.
typedef struct _HWID_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} HWID_RTL_PROCESS_MODULE_INFORMATION, *PHWID_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _HWID_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    HWID_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} HWID_RTL_PROCESS_MODULES, *PHWID_RTL_PROCESS_MODULES;

#define HWID_SystemModuleInformation 11

// Find ntoskrnl.exe base + size via ZwQuerySystemInformation(11).
// The kernel image is always module index 0.
static NTSTATUS hwid_find_ntoskrnl(PVOID* out_base, ULONG* out_size) {
    if (!out_base || !out_size) return STATUS_INVALID_PARAMETER;
    *out_base = NULL;
    *out_size = 0;

    ULONG bytes = 0;
    ZwQuerySystemInformation(HWID_SystemModuleInformation, NULL, 0, &bytes);
    if (!bytes) return STATUS_NOT_FOUND;

    // Headroom — system can grow the list between the size query and the data query.
    ULONG alloc = bytes + 0x1000;
    PHWID_RTL_PROCESS_MODULES mods = (PHWID_RTL_PROCESS_MODULES)
        hwid_allocate_pool(alloc, 'MIWH');
    if (!mods) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = ZwQuerySystemInformation(HWID_SystemModuleInformation, mods, alloc, &bytes);
    if (!NT_SUCCESS(st) || mods->NumberOfModules == 0) {
        hwid_free_pool(mods, 'MIWH');
        return NT_SUCCESS(st) ? STATUS_NOT_FOUND : st;
    }

    // Module[0] is always the kernel image.
    *out_base = mods->Modules[0].ImageBase;
    *out_size = mods->Modules[0].ImageSize;

    KIPC_LOG(
        "[HWID] ntoskrnl base=%p size=0x%X\n", *out_base, *out_size);

    hwid_free_pool(mods, 'MIWH');
    return (*out_base && *out_size) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// Wildcard-aware byte-pattern scan. Pattern: byte values; mask: 'x' = match,
// '?' = wildcard. Returns pointer to first match, or NULL.
static PUCHAR hwid_pattern_scan(PUCHAR base, SIZE_T size,
                                const UCHAR* pattern, const char* mask) {
    if (!base || !pattern || !mask || !size) return NULL;
    SIZE_T pat_len = strlen(mask);
    if (!pat_len || size < pat_len) return NULL;

    SIZE_T limit = size - pat_len;
    for (SIZE_T i = 0; i <= limit; i++) {
        BOOLEAN ok = TRUE;
        for (SIZE_T j = 0; j < pat_len; j++) {
            if (mask[j] == 'x' && base[i + j] != pattern[j]) { ok = FALSE; break; }
        }
        if (ok) return base + i;
    }
    return NULL;
}

// Decode a RIP-relative load. Given the address of an instruction containing
// a 32-bit displacement at `disp_offset` bytes from the instruction start,
// and the total instruction length `instr_len`, returns the absolute target.
//   (target = instr_start + instr_len + sign_extend(disp32))
static UINT64 hwid_resolve_rip_relative(PUCHAR instr, ULONG disp_offset, ULONG instr_len) {
    if (!instr) return 0;
    INT32 disp = *(INT32*)(instr + disp_offset);
    return (UINT64)(instr + instr_len) + (INT64)disp;
}

// Resolve nt!WmipSMBiosTablePhysicalAddress + nt!WmipSMBiosTableLength.
// Returns the physical address of Windows's pool copy of the SMBIOS table,
// and its length, by reading the resolved kernel globals.
static NTSTATUS smbios_resolve_kernel_globals(UINT64* out_phys, SIZE_T* out_size) {
    if (!out_phys || !out_size) return STATUS_INVALID_PARAMETER;
    *out_phys = 0;
    *out_size = 0;

    PVOID nt_base = NULL;
    ULONG nt_size = 0;
    NTSTATUS st = hwid_find_ntoskrnl(&nt_base, &nt_size);
    if (!NT_SUCCESS(st)) return st;

    // Try up to 6 pattern variants to cover Windows 10 20H1 through 11 25H3.
    //
    // Each pattern matches:
    //   mov rX, [WmipSMBiosTablePhys]   ; 48 8B ?? ?? ?? ?? ??
    //   test rX, rX                      ; 48 85 ??
    //   jz short label                   ; 74 ??
    //   mov rY, [WmipSMBiosTableLen]     ; 8B 15 / 8B 0D
    //
    // Registers differ between builds.  Variants:
    //   V0: rcx/edx  (Win10 22H2–Win11 24H2)
    //   V1: rax/eax  (some 25H2 previews)
    //   V2: rdx/eax  (some server builds)
    //   V3: r8/r9d   (Windows 11 25H3+)
    //   V4: rax/edx  (some insider builds)
    //   V5: r8/edx   (Windows 11 26xxx previews)
    struct { const UCHAR* pat; const char* mask; } variants[] = {
        // V0: mov rcx,[...]  test rcx,rcx  jz ...  mov edx,[...]
        { (const UCHAR*)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15",
          "xxx????xxxx?xx" },
        // V1: mov rax,[...]  test rax,rax  jz ...  mov eax,[...]
        { (const UCHAR*)"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x8B\x05",
          "xxx????xxxx?xx" },
        // V2: mov rdx,[...]  test rdx,rdx  jz ...  mov eax,[...]
        { (const UCHAR*)"\x48\x8B\x15\x00\x00\x00\x00\x48\x85\xD2\x74\x00\x8B\x05",
          "xxx????xxxx?xx" },
        // V3: mov r8,[...]   test r8,r8    jz ...  mov r9d,[...]
        { (const UCHAR*)"\x4C\x8B\x05\x00\x00\x00\x00\x4D\x85\xC0\x74\x00\x45\x8B\x0D",
          "xxx????xxxx?xxx" },
        // V4: mov rax,[...]  test rax,rax  jz ...  mov edx,[...]
        { (const UCHAR*)"\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x8B\x15",
          "xxx????xxxx?xx" },
        // V5: mov r8,[...]   test r8,r8    jz ...  mov edx,[...]
        { (const UCHAR*)"\x4C\x8B\x05\x00\x00\x00\x00\x4D\x85\xC0\x74\x00\x8B\x15",
          "xxx????xxxx?xx" },
    };

    PUCHAR hit = NULL;
    int      variant     = -1;
    UINT64   g_phys_addr_va = 0;
    UINT64   g_length_va    = 0;

    for (int vi = 0; vi < ARRAYSIZE(variants); vi++) {
        PUCHAR v = hwid_pattern_scan((PUCHAR)nt_base, nt_size,
                                     variants[vi].pat, variants[vi].mask);
        if (!v) continue;

        // Resolve globals depending on variant
        switch (vi) {
        case 0: // rcx (disp@+3,len=7) ; edx (disp@+12+2,len=6)
            g_phys_addr_va = hwid_resolve_rip_relative(v, 3, 7);
            g_length_va    = hwid_resolve_rip_relative(v + 12, 2, 6);
            break;
        case 1: // rax (disp@+3,len=7) ; eax (disp@+12+2,len=6)
            g_phys_addr_va = hwid_resolve_rip_relative(v, 3, 7);
            g_length_va    = hwid_resolve_rip_relative(v + 12, 2, 6);
            break;
        case 2: // rdx (disp@+3,len=7) ; eax (disp@+12+2,len=6)
            g_phys_addr_va = hwid_resolve_rip_relative(v, 3, 7);
            g_length_va    = hwid_resolve_rip_relative(v + 12, 2, 6);
            break;
        case 3: // r8  (disp@+3,len=7) ; r9d (disp@+14+3,len=8)
            g_phys_addr_va = hwid_resolve_rip_relative(v, 3, 7);
            g_length_va    = hwid_resolve_rip_relative(v + 14, 3, 8);
            break;
        case 4: // rax (disp@+3,len=7) ; edx (disp@+12+2,len=6)
            g_phys_addr_va = hwid_resolve_rip_relative(v, 3, 7);
            g_length_va    = hwid_resolve_rip_relative(v + 12, 2, 6);
            break;
        case 5: // r8  (disp@+3,len=7) ; edx (disp@+12+2,len=6)
            g_phys_addr_va = hwid_resolve_rip_relative(v, 3, 7);
            g_length_va    = hwid_resolve_rip_relative(v + 12, 2, 6);
            break;
        }

        if (g_phys_addr_va && g_length_va) {
            hit = v;
            variant = vi;
            KIPC_LOG(
                "[HWID] resolve_kernel_globals: pattern variant %d matched at offset 0x%llX\n",
                vi, (UINT64)(v - (PUCHAR)nt_base));
            break;
        }
    }

    if (!hit) {
        KIPC_LOG(
            "[HWID] resolve_kernel_globals: no pattern match (tried %zu variants)\n",
            ARRAYSIZE(variants));
        return STATUS_NOT_FOUND;
    }

    // g_phys_addr_va and g_length_va are already resolved per-variant
    // inside the pattern scan loop above.  Fallback for safety:
    if (!g_phys_addr_va || !g_length_va) {
        g_phys_addr_va = hwid_resolve_rip_relative(hit, 3, 7);
        g_length_va    = hwid_resolve_rip_relative(hit + 12, 2, 6);
    }

    if (!g_phys_addr_va || !g_length_va) {
        KIPC_LOG(
            "[HWID] resolve_kernel_globals: bogus RIP-rel resolution\n");
        return STATUS_NOT_FOUND;
    }

    // Bound-check that both globals live inside ntoskrnl.
    UINT64 nt_lo = (UINT64)nt_base;
    UINT64 nt_hi = nt_lo + nt_size;
    if (g_phys_addr_va < nt_lo || g_phys_addr_va >= nt_hi ||
        g_length_va    < nt_lo || g_length_va    >= nt_hi) {
        KIPC_LOG(
            "[HWID] resolve_kernel_globals: globals outside ntoskrnl range\n");
        return STATUS_NOT_FOUND;
    }

    // Read the globals. They're inside ntoskrnl's .data section so direct
    // VA read is safe — wrap in SEH for absolute belt-and-braces.
    UINT64 phys = 0;
    ULONG  len  = 0;
    __try {
        phys = *(volatile UINT64*)g_phys_addr_va;
        len  = *(volatile ULONG*) g_length_va;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KIPC_LOG(
            "[HWID] resolve_kernel_globals: SEH on global read\n");
        return STATUS_ACCESS_VIOLATION;
    }

    if (!phys || len < 0x10 || len > 0x20000) {
        KIPC_LOG(
            "[HWID] resolve_kernel_globals: implausible phys=0x%llX len=0x%X\n",
            phys, len);
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Validate the resolved physical address by reading the first 512 bytes
    // and checking for a valid SMBIOS structure table.  We verify:
    //   1. First structure header: Type 1, Length >= 0x19 (System Info with UUID)
    //   2. End-of-table marker (type 0x7F) found within the table
    // This is far more robust than the old 4-byte check which could pass on
    // random RAM data or MMIO reads.
    {
        ULONG check_size = (len > 512) ? 512 : (ULONG)len;
        if (check_size < 32) {
            KIPC_LOG(
                "[HWID] resolve_kernel_globals: table too small (%lu) at phys 0x%llX\n",
                check_size, phys);
            return STATUS_INVALID_DEVICE_STATE;
        }
        UCHAR check_buf[512];
        if (!NT_SUCCESS(hwid_phys_read(phys, check_buf, check_size))) {
            KIPC_LOG(
                "[HWID] resolve_kernel_globals: read failed at phys 0x%llX\n", phys);
            return STATUS_ACCESS_VIOLATION;
        }

        // Walk structures looking for end marker (0x7F)
        ULONG pos = 0;
        BOOLEAN found_end = FALSE;
        BOOLEAN found_type1 = FALSE;
        while (pos + 4 <= check_size) {
            UCHAR type = check_buf[pos];
            UCHAR st_len = check_buf[pos + 1];
            if (type == 0x7F) { found_end = TRUE; break; }
            if (st_len < 4) break;
            if (type == 1 && st_len >= 0x19) found_type1 = TRUE;
            pos += st_len;
            while (pos < check_size) {
                if (check_buf[pos] == 0 && (pos + 1 >= check_size || check_buf[pos + 1] == 0)) {
                    pos += 2;
                    break;
                }
                pos++;
            }
        }

        if (!found_end || !found_type1) {
            KIPC_LOG(
                "[HWID] resolve_kernel_globals: content validation failed at phys 0x%llX "
                "(found_end=%d found_type1=%d)\n", phys, (int)found_end, (int)found_type1);
            return STATUS_INVALID_DEVICE_STATE;
        }

        KIPC_LOG(
            "[HWID] resolve_kernel_globals: SMBIOS structure table validated at phys 0x%llX\n",
            phys);
    }

    *out_phys = phys;
    *out_size = (SIZE_T)len;

    KIPC_LOG(
        "[HWID] resolved SMBIOS pool copy: phys=0x%llX len=0x%X\n", phys, len);
    return STATUS_SUCCESS;
}

// ============================================================================
// ============================================================================
// Internal: Content-based physical SMBIOS table search (safe fallback)
//
// Uses the cached API table content as a search signature in physical RAM.
// This is immune to ntoskrnl code changes (unlike the kernel globals pattern
// scan) because it matches actual table content, not instruction bytes.
//
// Only searches ranges returned by MmGetPhysicalMemoryRanges() so it never
// touches MMIO or firmware memory — the BSOD source in the old EPS scan.
// ============================================================================

static NTSTATUS smbios_find_physical_by_signature(UINT64* out_phys, SIZE_T* out_size) {
    if (!out_phys || !out_size) return STATUS_INVALID_PARAMETER;
    *out_phys = 0;
    *out_size = 0;

    if (!g_smbios_content_cache.valid || !g_smbios_content_cache.data ||
        g_smbios_content_cache.length < 32) {
        return STATUS_NOT_FOUND;
    }

    PUCHAR sig_data = g_smbios_content_cache.data;
    ULONG  sig_len  = g_smbios_content_cache.length;

    // Use the first 128 bytes as signature — distinctive enough to avoid
    // false positives, short enough to read efficiently.
    ULONG sig_search = (sig_len > 128) ? 128 : sig_len;

    // Read a single 4 KB page candidate, compare first 128 bytes against signature.
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return STATUS_NOT_FOUND;

    NTSTATUS result = STATUS_NOT_FOUND;

    for (PPHYSICAL_MEMORY_RANGE r = ranges;
         r->BaseAddress.QuadPart || r->NumberOfBytes.QuadPart; r++) {
        UINT64 rstart = r->BaseAddress.QuadPart;
        UINT64 rsize  = r->NumberOfBytes.QuadPart;

        if (rsize < 0x10000) continue;

        // Scan up to first 256 MB of each range (SMBIOS pool copy is always
        // in the first few MB of non-paged pool).
        UINT64 rend = rstart + ((rsize > 0x10000000ULL) ? 0x10000000ULL : rsize);

        for (UINT64 pa = rstart; pa + sig_search <= rend; pa += PAGE_SIZE) {
            UCHAR page_buf[256];
            if (!NT_SUCCESS(hwid_phys_read(pa, page_buf, sig_search)))
                continue;

            if (memcmp(page_buf, sig_data, sig_search) == 0) {
                // Validate the full table by reading more and checking
                // for the SMBIOS end-of-table marker (type 0x7F).
                ULONG check_len = (sig_len > 512) ? 512 : sig_len;
                if ((ULONG)(rend - pa) < check_len) check_len = (ULONG)(rend - pa);
                UCHAR check_buf[512];
                if (!NT_SUCCESS(hwid_phys_read(pa, check_buf, check_len)))
                    continue;

                // Walk structures looking for end-of-table marker (0x7F)
                // within a reasonable distance.
                ULONG pos = 0;
                BOOLEAN found_end = FALSE;
                while (pos + 4 <= check_len) {
                    if (check_buf[pos] == 0x7F) { found_end = TRUE; break; }
                    UCHAR struct_len = check_buf[pos + 1];
                    if (struct_len < 4) break;
                    pos += struct_len;
                    // Skip strings
                    while (pos < check_len) {
                        if (check_buf[pos] == 0 && (pos + 1 >= check_len || check_buf[pos + 1] == 0)) {
                            pos += 2;
                            break;
                        }
                        pos++;
                    }
                }

                if (found_end) {
                    *out_phys = pa;
                    *out_size = sig_len;
                    result = STATUS_SUCCESS;
                    KIPC_LOG(
                        "[HWID] Found SMBIOS table via signature scan at phys 0x%llX "
                        "(len=%lu)\n", pa, sig_len);
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    if (ranges) ExFreePool(ranges);
    return result;
}

// ============================================================================
// Internal: find_smbios_table — resolves live SMBIOS physical + size.
//
// Strategy (safe-first):
//   1. Content-based signature scan in physical RAM (no false positives,
//      immune to ntoskrnl version changes).
//   2. Kernel global pattern scan (smbios_resolve_kernel_globals) fallback
//      for when the cache is empty.
//
// The old EPS-scan / physical-memory-firmware-scan is GONE — it was the
// source of the BSODs (writing into firmware-mapped pages or false-positive
// matches in unrelated memory).  Only regular RAM is ever accessed.
// ============================================================================

static NTSTATUS find_smbios_table(UINT64* out_phys, SIZE_T* out_size) {
    NTSTATUS st;

    // Try 1: content-based signature scan (zero false positive rate)
    if (g_smbios_content_cache.valid) {
        st = smbios_find_physical_by_signature(out_phys, out_size);
        if (NT_SUCCESS(st)) return st;
        KIPC_LOG(
            "[HWID] find_smbios_table: signature scan failed, trying kernel globals\n");
    }

    // Try 2: kernel globals pattern scan
    st = smbios_resolve_kernel_globals(out_phys, out_size);
    if (NT_SUCCESS(st)) {
        // Cross-validate against cache if available: read a page at the
        // resolved physical address and compare first 64 bytes.
        if (g_smbios_content_cache.valid && g_smbios_content_cache.data &&
            g_smbios_content_cache.length >= 64) {
            UCHAR verify[64];
            if (NT_SUCCESS(hwid_phys_read(*out_phys, verify, sizeof(verify)))) {
                if (memcmp(verify, g_smbios_content_cache.data, sizeof(verify)) != 0) {
                    KIPC_LOG(
                        "[HWID] find_smbios_table: kernel globals gave wrong content "
                        "(phys 0x%llX) — content mismatch with API data, rejecting!\n",
                        *out_phys);
                    *out_phys = 0;
                    *out_size = 0;
                    return STATUS_INVALID_DEVICE_STATE;
                }
                KIPC_LOG(
                    "[HWID] find_smbios_table: kernel globals content verified against API\n");
            }
        }
        return st;
    }

    return STATUS_NOT_FOUND;
}

// ============================================================================
// Internal: Parse SMBIOS table (from raw buffer) and extract HWID values
// ============================================================================

static NTSTATUS smbios_parse_table(PUCHAR table, ULONG table_len, PHWID_DATA out_data) {
    if (!table || !table_len || !out_data) return STATUS_INVALID_PARAMETER;

    PUCHAR table_end = table + table_len;
    PUCHAR pos = table;

    while (pos + 4 <= table_end) {
        PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)pos;

        if (hdr->Type == 0x7F) break; // End of table marker
        if (hdr->Length < 4) break;   // Bogus structure

        if (pos + hdr->Length > table_end) break;

        // Type 1: System Information
        if (hdr->Type == 1 && hdr->Length >= 0x08) {
            PSMBIOS_TYPE1 t1 = (PSMBIOS_TYPE1)pos;

            // UUID is at offset 8 (present if Length >= 0x19)
            if (hdr->Length >= 0x19) {
                memcpy(out_data->smbios_uuid, t1->Uuid, 16);
            }

            // Serial Number
            if (t1->SerialNumber) {
                PCHAR str = smbios_get_string(pos, (SIZE_T)table_len, t1->SerialNumber);
                if (str) {
                    hwid_strncpy(out_data->smbios_system_serial, str, HWID_MAX_SERIAL_LEN);
                }
            }

            // SKU Number
            if (t1->SkuNumber && hdr->Length >= 0x1B) {
                PCHAR str = smbios_get_string(pos, (SIZE_T)table_len, t1->SkuNumber);
                if (str) {
                    hwid_strncpy(out_data->smbios_system_sku, str, HWID_MAX_SERIAL_LEN);
                }
            }
        }

        // Type 2: Baseboard
        if (hdr->Type == 2 && hdr->Length >= 0x08) {
            PSMBIOS_TYPE2 t2 = (PSMBIOS_TYPE2)pos;
            if (t2->SerialNumber) {
                PCHAR str = smbios_get_string(pos, (SIZE_T)table_len, t2->SerialNumber);
                if (str) {
                    hwid_strncpy(out_data->smbios_baseboard_serial, str, HWID_MAX_SERIAL_LEN);
                }
            }
        }

        // Type 3: Chassis
        if (hdr->Type == 3 && hdr->Length >= 0x09) {
            PSMBIOS_TYPE3 t3 = (PSMBIOS_TYPE3)pos;
            if (t3->SerialNumber) {
                PCHAR str = smbios_get_string(pos, (SIZE_T)table_len, t3->SerialNumber);
                if (str) {
                    hwid_strncpy(out_data->smbios_chassis_serial, str, HWID_MAX_SERIAL_LEN);
                }
            }
        }

        // Skip to next structure:
        // 1. Skip formatted area
        pos += hdr->Length;
        // 2. Skip string table (until double-null)
        while (pos < table_end) {
            if (pos[0] == 0 && pos + 1 < table_end && pos[1] == 0) {
                pos += 2;
                break;
            }
            if (pos[0] == 0 && pos + 1 >= table_end) {
                pos += 1;
                break;
            }
            pos++;
        }
    }

    // Determine which components were found
    BOOLEAN has_uuid = FALSE;
    for (int i = 0; i < 16; i++) {
        if (out_data->smbios_uuid[i] != 0) { has_uuid = TRUE; break; }
    }
    if (has_uuid) out_data->components_present |= HWID_COMPONENT_SMBIOS_UUID;

    if (out_data->smbios_system_serial[0] ||
        out_data->smbios_baseboard_serial[0] ||
        out_data->smbios_chassis_serial[0]) {
        out_data->components_present |= HWID_COMPONENT_SMBIOS_SERIALS;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: Extract HWID values from SMBIOS using the Windows API
// (reliable on all systems — no physical memory scan)
// ============================================================================

static NTSTATUS smbios_extract_hwid(PHWID_DATA out_data) {
    if (!out_data) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(out_data, sizeof(HWID_DATA));

    // Use the API-based query path (works on all UEFI systems)
    PUCHAR table_buf = NULL;
    ULONG table_len = 0;
    NTSTATUS st = smbios_query_raw_table(&table_buf, &table_len);
    if (NT_SUCCESS(st) && table_buf && table_len > 0) {
        st = smbios_parse_table(table_buf, table_len, out_data);
        
        // Cache the raw API table data so physical patch functions can use
        // it as a search signature to find the correct physical addresses.
        if (!g_smbios_content_cache.valid) {
            g_smbios_content_cache.data   = (PUCHAR)hwid_allocate_pool(table_len, 'SBMC');
            if (g_smbios_content_cache.data) {
                memcpy(g_smbios_content_cache.data, table_buf, table_len);
                g_smbios_content_cache.length = table_len;
                g_smbios_content_cache.valid  = TRUE;
                KIPC_LOG(
                    "[HWID] Cached %lu bytes of SMBIOS table for phys signature scan\n",
                    table_len);
            }
        }
        
        hwid_free_pool(table_buf, 'BIWS');
        if (NT_SUCCESS(st)) {
            KIPC_LOG(
                "[HWID] SMBIOS extracted via API: uuid_present=%d serials_present=%d\n",
                (out_data->components_present & HWID_COMPONENT_SMBIOS_UUID) ? 1 : 0,
                (out_data->components_present & HWID_COMPONENT_SMBIOS_SERIALS) ? 1 : 0);
            return STATUS_SUCCESS;
        }
    }

    // Fallback: physical memory scan
    UINT64 table_phys = 0;
    SIZE_T table_size = 0;
    st = find_smbios_table(&table_phys, &table_size);
    if (!NT_SUCCESS(st)) {
        KIPC_LOG( "[HWID] SMBIOS extraction: both API and phys scan failed\n");
        return st;
    }

    if (table_size > 0x100000) table_size = 0x100000;

    // Defense-in-depth: re-validate table is in RAM before mapping
    if (!smbios_validate_table_in_ram(table_phys, table_size)) {
        KIPC_LOG(
            "[HWID] smbios_extract_hwid: table at 0x%llX size %zu not in RAM, rejecting\n",
            table_phys, table_size);
        return STATUS_ACCESS_DENIED;
    }

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = table_phys;
    PVOID mapped = MmMapIoSpaceEx(pa, table_size, PAGE_READWRITE);
    if (!mapped) return STATUS_UNSUCCESSFUL;

    st = smbios_parse_table((PUCHAR)mapped, (ULONG)table_size, out_data);
    MmUnmapIoSpace(mapped, table_size);

    if (NT_SUCCESS(st)) {
        KIPC_LOG(
            "[HWID] SMBIOS extracted via phys fallback\n");
        return STATUS_SUCCESS;
    }

    return st;
}

// ============================================================================
// Internal: Hand-rolled formatters (no RtlStringCbPrintfA dependency)
// ============================================================================
//
// These replace RtlStringCbPrintfA calls so the driver has no unresolved
// import from ntstrsafe.lib — important for manual-mapped (KDU) builds.
// All helpers write up to max_chars-1 characters and null-terminate.

// Write hex nibbles of 'value' into buf, writing exactly 'digits' nibbles
// (e.g. digits=8 writes 8 hex chars). Returns pointer past last written char.
static PCHAR hwid_hex_write(PCHAR buf, UINT64 value, int digits) {
    static const CHAR hex[] = "0123456789ABCDEF";
    for (int i = digits - 1; i >= 0; i--) {
        buf[i] = hex[value & 0xF];
        value >>= 4;
    }
    return buf + digits;
}

// Format: "SN" + 16 hex digits
static void hwid_format_serial64(PCHAR out, SIZE_T max_chars,
                                  UINT64 hi, UINT64 lo, const char* prefix) {
    if (max_chars < 3) { if (max_chars) *out = '\0'; return; }
    PCHAR p = out;
    SIZE_T remaining = max_chars;
    // Write prefix
    while (*prefix && remaining > 1) { *p++ = *prefix++; remaining--; }
    // Write hi as 8 hex digits, lo as 8 hex digits
    if (remaining > 8) { p = hwid_hex_write(p, hi, 8); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 8) { p = hwid_hex_write(p, lo, 8); }
    *p = '\0';
}

// Format: "{%08X-%04X-%04X-%04X-%04X%08X}"
static void hwid_format_guid(PCHAR out, SIZE_T max_chars,
                              UINT32 d1, UINT16 d2, UINT16 d3,
                              UINT16 d4, UINT16 d5_hi, UINT32 d5_lo) {
    if (max_chars < 2) { if (max_chars) *out = '\0'; return; }
    PCHAR p = out;
    SIZE_T remaining = max_chars;
    *p++ = '{'; remaining--;
    if (remaining > 8) { p = hwid_hex_write(p, d1, 8); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 1) { *p++ = '-'; remaining--; }
    if (remaining > 4) { p = hwid_hex_write(p, d2, 4); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 1) { *p++ = '-'; remaining--; }
    if (remaining > 4) { p = hwid_hex_write(p, d3, 4); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 1) { *p++ = '-'; remaining--; }
    if (remaining > 4) { p = hwid_hex_write(p, d4, 4); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 1) { *p++ = '-'; remaining--; }
    if (remaining > 4) { p = hwid_hex_write(p, d5_hi, 4); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 1) { p = hwid_hex_write(p, d5_lo, 8); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 1) { *p++ = '}'; }
    *p = '\0';
}

// Format: "%02X-%02X-%02X-%02X-%02X-%02X"
static void hwid_format_mac(PCHAR out, SIZE_T max_chars, UINT8 b0, UINT8 b1, UINT8 b2, UINT8 b3, UINT8 b4, UINT8 b5) {
    if (max_chars < 3) { if (max_chars) *out = '\0'; return; }
    PCHAR p = out;
    SIZE_T remaining = max_chars;
    UINT8 bytes[6] = { b0, b1, b2, b3, b4, b5 };
    for (int i = 0; i < 6; i++) {
        if (remaining > 2) { p = hwid_hex_write(p, bytes[i], 2); remaining = max_chars - (SIZE_T)(p - out); }
        if (i < 5 && remaining > 1) { *p++ = '-'; remaining--; }
    }
    *p = '\0';
}

// Format: "%04X-%04X"
static void hwid_format_vol_serial(PCHAR out, SIZE_T max_chars, UINT16 hi, UINT16 lo) {
    if (max_chars < 5) { if (max_chars) *out = '\0'; return; }
    PCHAR p = out;
    SIZE_T remaining = max_chars;
    if (remaining > 4) { p = hwid_hex_write(p, hi, 4); remaining = max_chars - (SIZE_T)(p - out); }
    if (remaining > 1) { *p++ = '-'; remaining--; }
    if (remaining > 4) { p = hwid_hex_write(p, lo, 4); }
    *p = '\0';
}

// ============================================================================
// Internal: Generate random spoofed HWID values
// ============================================================================

static VOID generate_spoofed_hwid(PHWID_DATA out_data, UINT64 seed, UINT32 components) {
    RtlZeroMemory(out_data, sizeof(HWID_DATA));

    if (seed) {
        xs128p_seed(seed);
    } else {
        // Use __rdtsc for seed.  KeQueryPerformanceCounter is not called
        // anywhere during driver load on the KDU-mapped image, so its
        // IAT slot can be left unresolved by the manual mapper and the
        // first call bugchecks with an execute-AV at the file-time
        // name-hint RVA.  __rdtsc is a CPU instruction — no IAT.
        xs128p_seed(((UINT64)__rdtsc()) ^ (UINT64)(ULONG_PTR)out_data);
    }

    // Generate GUID characters: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    static const CHAR hex_chars[] = "0123456789ABCDEF";

    // Spoofed SMBIOS UUID
    if (components & HWID_COMPONENT_SMBIOS_UUID) {
        for (int i = 0; i < 16; i++) {
            out_data->smbios_uuid[i] = (UCHAR)(xs128p_next() & 0xFF);
        }
        // Set version/variant bits for valid UUID v4 format
        out_data->smbios_uuid[6] = (out_data->smbios_uuid[6] & 0x0F) | 0x40; // version 4
        out_data->smbios_uuid[8] = (out_data->smbios_uuid[8] & 0x3F) | 0x80; // variant 1
    }

    // Spoofed serials
    if (components & HWID_COMPONENT_SMBIOS_SERIALS) {
        UINT64 s1 = xs128p_next();
        UINT64 s2 = xs128p_next();
        hwid_format_serial64(out_data->smbios_system_serial, HWID_MAX_SERIAL_LEN, s1, s2, "SN");
        s1 = xs128p_next();
        s2 = xs128p_next();
        hwid_format_serial64(out_data->smbios_baseboard_serial, HWID_MAX_SERIAL_LEN, s1, s2, "MB");
        s1 = xs128p_next();
        s2 = xs128p_next();
        hwid_format_serial64(out_data->smbios_chassis_serial, HWID_MAX_SERIAL_LEN, s1, s2, "CS");
        s1 = xs128p_next();
        hwid_format_serial64(out_data->smbios_system_sku, HWID_MAX_SERIAL_LEN, s1, 0, "SKU");
    }

    // Spoofed MachineGuid
    if (components & HWID_COMPONENT_REGISTRY_MACHINEGUID) {
        UINT64 g1 = xs128p_next();
        UINT64 g2 = xs128p_next();
        hwid_format_guid(out_data->machine_guid, HWID_MAX_GUID_LEN,
            (UINT32)(g1 >> 32), (UINT16)(g1 >> 16), (UINT16)(g1),
            (UINT16)(g2 >> 48), (UINT16)(g2 >> 32), (UINT32)(g2));
    }

    // Spoofed MAC
    if (components & HWID_COMPONENT_MAC_ADDRESS) {
        UINT64 m = xs128p_next();
        // Ensure locally administered, unicast address (bit 1 of first octet = 1, bit 0 = 0)
        UINT8 mac0 = (UINT8)((m & 0xFC) | 0x02);
        UINT8 mac1 = (UINT8)((m >> 8) & 0xFF);
        UINT8 mac2 = (UINT8)((m >> 16) & 0xFF);
        UINT8 mac3 = (UINT8)((m >> 24) & 0xFF);
        UINT8 mac4 = (UINT8)((m >> 32) & 0xFF);
        UINT8 mac5 = (UINT8)((m >> 40) & 0xFF);

        hwid_format_mac(out_data->mac_address, HWID_MAX_MAC_LEN,
                        mac0, mac1, mac2, mac3, mac4, mac5);
    }

    // Spoofed Volume Serial
    if (components & HWID_COMPONENT_VOLUME_SERIAL) {
        UINT32 vs_hi = (UINT32)(xs128p_next() & 0xFFFF);
        UINT32 vs_lo = (UINT32)(xs128p_next() & 0xFFFF);
        hwid_format_vol_serial(out_data->volume_serial, HWID_MAX_VOLUME_LEN,
                               (UINT16)vs_hi, (UINT16)vs_lo);
    }

    out_data->components_present = components;
}

// ============================================================================
// Internal: Patch SMBIOS table in physical memory
// ============================================================================

static NTSTATUS smbios_patch_hwid(PHWID_DATA spoof_data) {
    if (!spoof_data) return STATUS_INVALID_PARAMETER;

    UINT64 table_phys = 0;
    SIZE_T table_size = 0;
    NTSTATUS st = find_smbios_table(&table_phys, &table_size);
    if (!NT_SUCCESS(st)) return st;

    if (table_size > 0x100000) table_size = 0x100000;

    // Defense-in-depth: re-validate table is in RAM before mapping for write
    if (!smbios_validate_table_in_ram(table_phys, table_size)) {
        KIPC_LOG(
            "[HWID] smbios_patch_hwid: table at 0x%llX size %zu not in RAM, rejecting\n",
            table_phys, table_size);
        return STATUS_ACCESS_DENIED;
    }

    // Backup entire table into pool memory — this is our restore point.
    st = hwid_backup_physical(table_phys, table_size);
    if (!NT_SUCCESS(st)) {
        KIPC_LOG( "[HWID] Failed to backup SMBIOS table\n");
        return st;
    }

    // Cross-validate the physical content against known-good API data before
    // writing.  If the physical address is wrong (false-positive from kernel
    // globals pattern), we read-back garbage that won't match and abort
    // BEFORE corrupting anything.
    if (g_smbios_content_cache.valid && g_smbios_content_cache.data &&
        g_smbios_content_cache.length >= 64) {
        UCHAR verify[64];
        if (NT_SUCCESS(hwid_phys_read(table_phys, verify, sizeof(verify)))) {
            if (memcmp(verify, g_smbios_content_cache.data, sizeof(verify)) != 0) {
                KIPC_LOG(
                    "[HWID] smbios_patch_hwid: CONTENT MISMATCH at phys 0x%llX — "
                    "wrong address! Aborting write to prevent corruption.\n",
                    table_phys);
                hwid_restore_all_backups();
                return STATUS_INVALID_DEVICE_STATE;
            }
            KIPC_LOG(
                "[HWID] smbios_patch_hwid: physical content verified against API cache\n");
        }
    }

    // Map the table into system space, patch it, then unmap immediately.
    // We do NOT hold a long-lived mapping to firmware memory — the backup
    // is stored in pool, so restore works without a live MmMapIoSpace.
    PHYSICAL_ADDRESS sm_pa;
    sm_pa.QuadPart = table_phys;
    PVOID mapped = MmMapIoSpaceEx(sm_pa, table_size, PAGE_READWRITE);
    if (!mapped) {
        // Don't leak the backup entry — hwid_backup_physical pushed one.
        // Clear it since we can't proceed.  On restore the array entry still
        // has valid data, so this is safe — we just won't have patched anything.
        KIPC_LOG(
            "[HWID] MmMapIoSpaceEx failed for SMBIOS patch (keeping backup)\n");
        // The backup is still valid; this just means patch didn't happen.
        // On restore, the original bytes will be written back (no-op restore).
        return STATUS_UNSUCCESSFUL;
    }

    PUCHAR table = (PUCHAR)mapped;
    PUCHAR table_end = table + table_size;

    // Helper: patch a single SMBIOS string in place by index.
    auto patch_string_by_index = [&](PUCHAR struct_start, UCHAR struct_len,
                                     UCHAR string_index, PCHAR spoof_value) -> void {
        if (!string_index || !spoof_value || !spoof_value[0]) return;
        if (!(spoof_data->components_present & HWID_COMPONENT_SMBIOS_SERIALS)) return;

        PCHAR sp = (PCHAR)struct_start + struct_len;
        UCHAR si = 1;
        while (sp < (PCHAR)table_end && si <= string_index) {
            if (si == string_index) {
                SIZE_T orig_len = strlen(sp);
                SIZE_T spoof_len = strlen(spoof_value);
                SIZE_T copy_len = min(orig_len, spoof_len);
                if (copy_len > 0) {
                    memcpy(sp, spoof_value, copy_len);
                    if (spoof_len < orig_len) sp[copy_len] = '\0';
                    KIPC_LOG(
                        "[HWID] Patched serial string idx=%u (orig_len=%zu, copy=%zu)\n",
                        string_index, orig_len, copy_len);
                }
                return;
            }
            while (*sp) sp++;
            sp++;
            si++;
        }
    };

    // Walk and patch
    PUCHAR pos = table;
    while (pos < table_end) {
        PSMBIOS_HEADER hdr = (PSMBIOS_HEADER)pos;
        if (hdr->Type == 0x7F) break;
        if (hdr->Length < 4) break;

        // Type 1: System Information — patch UUID and serial
        if (hdr->Type == 1 && hdr->Length >= 0x08) {
            PSMBIOS_TYPE1 t1 = (PSMBIOS_TYPE1)pos;

            // Patch UUID (if structure has it)
            if (hdr->Length >= 0x19 && (spoof_data->components_present & HWID_COMPONENT_SMBIOS_UUID)) {
                memcpy(t1->Uuid, spoof_data->smbios_uuid, 16);
                KIPC_LOG( "[HWID] SMBIOS UUID patched\n");
            }

            // Patch system serial
            patch_string_by_index(pos, hdr->Length, t1->SerialNumber,
                                  spoof_data->smbios_system_serial);

            // Patch SKU (if present)
            if (hdr->Length >= 0x1B && t1->SkuNumber) {
                patch_string_by_index(pos, hdr->Length, t1->SkuNumber,
                                      spoof_data->smbios_system_sku);
            }
        }

        // Type 2: Baseboard — patch serial
        if (hdr->Type == 2 && hdr->Length >= 0x08) {
            PSMBIOS_TYPE2 t2 = (PSMBIOS_TYPE2)pos;
            patch_string_by_index(pos, hdr->Length, t2->SerialNumber,
                                  spoof_data->smbios_baseboard_serial);
        }

        // Type 3: Chassis — patch serial
        if (hdr->Type == 3 && hdr->Length >= 0x09) {
            PSMBIOS_TYPE3 t3 = (PSMBIOS_TYPE3)pos;
            patch_string_by_index(pos, hdr->Length, t3->SerialNumber,
                                  spoof_data->smbios_chassis_serial);
        }

        // Skip to next structure
        pos += hdr->Length;
        while (pos < table_end) {
            if (pos[0] == 0 && (pos + 1 >= table_end || pos[1] == 0)) {
                pos += 2;
                break;
            }
            pos++;
        }
    }

    // Allocate a snapshot of the *patched* table contents BEFORE unmapping.
    // We need this for the mssmbios registry write below — ZwSetValueKey at
    // PASSIVE_LEVEL can page-fault on an MmMapIoSpace mapping if the buffer
    // backing it is touched while paging is in flight, so we copy out first.
    PUCHAR snap = (PUCHAR)hwid_allocate_pool(table_size, 'NSWH');
    if (snap) {
        __try {
            memcpy(snap, mapped, table_size);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            hwid_free_pool(snap, 'NSWH');
            snap = NULL;
        }
    }

    // Unmap immediately — no long-lived mapping to firmware memory.
    MmUnmapIoSpace(mapped, table_size);

    // ── Mirror the patched table into the mssmbios registry cache ──
    // Some WMI / firmware-table consumers read from
    // HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData
    // instead of (or in addition to) the in-memory pool copy. Updating both
    // is what Example-2 does, and matches what most reputable spoofers do.
    if (snap) {
        HANDLE hMs = NULL;
        UNICODE_STRING msPath;
        RtlInitUnicodeString(&msPath,
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data");
        OBJECT_ATTRIBUTES oaMs;
        InitializeObjectAttributes(&oaMs, &msPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        NTSTATUS ms_st = ZwOpenKey(&hMs, KEY_WRITE, &oaMs);
        if (NT_SUCCESS(ms_st)) {
            UNICODE_STRING vn;
            RtlInitUnicodeString(&vn, L"SMBiosData");
            ms_st = ZwSetValueKey(hMs, &vn, 0, REG_BINARY, snap, (ULONG)table_size);
            ZwClose(hMs);
            KIPC_LOG(
                "[HWID] mssmbios SMBiosData write: 0x%X (%zu bytes)\n",
                ms_st, table_size);
        } else {
            KIPC_LOG(
                "[HWID] mssmbios key open failed: 0x%X (non-fatal)\n", ms_st);
        }

        hwid_free_pool(snap, 'NSWH');
    }

    KIPC_LOG( "[HWID] SMBIOS physical table patched and unmapped\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Internal: Find and patch registry MachineGuid in kernel memory
// ============================================================================

// The MachineGuid value lives in:
//   HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
//
// In kernel memory, the registry is cached via the Configuration Manager (Cm).
// The CmKeyControlBlock for the Cryptography key contains a cached value index.
// The actual data is in the registry hive file's in-memory representation.
//
// For a manual-mapped driver, the simplest approach is:
//   1. Open the registry key via ZwOpenKey
//   2. Query the value via ZwQueryValueKey to get the current value
//   3. The kernel caches this data — we need to find the physical page
//      that backs this cache and patch it.
//
// This is complex. For now, we use the straightforward approach: capture via
// the normal kernel API and apply spoofed values by writing to the registry
// directly (ZwSetValueKey).  This avoids PatchGuard entirely.
//
// DO NOT attempt to inline-hook NtQueryValueKey here — from a KDU-mapped
// driver, PatchGuard's periodic integrity scan detects the modified code
// and bugchecks CRITICAL_STRUCTURE_CORRUPTION (0x109) within minutes.
// The registry-write approach is the correct one for this architecture.

static NTSTATUS registry_capture_machineguid(PHWID_DATA out_data) {
    if (!out_data) return STATUS_INVALID_PARAMETER;

    // Use kernel registry API to read MachineGuid
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");

    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) {
        KIPC_LOG( "[HWID] ZwOpenKey(Cryptography) failed: 0x%X\n", st);
        return st;
    }

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"MachineGuid");

    UCHAR buf[512] = {};
    ULONG buf_size = sizeof(buf);
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buf;

    st = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, buf, buf_size, &buf_size);
    ZwClose(hKey);

    if (NT_SUCCESS(st) && kvpi->Type == REG_SZ && kvpi->DataLength > 0) {
        // Registry returns REG_SZ as UTF-16LE. Convert to ANSI for our CHAR buffer.
        UNICODE_STRING wide_str;
        wide_str.Buffer        = (PWCH)kvpi->Data;
        wide_str.Length        = (USHORT)min((ULONG)kvpi->DataLength, (ULONG)(sizeof(buf) - offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data)));
        wide_str.MaximumLength = wide_str.Length;

        ANSI_STRING ansi_str;
        RtlZeroMemory(&ansi_str, sizeof(ansi_str));
        NTSTATUS conv_st = RtlUnicodeStringToAnsiString(&ansi_str, &wide_str, TRUE);
        if (NT_SUCCESS(conv_st) && ansi_str.Buffer && ansi_str.Length > 0) {
            SIZE_T copy_len = min((SIZE_T)ansi_str.Length, (SIZE_T)HWID_MAX_GUID_LEN - 1);
            memcpy(out_data->machine_guid, ansi_str.Buffer, copy_len);
            out_data->machine_guid[copy_len] = '\0';
            out_data->components_present |= HWID_COMPONENT_REGISTRY_MACHINEGUID;
            KIPC_LOG( "[HWID] Captured MachineGuid: %s\n", out_data->machine_guid);
            RtlFreeAnsiString(&ansi_str);
            return STATUS_SUCCESS;
        }
        if (ansi_str.Buffer) RtlFreeAnsiString(&ansi_str);
        return conv_st;
    }

    return st;
}

// ============================================================================
// Internal: Capture MAC address from registry
// Enumerates all network adapters under the NDIS class GUID and reads
// the PermanentAddress (hardware MAC, always present) from the first
// physical adapter found (skipping virtual/WAN/miniport adapters).
// ============================================================================

// Helper: check if a registry value exists and read it (ANSI).
static NTSTATUS read_reg_string_ansi(HANDLE hKey, PCWSTR value_name,
                                     PCHAR out_buf, ULONG max_bytes) {
    UNICODE_STRING vn;
    RtlInitUnicodeString(&vn, value_name);

    UCHAR tmp[512] = {};
    ULONG tmp_size = sizeof(tmp);
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)tmp;

    NTSTATUS st = ZwQueryValueKey(hKey, &vn, KeyValuePartialInformation,
                                  tmp, tmp_size, &tmp_size);
    if (!NT_SUCCESS(st) || kvpi->DataLength == 0) return STATUS_NOT_FOUND;

    // Convert UTF-16LE REG_SZ to ANSI
    if (kvpi->Type == REG_SZ) {
        UNICODE_STRING ws;
        ws.Buffer        = (PWCH)kvpi->Data;
        ws.Length        = (USHORT)min((ULONG)kvpi->DataLength, (ULONG)(sizeof(tmp) - offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data)));
        ws.MaximumLength = ws.Length;

        ANSI_STRING as;
        RtlZeroMemory(&as, sizeof(as));
        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&as, &ws, TRUE)) &&
            as.Buffer && as.Length > 0) {
            SIZE_T copy = min((SIZE_T)as.Length, (SIZE_T)max_bytes - 1);
            memcpy(out_buf, as.Buffer, copy);
            out_buf[copy] = '\0';
            RtlFreeAnsiString(&as);
            return STATUS_SUCCESS;
        }
        if (as.Buffer) RtlFreeAnsiString(&as);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS capture_mac_address(PHWID_DATA out_data) {
    if (!out_data) return STATUS_INVALID_PARAMETER;

    // Network-adapter class GUID. Subkeys under it are NNNN (0000, 0001, 0002, ...).
    static const WCHAR* class_path =
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4D36E972-E325-11CE-BFC1-08002BE10318}";

    UNICODE_STRING classKey;
    RtlInitUnicodeString(&classKey, class_path);
    OBJECT_ATTRIBUTES oaClass;
    InitializeObjectAttributes(&oaClass, &classKey,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hClass = NULL;
    NTSTATUS st = ZwOpenKey(&hClass, KEY_READ, &oaClass);
    if (!NT_SUCCESS(st)) {
        KIPC_LOG(
            "[HWID] capture_mac: open class key failed 0x%X\n", st);
        return st;
    }

    // Buffer big enough for KEY_BASIC_INFORMATION + a 4-char NNNN name.
    UCHAR keyInfoBuf[256];
    ULONG resultLen = 0;
    BOOLEAN got_mac = FALSE;

    // Enumerate every subkey, regardless of index ordering. Real adapter is
    // typically 0007–0020 once virtual/WAN/loopback adapters take low slots.
    for (ULONG idx = 0; idx < 256 && !got_mac; idx++) {
        RtlZeroMemory(keyInfoBuf, sizeof(keyInfoBuf));
        st = ZwEnumerateKey(hClass, idx, KeyBasicInformation,
                            keyInfoBuf, sizeof(keyInfoBuf), &resultLen);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(st)) {
            // BUFFER_OVERFLOW or BUFFER_TOO_SMALL — name is longer than NNNN
            // (would only happen for the "Properties" subkey on some systems).
            // Just skip.
            continue;
        }

        PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)keyInfoBuf;

        // Adapter subkeys are 4 numeric digits.
        if (kbi->NameLength != 4 * sizeof(WCHAR)) continue;
        BOOLEAN all_digits = TRUE;
        for (ULONG c = 0; c < 4; c++) {
            WCHAR ch = kbi->Name[c];
            if (ch < L'0' || ch > L'9') { all_digits = FALSE; break; }
        }
        if (!all_digits) continue;

        // Build the full subkey path.
        WCHAR full_path[256];
        SIZE_T base_len = wcslen(class_path);
        if (base_len + 6 > ARRAYSIZE(full_path)) continue;
        memcpy(full_path, class_path, base_len * sizeof(WCHAR));
        full_path[base_len] = L'\\';
        full_path[base_len + 1] = kbi->Name[0];
        full_path[base_len + 2] = kbi->Name[1];
        full_path[base_len + 3] = kbi->Name[2];
        full_path[base_len + 4] = kbi->Name[3];
        full_path[base_len + 5] = L'\0';

        HANDLE hAdapter = NULL;
        UNICODE_STRING aPath;
        RtlInitUnicodeString(&aPath, full_path);
        OBJECT_ATTRIBUTES oaA;
        InitializeObjectAttributes(&oaA, &aPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        if (!NT_SUCCESS(ZwOpenKey(&hAdapter, KEY_READ, &oaA))) continue;

        // Filter out virtual/WAN/miniport adapters by DriverDesc.
        CHAR desc[128] = {};
        BOOLEAN skip = FALSE;
        if (NT_SUCCESS(read_reg_string_ansi(hAdapter, L"DriverDesc",
                                            desc, sizeof(desc)))) {
            if (strstr(desc, "Virtual") || strstr(desc, "WAN") ||
                strstr(desc, "Miniport") || strstr(desc, "VPN") ||
                strstr(desc, "TAP") || strstr(desc, "Loopback") ||
                strstr(desc, "Bluetooth") || strstr(desc, "Hyper-V") ||
                strstr(desc, "Kernel Debug") || strstr(desc, "Tunneling") ||
                strstr(desc, "6to4") || strstr(desc, "Teredo")) {
                skip = TRUE;
            }
        }

        if (skip) {
            ZwClose(hAdapter);
            continue;
        }

        // Try, in order: NetworkAddress (user-set override, persists what we'd
        // spoof anyway), PermanentAddress (hardware MAC), then a REG_BINARY
        // PhysicalAddress fallback.
        CHAR mac_buf[HWID_MAX_MAC_LEN] = {};
        BOOLEAN found = FALSE;

        if (NT_SUCCESS(read_reg_string_ansi(hAdapter, L"NetworkAddress",
                                            mac_buf, sizeof(mac_buf))) && mac_buf[0]) {
            found = TRUE;
        } else if (NT_SUCCESS(read_reg_string_ansi(hAdapter, L"PermanentAddress",
                                                   mac_buf, sizeof(mac_buf))) && mac_buf[0]) {
            found = TRUE;
        } else {
            // PhysicalAddress is REG_BINARY (6 raw bytes).
            UCHAR pbuf[256] = {};
            ULONG plen = sizeof(pbuf);
            UNICODE_STRING pn;
            RtlInitUnicodeString(&pn, L"PhysicalAddress");
            PKEY_VALUE_PARTIAL_INFORMATION pkv = (PKEY_VALUE_PARTIAL_INFORMATION)pbuf;
            if (NT_SUCCESS(ZwQueryValueKey(hAdapter, &pn, KeyValuePartialInformation,
                                           pbuf, plen, &plen)) &&
                pkv->Type == REG_BINARY && pkv->DataLength >= 6) {
                UINT8* pm = (UINT8*)pkv->Data;
                hwid_format_mac(out_data->mac_address, HWID_MAX_MAC_LEN,
                                pm[0], pm[1], pm[2], pm[3], pm[4], pm[5]);
                out_data->components_present |= HWID_COMPONENT_MAC_ADDRESS;
                ZwClose(hAdapter);
                ZwClose(hClass);
                KIPC_LOG(
                    "[HWID] Captured MAC from PhysicalAddress (subkey %04u): %s (%s)\n",
                    idx, out_data->mac_address, desc);
                return STATUS_SUCCESS;
            }
        }

        ZwClose(hAdapter);

        if (found) {
            // Normalize "0250F2517406" → "02-50-F2-51-74-06"; pass through
            // dashed/colon-separated forms unchanged.
            SIZE_T len = strlen(mac_buf);
            if (len == 12) {
                CHAR dash_mac[HWID_MAX_MAC_LEN];
                PCHAR dm = dash_mac;
                SIZE_T rem = sizeof(dash_mac);
                for (int bi = 0; bi < 6; bi++) {
                    if (rem > 2) {
                        *dm++ = mac_buf[bi * 2];
                        *dm++ = mac_buf[bi * 2 + 1];
                        rem -= 2;
                    }
                    if (bi < 5 && rem > 1) { *dm++ = '-'; rem--; }
                }
                *dm = '\0';
                hwid_strncpy(out_data->mac_address, dash_mac, HWID_MAX_MAC_LEN);
            } else {
                hwid_strncpy(out_data->mac_address, mac_buf, HWID_MAX_MAC_LEN);
            }
            out_data->components_present |= HWID_COMPONENT_MAC_ADDRESS;
            KIPC_LOG(
                "[HWID] Captured MAC: %s (subkey %04u, %s)\n",
                out_data->mac_address, idx, desc);
            got_mac = TRUE;
        }
    }

    ZwClose(hClass);

    if (got_mac) return STATUS_SUCCESS;

    KIPC_LOG( "[HWID] MAC capture: no physical adapter found\n");
    return STATUS_NOT_FOUND;
}

// ============================================================================
// Internal: Capture C: drive volume serial number
// ============================================================================

static NTSTATUS capture_volume_serial(PHWID_DATA out_data) {
    if (!out_data) return STATUS_INVALID_PARAMETER;

    // Open the C: drive and query its volume serial via FileFsVolumeInformation.
    // Try multiple paths for kernel-mode volume access
    static const WCHAR* vol_paths[] = {
        L"\\GLOBAL??\\C:",
        L"\\??\\C:",
        L"\\Device\\HarddiskVolume1",  // fallback for some SKUs
    };

    HANDLE hVol = NULL;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    IO_STATUS_BLOCK ioStatus;
    for (int vi = 0; vi < ARRAYSIZE(vol_paths); vi++) {
        UNICODE_STRING volPath;
        RtlInitUnicodeString(&volPath, vol_paths[vi]);
        OBJECT_ATTRIBUTES oa2;
        InitializeObjectAttributes(&oa2, &volPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        st = ZwCreateFile(&hVol, SYNCHRONIZE | FILE_READ_DATA, &oa2, &ioStatus,
                          NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(st)) break;
    }
    if (!NT_SUCCESS(st)) {
        KIPC_LOG( "[HWID] ZwCreateFile(C:) failed: 0x%X\n", st);
        return st;
    }

    // Query FileFsVolumeInformation
    struct {
        FILE_FS_VOLUME_INFORMATION info;
        WCHAR label[64];
    } vol_info;
    RtlZeroMemory(&vol_info, sizeof(vol_info));

    st = ZwQueryVolumeInformationFile(hVol, &ioStatus, &vol_info, sizeof(vol_info),
                                      FileFsVolumeInformation);
    ZwClose(hVol);

    if (NT_SUCCESS(st)) {
        ULONG serial = vol_info.info.VolumeSerialNumber;
        hwid_format_vol_serial(out_data->volume_serial, HWID_MAX_VOLUME_LEN,
                               (UINT16)((serial >> 16) & 0xFFFF), (UINT16)(serial & 0xFFFF));
        out_data->components_present |= HWID_COMPONENT_VOLUME_SERIAL;
        KIPC_LOG( "[HWID] Captured volume serial: %s\n", out_data->volume_serial);
        return STATUS_SUCCESS;
    }

    return st;
}

// ============================================================================
// Registry persistence for HWID spoofed values
// Stores/loads the spoofed HWID data to a registry key so it survives
// driver reloads (usermode IPC restart without reloading driver).
//
// Path: HKLM\SOFTWARE\Scootware\HWID
// Using SOFTWARE instead of Services avoids ACL mismatch on systems where
// the Services key has stricter permissions than a non-service driver can
// open for write.
// ============================================================================

#define HWID_PERSIST_KEY_PATH L"\\Registry\\Machine\\SOFTWARE\\Scootware\\HWID"

static NTSTATUS hwid_save_to_registry(PHWID_DATA data) {
    if (!data) return STATUS_INVALID_PARAMETER;

    NTSTATUS st;

    // Open or create the HKLM\SOFTWARE\Scootware key.
    // We open SOFTWARE directly, then create Scootware\HWID underneath it.
    UNICODE_STRING softwarePath;
    RtlInitUnicodeString(&softwarePath, L"\\Registry\\Machine\\SOFTWARE");

    OBJECT_ATTRIBUTES oaSoftware;
    InitializeObjectAttributes(&oaSoftware, &softwarePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hSoftware = NULL;

    __try {
        st = ZwOpenKey(&hSoftware, KEY_CREATE_SUB_KEY, &oaSoftware);
        if (!NT_SUCCESS(st)) {
            KIPC_LOG(
                "[HWID] hwid_save_to_registry: ZwOpenKey(SOFTWARE) failed 0x%X\n", st);
            return st;
        }

        // Create/open Scootware subkey
        UNICODE_STRING scootName;
        RtlInitUnicodeString(&scootName, L"Scootware");
        OBJECT_ATTRIBUTES oaScoot;
        InitializeObjectAttributes(&oaScoot, &scootName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hSoftware, NULL);

        HANDLE hScoot = NULL;
        st = ZwCreateKey(&hScoot, KEY_CREATE_SUB_KEY | KEY_WRITE, &oaScoot,
            0, NULL, REG_OPTION_NON_VOLATILE, NULL);
        if (!NT_SUCCESS(st)) {
            ZwClose(hSoftware);
            KIPC_LOG(
                "[HWID] hwid_save_to_registry: ZwCreateKey(Scootware) failed 0x%X\n", st);
            return st;
        }

        // Create/open HWID subkey
        UNICODE_STRING hwidName;
        RtlInitUnicodeString(&hwidName, L"HWID");
        OBJECT_ATTRIBUTES oaHwid;
        InitializeObjectAttributes(&oaHwid, &hwidName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hScoot, NULL);

        HANDLE hHwid = NULL;
        st = ZwCreateKey(&hHwid, KEY_WRITE, &oaHwid,
            0, NULL, REG_OPTION_NON_VOLATILE, NULL);
        ZwClose(hScoot);
        if (!NT_SUCCESS(st)) {
            ZwClose(hSoftware);
            KIPC_LOG(
                "[HWID] hwid_save_to_registry: ZwCreateKey(HWID) failed 0x%X\n", st);
            return st;
        }

        // Write HWID_DATA as a REG_BINARY value
        UNICODE_STRING valueName;
        RtlInitUnicodeString(&valueName, L"Data");

        st = ZwSetValueKey(hHwid, &valueName, 0, REG_BINARY, data, sizeof(HWID_DATA));
        ZwClose(hHwid);
        ZwClose(hSoftware);

        if (NT_SUCCESS(st)) {
            KIPC_LOG(
                "[HWID] Spoof data saved to registry (%zu bytes)\n", sizeof(HWID_DATA));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KIPC_LOG(
            "[HWID] hwid_save_to_registry: exception 0x%X\n", GetExceptionCode());
        if (hSoftware) ZwClose(hSoftware);
        return STATUS_UNSUCCESSFUL;
    }

    return st;
}

static NTSTATUS hwid_load_from_registry(PHWID_DATA out_data) {
    if (!out_data) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(out_data, sizeof(HWID_DATA));

    HANDLE hKey = NULL;
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath, HWID_PERSIST_KEY_PATH);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS st = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return st;

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"Data");

    UCHAR buf[sizeof(HWID_DATA) + 8] = {};
    ULONG buf_size = sizeof(buf);
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buf;

    st = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, buf, buf_size, &buf_size);
    ZwClose(hKey);

    if (NT_SUCCESS(st) && kvpi->Type == REG_BINARY &&
        kvpi->DataLength >= sizeof(HWID_DATA)) {
        memcpy(out_data, kvpi->Data, sizeof(HWID_DATA));
        KIPC_LOG( "[HWID] Spoof data loaded from registry\n");
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

// ============================================================================
// Public API Implementation
// ============================================================================

namespace HWIDSpoofer {

    NTSTATUS Initialize() {
        ExInitializeFastMutex(&g_hwid_lock);

        ExAcquireFastMutex(&g_hwid_lock);
        {
            if (g_hwid_state == HWID_STATE::HWID_STATE_ERROR) {
                ExReleaseFastMutex(&g_hwid_lock);
                return STATUS_UNSUCCESSFUL;
            }

            // Reset state
            RtlZeroMemory(&g_original_hwid, sizeof(g_original_hwid));
            RtlZeroMemory(&g_spoofed_hwid, sizeof(g_spoofed_hwid));
            hwid_clear_spoof_active();
            g_hwid_state = HWID_STATE::HWID_STATE_UNINITIALIZED;

            // NOTE: We deliberately do NOT auto-load persisted spoof data into
            // g_spoofed_hwid and mark the state as SPOOFED at init.
            //
            // The previous behavior caused a real bug: callers querying
            // GetCurrentData() would receive the stale persisted spoof values
            // (e.g. an old MachineGuid like 02C5365C-…) even when nothing was
            // currently spoofed on the live system. The spoofer is supposed to
            // reflect *current reality*, not whatever was last persisted.
            //
            // The persisted data still exists in the registry under
            //   HKLM\SOFTWARE\Scootware\HWID\Data
            // and can be explicitly re-loaded via LoadFromDisk() + ApplyCustom().
            //
            // State stays UNINITIALIZED until SaveOriginal() runs a fresh
            // capture from the live system.
        }
        ExReleaseFastMutex(&g_hwid_lock);

        KIPC_LOG( "[HWID] Module initialized\n");
        return STATUS_SUCCESS;
    }

    VOID Cleanup() {
        ExAcquireFastMutex(&g_hwid_lock);
        {
            if (hwid_is_spoof_active()) {
                // Release lock temporarily — RestoreOriginals will re-acquire
                ExReleaseFastMutex(&g_hwid_lock);
                RestoreOriginals();
                ExAcquireFastMutex(&g_hwid_lock);
            }
            RtlZeroMemory(&g_original_hwid, sizeof(g_original_hwid));
            RtlZeroMemory(&g_spoofed_hwid, sizeof(g_spoofed_hwid));
            hwid_clear_spoof_active();
            g_hwid_state = HWID_STATE::HWID_STATE_UNINITIALIZED;
        }
        ExReleaseFastMutex(&g_hwid_lock);
        KIPC_LOG( "[HWID] Module cleaned up\n");
    }

    BOOLEAN IsActive() {
        return hwid_is_spoof_active();
    }

    NTSTATUS SaveOriginal() {
        // Each capture_* routine below calls Zw* registry primitives (or
        // NDIS / IOCTL paths via ObReferenceObjectByName) that require
        // PASSIVE_LEVEL.  Holding g_hwid_lock (a fast mutex) across them
        // raises IRQL to APC_LEVEL and BSODs the first Zw* call with
        // IRQL_NOT_LESS_OR_EQUAL.  Capture into a local buffer outside
        // the lock; flip the global state under the lock once we have
        // a complete snapshot.
        NTSTATUS st = STATUS_SUCCESS;
        HWID_DATA staged = {};

        // Capture SMBIOS data — reads via NtQuerySystemInformation, safe
        // at PASSIVE_LEVEL only.
        NTSTATUS smbios_st = smbios_extract_hwid(&staged);
        if (!NT_SUCCESS(smbios_st)) {
            KIPC_LOG( "[HWID] SMBIOS extraction failed: 0x%X\n", smbios_st);
            st = smbios_st; // Non-fatal — keep going
        }

        // Capture MachineGuid via ZwOpenKey/ZwQueryValueKey.
        NTSTATUS guid_st = registry_capture_machineguid(&staged);
        if (!NT_SUCCESS(guid_st)) {
            KIPC_LOG( "[HWID] MachineGuid capture failed: 0x%X\n", guid_st);
        }

        // Capture MAC — goes through NDIS, requires PASSIVE_LEVEL.
        NTSTATUS mac_st = capture_mac_address(&staged);
        if (!NT_SUCCESS(mac_st)) {
            KIPC_LOG( "[HWID] MAC capture failed: 0x%X\n", mac_st);
        }

        // Capture Volume Serial — IRP path via storage stack, PASSIVE_LEVEL.
        NTSTATUS vol_st = capture_volume_serial(&staged);
        if (!NT_SUCCESS(vol_st)) {
            KIPC_LOG( "[HWID] Volume serial capture failed: 0x%X\n", vol_st);
        }

        // Timestamp — safe at any IRQL but we take it here for ordering.
        LARGE_INTEGER systime;
        KeQuerySystemTime(&systime);
        staged.timestamp = systime.QuadPart;

        // Publish the captured snapshot under the lock.
        ExAcquireFastMutex(&g_hwid_lock);
        if (staged.components_present == 0) {
            g_hwid_state = HWID_STATE::HWID_STATE_ERROR;
            ExReleaseFastMutex(&g_hwid_lock);
            KIPC_LOG( "[HWID] SaveOriginal: NO components captured!\n");
            return STATUS_UNSUCCESSFUL;
        }
        memcpy(&g_original_hwid, &staged, sizeof(HWID_DATA));
        g_hwid_state = HWID_STATE::HWID_STATE_CAPTURED;
        ExReleaseFastMutex(&g_hwid_lock);

        KIPC_LOG( "[HWID] Original HWID saved (components=0x%X)\n",
            staged.components_present);
        (void)st;
        return STATUS_SUCCESS;
    }

    // Helper: write a REG_SZ value to a registry key (UTF-16 source -> ANSI registry).
    static NTSTATUS write_reg_string(PHANDLE hKey, PCWSTR value_name, PCHAR ansi_value) {
        UNICODE_STRING vn;
        RtlInitUnicodeString(&vn, value_name);

        // Convert ANSI to UTF-16 for registry storage
        ANSI_STRING as;
        RtlInitAnsiString(&as, ansi_value);

        UNICODE_STRING ws;
        RtlZeroMemory(&ws, sizeof(ws));
        NTSTATUS st = RtlAnsiStringToUnicodeString(&ws, &as, TRUE);
        if (!NT_SUCCESS(st)) return st;

        st = ZwSetValueKey(*hKey, &vn, 0, REG_SZ, ws.Buffer, ws.Length + sizeof(WCHAR));
        RtlFreeUnicodeString(&ws);
        return st;
    }

    NTSTATUS ApplySpoof(UINT32 components, UINT64 random_seed) {
        NTSTATUS result = STATUS_SUCCESS;

        // ─── IRQL discipline ─────────────────────────────────────────────
        // ExAcquireFastMutex raises IRQL to APC_LEVEL.  The registry
        // primitives we use below (ZwOpenKey, ZwSetValueKey,
        // ZwDeleteValueKey) are documented PASSIVE_LEVEL-only — calling
        // them at APC_LEVEL bugchecks the box with IRQL_NOT_LESS_OR_EQUAL
        // (0xA) on the first ZwOpenKey, which is exactly the BSOD the
        // user reported on CMD_HWID_SPOOF.
        //
        // Strategy: hold the lock only across the in-memory state mutations
        // (g_hwid_state checks, generate_spoofed_hwid, hwid_set_spoof_active,
        // RtlZeroMemory on g_spoofed_hwid).  Drop it before ANY Zw* call.
        // The state machine is simple enough that the small race window
        // between drop and re-acquire is harmless — a concurrent ApplySpoof
        // call would just write the same bytes twice.
        // ────────────────────────────────────────────────────────────────

        ExAcquireFastMutex(&g_hwid_lock);
        if (g_hwid_state == HWID_STATE::HWID_STATE_UNINITIALIZED ||
            g_hwid_state == HWID_STATE::HWID_STATE_ERROR) {
            ExReleaseFastMutex(&g_hwid_lock);
            KIPC_LOG( "[HWID] ApplySpoof: not initialized\n");
            return STATUS_INVALID_DEVICE_STATE;
        }
        BOOLEAN was_spoofed = hwid_is_spoof_active();
        ExReleaseFastMutex(&g_hwid_lock);

        // If already spoofed, RestoreOriginals first (it takes the lock
        // internally; we are now at PASSIVE_LEVEL again).
        if (was_spoofed) {
            RestoreOriginals();
        }

        // Re-enter the protected region for the in-memory mutation.
        ExAcquireFastMutex(&g_hwid_lock);
        {
            // Re-check state — RestoreOriginals could have raced with a
            // concurrent Cleanup.  Bail cleanly if so.
            if (g_hwid_state == HWID_STATE::HWID_STATE_UNINITIALIZED ||
                g_hwid_state == HWID_STATE::HWID_STATE_ERROR) {
                ExReleaseFastMutex(&g_hwid_lock);
                return STATUS_INVALID_DEVICE_STATE;
            }

            // Generate spoofed values
            generate_spoofed_hwid(&g_spoofed_hwid, random_seed, components);

            // ── Step 1: Apply SMBIOS physical memory patch (best-effort) ──
            // GATED behind HWID_SPOOFER_PHYS_PATCH_ENABLED.  See hwid_spoofer.hpp
            // for the failure modes that make this path BSOD on common Win10/11
            // configurations.  When disabled, ApplySpoof falls through to the
            // registry + (TODO) MSSMBIOS-pool patch which is BSOD-free.
#if HWID_SPOOFER_PHYS_PATCH_ENABLED
            if (components & (HWID_COMPONENT_SMBIOS_UUID | HWID_COMPONENT_SMBIOS_SERIALS)) {
                NTSTATUS patch_st = smbios_patch_hwid(&g_spoofed_hwid);
                if (!NT_SUCCESS(patch_st)) {
                    KIPC_LOG(
                        "[HWID] SMBIOS physical patch failed: 0x%X (continuing with reg writes)\n", patch_st);
                    hwid_restore_all_backups();
                    // DON'T return — continue to write registry values
                } else {
                    KIPC_LOG( "[HWID] SMBIOS physical patched OK\n");
                }
            }
#else
            // Physical patch disabled — log once so the operator knows why
            // SMBIOS values don't appear changed in WMI / dmidecode output.
            if (components & (HWID_COMPONENT_SMBIOS_UUID | HWID_COMPONENT_SMBIOS_SERIALS)) {
                KIPC_LOG(
                    "[HWID] SMBIOS physical patch SKIPPED (HWID_SPOOFER_PHYS_PATCH_ENABLED=0) — "
                    "registry overrides still applied.  Anti-cheats querying the live SMBIOS "
                    "table will see the original values; those that hit the registry-cached "
                    "MSSMBIOS values (most do) will see the spoof.\n");
            }
#endif
        }
        // ─── Drop the lock BEFORE any Zw* registry call ──────────────────
        // Snapshot the spoofed values we need into stack locals so the
        // unprotected window below can't see torn writes from a concurrent
        // ApplySpoof.  CHAR arrays are small enough to copy cheaply.
        CHAR snap_machine_guid[HWID_MAX_GUID_LEN];
        CHAR snap_mac_address [HWID_MAX_MAC_LEN];
        memcpy(snap_machine_guid, g_spoofed_hwid.machine_guid, HWID_MAX_GUID_LEN);
        memcpy(snap_mac_address,  g_spoofed_hwid.mac_address,  HWID_MAX_MAC_LEN);
        ExReleaseFastMutex(&g_hwid_lock);

        // ── Step 2: Write spoofed MachineGuid to registry (PASSIVE_LEVEL) ──
        if (components & HWID_COMPONENT_REGISTRY_MACHINEGUID) {
            HANDLE hKey = NULL;
            UNICODE_STRING kp;
            RtlInitUnicodeString(&kp,
                L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_WRITE, &oa))) {
                NTSTATUS ws = write_reg_string(&hKey, L"MachineGuid", snap_machine_guid);
                ZwClose(hKey);
                if (NT_SUCCESS(ws))
                    KIPC_LOG( "[HWID] MachineGuid registry written\n");
                else
                    KIPC_LOG( "[HWID] MachineGuid registry write failed: 0x%X\n", ws);
            }
        }

        // ── Step 3: Write spoofed MAC to registry (PASSIVE_LEVEL) ──
        if ((components & HWID_COMPONENT_MAC_ADDRESS) && snap_mac_address[0]) {
            static const WCHAR* mac_paths[] = {
                L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
                L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\0001",
                L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
                L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\0000",
            };
            for (int mi = 0; mi < ARRAYSIZE(mac_paths); mi++) {
                HANDLE hKey = NULL;
                UNICODE_STRING kp;
                RtlInitUnicodeString(&kp, mac_paths[mi]);
                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_WRITE, &oa))) {
                    NTSTATUS ws = write_reg_string(&hKey, L"NetworkAddress", snap_mac_address);
                    ZwClose(hKey);
                    if (NT_SUCCESS(ws)) {
                        KIPC_LOG( "[HWID] MAC NetworkAddress written\n");
                        break;
                    }
                }
            }
        }

        // ── Mark as spoofed + persist (re-acquire briefly for state flip) ──
        ExAcquireFastMutex(&g_hwid_lock);
        hwid_set_spoof_active();
        g_hwid_state = HWID_STATE::HWID_STATE_SPOOFED;
        ExReleaseFastMutex(&g_hwid_lock);

        // Persist spoofed data to registry so it survives driver reloads.
        // hwid_save_to_registry also issues Zw* calls — keep it OUTSIDE the
        // lock for the same IRQL reason.
        hwid_save_to_registry(&g_spoofed_hwid);

        KIPC_LOG( "[HWID] Spoof applied (components=0x%X)\n", components);
        return result;
    }

    NTSTATUS RestoreOriginals() {
        // Same IRQL discipline as ApplySpoof: do all Zw* calls outside the
        // fast mutex (which raises to APC_LEVEL).  See ApplySpoof for the
        // detailed rationale — the BSOD this guards against is IRQL_NOT_
        // LESS_OR_EQUAL on the first ZwOpenKey while the lock is held.

        ExAcquireFastMutex(&g_hwid_lock);
        if (!hwid_is_spoof_active()) {
            ExReleaseFastMutex(&g_hwid_lock);
            KIPC_LOG( "[HWID] RestoreOriginals: not spoofed\n");
            return STATUS_SUCCESS;
        }

        // Restore physical memory patches under the lock — these touch
        // pool-resident backup buffers and don't issue Zw* calls.
#if HWID_SPOOFER_PHYS_PATCH_ENABLED
        hwid_restore_all_backups();
#endif

        // Snapshot the original MachineGuid for the registry write below,
        // then drop the lock before any Zw* call.
        CHAR snap_orig_guid[HWID_MAX_GUID_LEN];
        memcpy(snap_orig_guid, g_original_hwid.machine_guid, HWID_MAX_GUID_LEN);
        ExReleaseFastMutex(&g_hwid_lock);

        // Restore MachineGuid in registry (PASSIVE_LEVEL).
        if (snap_orig_guid[0]) {
            HANDLE hKey = NULL;
            UNICODE_STRING kp;
            RtlInitUnicodeString(&kp,
                L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_WRITE, &oa))) {
                write_reg_string(&hKey, L"MachineGuid", snap_orig_guid);
                ZwClose(hKey);
                KIPC_LOG( "[HWID] MachineGuid restored in registry\n");
            }
        }

        // Remove NetworkAddress override (delete it so hardware MAC is used again)
        static const WCHAR* rst_mac[] = {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
            L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\0001",
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
            L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\0000",
        };
        for (int mi = 0; mi < ARRAYSIZE(rst_mac); mi++) {
            HANDLE hKey = NULL;
            UNICODE_STRING kp2;
            RtlInitUnicodeString(&kp2, rst_mac[mi]);
            OBJECT_ATTRIBUTES oa2;
            InitializeObjectAttributes(&oa2, &kp2, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_WRITE, &oa2))) {
                UNICODE_STRING vn;
                RtlInitUnicodeString(&vn, L"NetworkAddress");
                ZwDeleteValueKey(hKey, &vn);
                ZwClose(hKey);
            }
        }

        // Final state flip under the lock.
        ExAcquireFastMutex(&g_hwid_lock);
        {

            RtlZeroMemory(&g_spoofed_hwid, sizeof(g_spoofed_hwid));
            hwid_clear_spoof_active();
            g_hwid_state = HWID_STATE::HWID_STATE_CAPTURED;
        }
        ExReleaseFastMutex(&g_hwid_lock);

        KIPC_LOG( "[HWID] Originals restored\n");
        return STATUS_SUCCESS;
    }

    NTSTATUS Reroll(UINT32 components) {
        // Reroll = RestoreOriginals + ApplySpoof — both acquire the lock
        // internally, so no need to hold it across both calls.
        NTSTATUS st = RestoreOriginals();
        if (!NT_SUCCESS(st) && st != STATUS_SUCCESS) {
            // RestoreOriginals returns SUCCESS even if not spoofed
        }

        // Build a unique seed from __rdtsc only — a CPU instruction
        // with no IAT dependency.  The previous revision mixed
        // KeQueryPerformanceCounter and KeQueryInterruptTime in here,
        // but both are imports that KDU's manual mapper has been
        // observed to leave unresolved (they're not called anywhere
        // during driver load), and the first call bugchecks with an
        // execute-AV at the unresolved file-time RVA.
        //
        // We take two TSC samples separated by a volatile scramble so
        // the second sample reflects a distinct point even when the
        // CPU pipeline collapses them.  Mixing in g_spoofed_hwid's
        // address adds a kernel-pool entropy bit.
        ULONG64 tsc1 = __rdtsc();
        volatile ULONG64 scramble = tsc1 * 0xBF58476D1CE4E5B9ULL;
        scramble ^= scramble >> 27;
        ULONG64 tsc2 = __rdtsc();
        UINT64 seed = tsc1
                    ^ (tsc2 * 0x9E3779B97F4A7C15ULL)
                    ^ scramble
                    ^ (UINT64)(ULONG_PTR)&g_spoofed_hwid;
        return ApplySpoof(components, seed);
    }

    NTSTATUS ApplyCustom(PHWID_DATA data, UINT32 components) {
        if (!data) return STATUS_INVALID_PARAMETER;

        // Same IRQL discipline as ApplySpoof.  See that function for the
        // full rationale on why every Zw* call below must happen with the
        // fast mutex released.

        ExAcquireFastMutex(&g_hwid_lock);
        if (g_hwid_state == HWID_STATE::HWID_STATE_UNINITIALIZED ||
            g_hwid_state == HWID_STATE::HWID_STATE_ERROR) {
            ExReleaseFastMutex(&g_hwid_lock);
            KIPC_LOG( "[HWID] ApplyCustom: not initialized\n");
            return STATUS_INVALID_DEVICE_STATE;
        }
        BOOLEAN was_spoofed = hwid_is_spoof_active();
        ExReleaseFastMutex(&g_hwid_lock);

        // If already spoofed, RestoreOriginals first (PASSIVE_LEVEL).
        if (was_spoofed) {
            RestoreOriginals();
        }

        // Stage the custom payload into our spoofed slot under the lock.
        ExAcquireFastMutex(&g_hwid_lock);
        if (g_hwid_state == HWID_STATE::HWID_STATE_UNINITIALIZED ||
            g_hwid_state == HWID_STATE::HWID_STATE_ERROR) {
            ExReleaseFastMutex(&g_hwid_lock);
            return STATUS_INVALID_DEVICE_STATE;
        }
        RtlZeroMemory(&g_spoofed_hwid, sizeof(g_spoofed_hwid));
        memcpy(&g_spoofed_hwid, data, sizeof(HWID_DATA));
        g_spoofed_hwid.components_present = components;

#if HWID_SPOOFER_PHYS_PATCH_ENABLED
        if (components & (HWID_COMPONENT_SMBIOS_UUID | HWID_COMPONENT_SMBIOS_SERIALS)) {
            NTSTATUS st = smbios_patch_hwid(&g_spoofed_hwid);
            if (!NT_SUCCESS(st)) {
                KIPC_LOG( "[HWID] ApplyCustom SMBIOS patch failed: 0x%X (continuing)\n", st);
                hwid_restore_all_backups();
            }
        }
#else
        if (components & (HWID_COMPONENT_SMBIOS_UUID | HWID_COMPONENT_SMBIOS_SERIALS)) {
            KIPC_LOG(
                "[HWID] ApplyCustom SMBIOS physical patch SKIPPED — registry path only\n");
        }
#endif

        // Snapshot the strings we need for the registry writes, then drop
        // the lock before any Zw* call.
        CHAR snap_guid[HWID_MAX_GUID_LEN];
        CHAR snap_mac [HWID_MAX_MAC_LEN];
        memcpy(snap_guid, g_spoofed_hwid.machine_guid, HWID_MAX_GUID_LEN);
        memcpy(snap_mac,  g_spoofed_hwid.mac_address,  HWID_MAX_MAC_LEN);
        ExReleaseFastMutex(&g_hwid_lock);

        // ── Registry writes at PASSIVE_LEVEL ──
        if (components & HWID_COMPONENT_REGISTRY_MACHINEGUID) {
            HANDLE hKey = NULL;
            UNICODE_STRING kp;
            RtlInitUnicodeString(&kp,
                L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_WRITE, &oa))) {
                write_reg_string(&hKey, L"MachineGuid", snap_guid);
                ZwClose(hKey);
                KIPC_LOG( "[HWID] ApplyCustom: MachineGuid written\n");
            }
        }

        if ((components & HWID_COMPONENT_MAC_ADDRESS) && snap_mac[0]) {
            static const WCHAR* mac_paths[] = {
                L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
                L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\0001",
                L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
                L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\0000",
            };
            for (int mi = 0; mi < ARRAYSIZE(mac_paths); mi++) {
                HANDLE hKey = NULL;
                UNICODE_STRING kp;
                RtlInitUnicodeString(&kp, mac_paths[mi]);
                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, &kp, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_WRITE, &oa))) {
                    write_reg_string(&hKey, L"NetworkAddress", snap_mac);
                    ZwClose(hKey);
                    KIPC_LOG( "[HWID] ApplyCustom: MAC written\n");
                    break;
                }
            }
        }

        // Final state flip.
        ExAcquireFastMutex(&g_hwid_lock);
        hwid_set_spoof_active();
        g_hwid_state = HWID_STATE::HWID_STATE_SPOOFED;
        ExReleaseFastMutex(&g_hwid_lock);

        // Persist (outside lock — issues Zw* calls).
        hwid_save_to_registry(&g_spoofed_hwid);

        KIPC_LOG( "[HWID] Custom spoof applied (components=0x%X)\n", components);
        return STATUS_SUCCESS;
    }

    HWID_STATE GetState() {
        ExAcquireFastMutex(&g_hwid_lock);
        HWID_STATE state = g_hwid_state;
        ExReleaseFastMutex(&g_hwid_lock);
        return state;
    }

    NTSTATUS SaveToDisk() {
        // hwid_save_to_registry issues Zw* calls and must run at
        // PASSIVE_LEVEL.  Snapshot the relevant struct under the lock,
        // release, then persist.
        HWID_DATA snap;
        ExAcquireFastMutex(&g_hwid_lock);
        PHWID_DATA src = hwid_is_spoof_active() ? &g_spoofed_hwid : &g_original_hwid;
        memcpy(&snap, src, sizeof(HWID_DATA));
        ExReleaseFastMutex(&g_hwid_lock);
        return hwid_save_to_registry(&snap);
    }

    NTSTATUS LoadFromDisk(PHWID_DATA out_data) {
        return hwid_load_from_registry(out_data);
    }

    NTSTATUS GetOriginalData(PHWID_DATA out_data) {
        if (!out_data) return STATUS_INVALID_PARAMETER;

        ExAcquireFastMutex(&g_hwid_lock);
        BOOLEAN need_capture =
            (g_hwid_state == HWID_STATE::HWID_STATE_UNINITIALIZED) ||
            (g_original_hwid.components_present == 0);
        ExReleaseFastMutex(&g_hwid_lock);

        // If we've never captured originals (or the previous capture failed
        // to find anything), do an implicit SaveOriginal now. This is the
        // common "first call after driver load" path — we'd rather give
        // usermode real data than STATUS_INVALID_DEVICE_STATE.
        //
        // Caveat: if a spoof is currently active, the values we read from the
        // live system right now ARE the spoofed values, not the originals.
        // We therefore only do the implicit capture when no spoof is active.
        if (need_capture && !hwid_is_spoof_active()) {
            (void)SaveOriginal();
        }

        ExAcquireFastMutex(&g_hwid_lock);
        memcpy(out_data, &g_original_hwid, sizeof(HWID_DATA));
        ExReleaseFastMutex(&g_hwid_lock);
        return STATUS_SUCCESS;
    }

    NTSTATUS GetCurrentData(PHWID_DATA out_data) {
        if (!out_data) return STATUS_INVALID_PARAMETER;

        ExAcquireFastMutex(&g_hwid_lock);

        if (hwid_is_spoof_active()) {
            // Spoof active → return what we applied. This is correct because
            // the spoofed values *are* what's in the live system right now.
            memcpy(out_data, &g_spoofed_hwid, sizeof(HWID_DATA));
            ExReleaseFastMutex(&g_hwid_lock);
            return STATUS_SUCCESS;
        }

        // No spoof active → always capture FRESH from the live system.
        // We never trust g_original_hwid here because:
        //   • It might be stale (captured a long time ago).
        //   • It might be zeroed (driver just initialized, SaveOriginal not
        //     yet run).
        //
        // This guarantees usermode always sees what's actually live.
        ExReleaseFastMutex(&g_hwid_lock);

        HWID_DATA fresh = {};
        (void)smbios_extract_hwid(&fresh);
        (void)registry_capture_machineguid(&fresh);
        (void)capture_mac_address(&fresh);
        (void)capture_volume_serial(&fresh);

        LARGE_INTEGER systime;
        KeQuerySystemTime(&systime);
        fresh.timestamp = systime.QuadPart;

        memcpy(out_data, &fresh, sizeof(HWID_DATA));
        return STATUS_SUCCESS;
    }

    NTSTATUS GetStorageDirectory(PWCHAR out_path, USHORT max_chars) {
        if (!out_path || max_chars == 0) return STATUS_INVALID_PARAMETER;

        // Build path: \??\C:\Users\<user>\AppData\Roaming\Scootware\HWID
        // In kernel mode, we use \SystemRoot, \??, etc.
        // For user-mode env vars, we read the USERPROFILE from the current process.

        // Simplified: use hard-coded approach. In production, you'd query
        // the environment block from the usermode process.
        // For now, we signal the usermode side to handle file I/O.
        
        // We'll pass the HWID_DATA via the IPC buffer and let usermode handle
        // the file I/O to %appdata%/Scootware/HWID.
        
        static const WCHAR persist_dir[] = L"Scootware\\HWID";
        SIZE_T copy_wchars = (sizeof(persist_dir) / sizeof(WCHAR));
        if ((SIZE_T)max_chars > copy_wchars) {
            memcpy(out_path, persist_dir, copy_wchars * sizeof(WCHAR));
            out_path[copy_wchars] = L'\0';
        }
        return STATUS_SUCCESS;
    }

} // namespace HWIDSpoofer

#endif // _KERNEL_MODE
