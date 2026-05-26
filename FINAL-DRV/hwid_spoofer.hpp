#pragma once
//
// hwid_spoofer.hpp
// HWID obfuscation / spoofing module for the CR3 driver.
//
// Handles:
//   - SMBIOS table patching  (System UUID, motherboard/chassis serials)
//   - Registry MachineGuid patching (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid)
//   - Volume/disk serial patching (storage device extension cache)
//   - MAC address patching (NDIS miniport adapter)
//
// All patching is done via physical memory access (no code hooks),
// safe for manual-mapped (KDU) drivers without triggering PatchGuard.
//
// =============================================================================
// HWID_SPOOFER_ENABLED — master compile-time switch.
//
// Set to 0 to keep the entire spoofer out of the boot path. When 0:
//   - DriverEntry does NOT call HWIDSpoofer::Initialize().
//   - DriverEntry teardown does NOT call HWIDSpoofer::Cleanup().
//   - All CMD_HWID_* IPC handlers return STATUS_IPC_ERROR without ever
//     touching SMBIOS / MmMapIoSpace / registry capture (the paths that
//     have been crashing the box on load with KMODE_EXCEPTION_NOT_HANDLED).
//
// The implementation file is still compiled and the public API still
// exists so callers compile, but every entry point short-circuits.
//
// Re-enable by flipping this to 1 ONLY AFTER the SMBIOS extraction +
// physical-memory patch paths in hwid_spoofer.cpp have been fixed.
// =============================================================================
#ifndef HWID_SPOOFER_ENABLED
#define HWID_SPOOFER_ENABLED 1
#endif

// =============================================================================
// HWID_SPOOFER_PHYS_PATCH_ENABLED — sub-feature gate for physical patches.
//
// The SMBIOS-physical-memory and MAC-physical-memory write paths use
// MmMapIoSpaceEx to map the firmware-published SMBIOS table (or the NDIS
// adapter's permanent-MAC structure) into the system VA space and overwrite
// the bytes in place.
//
// Reality on Win10/11 — even with the smbios_validate_table_in_ram guard
// and the content-match cross-check, the physical write can still BSOD on:
//   * Systems where the SMBIOS lives in `MEMORY_RESERVED` / ACPI-NV ranges
//     that DO show up in MmGetPhysicalMemoryRanges() but are protected by
//     SMM / SLAT / TXT and a write trips a machine-check (MCE bugcheck 0x9C
//     or KMODE_EXCEPTION_NOT_HANDLED 0x1E with second arg 0xC0000005).
//   * Some Intel ME / AMD PSP firmware revisions mark the BIOS-shadow page
//     readable but the underlying HW is ROM; the write fault path goes
//     through the chipset and bugchecks IRQL_NOT_LESS_OR_EQUAL.
//   * Hyper-V-enlightened kernels where the SMBIOS shadow lives in
//     a `secure` SLAT region; CR0.WP-style write tricks don't bypass the
//     EPT VIOLATION raised by the L1 hypervisor.
//
// The safe path forward (and what every reputable spoofer actually does):
//   * Patch the in-memory MSSMBIOS pool copy that Windows constructs at
//     boot and exposes via NtQuerySystemInformation(SystemFirmwareTable…).
//     That's regular NonPagedPool — safe to write.
//   * Write the MachineGuid and NDIS NetworkAddress registry overrides.
//     These survive reboots and are how AC vendors actually identify
//     a machine in practice.
//
// Until the physical patch can be hardened against the failure modes above,
// gate it behind this compile-time flag and DEFAULT IT OFF.  ApplySpoof and
// ApplyCustom continue to do the registry + MSSMBIOS-pool work; only the
// MmMapIoSpaceEx-into-firmware-page step is skipped.
// =============================================================================
#ifndef HWID_SPOOFER_PHYS_PATCH_ENABLED
#define HWID_SPOOFER_PHYS_PATCH_ENABLED 0
#endif

#include <ntifs.h>
#include <ntintsafe.h>

#ifdef _KERNEL_MODE

// ============================================================================
// HWID Component Identifiers
// ============================================================================

// Each HWID component that we can spoof.
// Bitmask values used to enable/disable individual components.
#define HWID_COMPONENT_SMBIOS_UUID       (1 << 0)
#define HWID_COMPONENT_SMBIOS_SERIALS    (1 << 1)
#define HWID_COMPONENT_REGISTRY_MACHINEGUID (1 << 2)
#define HWID_COMPONENT_VOLUME_SERIAL     (1 << 3)
#define HWID_COMPONENT_MAC_ADDRESS       (1 << 4)
#define HWID_COMPONENT_ALL               (0xFFFFFFFF)

// Maximum lengths for stored HWID strings
#define HWID_MAX_SERIAL_LEN    64
#define HWID_MAX_GUID_LEN      40
#define HWID_MAX_MAC_LEN       18
#define HWID_MAX_VOLUME_LEN    128
#define HWID_MAX_REG_VALUE     256

// ============================================================================
// Stored HWID values (original + spoofed)
// ============================================================================

#pragma pack(push, 1)
typedef struct _HWID_DATA {
    // --- SMBIOS ---
    UCHAR   smbios_uuid[16];                          // Type 1 System UUID (raw 16 bytes)
    CHAR    smbios_system_serial[HWID_MAX_SERIAL_LEN];   // Type 1 Serial Number
    CHAR    smbios_baseboard_serial[HWID_MAX_SERIAL_LEN];// Type 2 Serial Number
    CHAR    smbios_chassis_serial[HWID_MAX_SERIAL_LEN];  // Type 3 Serial Number
    CHAR    smbios_system_sku[HWID_MAX_SERIAL_LEN];      // Type 1 SKU Number

    // --- Registry ---
    CHAR    machine_guid[HWID_MAX_GUID_LEN];             // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid

    // --- Volume serial ---
    CHAR    volume_serial[HWID_MAX_VOLUME_LEN];          // C: drive volume serial (string form)

    // --- MAC Address ---
    CHAR    mac_address[HWID_MAX_MAC_LEN];               // Primary adapter MAC as XX-XX-XX-XX-XX-XX

    // --- Metadata ---
    UINT64  timestamp;                                   // When this data was saved
    UINT32  components_present;                          // Bitmask of components that were found
    UINT32  reserved;
} HWID_DATA, *PHWID_DATA;
#pragma pack(pop)

// ============================================================================
// Spoofer state machine
// ============================================================================

enum class HWID_STATE : UINT32 {
    HWID_STATE_UNINITIALIZED = 0,   // No original data saved yet
    HWID_STATE_CAPTURED,            // Original saved, no spoof active
    HWID_STATE_SPOOFED,             // Spoofed values active
    HWID_STATE_ERROR                // Something went wrong
};

// ============================================================================
// Public API
// ============================================================================

namespace HWIDSpoofer {

    //
    // Initialize the spoofer module. Must be called once at driver init.
    //
    NTSTATUS Initialize();

    //
    // Cleanup the spoofer module. Called during driver unload.
    //
    VOID Cleanup();

    //
    // Check if spoofing is currently active.
    //
    BOOLEAN IsActive();

    //
    // Save the current (original) HWID values into the driver cache.
    // Does NOT apply any spoofing.
    //
    NTSTATUS SaveOriginal();

    //
    // Apply spoofed HWID values.
    //   components: bitmask of HWID_COMPONENT_* flags, or HWID_COMPONENT_ALL
    //   If random_seed is 0, generates cryptographically random values.
    //   If random_seed is non-zero, uses it to seed the generator (reproducible).
    //
    NTSTATUS ApplySpoof(UINT32 components = HWID_COMPONENT_ALL, UINT64 random_seed = 0);

    //
    // Restore ALL hardware identifiers to their original values.
    //
    NTSTATUS RestoreOriginals();

    //
    // Generate new random spoofed values and apply them.
    // Essentially: RestoreOriginals() + ApplySpoof(components, 0)
    //
    NTSTATUS Reroll(UINT32 components = HWID_COMPONENT_ALL);

    //
    // Apply CUSTOM spoofed HWID values directly (no random generation).
    //   data: fully populated HWID_DATA with the custom values to apply.
    //   components: bitmask of HWID_COMPONENT_* to actually patch.
    //   This restores originals first if spoof is already active, then
    //   directly patches physical memory with the provided values.
    //
    NTSTATUS ApplyCustom(PHWID_DATA data, UINT32 components = HWID_COMPONENT_ALL);

    //
    // Get the current state and data.
    //
    HWID_STATE GetState();
    NTSTATUS GetOriginalData(PHWID_DATA out_data);
    NTSTATUS GetCurrentData(PHWID_DATA out_data);

    //
    // Save current spoofed HWID data to persistent registry storage.
    // Loaded automatically on next driver init.
    //
    NTSTATUS SaveToDisk();

    //
    // Load previously saved spoofed HWID data from persistent registry storage.
    //
    NTSTATUS LoadFromDisk(PHWID_DATA out_data);

    //
    // Get the user-visible path for HWID storage files.
    // Returns "C:\Users\<user>\AppData\Roaming\Scootware\HWID"
    //
    NTSTATUS GetStorageDirectory(PWCHAR out_path, USHORT max_chars);

} // namespace HWIDSpoofer

#endif // _KERNEL_MODE
