#pragma once

//
// shared_memory_ipc.h
// Shared protocol header for CR3 driver <-> usermode test program communication.
// Multi-slotted concurrent IPC version.
//

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#include <stdint.h>
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef int32_t  INT32;
typedef uint16_t UINT16;
typedef uint8_t  UINT8;
#endif

#include "ipc_config.h"

// Bumped MAGIC and VERSION for the multi-slotted implementation
#define IPC_MAGIC           0x504D585F49504332ULL // 'PMX_IPC2'
#define IPC_VERSION         2

#define IPC_MAX_SLOTS       16
#define IPC_SLOT_DATA_SIZE  0x1000  // 4096 bytes per slot data buffer

#define IPC_TARGET_PROCESS  IPC_APP_NAME

// Slot state flags (usermode sets to BUSY when locking a slot, FREE when done)
#define SLOT_STATE_FREE     0
#define SLOT_STATE_BUSY     1

// Command IDs
#define CMD_IDLE                0
#define CMD_READ_MEMORY         1
#define CMD_WRITE_MEMORY        2
#define CMD_GET_BASE_ADDRESS    3
#define CMD_RESOLVE_DTB         4
#define CMD_GET_GUARDED_REGION  5
#define CMD_MOUSE_MOVE          6
#define CMD_INJECT_DLL          7
#define CMD_PING                8
#define CMD_SHUTDOWN            9
#define CMD_GET_PEB             10
#define CMD_GET_MODULE          11
#define CMD_GET_PID             12
#define CMD_ALLOCATE            13
#define CMD_FREE                14
#define CMD_HANDOFF             15   // Loader pre-announces cheat PID + IPC VA to driver

// HWID Spoofer commands (20-29)
#define CMD_HWID_SAVE           20   // Save current HWID values to cache
#define CMD_HWID_SPOOF          21   // Apply spoofed HWID (random or from provided seed)
#define CMD_HWID_RESTORE        22   // Restore original HWID values
#define CMD_HWID_REROLL         23   // Generate new random HWID and apply
#define CMD_HWID_STATUS         24   // Get current spoofing state + HWID data
#define CMD_HWID_LOAD           25   // Load HWID data from usermode buffer into driver
#define CMD_HWID_GET_ORIGINAL   26   // Retrieve original HWID data to usermode
#define CMD_HWID_SAVE_TO_DISK   27   // Persist current spoof data to registry
#define CMD_HWID_LOAD_FROM_DISK 28   // Load persisted spoof data from registry

// Stealth validation / diagnostics commands (30-39)
#define CMD_STEALTH_STATUS      30   // Query thread spoofing, stack isolation, KPTI state
#define CMD_RW_CYCLE_TEST       31   // Execute a full read/write cycle with stack isolation
#define CMD_THREAD_VALIDATE     32   // Validate thread Win32StartAddress is spoofed
#define CMD_CAVE_INFO           33   // Return code cave address, module, patch bytes

// Status codes
#define STATUS_IPC_IDLE         0
#define STATUS_IPC_PROCESSING   1
#define STATUS_IPC_SUCCESS      2
#define STATUS_IPC_ERROR        3

#define IPC_SECURITY_CODE       0x76

#pragma pack(push, 1)

typedef struct _IPC_RW_DATA {
    UINT64  target_address;
    UINT64  buffer_size;
    UINT32  is_write;
    UINT32  use_cr3;
} IPC_RW_DATA, *PIPC_RW_DATA;

typedef struct _IPC_RESULT_DATA {
    UINT64  result;
} IPC_RESULT_DATA, *PIPC_RESULT_DATA;

typedef struct _IPC_MOUSE_DATA {
    INT32   x;
    INT32   y;
    UINT16  button_flags;
} IPC_MOUSE_DATA, *PIPC_MOUSE_DATA;

typedef struct _IPC_INJECT_DATA {
    UINT64  target_pid;
    UINT64  dll_usermode_ptr;
    UINT32  dll_size;
    UINT32  alloc_mode;    // one of INJ_ALLOC_* constants (0=between modules default)
} IPC_INJECT_DATA, *PIPC_INJECT_DATA;

typedef struct _IPC_MODULE_DATA {
    UINT32  name_len;
    UINT64  result;
} IPC_MODULE_DATA, *PIPC_MODULE_DATA;

typedef struct _IPC_PID_DATA {
    UINT32  name_len;
    UINT32  result_pid;
} IPC_PID_DATA, *PIPC_PID_DATA;

typedef struct _IPC_ALLOC_DATA {
    UINT64  address;
    UINT64  size;
    UINT32  allocation_type;
    UINT32  protect;
    UINT64  result;
} IPC_ALLOC_DATA, *PIPC_ALLOC_DATA;

typedef struct _IPC_FREE_DATA {
    UINT64  address;
    UINT32  free_type;
} IPC_FREE_DATA, *PIPC_FREE_DATA;

// CMD_HANDOFF: loader tells driver exactly where scootware.exe's IPC buffer is.
// This eliminates the blind EPROCESS walk + page scan on handoff.
// The driver stores {target_pid, ipc_va} and establishes the session directly
// once the loader's magic is burned (triggering discovery-thread teardown).
typedef struct _IPC_HANDOFF_DATA {
    UINT32  target_pid;   // PID of the cheat process (scootware.exe)
    UINT32  reserved;
    UINT64  ipc_va;       // VA of IPC_MEMORY buffer in the cheat's address space
} IPC_HANDOFF_DATA, *PIPC_HANDOFF_DATA;

// HWID Spoofer data structures
// These match the kernel-mode HWID_DATA struct in hwid_spoofer.hpp
#define HWID_MAX_SERIAL_LEN    64
#define HWID_MAX_GUID_LEN      40
#define HWID_MAX_MAC_LEN       18
#define HWID_MAX_VOLUME_LEN    128

// HWID component bitmask flags (mirrored from hwid_spoofer.hpp)
#define HWID_COMP_SMBIOS_UUID        (1 << 0)
#define HWID_COMP_SMBIOS_SERIALS     (1 << 1)
#define HWID_COMP_REGISTRY_GUID      (1 << 2)
#define HWID_COMP_VOLUME_SERIAL      (1 << 3)
#define HWID_COMP_MAC_ADDRESS        (1 << 4)
#define HWID_COMP_ALL                0xFFFFFFFF

typedef struct _IPC_HWID_DATA {
    UCHAR   smbios_uuid[16];
    CHAR    smbios_system_serial[HWID_MAX_SERIAL_LEN];
    CHAR    smbios_baseboard_serial[HWID_MAX_SERIAL_LEN];
    CHAR    smbios_chassis_serial[HWID_MAX_SERIAL_LEN];
    CHAR    smbios_system_sku[HWID_MAX_SERIAL_LEN];
    CHAR    machine_guid[HWID_MAX_GUID_LEN];
    CHAR    volume_serial[HWID_MAX_VOLUME_LEN];
    CHAR    mac_address[HWID_MAX_MAC_LEN];
    UINT64  timestamp;
    UINT32  components_present;
    UINT32  reserved;
} IPC_HWID_DATA, *PIPC_HWID_DATA;

// HWID command arguments
typedef struct _IPC_HWID_CMD {
    UINT32  components;          // Bitmask of HWID_COMP_* to spoof/reroll
    UINT64  random_seed;         // 0 = random, non-zero = use as seed
    UINT32  state;               // Output: current HWID_STATE enum value
    UINT32  active;              // Output: 1 if spoof is active, 0 otherwise
} IPC_HWID_CMD, *PIPC_HWID_CMD;

// ─── Stealth validation / diagnostics data structures (CMD_STEALTH_STATUS) ──
// Matches the kernel-mode STEALTH_STATUS struct defined in thread_spoof.h /
// syscall_stack_spoof.h and populated by the CMD_STEALTH_STATUS handler.
#define STEALTH_MAX_NAME_LEN 64

typedef struct _IPC_STEALTH_STATUS {
    // ── Thread spoofing (code cave) ────────────────────────────────────
    UINT32  thread_spoof_active;       // 1 if code cave was found + patched
    UINT64  cave_address;              // VA of the patched 0xCC bytes
    UINT64  cave_module_base;          // Base of the module containing the cave
    UINT64  cave_size;                 // Number of consecutive 0xCC bytes found
    UINT8   cave_patch_bytes[8];       // First 8 bytes at cave after patching
    CHAR    cave_module_name[STEALTH_MAX_NAME_LEN]; // e.g. "ntoskrnl.exe"

    // ── Stack isolation (KeExpandKernelStackAndCalloutEx) ──────────────
    UINT32  stack_isolation_active;    // 1 if expanded-stack callout is used
    UINT64  ret_gadget_address;        // VA of the 0xC3 gadget in ntoskrnl
    UINT64  ret_gadget_module_base;    // Base of ntoskrnl
    UINT32  expanded_stack_size;       // EXPANDED_STACK_SIZE used for callout

    // ── KPTI / KVA Shadow ──────────────────────────────────────────────
    UINT32  kpti_enabled;             // 1 if CR4.PCIDE set (KPTI active)
    UINT32  cr3_swap_capable;         // 1 if kernel CR3 available (can swap)
    UINT32  cr3_mode;                 // 0=CR3 swap, 1=MDL+attach, 2=expanded stack

    // ── Syscall / SSN ──────────────────────────────────────────────────
    UINT32  ntfvm_ssn;                // SSN for NtFreeVirtualMemory
    UINT32  ssn_resolved_dynamic;     // 1 if SSN was dynamic-resolved vs static

    // ── General driver state ───────────────────────────────────────────
    UINT32  worker_count;             // Number of IPC worker threads
    UINT32  discovery_active;         // 1 if discovery thread is running
    UINT32  target_attached;          // 1 if a target process is attached
    UINT32  target_pid;               // Current attached target PID (0=none)
    UINT64  target_cr3;               // Cached DTB for target (0=none)
    UINT64  target_base;              // Base address of target module
    CHAR    target_name[STEALTH_MAX_NAME_LEN]; // Image name of target process

    UINT32  reserved[4];             // Future expansion
} IPC_STEALTH_STATUS, *PIPC_STEALTH_STATUS;

// ─── RW cycle test data (CMD_RW_CYCLE_TEST) ────────────────────────────
typedef struct _IPC_RW_CYCLE_RESULT {
    UINT64  test_address;             // VA used for the test r/w
    UINT32  test_size;                // Bytes written + read back
    UINT32  mode_used;                // 0=CR3 swap, 1=MDL expanded stack, 2=MDL direct
    UINT32  write_success;            // 1 if write succeeded
    UINT32  read_success;             // 1 if read succeeded
    UINT32  data_match;               // 1 if read data matched written data
    UINT64  write_latency_ns;         // Round-trip latency for write op
    UINT64  read_latency_ns;          // Round-trip latency for read op
    UINT8   written_pattern[16];      // First 16 bytes of what was written
    UINT8   readback_pattern[16];     // First 16 bytes of what was read back
} IPC_RW_CYCLE_RESULT, *PIPC_RW_CYCLE_RESULT;

// Each slot represents one concurrent command execution
typedef struct _IPC_SLOT {
    volatile UINT32  slot_state;     // 0x00: SLOT_STATE_FREE or SLOT_STATE_BUSY
    volatile UINT32  status;         // 0x04: STATUS_IPC_*
    volatile UINT32  command;        // 0x08: CMD_*
    volatile UINT32  process_id;     // 0x0C: Target PID
    volatile UINT64  cr3_cached;     // 0x10: Cached DTB
    
    // Command-specific arguments
    union {
        IPC_RW_DATA      rw;
        IPC_RESULT_DATA  result;
        IPC_MOUSE_DATA   mouse;
        IPC_INJECT_DATA  inject;
        IPC_MODULE_DATA  module;
        IPC_PID_DATA     pid;
        IPC_ALLOC_DATA   alloc;
        IPC_FREE_DATA    free;
        IPC_HWID_CMD     hwid_cmd;
        IPC_HANDOFF_DATA handoff;   // CMD_HANDOFF: cheat PID + IPC VA hint
        UINT8            pad[0x30];
    } cmd_data;                          // 0x18
    
    UINT8 reserved[0xB8];                // 0x48 -> 0x100
    
    // Data buffer for this specific slot
    UINT8 data_buffer[IPC_SLOT_DATA_SIZE]; // 0x100 -> 0x1100
} IPC_SLOT, *PIPC_SLOT;

typedef struct _IPC_MEMORY {
    volatile UINT64  magic;          // 0x00
    volatile UINT32  version;        // 0x08
    volatile UINT32  active_slots;   // 0x0C
    
    IPC_SLOT slots[IPC_MAX_SLOTS];   // 0x10
} IPC_MEMORY, *PIPC_MEMORY;

#pragma pack(pop)

#define IPC_TOTAL_SIZE sizeof(IPC_MEMORY)
