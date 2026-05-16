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

// Code-cave step-debugging commands (40-49)
// Auto-spoofing is disabled in DriverEntry; each step is invoked manually
// from the GUI so the user can identify which step BSODs on baremetal.
// State carries across commands via g_thread_cave / KcfgPatch::Resolve cache.
#define CMD_CAVE_STEP_SCAN          40   // Scan one kernel module for a cave (no patch)
#define CMD_CAVE_STEP_PATCH         41   // Apply ENDBR64+JMP patch to current cave
#define CMD_CAVE_STEP_KCFG_RESOLVE  42   // Pattern-decode _guard_dispatch_icall + validate layout
#define CMD_CAVE_STEP_KCFG_PATCH    43   // Flip CFG bitmap bit for cave_address
#define CMD_CAVE_STEP_SPAWN         44   // Create a test thread using cave_address as start

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
    UINT32  kpti_enabled;             // 1 if KPTI active (UserDTB is a user-shadow CR3, differs from kernel CR3)
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

// ─── Cave step-debugging args + result (CMD_CAVE_STEP_*) ────────────────────
// Input goes through slot->cmd_data.cave_step.  Output goes into
// slot->data_buffer as IPC_CAVE_STEP_RESULT.  Only the fields relevant to the
// requested step are populated — others are zeroed.

typedef struct _IPC_CAVE_STEP_CMD {
    UINT32  module_index;        // SCAN: 0=ntoskrnl 1=hal 2=CI 3=fltmgr
    UINT32  spawn_wait_ms;       // SPAWN: ms to wait before reporting alive
    UINT64  reserved[3];
} IPC_CAVE_STEP_CMD, *PIPC_CAVE_STEP_CMD;

typedef struct _IPC_CAVE_STEP_RESULT {
    UINT32  step_id;             // The step that produced this result
    UINT32  ntstatus;            // NTSTATUS from the underlying call
    UINT64  worker_function_va;  // Address of ipc_worker_thread (always reported)

    // SCAN fields
    CHAR    scan_module_name[32];
    UINT64  scan_module_base;
    UINT64  scan_text_start;
    UINT64  scan_text_size;
    UINT64  scan_cave_address;   // 16-byte aligned position
    UINT64  scan_cave_size;      // patchable bytes after alignment
    UINT32  scan_aligned;        // 1 if cave_address & 0xF == 0
    UINT32  scan_reserved;

    // PATCH fields
    UINT32  patch_size;          // 9 (rel32) or 18 (abs64)
    UINT32  patch_used_rel32;    // 1 = rel32, 0 = abs64
    INT64   patch_disp;          // computed displacement
    UINT8   patch_bytes[18];     // bytes at cave_address after patch

    // KCFG_RESOLVE fields
    UINT64  kcfg_fptr_loc;
    UINT64  kcfg_fptr_value;
    UINT64  kcfg_nop_func;
    UINT32  kcfg_active;
    UINT32  kcfg_layout_valid;
    UINT64  kcfg_bitmap_base_loc;
    UINT64  kcfg_bitmap_base;
    CHAR    kcfg_probe_names[4][24];   // 4 probe export names (truncated to 24)
    UINT64  kcfg_probe_addrs[4];
    UINT8   kcfg_probe_bits[4];        // 0=clear, 1=set, 0xFF=read failed, 0xFE=not checked
    UINT8   kcfg_probe_reserved[4];
    UINT8   kcfg_dispatch_prologue[16]; // First 16 bytes of _guard_dispatch_icall

    // KCFG_PATCH fields
    UINT64  kcfg_target_addr;
    UINT64  kcfg_byte_addr;
    UINT64  kcfg_byte_offset;
    UINT32  kcfg_bit_in_byte;
    UINT8   kcfg_byte_before;
    UINT8   kcfg_byte_after;
    UINT8   kcfg_patch_reserved[2];

    // SPAWN fields
    UINT64  spawn_thread_handle;
    UINT64  spawn_thread_object;
    UINT32  spawn_create_status;
    UINT32  spawn_alive;         // 1 if thread is still alive after the delay
    UINT32  spawn_exit_status;   // exit code if not alive
    UINT32  spawn_test_ran;     // 1 = test target's first line was reached
    UINT64  spawn_embedded_target; // abs64 target read back from cave (verification)
    UINT8   spawn_cave_verify[8];  // first 8 bytes read back from cave before dispatch
} IPC_CAVE_STEP_RESULT, *PIPC_CAVE_STEP_RESULT;

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
        IPC_CAVE_STEP_CMD cave_step; // CMD_CAVE_STEP_*: step-debug args
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
