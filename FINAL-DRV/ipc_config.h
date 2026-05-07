#pragma once

//
// ipc_config.h
// Configuration header for IPC application settings.
// Modify these values to change app name, timeouts, and other settings.
// This file is included by shared_memory_ipc.h to provide modular configuration.
//

//
// Application name (process image name to search for)
// Change this to update the executable name the driver will search for
//
#ifndef IPC_APP_NAME
#define IPC_APP_NAME "scootware.exe"
#endif

//
// Initial process discovery timeout (milliseconds)
//
#ifndef IPC_PROCESS_DISCOVERY_TIMEOUT_MS
#define IPC_PROCESS_DISCOVERY_TIMEOUT_MS 2000
#endif

//
// IPC buffer discovery timeout (milliseconds)
//
#ifndef IPC_BUFFER_DISCOVERY_TIMEOUT_MS
#define IPC_BUFFER_DISCOVERY_TIMEOUT_MS 15000
#endif

//
// Command polling interval (milliseconds)
//
#ifndef IPC_POLL_INTERVAL_MS
#define IPC_POLL_INTERVAL_MS 10
#endif

//
// Retry interval when process not found (milliseconds)
//
#ifndef IPC_RETRY_INTERVAL_MS
#define IPC_RETRY_INTERVAL_MS 1000
#endif
