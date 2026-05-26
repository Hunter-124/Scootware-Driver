#pragma once
//
// kdebug.h
// ────────────────────────────────────────────────────────────────────────────
// STEALTH-AWARE KERNEL LOGGING
//
// Problem:
//   Every `DbgPrintEx(0x4d, 0xffffffff, "...")` site bakes its format string
//   literal into the driver's .rdata section.  In a manually-mapped driver,
//   .rdata lives in NonPagedPool — fully readable by any anti-cheat that
//   walks the pool with MmIsAddressValid + a string scanner.
//
//   The 245 distinct format strings we used during development form a
//   high-signal fingerprint: `[CR3-IPC]`, `CodeCave:`, `SyscallSpf:`,
//   `Stage1 DirectoryTableBase`, ...  Any of those substrings alone is
//   enough to flag the pool page as a hidden driver image.
//
// Solution:
//   Wrap every diagnostic call in `KIPC_LOG(fmt, ...)`.  In Release builds
//   the macro expands to `((void)0)`, so the compiler discards the format
//   literal entirely — the linker GC removes it from .rdata.  In Debug
//   builds the macro forwards verbatim to DbgPrintEx so kernel debugging
//   still works.
//
// Toggle:
//   * Default: stripped in Release, enabled in Debug.
//   * Override per-build by defining `KIPC_LOG_FORCE_ENABLE` to keep logs
//     in a Release build, or `KIPC_LOG_FORCE_DISABLE` to strip them from a
//     Debug build.
//
// Why we don't just `#undef DbgPrintEx`:
//   Other subsystems (e.g. the loader's bring-up shellcode, hwid_spoofer's
//   diagnostic path) may legitimately call DbgPrintEx with a different
//   component id at runtime.  Macro-redefinition would clobber every call
//   in the translation unit, including third-party code.  A bespoke macro
//   makes the intent explicit and only affects our own log sites.
// ────────────────────────────────────────────────────────────────────────────

// Authoritative decision on whether to keep the log strings:
//   1. Explicit force-disable wins.
//   2. Explicit force-enable next.
//   3. Otherwise, log iff _DEBUG is defined (i.e. the MSBuild Debug config).
#if defined(KIPC_LOG_FORCE_DISABLE)
  #define KIPC_LOG_ENABLED 0
#elif defined(KIPC_LOG_FORCE_ENABLE)
  #define KIPC_LOG_ENABLED 1
#elif defined(_DEBUG) || defined(DBG)
  #define KIPC_LOG_ENABLED 1
#else
  #define KIPC_LOG_ENABLED 0
#endif

#if KIPC_LOG_ENABLED
  // Forward to DbgPrintEx with the same component id we used historically
  // (0x4d = IHVDRIVER / DEFAULT, 0xffffffff = ERROR level — always logged).
  // Including ntddk.h here would create circular includes; the macro is
  // expanded at the call site after <ntifs.h> or <ntddk.h> is in scope.
  #define KIPC_LOG(fmt, ...) \
      DbgPrintEx(0x4d, 0xffffffff, fmt, ##__VA_ARGS__)
#else
  // Compile to a discarded expression.  Arguments are NOT evaluated — this
  // matters because some sites compute formatted values (e.g. cast a freed
  // pointer to print its old value); we don't want those evaluated either.
  #define KIPC_LOG(fmt, ...) ((void)0)
#endif

// Convenience: a log site that is so noisy we want it stripped even in
// debug builds unless the caller explicitly opts in.  Used for inner-loop
// diagnostics (per-poll spam) that drown out everything else when on.
#if defined(KIPC_LOG_VERBOSE) && KIPC_LOG_ENABLED
  #define KIPC_LOG_V(fmt, ...) KIPC_LOG(fmt, ##__VA_ARGS__)
#else
  #define KIPC_LOG_V(fmt, ...) ((void)0)
#endif
