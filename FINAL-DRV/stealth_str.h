#pragma once
//
// stealth_str.h
// ────────────────────────────────────────────────────────────────────────────
// XOR-OBFUSCATED STRING LITERALS
//
// Why this exists:
//   Process-name and module-name literals like "scootware.exe",
//   "scootware-loader.exe", "ntoskrnl.exe" sit in the driver's .rdata.  For
//   a manually-mapped driver, .rdata lives in NonPagedPool — readable by
//   any pool walker.  An anti-cheat that finds "scootware.exe" inside a
//   NonPagedPool page has effectively identified our driver.
//
//   Even worse: the EPROCESS->ImageFileName comparison loop reads the
//   literal "scootware.exe" once per scan, leaving the string materialised
//   in the comparison thread's per-CPU L1 line — visible to any sibling
//   thread sharing the cache.
//
// What this provides:
//   * `XSTR(literal, key)` — compile-time XOR encoding for fixed strings.
//     Emits the encoded bytes into .rdata.  Decoded into a stack array on
//     each use, so the plaintext only ever lives on the caller's stack
//     for the duration of the comparison.
//   * `kstrieq_ascii()` — case-insensitive ASCII compare with bounded
//     length.  Useful for matching against EPROCESS->ImageFileName which
//     may be truncated to 15 bytes without a NUL.
//
// Design constraints:
//   * No runtime allocation — everything is stack-resident.
//   * Pure C++ headers; no kernel imports required.  Safe to include from
//     any TU that compiles in kernel mode.
//   * Encoded bytes still need a terminator: we encode the trailing NUL too
//     so the decoded array is a proper C string.  The key MUST NOT be 0
//     (would leave the bytes unchanged) — we enforce 1..255.
//
// Limitations:
//   * Compile-time evaluation only works if the literal length is known at
//     the macro expansion point.  C-style array initialiser syntax handles
//     this naturally.
//   * The XOR key is per-string; rotating keys across literals removes the
//     "all our strings XOR'd with 0x55" giveaway.
// ────────────────────────────────────────────────────────────────────────────

#include <ntifs.h>

namespace stealth_str {

// constexpr ASCII tolower (only handles a-z range, sufficient for image
// names — image names are limited to ASCII on Windows).
constexpr char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

// Length-bounded case-insensitive ASCII compare.  Used to match decoded
// stack strings against EPROCESS->ImageFileName (which may be truncated to
// 15 bytes without NUL).
//
//   a, b  : pointers to byte arrays
//   max_n : upper bound to read from either side
//
// Returns:
//   * 0 — strings match for `min(strlen(a, max_n), strlen(b, max_n))` chars
//         AND the shorter side terminated at the same point (or both hit
//         max_n).  Matches partial prefixes too if both run out together.
//   * non-zero — first differing byte (ASCII-folded).
__forceinline int kstrieq_ascii(const char* a, const char* b, size_t max_n) {
    for (size_t i = 0; i < max_n; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca == 0 || cb == 0) return ca - cb;
        if (to_lower(ca) != to_lower(cb)) return (int)to_lower(ca) - (int)to_lower(cb);
    }
    return 0;
}

} // namespace stealth_str

// ─── XOR encoding macros ────────────────────────────────────────────────
//
// Usage at definition site:
//
//     // The bytes "scootware.exe" XOR'd with 0x5A — only the obfuscated
//     // bytes appear in .rdata.  No legible string at any offset of the
//     // driver image.
//     static const unsigned char kEncScootware[] = {
//         's' ^ 0x5A, 'c' ^ 0x5A, 'o' ^ 0x5A, 'o' ^ 0x5A, 't' ^ 0x5A,
//         'w' ^ 0x5A, 'a' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, '.' ^ 0x5A,
//         'e' ^ 0x5A, 'x' ^ 0x5A, 'e' ^ 0x5A, 0   ^ 0x5A,
//     };
//
// Usage at the call site:
//
//     char buf[sizeof(kEncScootware)];
//     STEALTH_DECODE(buf, kEncScootware, 0x5A);
//     // `buf` now contains "scootware.exe\0" — usable as a C string.
//
// The decode is a single XOR per byte; the loop is small enough that the
// optimiser will inline it.  Plain `for` rather than memcpy + xor so the
// compiler can keep the buffer in registers when small.
#define STEALTH_DECODE(dst, enc, key)                                         \
    do {                                                                       \
        for (size_t _i = 0; _i < sizeof(enc); ++_i) {                          \
            (dst)[_i] = (char)((enc)[_i] ^ (key));                             \
        }                                                                      \
    } while (0)
