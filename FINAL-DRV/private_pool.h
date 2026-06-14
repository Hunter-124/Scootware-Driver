#pragma once
//
// stealth_alloc.h
// ────────────────────────────────────────────────────────────────────────────
// RUNTIME-RANDOMIZED POOL TAGS
//
// Why this exists:
//   ExAllocatePoolWithTag / ExAllocatePool2 attach a 4-byte tag to each
//   NonPagedPool allocation.  Tags are stored in the pool header and are
//   enumerable from kernel mode (KeQueryActiveProcessors → ExGetPoolTagInfo)
//   and from usermode (NtQuerySystemInformation(SystemBigPoolInformation)
//   reports any allocation > PAGE_SIZE along with its tag).
//
//   Earlier revisions used the hardcoded tags 'tJnI', 'INRv', 'IORd', 'IFRv',
//   'jMpI'.  Those tags are byte-exact searchable from usermode — once an
//   anti-cheat learns them, every machine running our driver lights up on a
//   single API call.
//
// Strategy:
//   Generate one 4-byte tag per driver load using a runtime entropy source
//   (KeQueryPerformanceCounter mixed with KeQueryInterruptTime).  Constrain
//   the tag to plausible-looking lowercase-ASCII so it blends into the pool
//   tag table — bytes < 0x20 or > 0x7E would themselves be a red flag in
//   `!poolused` output.  Within a single boot the tag stays stable so we
//   can use ExFreePoolWithTag correctly, but two reboots produce different
//   tags — defeating any persistent signature.
//
//   The tag is also XOR-differentiated per allocation site so the injector's
//   IAT-scratch buffers, payload buffer, and HWID buffers don't all share an
//   identical tag (which itself would be a pattern).  All differentiated tags
//   are derived from the same base, so a single fresh tag table per boot
//   covers every allocation site.
//
// Caller pattern:
//   void* p = STEALTH_POOL_ALLOC(size, kStealthTagPayload);
//   ...
//   STEALTH_POOL_FREE(p, kStealthTagPayload);
//
//   The tag enum values are XOR offsets, not literal tags.  At expansion
//   time the macro mixes the boot-randomized base with the offset and calls
//   the appropriate ExAllocatePool variant.
// ────────────────────────────────────────────────────────────────────────────

#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>   // __rdtsc — CPU intrinsic, no IAT entry needed

// Per-allocation-site offsets.  Values are deliberately small so the final
// tag byte ordering stays close to ASCII; they're XORed into the lowest
// byte of the base tag, so site_payload and site_iat differ by a few bits
// but both still look like printable lowercase tags.
enum StealthAllocSite : ULONG {
    kStealthTagBase    = 0x00,  // generic pool scratch
    kStealthTagPayload = 0x01,  // injector DLL payload buffer
    kStealthTagIatN    = 0x02,  // injector import-name scratch
    kStealthTagIatO    = 0x03,  // injector import-ordinal scratch
    kStealthTagIatF    = 0x04,  // injector import-function scratch
    kStealthTagHwid    = 0x05,  // hwid_spoofer scratch
    kStealthTagModule  = 0x06,  // SystemModuleInformation buffer
    kStealthTagBigPool = 0x07,  // SystemBigPoolInformation buffer
};

namespace stealth_alloc {

// Initialized at DriverEntry by InitStealthPoolTag().  Looks like an ASCII
// tag (4 lowercase letters) but the exact letters are different each boot.
// MUST live in the driver image, not on the stack — the macros below take
// its address.
inline ULONG g_BaseTag = 0;

// One-byte ASCII alphabet pool used to construct the base tag from entropy.
// All 26 lowercase letters: pool walkers expect lowercase tags from drivers
// authored "naïvely", so this is the path of least suspicion.  We avoid
// uppercase to dodge the well-known kernel-internal tags ('MmSm', 'NtFs',
// 'Ntfr' etc.) which scanners may compare against an allow-list.
constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz";
constexpr ULONG kAlphabetLen = sizeof(kAlphabet) - 1;

// Initialize g_BaseTag from runtime entropy.  Safe to call once at
// DriverEntry; idempotent — re-calls are no-ops.  Returns the chosen tag.
//
// Entropy source: __rdtsc() ONLY — a CPU instruction with zero IAT
// dependencies.  Earlier revisions used KeQueryPerformanceCounter and
// KeQueryInterruptTime, both of which are imports.  KDU's manual mapper
// resolves the IAT lazily: imports that the *original* driver never
// called at load time (these two are only called from IPC paths in the
// rest of our code base — CR3 DTB Stage 3, HWID spoof, benchmark) get
// left in their file-time state, where the slot holds the name-hint
// RVA (e.g. 0x52a0c) instead of a valid VA.  Calling one of those
// bugchecks the box with an execute-AV at the unresolved RVA before
// SEH can engage.
//
// __rdtsc() is also a perfectly good per-boot entropy source: the
// counter advances from CPU reset, and the cycle count between CPU
// init and our DriverEntry varies massively between boots (boot device
// speed, firmware delay, other drivers loaded first, etc.).  Two reads
// separated by the splitmix step give enough variation for a 4-byte
// tag even on systems where TSC has been deliberately rendered
// monotone-by-frequency (TSC_INVARIANT).
__forceinline ULONG InitStealthPoolTag() {
    if (g_BaseTag != 0) return g_BaseTag;

    ULONG64 t1 = __rdtsc();
    // A tiny bit of useless work between reads so the second sample
    // differs from the first by more than the ~25-cycle RDTSC pipeline.
    volatile ULONG64 scramble = t1 * 0x9E3779B97F4A7C15ULL;
    scramble ^= scramble >> 13;
    ULONG64 t2 = __rdtsc();

    // splitmix64 mix.
    ULONG64 s = t1 ^ (t2 * 0x9E3779B97F4A7C15ULL) ^ scramble;
    s ^= (s >> 30);
    s *= 0xBF58476D1CE4E5B9ULL;
    s ^= (s >> 27);
    s *= 0x94D049BB133111EBULL;
    s ^= (s >> 31);

    // Pull four indices off the mixed state, one per tag byte.
    UCHAR b0 = kAlphabet[(s >>  0) % kAlphabetLen];
    UCHAR b1 = kAlphabet[(s >> 16) % kAlphabetLen];
    UCHAR b2 = kAlphabet[(s >> 32) % kAlphabetLen];
    UCHAR b3 = kAlphabet[(s >> 48) % kAlphabetLen];

    // Pool tags are stored little-endian: byte 0 ends up at the lowest
    // address of the tag dword.  We build the tag so byte 0 is at the LSB
    // when interpreted as a ULONG, matching the 'AbCd' literal convention.
    g_BaseTag = ((ULONG)b3 << 24) | ((ULONG)b2 << 16) |
                ((ULONG)b1 <<  8) |  (ULONG)b0;
    return g_BaseTag;
}

// XOR the lowest byte of the base tag with the per-site offset to derive
// a stable but distinct tag for each allocation site.  Keeps all four bytes
// printable (the offset is small enough that the result stays in [a..z]
// most of the time; even if it doesn't, the result is still a valid pool
// tag — the kernel doesn't constrain tag values).
__forceinline ULONG TagFor(ULONG site_offset) {
    if (g_BaseTag == 0) {
        InitStealthPoolTag();
    }
    return g_BaseTag ^ site_offset;
}

} // namespace stealth_alloc

// ─── Caller-facing allocation macros ────────────────────────────────────
//
// Use these in place of ExAllocatePool2 / ExAllocatePoolWithTag wherever
// a tag would otherwise be hardcoded.  The macros expand at the call site,
// so the tag is computed on every call (cheap — single global read + XOR).
//
// We prefer ExAllocatePool2 when available (Win10 2004+) and fall back to
// ExAllocatePoolWithTag on older builds.  The dynamic-resolve dance is
// duplicated from hwid_spoofer.cpp so this header can be self-contained.
//
// Note: callers must use STEALTH_POOL_FREE for symmetric tagging, not
// ExFreePool (which still works but inflates the 'None' bucket and breaks
// !poolused -p:<tag> attribution).

typedef PVOID (NTAPI* fn_ExAllocatePool2)(ULONG64 Flags, SIZE_T Size, ULONG Tag);
inline fn_ExAllocatePool2 g_StealthAllocPool2 = NULL;
inline BOOLEAN            g_StealthAllocPool2Resolved = FALSE;

__forceinline PVOID StealthPoolAlloc(SIZE_T Size, ULONG Tag) {
    if (!g_StealthAllocPool2Resolved) {
        UNICODE_STRING n;
        RtlInitUnicodeString(&n, L"ExAllocatePool2");
        g_StealthAllocPool2 =
            (fn_ExAllocatePool2)MmGetSystemRoutineAddress(&n);
        g_StealthAllocPool2Resolved = TRUE;
    }
    if (g_StealthAllocPool2) {
        // POOL_FLAG_NON_PAGED == 0x0000000000000040
        return g_StealthAllocPool2(0x40, Size, Tag);
    }
    return ExAllocatePoolWithTag(NonPagedPool, Size, Tag);
}

__forceinline VOID StealthPoolFree(PVOID Ptr, ULONG Tag) {
    if (Ptr) {
        ExFreePoolWithTag(Ptr, Tag);
    }
}

#define STEALTH_POOL_ALLOC(size, site) \
    StealthPoolAlloc((size), stealth_alloc::TagFor((site)))

#define STEALTH_POOL_FREE(ptr, site) \
    StealthPoolFree((ptr), stealth_alloc::TagFor((site)))
