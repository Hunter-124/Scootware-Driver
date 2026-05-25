/*
 * scootware_helper.cpp
 * ────────────────────
 *
 * IPC bridge that the Python MCP server drives over stdio.
 *
 * The kernel driver's scootware.exe discovery only scans pages WITHIN
 * the target's PE image (image_base .. image_base+SizeOfImage). So the
 * IPC buffer has to live in the helper's .bss — exactly how the GUI
 * scootware.exe does it. We can't share that memory back to Python
 * directly (it's not a file mapping), so instead Python issues
 * commands to us over stdin and reads results from stdout.
 *
 * Protocol — one line per request/response, space-separated tokens:
 *
 *   Request:   <cmd> <id> [arg1] [arg2] ...
 *   Response:  ok <id> [key=value key=value ...]
 *              err <id> reason=<urlencoded>
 *
 * Commands (id is a u64 set by the client, echoed back):
 *   ping       <id>
 *   read       <id> <pid> <addr_hex> <size> <use_cr3>
 *   write      <id> <pid> <addr_hex> <data_hex> <use_cr3>
 *   getpid     <id> <name>
 *   getbase    <id> <pid>
 *   getpeb     <id> <pid>
 *   getmodule  <id> <pid> <name_utf8>
 *   getdtb     <id> <pid>
 *   guarded    <id>
 *   alloc      <id> <pid> <size_hex> <type_hex> <protect_hex>
 *   free       <id> <pid> <addr_hex>
 *   shutdown   <id>
 *   bye        <id>           (clean exit — burn magic, exit 0)
 *
 * Reads return data_hex=<hex>. Writes return bytes=N. All addresses are
 * lowercase hex without 0x prefix in responses. Strings (errors) are
 * percent-encoded so newlines and spaces don't break the line protocol.
 *
 * BUILD:    helper/build.bat
 * OUTPUT:   helper/scootware.exe  (image name MUST be scootware.exe)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    // Bring in the same IPC layout the driver uses. The header is in
    // ../../FINAL-DRV; we point the include path there from build.bat.
    #include "shared_memory_ipc.h"
}

// ─── IPC buffer ─ MUST be inside our .bss so the driver finds it ───────
__declspec(align(4096)) static char g_ipc_storage[IPC_TOTAL_SIZE];
static PIPC_MEMORY g_mem = reinterpret_cast<PIPC_MEMORY>(g_ipc_storage);

static IPC_SLOT* slot_at(int i)           { return &g_mem->slots[i]; }
static void*     slot_cmd_data(int i)     { return &g_mem->slots[i].cmd_data; }
static uint8_t*  slot_data_buffer(int i)  { return  g_mem->slots[i].data_buffer; }

// ─── Stdio helpers ─────────────────────────────────────────────────────
static FILE* g_log = nullptr;   // optional: --logfile <path>

static void log_msg(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    fputc('\n', g_log);
    fflush(g_log);
    va_end(ap);
}

// Percent-encode a string so it can travel in a single line.
// Only encodes characters that would break parsing.
static void pct_encode(const char* in, char* out, size_t out_cap) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 4 < out_cap; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c == ' ' || c == '%' || c < 0x20 || c >= 0x7F || c == '"' || c == '\n' || c == '\r') {
            j += (size_t)snprintf(out + j, out_cap - j, "%%%02X", c);
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decode a continuous hex string (no separators) into bytes. Returns
// number of bytes decoded, or -1 on error.
static int decode_hex(const char* in, uint8_t* out, int out_cap) {
    int n = 0;
    while (*in && n < out_cap) {
        int hi = hex_digit(*in++);
        if (hi < 0) return -1;
        if (!*in) return -1;
        int lo = hex_digit(*in++);
        if (lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

// Write a uint8 buffer as lowercase hex to `out`. Returns bytes written.
static size_t encode_hex(const uint8_t* in, size_t n, char* out, size_t out_cap) {
    static const char DIGITS[] = "0123456789abcdef";
    size_t need = n * 2 + 1;
    if (need > out_cap) return 0;
    for (size_t i = 0; i < n; ++i) {
        out[i * 2    ] = DIGITS[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = DIGITS[in[i] & 0xF];
    }
    out[n * 2] = '\0';
    return n * 2;
}

// ─── Response emitters ─────────────────────────────────────────────────
static void emit_ok(uint64_t id, const char* extra) {
    if (extra && *extra)
        printf("ok %llu %s\n", (unsigned long long)id, extra);
    else
        printf("ok %llu\n", (unsigned long long)id);
    fflush(stdout);
}

static void emit_err(uint64_t id, const char* reason) {
    char enc[1024];
    pct_encode(reason ? reason : "", enc, sizeof(enc));
    printf("err %llu reason=%s\n", (unsigned long long)id, enc);
    fflush(stdout);
}

// ─── Command arming protocol ───────────────────────────────────────────
enum WaitResult { WR_SUCCESS, WR_ERROR, WR_TIMEOUT };

static WaitResult send_command(int slot, uint32_t cmd, uint32_t pid,
                                uint32_t timeout_ms) {
    IPC_SLOT* s = slot_at(slot);

    // Three-step arming (same protocol the IPC speed test uses).
    s->command    = CMD_IDLE;
    MemoryBarrier();
    s->process_id = pid;
    s->status     = STATUS_IPC_IDLE;
    MemoryBarrier();
    s->command    = cmd;

    DWORD start = GetTickCount();
    // Phase 1: ~10 ms tight spin
    while ((GetTickCount() - start) < 10) {
        UINT32 st = s->status;
        if (st == STATUS_IPC_SUCCESS) return WR_SUCCESS;
        if (st == STATUS_IPC_ERROR)   return WR_ERROR;
        YieldProcessor();
    }
    // Phase 2: yield-based
    while ((GetTickCount() - start) < timeout_ms) {
        UINT32 st = s->status;
        if (st == STATUS_IPC_SUCCESS) return WR_SUCCESS;
        if (st == STATUS_IPC_ERROR)   return WR_ERROR;
        SwitchToThread();
        Sleep(1);
    }
    return WR_TIMEOUT;
}

// ─── Token parser ──────────────────────────────────────────────────────
struct Args {
    char* tokens[16];
    int   count;
};

// Splits `line` in place on spaces. `line` MUST be writable.
static void split_args(char* line, Args* out) {
    out->count = 0;
    char* p = line;
    // Strip trailing newline
    size_t L = strlen(p);
    while (L && (p[L-1] == '\n' || p[L-1] == '\r')) p[--L] = '\0';

    while (*p && out->count < 16) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        out->tokens[out->count++] = p;
        while (*p && *p != ' ' && *p != '\t') ++p;
        if (*p) *p++ = '\0';
    }
}

// Parse uint64 from a string supporting 0x prefix.
static bool parse_u64(const char* s, uint64_t* out) {
    if (!s || !*s) return false;
    char* end = nullptr;
    uint64_t v;
    if ((s[0] == '0' && (s[1] == 'x' || s[1] == 'X')))
        v = _strtoui64(s + 2, &end, 16);
    else
        v = _strtoui64(s, &end, 10);
    if (!end || *end) return false;
    *out = v;
    return true;
}

static bool parse_u32(const char* s, uint32_t* out) {
    uint64_t v;
    if (!parse_u64(s, &v) || v > 0xFFFFFFFFULL) return false;
    *out = (uint32_t)v;
    return true;
}

// ─── Per-command handlers ──────────────────────────────────────────────
static void cmd_ping(uint64_t id) {
    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    WaitResult wr = send_command(0, CMD_PING, 0, 2000);
    QueryPerformanceCounter(&t1);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    double us = (double)(t1.QuadPart - t0.QuadPart) * 1e6 / (double)f.QuadPart;
    char extra[64];
    snprintf(extra, sizeof(extra), "elapsed_us=%.1f", us);
    emit_ok(id, extra);
}

static void cmd_read(uint64_t id, uint32_t pid, uint64_t addr,
                      uint32_t size, uint32_t use_cr3) {
    if (size == 0 || size > IPC_SLOT_DATA_SIZE) {
        emit_err(id, "size must be in (0, 4096]");
        return;
    }
    IPC_RW_DATA* rw = (IPC_RW_DATA*)slot_cmd_data(0);
    rw->target_address = addr;
    rw->buffer_size    = size;
    rw->is_write       = 0;
    rw->use_cr3        = use_cr3 ? 1 : 0;
    WaitResult wr = send_command(0, CMD_READ_MEMORY, pid, 10000);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    // Encode response data as hex. Buffer needs ~ 2*size + prefix.
    static char hexbuf[IPC_SLOT_DATA_SIZE * 2 + 32];
    size_t off = (size_t)snprintf(hexbuf, sizeof(hexbuf), "data_hex=");
    encode_hex(slot_data_buffer(0), size, hexbuf + off, sizeof(hexbuf) - off);
    emit_ok(id, hexbuf);
}

static void cmd_write(uint64_t id, uint32_t pid, uint64_t addr,
                       const char* data_hex, uint32_t use_cr3) {
    int n = decode_hex(data_hex,
                       slot_data_buffer(0),
                       IPC_SLOT_DATA_SIZE);
    if (n < 0) { emit_err(id, "bad data_hex"); return; }
    if (n == 0) { emit_err(id, "empty data"); return; }

    IPC_RW_DATA* rw = (IPC_RW_DATA*)slot_cmd_data(0);
    rw->target_address = addr;
    rw->buffer_size    = (uint64_t)n;
    rw->is_write       = 1;
    rw->use_cr3        = use_cr3 ? 1 : 0;
    WaitResult wr = send_command(0, CMD_WRITE_MEMORY, pid, 10000);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    char extra[32];
    snprintf(extra, sizeof(extra), "bytes=%d", n);
    emit_ok(id, extra);
}

static void cmd_getpid(uint64_t id, const char* name) {
    size_t len = strlen(name);
    if (len == 0 || len > 255) { emit_err(id, "bad name"); return; }
    memcpy(slot_data_buffer(0), name, len);
    IPC_PID_DATA* pd = (IPC_PID_DATA*)slot_cmd_data(0);
    pd->name_len = (UINT32)len;
    WaitResult wr = send_command(0, CMD_GET_PID, 0, 5000);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    char extra[32];
    snprintf(extra, sizeof(extra), "pid=%u",
             ((IPC_PID_DATA*)slot_cmd_data(0))->result_pid);
    emit_ok(id, extra);
}

static void cmd_result_for(uint64_t id, uint32_t pid, uint32_t cmd,
                            const char* key, uint32_t timeout_ms = 5000) {
    WaitResult wr = send_command(0, cmd, pid, timeout_ms);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    char extra[64];
    snprintf(extra, sizeof(extra), "%s=%llx", key,
             (unsigned long long)((IPC_RESULT_DATA*)slot_cmd_data(0))->result);
    emit_ok(id, extra);
}

static void cmd_getmodule(uint64_t id, uint32_t pid, const char* name_utf8) {
    // Convert UTF-8 name to UTF-16LE in the slot data buffer.
    int wch = MultiByteToWideChar(CP_UTF8, 0, name_utf8, -1, nullptr, 0);
    if (wch <= 1 || wch > 256) { emit_err(id, "bad module name"); return; }
    wchar_t wbuf[256];
    if (MultiByteToWideChar(CP_UTF8, 0, name_utf8, -1, wbuf, wch) <= 0) {
        emit_err(id, "utf16 conv failed"); return;
    }
    int name_chars = wch - 1; // exclude trailing NUL
    memcpy(slot_data_buffer(0), wbuf, (size_t)name_chars * 2);
    IPC_MODULE_DATA* md = (IPC_MODULE_DATA*)slot_cmd_data(0);
    md->name_len = (UINT32)name_chars;
    WaitResult wr = send_command(0, CMD_GET_MODULE, pid, 5000);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    char extra[64];
    snprintf(extra, sizeof(extra), "base=%llx",
             (unsigned long long)((IPC_MODULE_DATA*)slot_cmd_data(0))->result);
    emit_ok(id, extra);
}

static void cmd_alloc(uint64_t id, uint32_t pid, uint64_t size,
                       uint32_t type, uint32_t protect) {
    IPC_ALLOC_DATA* ad = (IPC_ALLOC_DATA*)slot_cmd_data(0);
    ad->address         = 0;
    ad->size            = size;
    ad->allocation_type = type;
    ad->protect         = protect;
    WaitResult wr = send_command(0, CMD_ALLOCATE, pid, 10000);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    char extra[64];
    snprintf(extra, sizeof(extra), "addr=%llx",
             (unsigned long long)((IPC_ALLOC_DATA*)slot_cmd_data(0))->result);
    emit_ok(id, extra);
}

static void cmd_free(uint64_t id, uint32_t pid, uint64_t addr) {
    IPC_FREE_DATA* fd = (IPC_FREE_DATA*)slot_cmd_data(0);
    fd->address   = addr;
    fd->free_type = MEM_RELEASE;
    WaitResult wr = send_command(0, CMD_FREE, pid, 5000);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    emit_ok(id, "");
}

static void cmd_shutdown(uint64_t id) {
    WaitResult wr = send_command(0, CMD_SHUTDOWN, 0, 5000);
    if (wr != WR_SUCCESS) {
        emit_err(id, wr == WR_TIMEOUT ? "timeout" : "driver error");
        return;
    }
    emit_ok(id, "");
}

// ─── Main loop ─────────────────────────────────────────────────────────
static void init_ipc_buffer() {
    memset(g_mem, 0, IPC_TOTAL_SIZE);
    g_mem->magic        = IPC_MAGIC;
    g_mem->version      = IPC_VERSION;
    g_mem->active_slots = IPC_MAX_SLOTS;
    for (int i = 0; i < IPC_MAX_SLOTS; ++i) {
        g_mem->slots[i].slot_state = SLOT_STATE_FREE;
        g_mem->slots[i].status     = STATUS_IPC_IDLE;
        g_mem->slots[i].command    = CMD_IDLE;
    }
}

static void burn_magic() {
    g_mem->magic = 0;
}

int wmain(int argc, wchar_t** argv) {
    // Optional --logfile <path> for debugging.
    for (int i = 1; i + 1 < argc; ++i) {
        if (wcscmp(argv[i], L"--logfile") == 0) {
            g_log = _wfopen(argv[i + 1], L"w");
        }
    }

    // We use the line protocol; switch stdout to binary so Windows
    // doesn't translate \n to \r\n behind our backs.
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stdin),  _O_BINARY);
    setvbuf(stdout, nullptr, _IONBF, 0);

    init_ipc_buffer();

    // Announce ourselves so the parent can confirm we're alive and
    // grab the IPC buffer address (for debug/logging).
    printf("ready ipc_va=%llx size=%zu\n",
           (unsigned long long)(uintptr_t)g_mem, sizeof(g_ipc_storage));
    fflush(stdout);
    log_msg("helper started, ipc_va=%p", g_mem);

    char line[16 * 1024];
    while (fgets(line, sizeof(line), stdin)) {
        Args a;
        split_args(line, &a);
        if (a.count == 0) continue;

        const char* cmd = a.tokens[0];
        if (a.count < 2) { emit_err(0, "missing id"); continue; }
        uint64_t id;
        if (!parse_u64(a.tokens[1], &id)) { emit_err(0, "bad id"); continue; }

        if (strcmp(cmd, "ping") == 0) {
            cmd_ping(id);
        } else if (strcmp(cmd, "read") == 0 && a.count == 6) {
            uint32_t pid, size, cr3;
            uint64_t addr;
            if (!parse_u32(a.tokens[2], &pid) ||
                !parse_u64(a.tokens[3], &addr) ||
                !parse_u32(a.tokens[4], &size) ||
                !parse_u32(a.tokens[5], &cr3)) {
                emit_err(id, "bad args"); continue;
            }
            cmd_read(id, pid, addr, size, cr3);
        } else if (strcmp(cmd, "write") == 0 && a.count == 6) {
            uint32_t pid, cr3;
            uint64_t addr;
            if (!parse_u32(a.tokens[2], &pid) ||
                !parse_u64(a.tokens[3], &addr) ||
                !parse_u32(a.tokens[5], &cr3)) {
                emit_err(id, "bad args"); continue;
            }
            cmd_write(id, pid, addr, a.tokens[4], cr3);
        } else if (strcmp(cmd, "getpid") == 0 && a.count == 3) {
            cmd_getpid(id, a.tokens[2]);
        } else if (strcmp(cmd, "getbase") == 0 && a.count == 3) {
            uint32_t pid;
            if (!parse_u32(a.tokens[2], &pid)) { emit_err(id, "bad pid"); continue; }
            cmd_result_for(id, pid, CMD_GET_BASE_ADDRESS, "base");
        } else if (strcmp(cmd, "getpeb") == 0 && a.count == 3) {
            uint32_t pid;
            if (!parse_u32(a.tokens[2], &pid)) { emit_err(id, "bad pid"); continue; }
            cmd_result_for(id, pid, CMD_GET_PEB, "peb");
        } else if (strcmp(cmd, "getmodule") == 0 && a.count == 4) {
            uint32_t pid;
            if (!parse_u32(a.tokens[2], &pid)) { emit_err(id, "bad pid"); continue; }
            cmd_getmodule(id, pid, a.tokens[3]);
        } else if (strcmp(cmd, "getdtb") == 0 && a.count == 3) {
            uint32_t pid;
            if (!parse_u32(a.tokens[2], &pid)) { emit_err(id, "bad pid"); continue; }
            cmd_result_for(id, pid, CMD_RESOLVE_DTB, "cr3");
        } else if (strcmp(cmd, "guarded") == 0) {
            cmd_result_for(id, 0, CMD_GET_GUARDED_REGION, "addr");
        } else if (strcmp(cmd, "alloc") == 0 && a.count == 6) {
            uint32_t pid, type, protect;
            uint64_t size;
            if (!parse_u32(a.tokens[2], &pid) ||
                !parse_u64(a.tokens[3], &size) ||
                !parse_u32(a.tokens[4], &type) ||
                !parse_u32(a.tokens[5], &protect)) {
                emit_err(id, "bad args"); continue;
            }
            cmd_alloc(id, pid, size, type, protect);
        } else if (strcmp(cmd, "free") == 0 && a.count == 4) {
            uint32_t pid;
            uint64_t addr;
            if (!parse_u32(a.tokens[2], &pid) ||
                !parse_u64(a.tokens[3], &addr)) {
                emit_err(id, "bad args"); continue;
            }
            cmd_free(id, pid, addr);
        } else if (strcmp(cmd, "shutdown") == 0) {
            cmd_shutdown(id);
        } else if (strcmp(cmd, "bye") == 0) {
            burn_magic();
            emit_ok(id, "");
            break;
        } else {
            emit_err(id, "unknown command");
        }
    }
    log_msg("helper exiting");
    if (g_log) fclose(g_log);
    return 0;
}
