//
// ipc_speed_test.cpp
//
// All-in-one driver utility with three tabs:
//   1) Speed Testing  — benchmark the shared-memory IPC driver
//   2) Memory Ops     — read/write memory, resolve base/CR3, inject, allocate
//   3) HWID Spoofing  — SMBIOS/registry/mac/volume HWID manipulation
//
// The executable MUST be named `scootware.exe` (see IPC_APP_NAME in ipc_config.h)
// so the driver will attach to its memory. Run as Administrator after loading drv.sys.
//

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <timeapi.h>
#include <commdlg.h>
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "comdlg32.lib")

#include <algorithm>
#include <atomic>
#include <cmath>
#include <numeric>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <d3d11.h>
#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include "shared_memory_ipc.h"

// ============================================================================
// Shared globals
// ============================================================================
static std::mutex       g_log_mutex;
static std::vector<std::string> g_log_lines;
static std::atomic<float>       g_progress_current{0.0f};
static std::atomic<bool>        g_benchmark_running{false};
static std::atomic<bool>        g_benchmark_stop_requested{false};
static std::string              g_current_test_name = "Idle";

static bool benchmark_wants_stop() {
    return g_benchmark_stop_requested.load(std::memory_order_relaxed);
}

static void LOG_PRINT(const char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_lines.push_back(buf);
}
#define printf LOG_PRINT

// Shared IPC buffer (driver scans for IPC_MAGIC at the start of a 4 KiB page)
__declspec(align(4096)) static char g_ipc_storage[IPC_TOTAL_SIZE];
static PIPC_MEMORY g_mem = reinterpret_cast<PIPC_MEMORY>(g_ipc_storage);

static inline IPC_SLOT* slot_at(int i)          { return &g_mem->slots[i]; }
static inline void*     slot_cmd_data(int i)    { return &g_mem->slots[i].cmd_data; }
static inline uint8_t*  slot_data_buffer(int i) { return  g_mem->slots[i].data_buffer; }
static constexpr size_t kSlotDataSize = IPC_SLOT_DATA_SIZE;

// ============================================================================
// High-resolution timing
// ============================================================================
static double g_qpc_to_ns = 0.0;

static void init_timing() {
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_qpc_to_ns = 1e9 / (double)f.QuadPart;
    timeBeginPeriod(1);
    atexit([]() { timeEndPeriod(1); });
}

static void pin_benchmark_thread() {
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1); // CPU 0
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
}

static inline uint64_t now_ns() {
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((double)c.QuadPart * g_qpc_to_ns);
}

// ============================================================================
// Command dispatch — adaptive spin/yield/sleep (shared by all tabs)
// ============================================================================
enum class WaitResult { Success, Error, Timeout };
static std::atomic<uint32_t> g_pace_us{0};
static std::mutex g_slot0_mutex;

static inline void apply_pacing() {
    uint32_t p = g_pace_us.load(std::memory_order_relaxed);
    if (!p) return;
    if (p < 1000) { uint64_t end = now_ns() + (uint64_t)p * 1000ull; while (now_ns() < end) _mm_pause(); }
    else { Sleep(p / 1000); }
}

static WaitResult send_command_unlocked(int slot_idx,
                                        UINT32 command,
                                        UINT32 target_pid,
                                        uint32_t timeout_ms = 5000);

static WaitResult send_command(int slot_idx,
                               UINT32 command,
                               UINT32 target_pid,
                               uint32_t timeout_ms = 5000)
{
    if (slot_idx == 0) {
        std::lock_guard<std::mutex> lk(g_slot0_mutex);
        return send_command_unlocked(slot_idx, command, target_pid, timeout_ms);
    }
    return send_command_unlocked(slot_idx, command, target_pid, timeout_ms);
}

static WaitResult send_command_unlocked(int slot_idx,
                                        UINT32 command,
                                        UINT32 target_pid,
                                        uint32_t timeout_ms)
{
    IPC_SLOT* s = slot_at(slot_idx);

    //
    // Three-step arming protocol. The driver's worker picks up a slot
    // when it sees `command != CMD_IDLE && status == STATUS_IPC_IDLE`.
    // After a successful previous op this slot holds
    //   { command = PREV_CMD, status = SUCCESS }.
    // If we simply wrote `status = IDLE` first and `command = NEW` second,
    // there is a tiny window where the slot looks like
    //   { command = PREV_CMD, status = IDLE }
    // which the worker will happily re-execute using whatever we have
    // already written into cmd_data.rw for the NEW op. The worker then
    // flips status = SUCCESS, our spin-wait returns immediately thinking
    // the NEW command completed, and we march on with torn data. This
    // was irrelevant when the worker polled every ~15 ms — the window
    // was nanoseconds wide — but with sub-microsecond polling it hits
    // deterministically, and at a size transition (1024 -> 4096) it's
    // observed as scootware.exe AV'ing on a half-mutated slot.
    //
    // Step 1: invalidate the command field so the worker ignores this
    //         slot no matter what state it samples next.
    // Step 2: flip status back to IDLE and update process_id, now safe.
    // Step 3: publish the new command with a full barrier so the
    //         worker never sees a newer command before an IDLE status.
    //
	s->command    = CMD_IDLE;
	MemoryBarrier();
	s->process_id = target_pid;
	s->status     = STATUS_IPC_IDLE;
	MemoryBarrier();
	s->command    = command;

    const uint64_t start_ns    = now_ns();
    const uint64_t deadline_ns = start_ns + (uint64_t)timeout_ms * 1'000'000ull;

    //
    // Phase 1: time-bounded tight spin.
    //
    // Previously this was `for i in 0..50'000: _mm_pause()`. The
    // number-of-iterations approach is deeply broken on modern CPUs:
    // Skylake+ PAUSE is ~140 cycles, so 50k iterations is already ~1.7
    // ms of wall time — fine when the kernel worker is hot, useless if
    // the worker just woke from a yield (which can take ~15 ms). And
    // once Phase 1 expires, Phase 2 goes into SwitchToThread which
    // itself forfeits a full scheduler quantum, *adding* ~15 ms to our
    // observed latency instead of reducing it.
    //
    // We budget Phase 1 at ~10 ms of real wall time, measured by QPC
    // rather than iteration count. That comfortably covers even a
    // worker that was asleep waiting for quantum expiry, so the vast
    // majority of ops never leave the hot phase — no context switch,
    // no Sleep rounding. Single-core CPU cost of 10 ms of PAUSE is
    // negligible; we give it up the instant the driver acks.
    //
    const uint64_t phase1_deadline_ns = start_ns + 10'000'000ull; // 10 ms
    while (now_ns() < phase1_deadline_ns) {
        UINT32 st = s->status;
        if (st == STATUS_IPC_SUCCESS) return WaitResult::Success;
        if (st == STATUS_IPC_ERROR)   return WaitResult::Error;
        _mm_pause();
    }

    // Phase 2: cooperative yield with short check cadence. Capped at
    // ~10 ms so we still hit Phase 3 eventually if the driver is
    // truly gone.
    const uint64_t phase2_deadline_ns = start_ns + 20'000'000ull; // total 20 ms
    while (now_ns() < phase2_deadline_ns && now_ns() < deadline_ns) {
        UINT32 st = s->status;
        if (st == STATUS_IPC_SUCCESS) return WaitResult::Success;
        if (st == STATUS_IPC_ERROR)   return WaitResult::Error;
        SwitchToThread();
    }

    // Phase 3: 1 ms sleeps until deadline.
    while (now_ns() < deadline_ns) {
        UINT32 st = s->status;
        if (st == STATUS_IPC_SUCCESS) return WaitResult::Success;
        if (st == STATUS_IPC_ERROR)   return WaitResult::Error;
        Sleep(1);
    }
    return WaitResult::Timeout;
}

// ============================================================================
// Chunked read / write helpers
// ============================================================================
static bool drv_read(int slot, uint32_t pid, uint64_t addr, void* dst, size_t size, bool use_cr3) {
    uint8_t* p = (uint8_t*)dst;
    while (size > 0) {
        size_t chunk = std::min(size, kSlotDataSize);
        IPC_RW_DATA* rw = (IPC_RW_DATA*)slot_cmd_data(slot);
        rw->target_address = addr; rw->buffer_size = chunk; rw->is_write = 0; rw->use_cr3 = use_cr3 ? 1u : 0u;
        if (send_command(slot, CMD_READ_MEMORY, pid, 10'000) != WaitResult::Success) return false;
        memcpy(p, slot_data_buffer(slot), chunk);
        p += chunk; addr += chunk; size -= chunk; apply_pacing();
    }
    return true;
}

static bool drv_write(int slot, uint32_t pid, uint64_t addr, const void* src, size_t size, bool use_cr3) {
    const uint8_t* p = (const uint8_t*)src;
    while (size > 0) {
        size_t chunk = std::min(size, kSlotDataSize);
        IPC_RW_DATA* rw = (IPC_RW_DATA*)slot_cmd_data(slot);
        rw->target_address = addr; rw->buffer_size = chunk; rw->is_write = 1; rw->use_cr3 = use_cr3 ? 1u : 0u;
        memcpy(slot_data_buffer(slot), p, chunk);
        if (send_command(slot, CMD_WRITE_MEMORY, pid, 10'000) != WaitResult::Success) return false;
        p += chunk; addr += chunk; size -= chunk; apply_pacing();
    }
    return true;
}

static bool drv_resolve_dtb(uint32_t pid, uint64_t* out_cr3 = nullptr) {
    if (send_command(0, CMD_RESOLVE_DTB, pid, 5000) != WaitResult::Success) return false;
    IPC_RESULT_DATA* r = (IPC_RESULT_DATA*)slot_cmd_data(0);
    if (out_cr3) *out_cr3 = r->result;
    return r->result != 0;
}

// ============================================================================
// Generic command helpers for all CMD_* types
// ============================================================================
static uint64_t drv_get_base_address(uint32_t pid) {
    if (send_command(0, CMD_GET_BASE_ADDRESS, pid, 5000) != WaitResult::Success) return 0;
    return ((IPC_RESULT_DATA*)slot_cmd_data(0))->result;
}

static uint64_t drv_get_peb(uint32_t pid) {
    if (send_command(0, CMD_GET_PEB, pid, 5000) != WaitResult::Success) return 0;
    return ((IPC_RESULT_DATA*)slot_cmd_data(0))->result;
}

static uint64_t drv_get_guarded_region() {
    if (send_command(0, CMD_GET_GUARDED_REGION, 0, 5000) != WaitResult::Success) return 0;
    return ((IPC_RESULT_DATA*)slot_cmd_data(0))->result;
}

static uint64_t drv_get_module_base(uint32_t pid, const wchar_t* module_name, int name_len) {
    if (!name_len || name_len > 256) return 0;
    memcpy(slot_data_buffer(0), module_name, name_len * 2);
    slot_cmd_data(0); // touch
    ((IPC_MODULE_DATA*)slot_cmd_data(0))->name_len = name_len;
    if (send_command(0, CMD_GET_MODULE, pid, 5000) != WaitResult::Success) return 0;
    return ((IPC_MODULE_DATA*)slot_cmd_data(0))->result;
}

static uint32_t drv_get_pid_by_name(const char* proc_name) {
    int len = (int)strlen(proc_name);
    if (!len || len > 255) return 0;
    memcpy(slot_data_buffer(0), proc_name, len);
    ((IPC_PID_DATA*)slot_cmd_data(0))->name_len = len;
    if (send_command(0, CMD_GET_PID, 0, 5000) != WaitResult::Success) return 0;
    return ((IPC_PID_DATA*)slot_cmd_data(0))->result_pid;
}

static uint64_t drv_allocate(uint32_t pid, uint64_t preferred, uint64_t size, uint32_t type, uint32_t protect) {
    ((IPC_ALLOC_DATA*)slot_cmd_data(0))->address = preferred;
    ((IPC_ALLOC_DATA*)slot_cmd_data(0))->size = size;
    ((IPC_ALLOC_DATA*)slot_cmd_data(0))->allocation_type = type;
    ((IPC_ALLOC_DATA*)slot_cmd_data(0))->protect = protect;
    if (send_command(0, CMD_ALLOCATE, pid, 10000) != WaitResult::Success) return 0;
    return ((IPC_ALLOC_DATA*)slot_cmd_data(0))->result;
}

static bool drv_free(uint32_t pid, uint64_t address, uint32_t free_type) {
    ((IPC_FREE_DATA*)slot_cmd_data(0))->address = address;
    ((IPC_FREE_DATA*)slot_cmd_data(0))->free_type = free_type;
    return send_command(0, CMD_FREE, pid, 5000) == WaitResult::Success;
}

static bool drv_mouse_move(int32_t x, int32_t y, uint16_t btn) {
    ((IPC_MOUSE_DATA*)slot_cmd_data(0))->x = x;
    ((IPC_MOUSE_DATA*)slot_cmd_data(0))->y = y;
    ((IPC_MOUSE_DATA*)slot_cmd_data(0))->button_flags = btn;
    return send_command(0, CMD_MOUSE_MOVE, 0, 5000) == WaitResult::Success;
}

// Inject DLL: driver reads the DLL bytes directly from our process VA via the
// CR3-physical-read pipeline, so we just hand it the heap pointer.
// alloc_mode: INJ_ALLOC_* constant forwarded directly to the injector subsystem.
//
// NB: the previous version copied (up to) the first 4 KB of the DLL into slot
// 0's data buffer and pointed the driver at that buffer.  For any DLL larger
// than IPC_SLOT_DATA_SIZE the driver then read past the slot into adjacent
// shared-memory pages — getting garbage and parsing a corrupted PE.  Since the
// driver reads cross-process anyway, the simplest fix is to pass the original
// user-mode pointer directly; no slot copy is required.
static uint64_t drv_inject_dll(uint32_t target_pid, const void* dll_bytes, uint32_t dll_size, uint32_t alloc_mode) {
    if (!dll_bytes || !dll_size || dll_size > 32 * 1024 * 1024) return 0;

    IPC_INJECT_DATA* inj = (IPC_INJECT_DATA*)slot_cmd_data(0);
    inj->target_pid      = target_pid;
    inj->dll_usermode_ptr = (uint64_t)dll_bytes; // caller-owned VA in our process space
    inj->dll_size        = dll_size;
    inj->alloc_mode      = alloc_mode;

    if (send_command(0, CMD_INJECT_DLL, (uint32_t)GetCurrentProcessId(), 15000) != WaitResult::Success)
        return 0;
    return ((IPC_RESULT_DATA*)slot_cmd_data(0))->result;
}

// ============================================================================
// HWID command wrappers
// ============================================================================
static bool drv_hwid_save() {
    return send_command(0, CMD_HWID_SAVE, 0, 10000) == WaitResult::Success;
}

static bool drv_hwid_spoof(uint32_t components, uint64_t seed) {
    ((IPC_HWID_CMD*)slot_cmd_data(0))->components = components;
    ((IPC_HWID_CMD*)slot_cmd_data(0))->random_seed = seed;
    return send_command(0, CMD_HWID_SPOOF, 0, 15000) == WaitResult::Success;
}

static bool drv_hwid_restore() {
    return send_command(0, CMD_HWID_RESTORE, 0, 15000) == WaitResult::Success;
}

static bool drv_hwid_reroll(uint32_t components) {
    ((IPC_HWID_CMD*)slot_cmd_data(0))->components = components;
    return send_command(0, CMD_HWID_REROLL, 0, 15000) == WaitResult::Success;
}

static bool drv_hwid_status(uint32_t* out_state, uint32_t* out_active, IPC_HWID_DATA* out_data) {
    if (send_command(0, CMD_HWID_STATUS, 0, 10000) != WaitResult::Success) return false;
    if (out_state)  *out_state  = ((IPC_HWID_CMD*)slot_cmd_data(0))->state;
    if (out_active) *out_active = ((IPC_HWID_CMD*)slot_cmd_data(0))->active;
    if (out_data)   memcpy(out_data, slot_data_buffer(0), sizeof(IPC_HWID_DATA));
    return true;
}

static bool drv_hwid_get_original(IPC_HWID_DATA* out_data) {
    if (!out_data) return false;
    if (send_command(0, CMD_HWID_GET_ORIGINAL, 0, 10000) != WaitResult::Success) return false;
    memcpy(out_data, slot_data_buffer(0), sizeof(IPC_HWID_DATA));
    return true;
}

static bool drv_hwid_load(uint32_t components, uint64_t seed, const IPC_HWID_DATA* data) {
    if (data) memcpy(slot_data_buffer(0), data, sizeof(IPC_HWID_DATA));
    ((IPC_HWID_CMD*)slot_cmd_data(0))->components = components;
    ((IPC_HWID_CMD*)slot_cmd_data(0))->random_seed = seed;
    return send_command(0, CMD_HWID_LOAD, 0, 15000) == WaitResult::Success;
}

// ============================================================================
// Stealth validation / diagnostic command wrappers (CMD_STEALTH_STATUS, etc.)
// ============================================================================
static bool drv_stealth_status(IPC_STEALTH_STATUS* out) {
    if (!out) return false;
    if (send_command(0, CMD_STEALTH_STATUS, 0, 10000) != WaitResult::Success) return false;
    memcpy(out, slot_data_buffer(0), sizeof(IPC_STEALTH_STATUS));
    return true;
}

static bool drv_rw_cycle_test(IPC_RW_CYCLE_RESULT* out) {
    if (!out) return false;
    if (send_command(0, CMD_RW_CYCLE_TEST, 0, 15000) != WaitResult::Success) return false;
    memcpy(out, slot_data_buffer(0), sizeof(IPC_RW_CYCLE_RESULT));
    return true;
}

static bool drv_thread_validate(uint64_t* out_result, char* report_buf, size_t report_size) {
    if (send_command(0, CMD_THREAD_VALIDATE, 0, 5000) != WaitResult::Success) return false;
    if (out_result) *out_result = ((IPC_RESULT_DATA*)slot_cmd_data(0))->result;
    if (report_buf && report_size) {
        memcpy(report_buf, slot_data_buffer(0), report_size - 1);
        report_buf[report_size - 1] = 0;
    }
    return true;
}

// ============================================================================
// Benchmark functions (kept from original)
// ============================================================================
struct LatencyStats {
    size_t n = 0; double avg_ns = 0.0;
    uint64_t min_ns = 0, p50_ns = 0, p95_ns = 0, p99_ns = 0, max_ns = 0;
};

static LatencyStats compute_stats(std::vector<uint64_t> s) {
    LatencyStats out;
    if (s.empty()) return out;
    std::sort(s.begin(), s.end());
    out.n = s.size(); out.min_ns = s.front(); out.max_ns = s.back();
    out.p50_ns = s[(size_t)(0.50 * (s.size() - 1))];
    out.p95_ns = s[(size_t)(0.95 * (s.size() - 1))];
    out.p99_ns = s[(size_t)(0.99 * (s.size() - 1))];
    out.avg_ns = std::accumulate(s.begin(), s.end(), 0.0) / (double)s.size();
    return out;
}

static void print_latency_row(const char* label, const LatencyStats& st) {
    if (st.n == 0) { printf("  %-36s no samples\n", label); return; }
    printf("  %-36s n=%5zu  avg=%7.1f us  min=%6.1f  p50=%6.1f  p95=%7.1f  p99=%7.1f  max=%8.1f  (us)\n",
           label, st.n, st.avg_ns/1000.0, st.min_ns/1000.0, st.p50_ns/1000.0,
           st.p95_ns/1000.0, st.p99_ns/1000.0, st.max_ns/1000.0);
}

static FILE* g_csv = nullptr;
static void csv_header() {
    if (!g_csv) return;
    fprintf(g_csv, "test,variant,size_bytes,threads,iterations,avg_us,min_us,p50_us,p95_us,p99_us,max_us,throughput_MBps\n");
    fflush(g_csv);
}
static void csv_row(const char* test, const char* variant, size_t size, int threads, size_t iters, const LatencyStats& st, double mbps) {
    if (!g_csv) return;
    fprintf(g_csv, "%s,%s,%zu,%d,%zu,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
            test, variant, size, threads, iters, st.avg_ns/1000.0, st.min_ns/1000.0,
            st.p50_ns/1000.0, st.p95_ns/1000.0, st.p99_ns/1000.0, st.max_ns/1000.0, mbps);
    fflush(g_csv);
}

static void bench_ping(int iterations) {
    printf("\n== PING round-trip latency ==\n");
    std::vector<uint64_t> samples; samples.reserve(iterations);
    for (int i = 0; i < iterations; ++i) {
        if (benchmark_wants_stop()) { printf("[*] PING stopped early.\n"); return; }
        g_progress_current = (float)i / iterations;
        uint64_t t0 = now_ns();
        WaitResult r = send_command(0, CMD_PING, 0, 2000);
        uint64_t t1 = now_ns();
        if (r != WaitResult::Success) { printf("[!] PING failed at iter %d\n", i); return; }
        samples.push_back(t1 - t0);
    }
    LatencyStats st = compute_stats(samples);
    print_latency_row("PING RTT", st);
    csv_row("ping","rtt",0,1,samples.size(),st,0.0);
}

static void bench_rw_latency(uint32_t pid, uint64_t addr, size_t size, int iterations, bool use_cr3) {
    const char* variant = use_cr3 ? "cr3" : "mm";
    std::vector<uint64_t> wr, rd; wr.reserve(iterations); rd.reserve(iterations);
    std::vector<uint8_t> buf(size);
    for (size_t i = 0; i < size; ++i) buf[i] = (uint8_t)(i & 0xFF);
    drv_write(0, pid, addr, buf.data(), size, use_cr3);
    drv_read(0, pid, addr, buf.data(), size, use_cr3);
    int fw=0, fr=0;
    for (int i = 0; i < iterations; ++i) {
        if (benchmark_wants_stop()) { printf("[*] Latency sweep stopped [%s].\n", variant); return; }
        g_progress_current = (float)i / iterations;
        uint64_t t0=now_ns(); bool okw=drv_write(0,pid,addr,buf.data(),size,use_cr3); uint64_t t1=now_ns();
        if (okw) wr.push_back(t1-t0); else if (++fw>=5) break;
        uint64_t t2=now_ns(); bool okr=drv_read(0,pid,addr,buf.data(),size,use_cr3); uint64_t t3=now_ns();
        if (okr) rd.push_back(t3-t2); else if (++fr>=5) break;
    }
    LatencyStats sw=compute_stats(wr), sr=compute_stats(rd);
    char lw[96],lr[96]; _snprintf_s(lw,_TRUNCATE,"WRITE %6zuB [%s]",size,variant); _snprintf_s(lr,_TRUNCATE,"READ  %6zuB [%s]",size,variant);
    print_latency_row(lw,sw); print_latency_row(lr,sr);
    csv_row("rw_latency",(std::string("write_")+variant).c_str(),size,1,wr.size(),sw,0.0);
    csv_row("rw_latency",(std::string("read_")+variant).c_str(),size,1,rd.size(),sr,0.0);
}

static void bench_throughput_single(uint32_t pid, uint64_t base_addr, uint64_t region_size, size_t size, uint64_t total_bytes, bool is_write, bool use_cr3) {
    std::vector<uint8_t> buf(size,0xA5);
    uint64_t addr=base_addr, end=base_addr+region_size, done=0, t0=now_ns();
    while (done<total_bytes) {
        if (benchmark_wants_stop()) { printf("[*] Throughput stopped.\n"); return; }
        g_progress_current=(float)done/total_bytes;
        size_t chunk=(size_t)std::min<uint64_t>(size,total_bytes-done);
        if(addr+chunk>end) addr=base_addr;
        bool ok=is_write?drv_write(0,pid,addr,buf.data(),chunk,use_cr3):drv_read(0,pid,addr,buf.data(),chunk,use_cr3);
        if(!ok){printf("[!] %s failed\n",is_write?"write":"read");return;}
        addr+=chunk;done+=chunk;
    }
    uint64_t t1=now_ns(); double secs=(t1-t0)/1e9, mb=(double)done/(1024.0*1024.0);
    printf("  %-5s size=%7zuB  total=%7.2f MB  time=%7.3fs  -> %8.2f MB/s  [%s]\n",
           is_write?"write":"read ",size,mb,secs,mb/secs,use_cr3?"cr3":"mm");
    LatencyStats nil; csv_row("throughput_1t",(std::string(is_write?"write_":"read_")+(use_cr3?"cr3":"mm")).c_str(),size,1,(size_t)(done/size),nil,mb/secs);
}

struct WorkerResult{uint64_t bytes_done=0;bool ok=true;};
static void throughput_worker(int slot,uint32_t pid,uint64_t addr,size_t size,uint64_t total,bool is_write,bool use_cr3,std::atomic<bool>* go,WorkerResult* out){
    std::vector<uint8_t> buf(size,(uint8_t)(slot*17+1));
    while(!go->load(std::memory_order_acquire)) _mm_pause();
    uint64_t done=0;
    while(done<total){
        if(benchmark_wants_stop())break;
        g_progress_current=(float)done/total;
        size_t chunk=(size_t)std::min<uint64_t>(size,total-done);
        bool ok=is_write?drv_write(slot,pid,addr+done,buf.data(),chunk,use_cr3):drv_read(slot,pid,addr+done,buf.data(),chunk,use_cr3);
        if(!ok){out->ok=false;break;} done+=chunk;
    } out->bytes_done=done;
}

static void bench_throughput_multi(uint32_t pid,uint64_t base_addr,size_t size,int threads,uint64_t bpt,bool is_write,bool use_cr3){
    if((UINT32)threads>g_mem->active_slots) g_mem->active_slots=threads;
    std::vector<std::thread> workers; std::vector<WorkerResult> results(threads); std::atomic<bool> go(false);
    for(int i=0;i<threads;++i) workers.emplace_back(throughput_worker,i%IPC_MAX_SLOTS,pid,base_addr+(uint64_t)i*(bpt+4096),size,bpt,is_write,use_cr3,&go,&results[i]);
    uint64_t t0=now_ns(); go.store(true,std::memory_order_release); for(auto&t:workers)t.join(); uint64_t t1=now_ns();
    uint64_t total=0; bool all_ok=true; for(auto&r:results){total+=r.bytes_done;all_ok&=r.ok;}
    double secs=(t1-t0)/1e9; double mb=(double)total/(1024.0*1024.0);
    printf("  %-5s threads=%2d size=%6zuB total=%8.2f MB time=%7.3fs -> %9.2f MB/s [%s]%s\n",
           is_write?"write":"read ",threads,size,mb,secs,mb/secs,use_cr3?"cr3":"mm",all_ok?"":" (partial)");
    LatencyStats nil; csv_row("throughput_nt",(std::string(is_write?"write_":"read_")+(use_cr3?"cr3":"mm")).c_str(),size,threads,(size_t)(total/size),nil,mb/secs);
}

// ============================================================================
// run_benchmark — benchmark entry point (called from Speed Test tab)
// ============================================================================
int run_benchmark(int argc, char** argv) {
    pin_benchmark_thread();
    void* scratch_region = nullptr;
    bool completed_all = false;
    struct Options {
        uint32_t target_pid = 0; int ping_iters = 500; int latency_iters = 100;
        uint64_t throughput_bytes = 1ull * 1024 * 1024; int max_threads = IPC_MAX_SLOTS;
        uint32_t pace_us = 0; bool test_cr3 = false; bool test_mm = true;
        bool test_throughput = false; bool test_multi = false; bool quick = false;
        std::string csv_path;
    } opts;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* /*f*/) -> const char* { if (++i >= argc) return nullptr; return argv[i]; };
        if (a == "--iters") { auto v = need("--iters"); if (!v) return 0; opts.latency_iters = atoi(v); }
        else if (a == "--ping") { auto v = need("--ping"); if (!v) return 0; opts.ping_iters = atoi(v); }
        else if (a == "--bytes") { auto v = need("--bytes"); if (!v) return 0; opts.throughput_bytes = (uint64_t)_atoi64(v); }
        else if (a == "--pace-us") { auto v = need("--pace-us"); if (!v) return 0; opts.pace_us = (uint32_t)atoi(v); }
        else if (a == "--cr3") opts.test_cr3 = true;
        else if (a == "--throughput") opts.test_throughput = true;
        else if (a == "--multi") opts.test_multi = true;
        else if (a == "--csv") { auto v = need("--csv"); if (!v) return 0; opts.csv_path = v; }
        else if (a == "--quick") opts.quick = true;
    }
    if (opts.quick) { opts.latency_iters = std::min(opts.latency_iters, 100); opts.ping_iters = std::min(opts.ping_iters, 50); opts.throughput_bytes = std::min<uint64_t>(opts.throughput_bytes, 256ull * 1024); }

    // CSV setup
    if (!opts.csv_path.empty()) {
        if (fopen_s(&g_csv, opts.csv_path.c_str(), "w") != 0 || !g_csv) return 1;
        csv_header();
    }

    // Reset slots
    { std::lock_guard<std::mutex> lk(g_slot0_mutex); for (int i = 0; i < IPC_MAX_SLOTS; ++i) { g_mem->slots[i].slot_state = SLOT_STATE_FREE; g_mem->slots[i].status = STATUS_IPC_IDLE; g_mem->slots[i].command = CMD_IDLE; } }
    printf("[+] IPC buffer @ %p\n", (void*)g_mem);

    // Target (declare early so goto doesn't skip init)
    uint32_t tpid = opts.target_pid ? opts.target_pid : GetCurrentProcessId();
    uint64_t base_addr = 0;
    bool handshake_ok = false;

    // Handshake
    printf("[*] Waiting for driver handshake...\n");
    for (int t = 0; t < 120; ++t) {
        if (benchmark_wants_stop()) break;
        if (send_command(0, CMD_PING, 0, 1000) == WaitResult::Success) { handshake_ok = true; break; }
        Sleep(500);
    }
    if (!handshake_ok) { printf("[-] Driver did not respond.\n"); goto cleanup; }
    printf("[+] Driver handshake OK. PID: %u\n", tpid);

    // Scratch
    scratch_region = VirtualAlloc(nullptr, 64 * 1024 * 1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!scratch_region) { printf("[-] VirtualAlloc failed.\n"); goto cleanup; }
    memset(scratch_region, 0xA5, 64 * 1024 * 1024);
    base_addr = (uint64_t)scratch_region;
    g_pace_us.store(opts.pace_us, std::memory_order_relaxed);

    // Benchmarks - use blocks to avoid goto-skips-init errors
    {
        bench_ping(opts.ping_iters);
        if (benchmark_wants_stop()) goto done;

        if (opts.test_cr3) {
            uint64_t cr3v = 0;
            if (drv_resolve_dtb(tpid, &cr3v) && cr3v != 0) printf("\n[+] CR3: 0x%llX\n", (unsigned long long)cr3v);
            else opts.test_cr3 = false;
        }
        if (benchmark_wants_stop()) goto done;

        std::vector<size_t> lsz = { 1, 8, 64, 256, 1024 };
        std::vector<std::pair<bool, const char*>> variants;
        if (opts.test_mm) variants.emplace_back(false, "MmCopyVirtualMemory");
        if (opts.test_cr3) variants.emplace_back(true, "CR3 direct");

        for (auto [cr3v, lb] : variants) {
            if (benchmark_wants_stop()) goto done;
            printf("\n== Single-op latency [%s] ==\n", lb);
            for (size_t sz : lsz) {
                if (benchmark_wants_stop()) goto done;
                bench_rw_latency(tpid, base_addr, sz, opts.latency_iters, cr3v);
            }
        }

        if (opts.test_throughput) {
            for (auto [cr3v, lb] : variants) {
                if (benchmark_wants_stop()) goto done;
                printf("\n== Throughput 1T [%s] ==\n", lb);
                std::vector<size_t> ts = { 256, 1024 };
                for (size_t sz : ts) {
                    if (benchmark_wants_stop()) goto done;
                    bench_throughput_single(tpid, base_addr, 64 * 1024 * 1024, sz, opts.throughput_bytes, true, cr3v);
                    if (benchmark_wants_stop()) goto done;
                    bench_throughput_single(tpid, base_addr, 64 * 1024 * 1024, sz, opts.throughput_bytes, false, cr3v);
                }
            }
        }

        if (opts.test_multi) {
            for (auto [cr3v, lb] : variants) {
                if (benchmark_wants_stop()) goto done;
                printf("\n== Multi-thread scaling [%s] ==\n", lb);
                for (int t = 1; t <= opts.max_threads; t = (t == 1 ? 2 : t + 2)) {
                    if (benchmark_wants_stop()) goto done;
                    bench_throughput_multi(tpid, base_addr + 4096, 4096, t, opts.throughput_bytes, true, cr3v);
                    if (benchmark_wants_stop()) goto done;
                    bench_throughput_multi(tpid, base_addr + 4096, 4096, t, opts.throughput_bytes, false, cr3v);
                }
            }
        }
    }

done:
    if (!benchmark_wants_stop()) { printf("\n[+] Benchmark complete.\n"); completed_all = true; }
    else printf("\n[*] Benchmark stopped.\n");

cleanup:
    if (scratch_region) VirtualFree(scratch_region, 0, MEM_RELEASE);
    if (g_csv) { fclose(g_csv); g_csv = nullptr; }
    g_benchmark_stop_requested = false; g_benchmark_running = false;
    g_progress_current = completed_all ? 1.0f : 0.0f;
    g_current_test_name = completed_all ? "Finished" : "Idle";
    return 0;
}

// ============================================================================
// D3D11 UI Application
// ============================================================================
static ID3D11Device* g_pd3dDevice=nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext=nullptr;
static IDXGISwapChain* g_pSwapChain=nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView=nullptr;

static bool CreateDeviceD3D(HWND hWnd){
    DXGI_SWAP_CHAIN_DESC sd{}; sd.BufferCount=2; sd.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator=60; sd.BufferDesc.RefreshRate.Denominator=1;
    sd.Flags=DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH; sd.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow=hWnd; sd.SampleDesc.Count=1; sd.Windowed=TRUE; sd.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL fl; const D3D_FEATURE_LEVEL fla[2]={D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_0};
    if(D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,fla,2,D3D11_SDK_VERSION,&sd,&g_pSwapChain,&g_pd3dDevice,&fl,&g_pd3dDeviceContext)!=S_OK) return false;
    ID3D11Texture2D* pBB; g_pSwapChain->GetBuffer(0,IID_PPV_ARGS(&pBB));
    g_pd3dDevice->CreateRenderTargetView(pBB,nullptr,&g_mainRenderTargetView); pBB->Release();
    return true;
}
static void CleanupDeviceD3D(){
    if(g_mainRenderTargetView){g_mainRenderTargetView->Release();g_mainRenderTargetView=nullptr;}
    if(g_pSwapChain){g_pSwapChain->Release();g_pSwapChain=nullptr;}
    if(g_pd3dDeviceContext){g_pd3dDeviceContext->Release();g_pd3dDeviceContext=nullptr;}
    if(g_pd3dDevice){g_pd3dDevice->Release();g_pd3dDevice=nullptr;}
}
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND,UINT,WPARAM,LPARAM);
LRESULT WINAPI WndProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    if(ImGui_ImplWin32_WndProcHandler(hWnd,msg,wParam,lParam)) return true;
    switch(msg){
        case WM_SIZE:
            if(g_pd3dDevice&&wParam!=SIZE_MINIMIZED){
                if(g_mainRenderTargetView){g_mainRenderTargetView->Release();g_mainRenderTargetView=nullptr;}
                g_pSwapChain->ResizeBuffers(0,(UINT)LOWORD(lParam),(UINT)HIWORD(lParam),DXGI_FORMAT_UNKNOWN,0);
                ID3D11Texture2D* pBB; g_pSwapChain->GetBuffer(0,IID_PPV_ARGS(&pBB));
                g_pd3dDevice->CreateRenderTargetView(pBB,nullptr,&g_mainRenderTargetView); pBB->Release();
            } return 0;
        case WM_DESTROY: ::PostQuitMessage(0); return 0;
    } return ::DefWindowProc(hWnd,msg,wParam,lParam);
}

// ============================================================================
// Forward declarations for tab functions
// ============================================================================
static void DrawSpeedTestTab(const std::vector<std::string>& args_vec);
static void DrawMemOpsTab();
static void DrawHWIDTab();
static void DrawColorValidationTab();
static void DrawStealthStatusTab();
static void DrawInjectTab();

// ============================================================================
// Helper: render a shared log window (used by all tabs)
// ============================================================================
static void DrawLogWindow() {
    ImGui::Separator();
    ImGui::Text("Console Output:");
    ImGui::BeginChild("LogScrollRegion", ImVec2(0, 180), true, ImGuiWindowFlags_HorizontalScrollbar);
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        for (const auto& line : g_log_lines) {
            ImGui::TextUnformatted(line.c_str());
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 10.0f)
            ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char** argv) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, "Scootware_Class", nullptr };
    ::RegisterClassEx(&wc);
    HWND hwnd = ::CreateWindow(wc.lpszClassName, "Scootware Driver Control Center", WS_OVERLAPPEDWINDOW, 100, 100, 1280, 860, nullptr, nullptr, wc.hInstance, nullptr);
    if (!CreateDeviceD3D(hwnd)) { CleanupDeviceD3D(); ::UnregisterClass(wc.lpszClassName, wc.hInstance); return 1; }
    ::ShowWindow(hwnd, SW_SHOWDEFAULT); ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION(); ImGui::CreateContext(); ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.Fonts->AddFontDefault();
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd); ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    init_timing();

    // Write IPC header so driver can discover us immediately
    memset(g_mem, 0, IPC_TOTAL_SIZE);
    g_mem->magic = IPC_MAGIC; g_mem->version = IPC_VERSION; g_mem->active_slots = IPC_MAX_SLOTS;
    for (int i = 0; i < IPC_MAX_SLOTS; ++i) {
        g_mem->slots[i].slot_state = SLOT_STATE_FREE; g_mem->slots[i].status = STATUS_IPC_IDLE; g_mem->slots[i].command = CMD_IDLE;
    }

    std::vector<std::string> args_vec;
    for (int i = 0; i < argc; i++) args_vec.push_back(argv[i]);

    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg); ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        ImGui_ImplDX11_NewFrame(); ImGui_ImplWin32_NewFrame(); ImGui::NewFrame();

        // ── Main full-screen window ──
        ImGui::SetNextWindowPos(ImVec2(0, 0)); ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Scootware Control Center", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize);
        ImGui::Text("Scootware Driver Control Center"); ImGui::SameLine(ImGui::GetWindowWidth() - 220);
        if (ImGui::Button("Unload Driver", ImVec2(200, 24))) {
            LOG_PRINT("[*] Sending CMD_SHUTDOWN...");
            if (send_command(0, CMD_SHUTDOWN, 0, 5000) == WaitResult::Success)
                LOG_PRINT("[+] Driver unloaded.");
            else LOG_PRINT("[-] Failed to unload driver.");
        }
        ImGui::Separator();

        // ── Tab bar ──
        static int g_active_tab = 0;
        const char* tabs[] = { "Speed Testing", "Memory Operations", "HWID Spoofing", "Color Validation", "Stealth Status", "DLL Injection" };
        for (int i = 0; i < 6; i++) {
            if (i > 0) ImGui::SameLine();
            if (ImGui::Button(tabs[i], ImVec2(155, 28))) g_active_tab = i;
        }
        ImGui::Separator();

        switch (g_active_tab) {
            case 0: DrawSpeedTestTab(args_vec); break;
            case 1: DrawMemOpsTab();            break;
            case 2: DrawHWIDTab();              break;
            case 3: DrawColorValidationTab();   break;
            case 4: DrawStealthStatusTab();     break;
            case 5: DrawInjectTab();            break;
        }

        DrawLogWindow();
        ImGui::End();

        // ── Render ──
        ImGui::Render();
        const float clear_color[4] = { 0.07f, 0.07f, 0.10f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown(); ImGui_ImplWin32_Shutdown(); ImGui::DestroyContext();
    CleanupDeviceD3D(); ::DestroyWindow(hwnd); ::UnregisterClass(wc.lpszClassName, wc.hInstance);
    return 0;
}

// ============================================================================
// TAB 1: Speed Testing (benchmark)
// ============================================================================
static void DrawSpeedTestTab(const std::vector<std::string>& args_vec) {
    ImGui::Text("Speed Testing - Driver IPC Performance Benchmark"); ImGui::Separator();

    static bool opt_throughput = false;
    static bool opt_multi = false;
    static bool opt_include_cr3 = false;

    ImGui::Checkbox("Enable Throughput Tests", &opt_throughput);
    ImGui::SameLine();
    ImGui::Checkbox("Enable Multi-thread Tests", &opt_multi);
    ImGui::SameLine();
    ImGui::Checkbox("Include CR3 (direct page map) tests", &opt_include_cr3);
    ImGui::Separator();

    // Benchmark controls
    if (ImGui::Button(g_benchmark_running ? "Running..." : "Start Benchmark", ImVec2(200, 40))) {
        if (!g_benchmark_running) {
            g_benchmark_stop_requested = false;
            g_benchmark_running = true;
            g_log_lines.clear();
            g_progress_current = 0.0f;
            g_current_test_name = "Running Benchmark Suite...";
            bool run_tput = opt_throughput;
            bool run_multi = opt_multi;
            bool run_cr3 = opt_include_cr3;
            std::thread([args_vec, run_tput, run_multi, run_cr3]() {
                std::vector<std::string> local_args = args_vec;
                if (run_tput) local_args.push_back("--throughput");
                if (run_multi) local_args.push_back("--multi");
                if (run_cr3) local_args.push_back("--cr3");
                std::vector<char*> pt_args;
                for (auto& s : local_args) pt_args.push_back((char*)s.c_str());
                run_benchmark((int)pt_args.size(), pt_args.data());
            }).detach();
        }
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!g_benchmark_running);
    if (ImGui::Button("Stop Tests", ImVec2(140, 40))) g_benchmark_stop_requested = true;
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (g_benchmark_running) {
        ImGui::Text("Status: %s", g_current_test_name.c_str());
        ImGui::ProgressBar(g_progress_current, ImVec2(-1.0f, 0.0f));
    } else {
        ImGui::Text("Status: Idle");
        ImGui::ProgressBar(0.0f, ImVec2(-1.0f, 0.0f));
    }

    // Driver connection status
    ImGui::Separator();
    static bool g_driver_connected = false;
    if (ImGui::Button("Test Driver Connection", ImVec2(220, 28))) {
        if (send_command(0, CMD_PING, 0, 3000) == WaitResult::Success) {
            LOG_PRINT("[+] Driver is connected and responding.");
            g_driver_connected = true;
        } else {
            LOG_PRINT("[-] Driver not responding. Ensure drv.sys is loaded.");
            g_driver_connected = false;
        }
    }
    ImGui::SameLine();
    ImGui::TextColored(g_driver_connected ? ImVec4(0,1,0,1) : ImVec4(1,0,0,1),
                       g_driver_connected ? "Connected" : "Disconnected");
}

// ============================================================================
// TAB 2: Memory Operations
// ============================================================================
struct MemOpsState {
    char target_process[64] = "notepad.exe";
    uint32_t target_pid = 0;
    uint64_t read_address = 0;
    int read_size = 256;
    uint64_t write_address = 0;
    char write_data_hex[4096] = "";
    uint64_t alloc_size = 0x1000;
    int alloc_type = 0; // 0=MEM_COMMIT, 1=MEM_RESERVE
    int alloc_protect = 0; // 0=PAGE_READWRITE, 1=PAGE_EXECUTE_READWRITE
    uint64_t alloc_result = 0;
    uint64_t free_address = 0;
    char module_name[256] = "";
    uint64_t module_base = 0;
    uint64_t resolved_cr3 = 0;
    uint64_t base_address = 0;
    uint64_t peb_address = 0;
    uint64_t guarded_region = 0;
    uint64_t inject_pid = 0;
    char inject_path[512] = "";
    int mouse_x = 0, mouse_y = 0;
    char read_result_hex[8192] = "";
    int read_result_len = 0;
};

static MemOpsState g_memops;

static void DrawMemOpsTab() {
    ImGui::Text("Memory Manipulation - Read, Write, Base, CR3, Inject"); ImGui::Separator();

    if (ImGui::CollapsingHeader("Process Selection", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::InputText("Process Name", g_memops.target_process, sizeof(g_memops.target_process));
        ImGui::SameLine();
        if (ImGui::Button("Find PID", ImVec2(120, 24))) {
            uint32_t pid = 0;
            // Try local process enumeration first
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
                if (Process32First(snap, &pe)) {
                    do {
                        if (_stricmp(pe.szExeFile, g_memops.target_process) == 0) {
                            pid = pe.th32ProcessID; break;
                        }
                    } while (Process32Next(snap, &pe));
                }
                CloseHandle(snap);
            }
            if (!pid) pid = drv_get_pid_by_name(g_memops.target_process);
            g_memops.target_pid = pid;
            if (pid) LOG_PRINT("[+] Found PID %u for %s", pid, g_memops.target_process);
            else LOG_PRINT("[-] Process '%s' not found", g_memops.target_process);
        }
        ImGui::SameLine();
        ImGui::Text("Target PID: %u", g_memops.target_pid);
    }

    if (ImGui::CollapsingHeader("Process Info", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::Button("Get Base Address", ImVec2(180, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else {
                uint64_t ba = drv_get_base_address(g_memops.target_pid);
                g_memops.base_address = ba;
                if (ba) LOG_PRINT("[+] Base Address: 0x%llX", (unsigned long long)ba);
                else LOG_PRINT("[-] Failed to get base address.");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Resolve DTB / CR3", ImVec2(180, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else {
                uint64_t cr3v = 0;
                if (drv_resolve_dtb(g_memops.target_pid, &cr3v)) {
                    g_memops.resolved_cr3 = cr3v;
                    LOG_PRINT("[+] CR3: 0x%llX", (unsigned long long)cr3v);
                } else LOG_PRINT("[-] Failed to resolve DTB.");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Get PEB", ImVec2(120, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else {
                uint64_t peb = drv_get_peb(g_memops.target_pid);
                g_memops.peb_address = peb;
                if (peb) LOG_PRINT("[+] PEB: 0x%llX", (unsigned long long)peb);
                else LOG_PRINT("[-] Failed to get PEB.");
            }
        }
        ImGui::Text("Base:  0x%llX   CR3: 0x%llX   PEB: 0x%llX",
                    (unsigned long long)g_memops.base_address,
                    (unsigned long long)g_memops.resolved_cr3,
                    (unsigned long long)g_memops.peb_address);

        if (ImGui::Button("Get Guarded Region", ImVec2(180, 24))) {
            uint64_t gr = drv_get_guarded_region();
            g_memops.guarded_region = gr;
            if (gr) LOG_PRINT("[+] Guarded Region: 0x%llX", (unsigned long long)gr);
            else LOG_PRINT("[-] Failed to get guarded region.");
        }
        ImGui::SameLine();
        ImGui::Text("Guarded: 0x%llX", (unsigned long long)g_memops.guarded_region);

        // Module lookup
        ImGui::InputText("Module Name (wide)", g_memops.module_name, sizeof(g_memops.module_name));
        ImGui::SameLine();
        if (ImGui::Button("Get Module Base", ImVec2(160, 24))) {
            if (!g_memops.target_pid || !g_memops.module_name[0]) {
                LOG_PRINT("[-] Need PID and module name.");
            } else {
                // Convert narrow to wide
                wchar_t wname[256]; int wlen = (int)strlen(g_memops.module_name);
                for (int i = 0; i < wlen; i++) wname[i] = (wchar_t)g_memops.module_name[i];
                wname[wlen] = 0;
                uint64_t mb = drv_get_module_base(g_memops.target_pid, wname, wlen);
                g_memops.module_base = mb;
                if (mb) LOG_PRINT("[+] Module '%s' base: 0x%llX", g_memops.module_name, (unsigned long long)mb);
                else LOG_PRINT("[-] Module not found.");
            }
        }
        ImGui::SameLine();
        ImGui::Text("Module Base: 0x%llX", (unsigned long long)g_memops.module_base);
    }

    if (ImGui::CollapsingHeader("Memory Read / Write", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::InputScalar("Read Address", ImGuiDataType_U64, &g_memops.read_address, nullptr, nullptr, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::SameLine();
        ImGui::InputInt("Size", &g_memops.read_size); if (g_memops.read_size < 1) g_memops.read_size = 1; if (g_memops.read_size > 4096) g_memops.read_size = 4096;
        if (ImGui::Button("Read Memory", ImVec2(160, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else {
                std::vector<uint8_t> buf(g_memops.read_size);
                if (drv_read(0, g_memops.target_pid, g_memops.read_address, buf.data(), g_memops.read_size, true)) {
                    char hex[8192]; int pos = 0;
                    for (int i = 0; i < g_memops.read_size && pos < (int)sizeof(hex) - 8; i++) {
                        pos += _snprintf_s(hex + pos, sizeof(hex) - pos, _TRUNCATE, "%02X ", buf[i]);
                        if ((i + 1) % 16 == 0) { hex[pos++] = '\n'; hex[pos] = 0; }
                    }
                    g_memops.read_result_len = g_memops.read_size;
                    memcpy(g_memops.read_result_hex, hex, sizeof(g_memops.read_result_hex));
                    LOG_PRINT("[+] Read %d bytes from 0x%llX", g_memops.read_size, (unsigned long long)g_memops.read_address);
                } else LOG_PRINT("[-] Read failed.");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Read (no CR3)", ImVec2(160, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else {
                std::vector<uint8_t> buf(g_memops.read_size);
                if (drv_read(0, g_memops.target_pid, g_memops.read_address, buf.data(), g_memops.read_size, false)) {
                    char hex[8192]; int pos = 0;
                    for (int i = 0; i < g_memops.read_size && pos < (int)sizeof(hex) - 8; i++) {
                        pos += _snprintf_s(hex + pos, sizeof(hex) - pos, _TRUNCATE, "%02X ", buf[i]);
                        if ((i + 1) % 16 == 0) { hex[pos++] = '\n'; hex[pos] = 0; }
                    }
                    g_memops.read_result_len = g_memops.read_size;
                    memcpy(g_memops.read_result_hex, hex, sizeof(g_memops.read_result_hex));
                    LOG_PRINT("[+] Read %d bytes (MmCopy) from 0x%llX", g_memops.read_size, (unsigned long long)g_memops.read_address);
                } else LOG_PRINT("[-] Read (no CR3) failed.");
            }
        }
        ImGui::InputTextMultiline("Read Result", g_memops.read_result_hex, sizeof(g_memops.read_result_hex), ImVec2(0, 100), ImGuiInputTextFlags_ReadOnly);

        ImGui::InputScalar("Write Address", ImGuiDataType_U64, &g_memops.write_address, nullptr, nullptr, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::InputText("Hex Data (space-separated bytes)", g_memops.write_data_hex, sizeof(g_memops.write_data_hex));
        if (ImGui::Button("Write Memory", ImVec2(160, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else {
                // Parse hex string
                std::vector<uint8_t> data;
                char* p = g_memops.write_data_hex;
                while (*p) {
                    while (*p == ' ') p++;
                    if (!*p) break;
                    unsigned int val; int n;
                    if (sscanf_s(p, "%02x%n", &val, &n) >= 1) {
                        data.push_back((uint8_t)val); p += n;
                    } else break;
                }
                if (data.empty()) { LOG_PRINT("[-] No hex data to write."); }
                else if (drv_write(0, g_memops.target_pid, g_memops.write_address, data.data(), data.size(), true)) {
                    LOG_PRINT("[+] Wrote %zu bytes to 0x%llX", data.size(), (unsigned long long)g_memops.write_address);
                } else LOG_PRINT("[-] Write failed.");
            }
        }
    }

    if (ImGui::CollapsingHeader("Memory Allocation / Free", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::InputScalar("Alloc Size", ImGuiDataType_U64, &g_memops.alloc_size);
        ImGui::Combo("Alloc Type", &g_memops.alloc_type, "MEM_COMMIT\0MEM_RESERVE\0MEM_COMMIT|RESERVE\0");
        ImGui::Combo("Protection", &g_memops.alloc_protect, "PAGE_READWRITE\0PAGE_EXECUTE_READWRITE\0PAGE_READONLY\0");
        if (ImGui::Button("Allocate Memory", ImVec2(180, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else {
                uint32_t type = MEM_COMMIT;
                if (g_memops.alloc_type == 1) type = MEM_RESERVE;
                else if (g_memops.alloc_type == 2) type = MEM_COMMIT | MEM_RESERVE;
                uint32_t prot = PAGE_READWRITE;
                if (g_memops.alloc_protect == 1) prot = PAGE_EXECUTE_READWRITE;
                else if (g_memops.alloc_protect == 2) prot = PAGE_READONLY;
                uint64_t result = drv_allocate(g_memops.target_pid, 0, g_memops.alloc_size, type, prot);
                g_memops.alloc_result = result;
                if (result) LOG_PRINT("[+] Allocated 0x%llX bytes at 0x%llX", (unsigned long long)g_memops.alloc_size, (unsigned long long)result);
                else LOG_PRINT("[-] Allocation failed.");
            }
        }
        ImGui::SameLine();
        ImGui::Text("Result: 0x%llX", (unsigned long long)g_memops.alloc_result);

        ImGui::InputScalar("Free Address", ImGuiDataType_U64, &g_memops.free_address, nullptr, nullptr, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::SameLine();
        if (ImGui::Button("Free Memory", ImVec2(140, 24))) {
            if (!g_memops.target_pid) { LOG_PRINT("[-] Select a process first."); }
            else if (drv_free(g_memops.target_pid, g_memops.free_address, MEM_RELEASE)) {
                LOG_PRINT("[+] Freed 0x%llX", (unsigned long long)g_memops.free_address);
            } else LOG_PRINT("[-] Free failed.");
        }
    }

    if (ImGui::CollapsingHeader("Mouse Control", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::InputInt("Mouse X", &g_memops.mouse_x);
        ImGui::SameLine();
        ImGui::InputInt("Mouse Y", &g_memops.mouse_y);
        ImGui::SameLine();
        if (ImGui::Button("Move Mouse", ImVec2(140, 24))) {
            if (drv_mouse_move(g_memops.mouse_x, g_memops.mouse_y, 0))
                LOG_PRINT("[+] Mouse moved to (%d, %d)", g_memops.mouse_x, g_memops.mouse_y);
            else LOG_PRINT("[-] Mouse move failed.");
        }
    }
}

// ============================================================================
// TAB 3: HWID Spoofing
// ============================================================================
struct HWIDState {
    uint32_t state = 0;       // 0=Uninit, 1=Captured, 2=Spoofed, 3=Error
    uint32_t active = 0;
    IPC_HWID_DATA current_data{};
    IPC_HWID_DATA original_data{};
    uint32_t spoof_components = HWID_COMP_ALL;
    uint64_t spoof_seed = 0;
    bool auto_refreshed = false; // auto-refresh on first tab draw
    double last_auto_refresh = 0.0; // timestamp of last periodic refresh
    std::vector<std::string> saved_files; // list of *.hwid files in appdata
    char smbios_uuid_str[48] = "";
    char smbios_system_serial[HWID_MAX_SERIAL_LEN] = "";
    char smbios_baseboard_serial[HWID_MAX_SERIAL_LEN] = "";
    char smbios_chassis_serial[HWID_MAX_SERIAL_LEN] = "";
    char machine_guid[HWID_MAX_GUID_LEN] = "";
    char volume_serial[HWID_MAX_VOLUME_LEN] = "";
    char mac_address[HWID_MAX_MAC_LEN] = "";
    bool custom_edit_mode = false;
};

static HWIDState g_hwid;

// ============================================================================
// HWID file persistence — %appdata%/Scootware/HWID/*.hwid
// ============================================================================
static std::string GetHWIDDirectory() {
    char appdata[MAX_PATH];
    GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
    std::string base = std::string(appdata) + "\\Scootware";
    std::string dir  = base + "\\HWID";
    CreateDirectoryA(base.c_str(), nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

static bool SaveHWIDToFile(const std::string& filename, const IPC_HWID_DATA& data) {
    std::string path = GetHWIDDirectory() + "\\" + filename;
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, &data, sizeof(data), &written, nullptr);
    CloseHandle(h);
    return ok && written == sizeof(data);
}

static bool LoadHWIDFromFile(const std::string& filename, IPC_HWID_DATA& data) {
    std::string path = GetHWIDDirectory() + "\\" + filename;
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD read = 0;
    BOOL ok = ReadFile(h, &data, sizeof(data), &read, nullptr);
    CloseHandle(h);
    return ok && read == sizeof(data);
}

static bool DeleteHWIDFile(const std::string& filename) {
    std::string path = GetHWIDDirectory() + "\\" + filename;
    return DeleteFileA(path.c_str()) != 0;
}

static std::vector<std::string> ListHWIDFiles() {
    std::vector<std::string> files;
    std::string dir  = GetHWIDDirectory();
    std::string pat  = dir + "\\*.hwid";
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pat.c_str(), &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                files.push_back(ffd.cFileName);
        } while (FindNextFileA(hFind, &ffd));
        FindClose(hFind);
    }
    return files;
}

static std::string TimestampForHWID() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[64];
    _snprintf_s(buf, _TRUNCATE, "hwid_%04d%02d%02d_%02d%02d%02d.hwid",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

// Format one HWID_DATA into a short summary line (UUID first group + MAC + Volume)
static std::string HWIDSummary(const IPC_HWID_DATA& data) {
    char buf[128];
    _snprintf_s(buf, _TRUNCATE,
        "UUID=%02X%02X%02X%02X-%02X%02X-%02X%02X  MAC=%s  Vol=%s",
        data.smbios_uuid[3], data.smbios_uuid[2], data.smbios_uuid[1], data.smbios_uuid[0],
        data.smbios_uuid[5], data.smbios_uuid[4],
        data.smbios_uuid[7], data.smbios_uuid[6],
        data.mac_address, data.volume_serial);
    return std::string(buf);
}

static void hwid_update_display() {
    // Format UUID for display — SMBIOS stores the first 3 fields in LE,
    // so we swap bytes to match what WMI / Get-WmiObject shows.
    // Indices 0-3: TimeLow (LE DWORD), 4-5: TimeMid (LE WORD),
    // 6-7: TimeHiAndVersion (LE WORD), 8-15: ClockSeq+Node (raw).
    uint8_t uuid_display[16];
    uuid_display[0] = g_hwid.current_data.smbios_uuid[3];
    uuid_display[1] = g_hwid.current_data.smbios_uuid[2];
    uuid_display[2] = g_hwid.current_data.smbios_uuid[1];
    uuid_display[3] = g_hwid.current_data.smbios_uuid[0];
    uuid_display[4] = g_hwid.current_data.smbios_uuid[5];
    uuid_display[5] = g_hwid.current_data.smbios_uuid[4];
    uuid_display[6] = g_hwid.current_data.smbios_uuid[7];
    uuid_display[7] = g_hwid.current_data.smbios_uuid[6];
    memcpy(&uuid_display[8], &g_hwid.current_data.smbios_uuid[8], 8);
    _snprintf_s(g_hwid.smbios_uuid_str, _TRUNCATE,
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        uuid_display[0], uuid_display[1],
        uuid_display[2], uuid_display[3],
        uuid_display[4], uuid_display[5],
        uuid_display[6], uuid_display[7],
        uuid_display[8], uuid_display[9],
        uuid_display[10], uuid_display[11],
        uuid_display[12], uuid_display[13],
        uuid_display[14], uuid_display[15]);
    memcpy(g_hwid.smbios_system_serial, g_hwid.current_data.smbios_system_serial, HWID_MAX_SERIAL_LEN);
    memcpy(g_hwid.smbios_baseboard_serial, g_hwid.current_data.smbios_baseboard_serial, HWID_MAX_SERIAL_LEN);
    memcpy(g_hwid.smbios_chassis_serial, g_hwid.current_data.smbios_chassis_serial, HWID_MAX_SERIAL_LEN);
    memcpy(g_hwid.machine_guid, g_hwid.current_data.machine_guid, HWID_MAX_GUID_LEN);
    memcpy(g_hwid.volume_serial, g_hwid.current_data.volume_serial, HWID_MAX_VOLUME_LEN);
    memcpy(g_hwid.mac_address, g_hwid.current_data.mac_address, HWID_MAX_MAC_LEN);
}

static const char* hwid_state_str(uint32_t st) {
    switch (st) {
        case 0: return "Uninitialized";
        case 1: return "Captured (originals saved)";
        case 2: return "Spoofed";
        case 3: return "Error";
        default: return "Unknown";
    }
}

static void DrawHWIDTab() {
    // ── Periodic auto-refresh every ~2 seconds ──
    double now = ImGui::GetTime();
    if (!g_hwid.auto_refreshed || (now - g_hwid.last_auto_refresh) > 2.0) {
        uint32_t st = 0, act = 0;
        IPC_HWID_DATA hwid{};
        if (drv_hwid_status(&st, &act, &hwid)) {
            g_hwid.state = st; g_hwid.active = act; g_hwid.current_data = hwid;
            hwid_update_display();

            // Auto-save original (untampered) HWID to disk on first capture
            if (!g_hwid.auto_refreshed) {
                IPC_HWID_DATA od{};
                if (drv_hwid_get_original(&od)) {
                    g_hwid.original_data = od;
                    if (SaveHWIDToFile("original.hwid", od))
                        LOG_PRINT("[+] Original HWID auto-saved to %%appdata%%/Scootware/HWID/original.hwid");
                }
                // Refresh saved file list
                g_hwid.saved_files = ListHWIDFiles();
            }
        }
        g_hwid.auto_refreshed = true;
        g_hwid.last_auto_refresh = now;
    }

    ImGui::Text("HWID Spoofing - SMBIOS, Registry, Volume, MAC"); ImGui::Separator();

    // Helper: refresh HWID state + display data from driver
    auto hwid_refresh = [&]() -> bool {
        uint32_t st = 0, act = 0;
        IPC_HWID_DATA hwid{};
        if (drv_hwid_status(&st, &act, &hwid)) {
            g_hwid.state = st; g_hwid.active = act; g_hwid.current_data = hwid;
            hwid_update_display();
            return true;
        }
        return false;
    };

    // ── Status ──
    if (ImGui::CollapsingHeader("Status & Controls", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Text("Spoof State: %s", hwid_state_str(g_hwid.state));
        ImGui::TextColored(g_hwid.active ? ImVec4(1,0.5f,0,1) : ImVec4(0,1,0,1),
                           g_hwid.active ? "Spoof ACTIVE" : "Spoof INACTIVE");
        ImGui::Separator();

        // ── Component selection ──
        ImGui::Text("Spoof Components:");
        static bool c_uuid = true, c_serials = true, c_guid = true, c_vol = true, c_mac = true;
        ImGui::Checkbox("SMBIOS UUID", &c_uuid); ImGui::SameLine();
        ImGui::Checkbox("SMBIOS Serials", &c_serials); ImGui::SameLine();
        ImGui::Checkbox("Machine GUID", &c_guid); ImGui::SameLine();
        ImGui::Checkbox("Volume Serial", &c_vol); ImGui::SameLine();
        ImGui::Checkbox("MAC Address", &c_mac);
        uint32_t comps = (c_uuid ? HWID_COMP_SMBIOS_UUID : 0) | (c_serials ? HWID_COMP_SMBIOS_SERIALS : 0) |
                         (c_guid ? HWID_COMP_REGISTRY_GUID : 0) | (c_vol ? HWID_COMP_VOLUME_SERIAL : 0) |
                         (c_mac ? HWID_COMP_MAC_ADDRESS : 0);
        g_hwid.spoof_components = comps;
        ImGui::Separator();

        // ── Action buttons ──
        ImGui::InputScalar("Random Seed (0=random)", ImGuiDataType_U64, &g_hwid.spoof_seed);
        if (ImGui::Button("Apply Spoof", ImVec2(160, 28))) {
            if (drv_hwid_spoof(g_hwid.spoof_components, g_hwid.spoof_seed)) {
                hwid_refresh();
                // Auto-save this spoofed HWID to disk
                IPC_HWID_DATA od{};
                if (drv_hwid_get_original(&od)) {
                    g_hwid.original_data = od;
                }
                SaveHWIDToFile(TimestampForHWID(), g_hwid.current_data);
                g_hwid.saved_files = ListHWIDFiles();
                LOG_PRINT("[+] Spoof applied (comps=0x%X, seed=%llu) and saved to disk",
                    g_hwid.spoof_components, (unsigned long long)g_hwid.spoof_seed);
            } else LOG_PRINT("[-] Spoof failed.");
        }
        ImGui::SameLine();
        if (ImGui::Button("Restore Originals", ImVec2(180, 28))) {
            if (drv_hwid_restore()) {
                hwid_refresh();
                LOG_PRINT("[+] Originals restored.");
            } else LOG_PRINT("[-] Restore failed.");
        }
        ImGui::SameLine();
        if (ImGui::Button("Reroll", ImVec2(120, 28))) {
            if (drv_hwid_reroll(g_hwid.spoof_components)) {
                hwid_refresh();
                // Auto-save re-rolled HWID to disk
                SaveHWIDToFile(TimestampForHWID(), g_hwid.current_data);
                g_hwid.saved_files = ListHWIDFiles();
                LOG_PRINT("[+] HWID re-rolled and saved to disk.");
            } else LOG_PRINT("[-] Reroll failed.");
        }
    }

    // ── Display current HWID values ──
    if (ImGui::CollapsingHeader("Current HWID Values", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto field = [](const char* label, const char* val, ImU32 color = 0) {
            if (val && val[0]) {
                if (color) { ImGui::TextColored(ImColor(color), "%s: ", label); ImGui::SameLine(); ImGui::Text("%s", val); }
                else       { ImGui::Text("%s: ", label); ImGui::SameLine(); ImGui::Text("%s", val); }
            } else {
                ImGui::Text("%s: ", label); ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1), "(not found/empty)");
            }
        };
        field("SMBIOS UUID",      g_hwid.smbios_uuid_str, 0xFF44CCFF);
        field("System Serial",    g_hwid.smbios_system_serial);
        field("Baseboard Serial", g_hwid.smbios_baseboard_serial);
        field("Chassis Serial",   g_hwid.smbios_chassis_serial);
        field("Machine GUID",     g_hwid.machine_guid);
        field("Volume Serial",    g_hwid.volume_serial);
        field("MAC Address",      g_hwid.mac_address);
        ImGui::Text("Components Mask:  0x%X", g_hwid.current_data.components_present);
    }

    // ── Edit and load custom HWID ──
    if (ImGui::CollapsingHeader("Custom HWID Editor", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Text("Edit custom HWID values to load into driver:");
        ImGui::InputText("SMBIOS UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)", g_hwid.smbios_uuid_str, sizeof(g_hwid.smbios_uuid_str));
        ImGui::InputText("System Serial", g_hwid.smbios_system_serial, HWID_MAX_SERIAL_LEN);
        ImGui::InputText("Baseboard Serial", g_hwid.smbios_baseboard_serial, HWID_MAX_SERIAL_LEN);
        ImGui::InputText("Chassis Serial", g_hwid.smbios_chassis_serial, HWID_MAX_SERIAL_LEN);
        ImGui::InputText("Machine GUID", g_hwid.machine_guid, HWID_MAX_GUID_LEN);
        ImGui::InputText("Volume Serial", g_hwid.volume_serial, HWID_MAX_VOLUME_LEN);
        ImGui::InputText("MAC Address (XX-XX-XX-XX-XX-XX)", g_hwid.mac_address, HWID_MAX_MAC_LEN);

        if (ImGui::Button("Load Custom HWID && Apply", ImVec2(260, 28))) {
            IPC_HWID_DATA custom{};
            // Parse UUID
            unsigned int u[16];
            int parsed = sscanf_s(g_hwid.smbios_uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                &u[0],&u[1],&u[2],&u[3],&u[4],&u[5],&u[6],&u[7],&u[8],&u[9],&u[10],&u[11],&u[12],&u[13],&u[14],&u[15]);
            if (parsed == 16) for (int i = 0; i < 16; i++) custom.smbios_uuid[i] = (uint8_t)u[i];
            memcpy(custom.smbios_system_serial, g_hwid.smbios_system_serial, HWID_MAX_SERIAL_LEN);
            memcpy(custom.smbios_baseboard_serial, g_hwid.smbios_baseboard_serial, HWID_MAX_SERIAL_LEN);
            memcpy(custom.smbios_chassis_serial, g_hwid.smbios_chassis_serial, HWID_MAX_SERIAL_LEN);
            memcpy(custom.machine_guid, g_hwid.machine_guid, HWID_MAX_GUID_LEN);
            memcpy(custom.volume_serial, g_hwid.volume_serial, HWID_MAX_VOLUME_LEN);
            memcpy(custom.mac_address, g_hwid.mac_address, HWID_MAX_MAC_LEN);
            custom.components_present = g_hwid.spoof_components;

            if (drv_hwid_load(g_hwid.spoof_components, 1, &custom)) {
                hwid_refresh();
                // Auto-save custom HWID to disk
                SaveHWIDToFile(TimestampForHWID(), g_hwid.current_data);
                g_hwid.saved_files = ListHWIDFiles();
                LOG_PRINT("[+] Custom HWID loaded, applied, and saved to disk.");
            } else LOG_PRINT("[-] Failed to load custom HWID.");
        }
    }

    // ── Original HWID values ──
    if (ImGui::CollapsingHeader("Original (Untampered) HWID", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (g_hwid.original_data.components_present == 0 && g_hwid.auto_refreshed) {
            ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1), "No original data available yet (driver may not have captured it).");
        } else {
            char uuid_str[48];
            uint8_t u[16];
            u[0]=g_hwid.original_data.smbios_uuid[3]; u[1]=g_hwid.original_data.smbios_uuid[2];
            u[2]=g_hwid.original_data.smbios_uuid[1]; u[3]=g_hwid.original_data.smbios_uuid[0];
            u[4]=g_hwid.original_data.smbios_uuid[5]; u[5]=g_hwid.original_data.smbios_uuid[4];
            u[6]=g_hwid.original_data.smbios_uuid[7]; u[7]=g_hwid.original_data.smbios_uuid[6];
            memcpy(&u[8], &g_hwid.original_data.smbios_uuid[8], 8);
            _snprintf_s(uuid_str, _TRUNCATE,
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
            ImGui::Text("SMBIOS UUID:      %s", uuid_str);
            ImGui::Text("Machine GUID:     %s", g_hwid.original_data.machine_guid);
            ImGui::Text("Volume Serial:    %s", g_hwid.original_data.volume_serial);
            ImGui::Text("MAC Address:      %s", g_hwid.original_data.mac_address);
            ImGui::TextColored(ImVec4(0.620f, 0.620f, 0.660f, 1.00f), "(Auto-saved to %%appdata%%/Scootware/HWID/original.hwid)");
        }
    }

    // ── Saved HWIDs list ──
    if (ImGui::CollapsingHeader("Saved HWIDs on Disk", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (g_hwid.saved_files.empty()) {
            ImGui::TextColored(ImVec4(0.620f, 0.620f, 0.660f, 1.00f), "No saved HWID files found in %%appdata%%/Scootware/HWID/");
        } else {
            ImGui::Text("Location: %%appdata%%/Scootware/HWID/");
            ImGui::Separator();
            // Collect files to delete (don't modify vector while iterating)
            std::string to_delete;
            int idx = 0;
            for (const auto& fname : g_hwid.saved_files) {
                ImGui::PushID(idx);
                ImGui::Text("%s", fname.c_str());
                ImGui::SameLine();
                // Try to load and show a summary
                IPC_HWID_DATA tmp{};
                if (LoadHWIDFromFile(fname, tmp)) {
                    std::string summary = HWIDSummary(tmp);
                    ImGui::TextColored(ImVec4(0.620f, 0.620f, 0.660f, 1.00f), "  %s", summary.c_str());
                    ImGui::SameLine();
                }
                if (ImGui::SmallButton("Delete")) {
                    to_delete = fname;
                }
                ImGui::PopID();
                idx++;
            }
            if (!to_delete.empty()) {
                if (DeleteHWIDFile(to_delete)) {
                    LOG_PRINT("[+] Deleted HWID file: %s", to_delete.c_str());
                } else {
                    LOG_PRINT("[-] Failed to delete HWID file: %s", to_delete.c_str());
                }
                g_hwid.saved_files = ListHWIDFiles();
            }
        }
        ImGui::Separator();
        if (ImGui::SmallButton("Refresh File List")) {
            g_hwid.saved_files = ListHWIDFiles();
        }
    }
}

// ============================================================================
// TAB 4: Color Validation — Visual Read/Write Verification
// ============================================================================
struct ColorValidationState {
    bool    initialized = false;
    bool    cr3_resolved = false;   // whether we've resolved DTB for CR3 path
    uint8_t color_buf[4] = { 0, 0, 0, 0 };
    uint64_t buf_addr = 0;
    float   last_r_byte = 0.0f, last_g_byte = 0.0f, last_b_byte = 0.0f;
    bool    paused = false;
    float   cycle_speed = 3.5f;
    float   hue_offset = 0.0f;

    // ── Method selection ──
    bool test_mm  = true;   // MmCopyVirtualMemory  (use_cr3=false)
    bool test_cr3 = true;   // CR3 direct page walk (use_cr3=true)

    // ── Per-method counters (index 0 = MM, 1 = CR3) ──
    int write_ok_count[2]    = {0,0};
    int write_fail_count[2]  = {0,0};
    int read_ok_count[2]     = {0,0};
    int read_fail_count[2]   = {0,0};
    int match_count[2]       = {0,0};
    int mismatch_count[2]    = {0,0};

    // ── Per-method readback values ──
    uint8_t read_r[2] = {0,0};
    uint8_t read_g[2] = {0,0};
    uint8_t read_b[2] = {0,0};
};

static ColorValidationState g_colorval;

// HSV -> RGB helper
static void hsv_to_rgb(float h, float s, float v, float& r, float& g, float& b) {
    h = fmodf(h, 360.0f);
    if (h < 0.0f) h += 360.0f;
    float c = v * s;
    float x = c * (1.0f - fabsf(fmodf(h / 60.0f, 2.0f) - 1.0f));
    float m = v - c;
    if      (h < 60.0f)  { r = c; g = x; b = 0; }
    else if (h < 120.0f) { r = x; g = c; b = 0; }
    else if (h < 180.0f) { r = 0; g = c; b = x; }
    else if (h < 240.0f) { r = 0; g = x; b = c; }
    else if (h < 300.0f) { r = x; g = 0; b = c; }
    else                  { r = c; g = 0; b = x; }
    r += m; g += m; b += m;
}

static void DrawColorValidationTab() {
    ImGui::Text("Color Validation — Visual Read/Write Verification via Driver"); ImGui::Separator();

    const uint32_t my_pid = GetCurrentProcessId();
    const size_t   kBufSize = 4;

    // ── One-time init ──
    if (!g_colorval.initialized) {
        void* alloc = VirtualAlloc(nullptr, kBufSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (alloc) {
            g_colorval.buf_addr = (uint64_t)alloc;
            memset(alloc, 0, kBufSize);
            LOG_PRINT("[+] Color validation buffer @ 0x%llX", (unsigned long long)g_colorval.buf_addr);
        } else {
            LOG_PRINT("[-] Failed to allocate color validation buffer!");
        }

        // Pre-resolve DTB/CR3 for this process so CR3 read/write works immediately
        uint64_t cr3_out = 0;
        if (drv_resolve_dtb(my_pid, &cr3_out) && cr3_out != 0) {
            g_colorval.cr3_resolved = true;
            LOG_PRINT("[+] Pre-resolved CR3 for color validation: 0x%llX", (unsigned long long)cr3_out);
        } else {
            LOG_PRINT("[-] CR3 pre-resolve failed — CR3 method will fall back");
        }

        g_colorval.initialized = true;
    }

    // ── Controls row ──
    ImGui::Checkbox("Pause Animation", &g_colorval.paused);
    ImGui::SameLine();
    ImGui::SliderFloat("Cycle (sec)", &g_colorval.cycle_speed, 0.5f, 10.0f, "%.1f");
    ImGui::SameLine();
    ImGui::SliderFloat("Hue Offset", &g_colorval.hue_offset, 0.0f, 360.0f, "%.0f deg");

    if (ImGui::Button("Reset Counters", ImVec2(150, 22))) {
        for (int i = 0; i < 2; i++) {
            g_colorval.write_ok_count[i] = g_colorval.write_fail_count[i] = 0;
            g_colorval.read_ok_count[i]  = g_colorval.read_fail_count[i]  = 0;
            g_colorval.mismatch_count[i] = g_colorval.match_count[i] = 0;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Realloc Buffer", ImVec2(150, 22))) {
        if (g_colorval.buf_addr) { VirtualFree((void*)g_colorval.buf_addr, 0, MEM_RELEASE); g_colorval.buf_addr = 0; }
        void* alloc = VirtualAlloc(nullptr, kBufSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (alloc) {
            g_colorval.buf_addr = (uint64_t)alloc;
            memset(alloc, 0, kBufSize);
            LOG_PRINT("[+] Reallocated buffer @ 0x%llX", (unsigned long long)g_colorval.buf_addr);
        }
    }

    ImGui::Separator();

    // ── Method selection checkboxes ──
    ImGui::Text("Memory Manipulation Methods:");
    ImGui::Checkbox("MmCopyVirtualMemory  (no CR3)", &g_colorval.test_mm);
    ImGui::SameLine(0.0f, 24.0f);
    ImGui::Checkbox("CR3 Direct Page Walk   (use_cr3)", &g_colorval.test_cr3);
    ImGui::Separator();

    // ── Compute current target color from time ──
    float hue = 0.0f;
    if (!g_colorval.paused) {
        DWORD tick = GetTickCount();
        float cycle = fmodf((float)tick / 1000.0f, g_colorval.cycle_speed) / g_colorval.cycle_speed;
        hue = fmodf(cycle * 360.0f + g_colorval.hue_offset, 360.0f);
    } else {
        hue = fmodf(g_colorval.hue_offset, 360.0f);
    }

    float fr, fg, fb;
    hsv_to_rgb(hue, 1.0f, 1.0f, fr, fg, fb);
    uint8_t tr = (uint8_t)(fr * 255.0f);
    uint8_t tg = (uint8_t)(fg * 255.0f);
    uint8_t tb = (uint8_t)(fb * 255.0f);
    uint8_t target[4] = { tr, tg, tb, 0xFF };

    g_colorval.last_r_byte = (float)tr / 255.0f;
    g_colorval.last_g_byte = (float)tg / 255.0f;
    g_colorval.last_b_byte = (float)tb / 255.0f;

    // ── Method definitions ──
    struct MethodDef {
        const char* name;
        const char* label_short;
        bool  enabled;
        int   idx;       // 0=MM, 1=CR3
        bool  use_cr3;
    };
    MethodDef methods[2] = {
        { "MmCopyVirtualMemory", "MM",  g_colorval.test_mm,  0, false },
        { "CR3 Direct",          "CR3", g_colorval.test_cr3, 1, true  },
    };

    const float tile_size = 160.0f;
    float avail = ImGui::GetContentRegionAvail().x;

    // ── Run test for each selected method, render tiles ──
    for (int m = 0; m < 2; m++) {
        auto& md = methods[m];
        if (!md.enabled) continue;

        // Run write + read for this method
        bool write_ok = false, read_ok = false;
        uint8_t rr = 0, rg = 0, rb = 0;

        if (g_colorval.buf_addr) {
            write_ok = drv_write(0, my_pid, g_colorval.buf_addr, target, 4, md.use_cr3);
            if (write_ok) g_colorval.write_ok_count[md.idx]++;
            else          g_colorval.write_fail_count[md.idx]++;

            uint8_t readback[4] = { 0 };
            read_ok = drv_read(0, my_pid, g_colorval.buf_addr, readback, 4, md.use_cr3);
            if (read_ok) {
                g_colorval.read_ok_count[md.idx]++;
                rr = readback[0]; rg = readback[1]; rb = readback[2];
                g_colorval.read_r[md.idx] = rr;
                g_colorval.read_g[md.idx] = rg;
                g_colorval.read_b[md.idx] = rb;
                if (rr == tr && rg == tg && rb == tb) g_colorval.match_count[md.idx]++;
                else g_colorval.mismatch_count[md.idx]++;
            } else {
                g_colorval.read_fail_count[md.idx]++;
                rr = g_colorval.read_r[md.idx];
                rg = g_colorval.read_g[md.idx];
                rb = g_colorval.read_b[md.idx];
            }
        }

        // ── Render method header ──
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 1.0f, 1.0f), "Method: %s", md.name);
        float row_avail = avail;
        float pair_w = tile_size * 2.0f + 30.0f;
        float left_x = ImGui::GetCursorPosX() + ((row_avail - pair_w) * 0.5f);
        if (left_x < ImGui::GetCursorPosX()) left_x = ImGui::GetCursorPosX();
        ImGui::SetCursorPosX(left_x);

        // ── WRITE tile ──
        {
            char wt_id[16]; _snprintf_s(wt_id, _TRUNCATE, "##WT_%d", m);
            ImGui::BeginGroup();
            ImVec2 wpos = ImGui::GetCursorScreenPos();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 wMin = wpos;
            ImVec2 wMax = ImVec2(wpos.x + tile_size, wpos.y + tile_size);
            dl->AddRectFilled(wMin, wMax, IM_COL32(tr, tg, tb, 255));
            dl->AddRect(wMin, wMax, IM_COL32(255,255,255,80), 0.0f, 0, 1.5f);
            ImGui::InvisibleButton(wt_id, ImVec2(tile_size, tile_size));
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "WRITTEN");
            char hex[32]; _snprintf_s(hex, _TRUNCATE, "#%02X%02X%02X", tr, tg, tb);
            ImGui::Text("Sent: %s", hex);
            ImGui::Text("%s", write_ok ? "Write: OK" : "Write: FAIL");
            ImGui::EndGroup();
        }

        ImGui::SameLine(0.0f, 30.0f);

        // ── READ tile ──
        {
            char rt_id[16]; _snprintf_s(rt_id, _TRUNCATE, "##RT_%d", m);
            ImGui::BeginGroup();
            ImVec2 rpos = ImGui::GetCursorScreenPos();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            ImVec2 rMin = rpos;
            ImVec2 rMax = ImVec2(rpos.x + tile_size, rpos.y + tile_size);
            dl->AddRectFilled(rMin, rMax, IM_COL32(rr, rg, rb, 255));
            dl->AddRect(rMin, rMax, IM_COL32(255,255,255,80), 0.0f, 0, 1.5f);
            ImGui::InvisibleButton(rt_id, ImVec2(tile_size, tile_size));
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.6f, 1.0f), "READ BACK");
            char hex[32]; _snprintf_s(hex, _TRUNCATE, "#%02X%02X%02X", rr, rg, rb);
            ImGui::Text("Got:  %s", hex);
            if (read_ok) {
                if (rr == tr && rg == tg && rb == tb)
                    ImGui::TextColored(ImVec4(0,1,0,1), "MATCH!");
                else
                    ImGui::TextColored(ImVec4(1,0.8f,0,1), "MISMATCH!");
            } else {
                ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "Read: FAIL");
            }
            ImGui::EndGroup();
        }

        // ── Per-method stats ──
        ImGui::Spacing();
        int idx = md.idx;
        ImGui::Text("  Writes: %d OK / %d FAIL  |  Reads: %d OK / %d FAIL  |  Match: %d / Mismatch: %d",
                    g_colorval.write_ok_count[idx], g_colorval.write_fail_count[idx],
                    g_colorval.read_ok_count[idx],  g_colorval.read_fail_count[idx],
                    g_colorval.match_count[idx],    g_colorval.mismatch_count[idx]);
        ImGui::Separator();
    }

    // ── Global info ──
    ImGui::Text("Buffer: 0x%llX  |  PID: %u  |  Hue: %.0f deg",
                (unsigned long long)g_colorval.buf_addr, my_pid, hue);
    ImGui::TextWrapped(
        "Each enabled method writes the same target color to the test buffer, "
        "then reads it back. If the driver's read/write is consistent, the two "
        "tiles will always match."
    );
}

// ============================================================================
// TAB 5: Stealth Status — Thread Spoofing + Stack Isolation Validation
// ============================================================================
static void DrawStealthStatusTab() {
    ImGui::Text("Stealth Status - Thread Spoofing & Stack Isolation Diagnostics"); ImGui::Separator();

    static bool auto_refresh = true;
    ImGui::Checkbox("Auto-refresh (2s)", &auto_refresh);
    ImGui::SameLine();
    if (ImGui::Button("Refresh All", ImVec2(140, 28))) {
        // Manual refresh triggers all queries below
    }

    // Periodic auto-refresh
    static double last_refresh = 0.0;
    double now = ImGui::GetTime();
    if (auto_refresh && (now - last_refresh) > 2.0) {
        last_refresh = now;
        // Queries happen inline below
    }
    bool do_query = auto_refresh ? ((now - last_refresh) > 2.0 || last_refresh == 0.0) : false;
    if (do_query) last_refresh = now;

    // Static state shared across collapsible headers in this tab
    static IPC_STEALTH_STATUS stealth = {};
    static bool stealth_loaded = false;

    // ── Full Stealth Status ─────────────────────────────────────────────
    if (ImGui::CollapsingHeader("Full Stealth Diagnostic", ImGuiTreeNodeFlags_DefaultOpen)) {

        if (ImGui::Button("Query Stealth Status", ImVec2(200, 28)) || (do_query && !stealth_loaded)) {
            if (drv_stealth_status(&stealth)) {
                stealth_loaded = true;
                LOG_PRINT("[+] Stealth status retrieved.");
            } else {
                LOG_PRINT("[-] Failed to query stealth status. Driver connected?");
            }
        }

        if (stealth_loaded) {
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "--- Thread Spoofing (Code Cave) ---");

            bool spoof_ok = stealth.thread_spoof_active != 0;
            ImGui::TextColored(spoof_ok ? ImVec4(0,1,0,1) : ImVec4(1,0.3f,0.3f,1),
                               spoof_ok ? "Thread Start Address: SPOOFED" : "Thread Start Address: NOT SPOOFED (DETECTABLE)");
            ImGui::Text("  Cave Address:     0x%llX", (unsigned long long)stealth.cave_address);
            ImGui::Text("  Cave Module Base: 0x%llX", (unsigned long long)stealth.cave_module_base);
            ImGui::Text("  Cave Size:        %u bytes", stealth.cave_size);
            ImGui::Text("  Module:           %s", stealth.cave_module_name[0] ? stealth.cave_module_name : "(unknown)");
            ImGui::Text("  Patch Bytes:      %02X %02X %02X %02X %02X %02X %02X %02X",
                       stealth.cave_patch_bytes[0], stealth.cave_patch_bytes[1],
                       stealth.cave_patch_bytes[2], stealth.cave_patch_bytes[3],
                       stealth.cave_patch_bytes[4], stealth.cave_patch_bytes[5],
                       stealth.cave_patch_bytes[6], stealth.cave_patch_bytes[7]);

            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "--- Stack Isolation (Expanded Stack) ---");

            bool stack_ok = stealth.stack_isolation_active != 0;
            ImGui::TextColored(stack_ok ? ImVec4(0,1,0,1) : ImVec4(1,0.8f,0,1),
                               stack_ok ? "Expanded Stack Callout: ACTIVE" : "Expanded Stack Callout: NOT ACTIVE (gadget not found)");
            ImGui::Text("  Ret Gadget:       0x%llX", (unsigned long long)stealth.ret_gadget_address);
            ImGui::Text("  Gadget Module:    0x%llX (ntoskrnl)", (unsigned long long)stealth.ret_gadget_module_base);
            ImGui::Text("  Stack Size:       0x%X (%u KB)", stealth.expanded_stack_size, stealth.expanded_stack_size / 1024);

            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "--- KPTI / KVA Shadow ---");
            ImGui::Text("  KPTI Enabled:      %s", stealth.kpti_enabled ? "YES (UserDTB is shadow CR3)" : "NO (UserDTB == kernel CR3)");
            ImGui::Text("  CR3 Swap Capable:   %s", stealth.cr3_swap_capable ? "YES (kernel CR3)" : "NO (user shadow CR3)");
            const char* mode_names[] = { "CR3 Swap (stealthiest)", "MDL Direct (detectable)", "MDL + Expanded Stack" };
            ImGui::Text("  Active RW Mode:     %s", mode_names[stealth.cr3_mode > 2 ? 1 : stealth.cr3_mode]);

            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "--- Syscall / SSN ---");
            ImGui::Text("  NtFreeVirtualMemory SSN:  0x%X", stealth.ntfvm_ssn);
            ImGui::Text("  SSN Resolve Method:        %s", stealth.ssn_resolved_dynamic ? "Dynamic (ntdll stub)" : "Static table / unknown");

            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "--- Driver State ---");
            ImGui::Text("  IPC Workers:        %u", stealth.worker_count);
            ImGui::Text("  Discovery Thread:   %s", stealth.discovery_active ? "Running" : "Stopped");
            ImGui::Text("  Target Attached:    %s", stealth.target_attached ? "YES" : "NO");
            if (stealth.target_attached) {
                ImGui::Text("  Target PID:         %u", stealth.target_pid);
                ImGui::Text("  Target Name:        %s", stealth.target_name[0] ? stealth.target_name : "(unknown)");
                ImGui::Text("  Target CR3:         0x%llX", (unsigned long long)stealth.target_cr3);
                ImGui::Text("  Target Base:        0x%llX", (unsigned long long)stealth.target_base);
            }

            // ── Overall stealth assessment ──
            ImGui::Separator();
            int score = 0;
            if (spoof_ok) score += 40;
            if (stack_ok || stealth.cr3_mode == 0) score += 30; // CR3 swap is stealthy without stack isolation
            if (stealth.cr3_swap_capable) score += 20;
            if (stealth.ssn_resolved_dynamic) score += 10;

            ImVec4 score_color;
            const char* verdict;
            if (score >= 80)      { score_color = ImVec4(0,1,0,1); verdict = "EXCELLENT - All stealth measures active"; }
            else if (score >= 50) { score_color = ImVec4(0.8f,0.8f,0,1); verdict = "GOOD - Core protection active"; }
            else if (score >= 30) { score_color = ImVec4(1,0.6f,0,1); verdict = "FAIR - Some measures missing"; }
            else                  { score_color = ImVec4(1,0,0,1); verdict = "POOR - Highly detectable!"; }

            ImGui::TextColored(score_color, "Stealth Score: %d/100 - %s", score, verdict);
            ImGui::ProgressBar((float)score / 100.0f, ImVec2(-1, 20), "");
        } else {
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1), "Click 'Query Stealth Status' to populate diagnostics.");
        }
    }

    // ── Thread Start Address Validation ──────────────────────────────────
    if (ImGui::CollapsingHeader("Thread Win32StartAddress Check", ImGuiTreeNodeFlags_DefaultOpen)) {
        static char thread_report[2048] = "";
        static uint64_t thread_result = 0;
        static bool thread_checked = false;

        if (ImGui::Button("Check Current Thread", ImVec2(220, 28)) || (do_query && !thread_checked && stealth_loaded)) {
            if (drv_thread_validate(&thread_result, thread_report, sizeof(thread_report))) {
                thread_checked = true;
                LOG_PRINT("[+] Thread validation complete. Result: %s", thread_result ? "PASS" : "FAIL");
            } else {
                LOG_PRINT("[-] Thread validation query failed.");
            }
        }

        if (thread_checked) {
            ImGui::TextColored(thread_result ? ImVec4(0,1,0,1) : ImVec4(1,0,0,1),
                               "Result: %s", thread_result ? "PASS - Start address in loaded module" : "FAIL - Start address in unbacked memory!");
            ImGui::Separator();
            ImGui::Text("Driver Report:");
            ImGui::BeginChild("ThreadReport", ImVec2(0, 80), true);
            ImGui::TextUnformatted(thread_report);
            ImGui::EndChild();
        }
    }

    // ── Read/Write Cycle Test ────────────────────────────────────────────
    if (ImGui::CollapsingHeader("RW Cycle Test (with current stealth mode)", ImGuiTreeNodeFlags_DefaultOpen)) {
        static IPC_RW_CYCLE_RESULT cycle = {};
        static bool cycle_run = false;

        if (ImGui::Button("Run RW Cycle Test", ImVec2(200, 28))) {
            if (drv_rw_cycle_test(&cycle)) {
                cycle_run = true;
                const char* mode_str = cycle.mode_used == 0 ? "CR3 Swap" :
                                       cycle.mode_used == 1 ? "MDL + Expanded Stack" :
                                       cycle.mode_used == 2 ? "MDL Direct" : "SKIPPED";
                LOG_PRINT("[+] RW cycle test complete. Mode=%s Write=%s Read=%s Match=%s",
                         mode_str,
                         cycle.write_success ? "OK" : "FAIL",
                         cycle.read_success ? "OK" : "FAIL",
                         cycle.data_match ? "YES" : "NO");
            } else {
                LOG_PRINT("[-] RW cycle test query failed.");
            }
        }

        if (cycle_run) {
            ImGui::Separator();

            // mode_used == 0xFF means no target was attached when the test ran
            // (g_test_process was NULL). Display it explicitly instead of
            // clamping 0xFF to index 2 ("MDL Direct"), which was misleading.
            if (cycle.mode_used == 0xFF) {
                ImGui::TextColored(ImVec4(1,0.5f,0,1),
                    "  Mode Used:      SKIPPED (no target attached — run CMD_RESOLVE_DTB first)");
            } else {
                const char* mode_names[] = { "CR3 Swap (stealthiest)", "MDL + Expanded Stack", "MDL Direct (detectable)" };
                ImGui::Text("  Mode Used:      %s", mode_names[cycle.mode_used > 2 ? 2 : cycle.mode_used]);
                ImGui::Text("  Test Address:   0x%llX", (unsigned long long)cycle.test_address);
                ImGui::Text("  Test Size:      %u bytes", cycle.test_size);

                ImGui::TextColored(cycle.write_success ? ImVec4(0,1,0,1) : ImVec4(1,0,0,1),
                                   "  Write:          %s", cycle.write_success ? "SUCCESS" : "FAILED");
                ImGui::TextColored(cycle.read_success ? ImVec4(0,1,0,1) : ImVec4(1,0,0,1),
                                   "  Read:           %s", cycle.read_success ? "SUCCESS" : "FAILED");
                ImGui::TextColored(cycle.data_match ? ImVec4(0,1,0,1) : ImVec4(1,0.5f,0,1),
                                   "  Data Match:     %s", cycle.data_match ? "YES (correct)" : "NO (corrupted!)");

                // Show pattern comparison
                char hex_wr[128], hex_rd[128];
                int pw = 0, pr = 0;
                for (int i = 0; i < __min(16, (int)cycle.test_size); i++) {
                    pw += _snprintf_s(hex_wr + pw, sizeof(hex_wr) - pw, _TRUNCATE, "%02X ", cycle.written_pattern[i]);
                    pr += _snprintf_s(hex_rd + pr, sizeof(hex_rd) - pr, _TRUNCATE, "%02X ", cycle.readback_pattern[i]);
                }
                ImGui::Text("  Written:        %s", hex_wr);
                ImGui::Text("  Readback:       %s", hex_rd);

                // Latency
                ImGui::Text("  Write Latency:  ~%llu ns (%.1f us)", (unsigned long long)cycle.write_latency_ns,
                           (double)cycle.write_latency_ns / 1000.0);
                ImGui::Text("  Read Latency:   ~%llu ns (%.1f us)", (unsigned long long)cycle.read_latency_ns,
                           (double)cycle.read_latency_ns / 1000.0);
            }
        }
    }

}

// ============================================================================
// TAB 6: DLL Injection
// ============================================================================
static void DrawInjectTab() {
    static char  s_dll_path[512]   = "";
    static UINT64 s_target_pid      = 0;
    static int   s_alloc_mode       = 1;  // default: between legit modules
    static uint64_t s_last_result   = 0;
    static bool  s_last_ok          = false;
    static bool  s_injected_once    = false;

    // alloc mode labels match INJ_ALLOC_* constants in injector_api.hpp
    static const char* k_alloc_labels[] = {
        "0 - Inside Main Module (hijack null PFN)",
        "1 - Between Legit Modules (recommended)",
        "2 - At Low Address  (<4 GB non-present PML4)",
        "3 - At High Address (>128 TB non-present PML4)",
    };

    ImGui::Text("DLL Injection - PT-injector stealth manual map"); ImGui::Separator();

    // ── Process picker ───────────────────────────────────────────────────
    if (ImGui::CollapsingHeader("Target Process", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::InputScalar("Target PID", ImGuiDataType_U64, &s_target_pid);

        ImGui::SameLine();
        if (ImGui::Button("Snapshot", ImVec2(100, 22))) {
            // Populate a quick process list in the log for reference
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe = { sizeof(pe) };
                LOG_PRINT("[*] Running processes:");
                if (Process32First(snap, &pe)) {
                    do {
                        LOG_PRINT("    PID %-6lu  %s", (unsigned long)pe.th32ProcessID, pe.szExeFile);
                    } while (Process32Next(snap, &pe));
                }
                CloseHandle(snap);
            }
        }

        if (s_target_pid) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)s_target_pid);
            if (hProc) {
                char exe_name[MAX_PATH] = "<unknown>";
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameA(hProc, 0, exe_name, &sz);
                ImGui::TextColored(ImVec4(0,1,0,1), "Target: %s (PID %llu)", exe_name, (unsigned long long)s_target_pid);
                CloseHandle(hProc);
            } else {
                ImGui::TextColored(ImVec4(1,0.5f,0,1), "PID %llu: cannot open (process gone or no access)", (unsigned long long)s_target_pid);
            }
        }
    }

    // ── DLL selection ────────────────────────────────────────────────────
    if (ImGui::CollapsingHeader("DLL", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::InputText("DLL Path", s_dll_path, sizeof(s_dll_path));
        ImGui::SameLine();
        if (ImGui::Button("Browse...", ImVec2(90, 22))) {
            OPENFILENAMEA ofn = {};
            char file[MAX_PATH] = "";
            ofn.lStructSize = sizeof(ofn);
            ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
            ofn.lpstrFile   = file;
            ofn.nMaxFile    = MAX_PATH;
            ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            ofn.lpstrTitle  = "Select DLL to inject";
            if (GetOpenFileNameA(&ofn))
                strncpy_s(s_dll_path, sizeof(s_dll_path), file, _TRUNCATE);
        }

        if (s_dll_path[0]) {
            DWORD attr = GetFileAttributesA(s_dll_path);
            if (attr == INVALID_FILE_ATTRIBUTES) {
                ImGui::TextColored(ImVec4(1,0,0,1), "File not found");
            } else {
                HANDLE hf = CreateFileA(s_dll_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                if (hf != INVALID_HANDLE_VALUE) {
                    DWORD sz = GetFileSize(hf, nullptr);
                    CloseHandle(hf);
                    ImGui::TextColored(ImVec4(0,1,0,1), "File OK  (%.1f KB)", sz / 1024.0f);
                }
            }
        }
    }

    // ── Alloc mode ───────────────────────────────────────────────────────
    if (ImGui::CollapsingHeader("Stealth Allocation Mode", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (int i = 0; i < 4; i++) {
            if (ImGui::RadioButton(k_alloc_labels[i], &s_alloc_mode, i))
                s_alloc_mode = i;
        }
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.7f,0.7f,0.7f,1),
            "Mode 1 (between modules) is the best default.\n"
            "Mode 0 (inside main module) requires a null PFN slot — not always available.\n"
            "Modes 2/3 allocate in non-present PML4 regions; very stealthy but may trip\n"
            "some scanners that enumerate all VADs.");
    }

    // ── Inject button ────────────────────────────────────────────────────
    ImGui::Separator();
    bool can_inject = s_target_pid != 0 && s_dll_path[0] != '\0';
    if (!can_inject) ImGui::BeginDisabled();
    bool do_inject = ImGui::Button("  Inject DLL  ", ImVec2(180, 32));
    if (!can_inject) ImGui::EndDisabled();

    if (!can_inject) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1,0.5f,0,1), "Set target PID and DLL path first.");
    }

    if (do_inject) {
        s_last_ok = false; s_last_result = 0; s_injected_once = true;
        HANDLE hFile = CreateFileA(s_dll_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            LOG_PRINT("[-] Inject: cannot open '%s'  error=%lu", s_dll_path, GetLastError());
        } else {
            DWORD dll_size = GetFileSize(hFile, nullptr);
            if (dll_size == 0 || dll_size > 32 * 1024 * 1024) {
                LOG_PRINT("[-] Inject: DLL size invalid (%lu bytes).", (unsigned long)dll_size);
            } else {
                std::vector<uint8_t> dll_data(dll_size);
                DWORD bytes_read = 0;
                if (!ReadFile(hFile, dll_data.data(), dll_size, &bytes_read, nullptr) || bytes_read != dll_size) {
                    LOG_PRINT("[-] Inject: read error  error=%lu", GetLastError());
                } else {
                    LOG_PRINT("[*] Injecting %lu KB into PID %llu (alloc_mode=%d)...",
                              (unsigned long)(dll_size / 1024), (unsigned long long)s_target_pid, s_alloc_mode);
                    uint64_t result = drv_inject_dll((uint32_t)s_target_pid, dll_data.data(), dll_size, (uint32_t)s_alloc_mode);
                    if (result) {
                        s_last_result = result; s_last_ok = true;
                        LOG_PRINT("[+] DLL mapped at 0x%llX in PID %llu", (unsigned long long)result, (unsigned long long)s_target_pid);
                    } else {
                        LOG_PRINT("[-] Injection failed (driver returned 0). Check DbgView for kernel logs.");
                    }
                }
            }
            CloseHandle(hFile);
        }
    }

    // ── Last result ──────────────────────────────────────────────────────
    if (s_injected_once) {
        ImGui::Spacing();
        if (s_last_ok) {
            ImGui::TextColored(ImVec4(0,1,0,1), "Last result: MAPPED at 0x%llX", (unsigned long long)s_last_result);
        } else {
            ImGui::TextColored(ImVec4(1,0,0,1), "Last result: FAILED");
            ImGui::TextColored(ImVec4(0.7f,0.7f,0.7f,1), "Attach DebugView to see kernel DbgPrint output from the driver.");
        }
    }
}
