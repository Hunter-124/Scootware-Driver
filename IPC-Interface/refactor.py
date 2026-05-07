import re

with open('ipc_speed_test.cpp', 'r') as f:
    code = f.read()

includes = """#include <mutex>
#include <thread>
#include <string>
#include <vector>
#include <atomic>
#include <d3d11.h>
#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"

static std::mutex g_log_mutex;
static std::vector<std::string> g_log_lines;
static std::atomic<float> g_progress_current{0.0f};
static std::atomic<bool> g_benchmark_running{false};
static std::string g_current_test_name = "Idle";

static void LOG_PRINT(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_lines.push_back(buf);
}
#define printf LOG_PRINT
"""

code = re.sub(r'#include <vector>', includes, code)

code = re.sub(r'(for\s*\(\s*int\s+i\s*=\s*0;\s*i\s*<\s*iterations;\s*\+\+i\s*\)\s*\{)',
              r'\1\n        g_progress_current = (float)i / iterations;', code)

code = re.sub(r'(while\s*\(\s*done\s*<\s*total_bytes\s*\)\s*\{)',
              r'\1\n        g_progress_current = (float)done / total_bytes;', code)

code = re.sub(r'(while\s*\(\s*now_ns\(\)\s*<\s*end_ns\s*\)\s*\{)',
              r'\1\n        g_progress_current = (float)(now_ns() - t0) / (end_ns - t0);', code)

code = code.replace('int main(int argc, char** argv)', 'int run_benchmark(int argc, char** argv)')

code = code.replace('return 0;\n}', 'g_benchmark_running = false;\n    g_progress_current = 1.0f;\n    g_current_test_name = "Finished";\n    return 0;\n}')

imgui_main = """
// =====================================================================
// UI Application
// =====================================================================
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
    return true;
}

static void CleanupDeviceD3D() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;
    switch (msg) {
        case WM_SIZE:
            if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
                if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
                g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                ID3D11Texture2D* pBackBuffer;
                g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
                g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
                pBackBuffer->Release();
            }
            return 0;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}

int main(int argc, char** argv) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, "IPC_Speed_Test_Class", nullptr };
    ::RegisterClassEx(&wc);
    HWND hwnd = ::CreateWindow(wc.lpszClassName, "IPC Speed Test", WS_OVERLAPPEDWINDOW, 100, 100, 1024, 768, nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    std::vector<std::string> args_vec;
    for (int i=0; i<argc; i++) args_vec.push_back(argv[i]);

    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Speed Test Dashboard", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize);

        ImGui::Text("Scootware Driver Performance Test");
        ImGui::Separator();

        if (ImGui::Button(g_benchmark_running ? "Running..." : "Start Benchmark", ImVec2(200, 40))) {
            if (!g_benchmark_running) {
                g_benchmark_running = true;
                g_log_lines.clear();
                g_progress_current = 0.0f;
                g_current_test_name = "Running Benchmark Suite...";
                
                std::thread([args_vec]() {
                    std::vector<char*> pt_args;
                    for (auto& s : args_vec) pt_args.push_back((char*)s.c_str());
                    run_benchmark((int)pt_args.size(), pt_args.data());
                }).detach();
            }
        }

        ImGui::SameLine();
        if (g_benchmark_running) {
            ImGui::Text("Status: %s", g_current_test_name.c_str());
            ImGui::ProgressBar(g_progress_current, ImVec2(-1.0f, 0.0f));
        } else {
            ImGui::Text("Status: Idle");
            ImGui::ProgressBar(0.0f, ImVec2(-1.0f, 0.0f));
        }

        ImGui::Separator();
        ImGui::Text("Console Output:");
        
        ImGui::BeginChild("LogScrollRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            for (const auto& line : g_log_lines) {
                ImGui::TextUnformatted(line.c_str());
            }
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 10.0f)
                ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();

        ImGui::End();

        ImGui::Render();
        const float clear_color[4] = { 0.1f, 0.1f, 0.1f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}
"""

code += imgui_main

with open('ipc_speed_test.cpp', 'w') as f:
    f.write(code)
