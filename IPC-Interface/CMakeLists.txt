cmake_minimum_required(VERSION 3.15)
project(ipc_speed_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The driver only attaches to a process whose image name matches
# IPC_APP_NAME in ipc_config.h (default "scootware.exe"), so the target
# MUST be named scootware.
add_executable(scootware ipc_speed_test.cpp)

target_include_directories(scootware PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../FINAL-DRV
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui-master
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui-master/backends
)

target_sources(scootware PRIVATE
    imgui-master/imgui.cpp
    imgui-master/imgui_draw.cpp
    imgui-master/imgui_tables.cpp
    imgui-master/imgui_widgets.cpp
    imgui-master/backends/imgui_impl_win32.cpp
    imgui-master/backends/imgui_impl_dx11.cpp
)

target_link_libraries(scootware PRIVATE d3d11 d3dcompiler dxgi)

# GUI only: no console window. Keep int main() via mainCRTStartup (not WinMain).
if(WIN32)
    if(MSVC)
        target_link_options(scootware PRIVATE
            /SUBSYSTEM:WINDOWS
            /ENTRY:mainCRTStartup
        )
    elseif(MINGW)
        target_link_options(scootware PRIVATE -mwindows)
    endif()
endif()

if(MSVC)
    target_compile_options(scootware PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(scootware PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
    # Release is fine; keep PDBs so latency profiles are useful.
    set_target_properties(scootware PROPERTIES
        LINK_FLAGS "/DEBUG"
    )
endif()

# Optimize by default (release build is what you want for benchmarking).
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()
