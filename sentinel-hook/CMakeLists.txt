# sentinel-hook: User-mode hooking DLL (C17)
cmake_minimum_required(VERSION 3.20)

add_library(sentinel-hook SHARED
    main.c
    hook_engine.c
    hooks_common.c
    hooks_memory.c
    hooks_thread.c
    hooks_section.c
    hooks_process.c
    pipe_client.c
)

target_include_directories(sentinel-hook PRIVATE ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(sentinel-hook PRIVATE ole32.lib advapi32.lib)
set_target_properties(sentinel-hook PROPERTIES
    C_STANDARD 17
    OUTPUT_NAME "sentinel-hook"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "sentinel-hook: Configured (hooking DLL with hook engine)")
