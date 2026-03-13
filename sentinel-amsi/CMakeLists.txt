# sentinel-amsi: Custom AMSI provider DLL (COM in-process server)
cmake_minimum_required(VERSION 3.20)

add_library(sentinel-amsi SHARED
    dllmain.cpp
    amsi_provider.cpp
    sentinel-amsi.def
)

target_include_directories(sentinel-amsi PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ole32.lib — COM (CoTaskMemAlloc for DisplayName)
# advapi32.lib — Registry operations (if needed from DLL side)
target_link_libraries(sentinel-amsi PRIVATE ole32.lib advapi32.lib)

set_target_properties(sentinel-amsi PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "sentinel-amsi"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "sentinel-amsi: Configured (custom AMSI provider DLL)")
