# akesoedr-amsi: Custom AMSI provider DLL (COM in-process server)
cmake_minimum_required(VERSION 3.20)

add_library(akesoedr-amsi SHARED
    dllmain.cpp
    amsi_provider.cpp
    akesoedr-amsi.def
)

target_include_directories(akesoedr-amsi PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ole32.lib — COM (CoTaskMemAlloc for DisplayName)
# advapi32.lib — Registry operations (if needed from DLL side)
target_link_libraries(akesoedr-amsi PRIVATE ole32.lib advapi32.lib)

set_target_properties(akesoedr-amsi PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "akesoedr-amsi"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "akesoedr-amsi: Configured (custom AMSI provider DLL)")
