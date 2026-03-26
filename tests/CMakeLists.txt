# tests: Integration test harness
cmake_minimum_required(VERSION 3.20)

# ── IPC round-trip test ──────────────────────────────────────────────────────
add_executable(test_ipc_roundtrip test_ipc_roundtrip.c)
target_include_directories(test_ipc_roundtrip PRIVATE ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(test_ipc_roundtrip PRIVATE ole32)  # CoCreateGuid
set_target_properties(test_ipc_roundtrip PROPERTIES C_STANDARD 17)

add_test(NAME ipc_roundtrip COMMAND test_ipc_roundtrip)

# ── Test consumer (P1-T4) ────────────────────────────────────────────────────
# Connects to the driver's filter communication port and prints events.
# Requires fltLib.lib (Filter Manager user-mode library).
add_executable(test_consumer test_consumer.c)
target_include_directories(test_consumer PRIVATE ${CMAKE_SOURCE_DIR}/common)
target_link_libraries(test_consumer PRIVATE fltLib ole32)
set_target_properties(test_consumer PROPERTIES
    C_STANDARD 17
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

# ── XLL test payload (P10-T1) ───────────────────────────────────────────────
# Excel XLL add-in with benign calc.exe shellcode for attack-chain testing.
# Builds as a DLL with .xll suffix; exports xlAutoOpen via .def file.
add_library(test_xll SHARED payloads/test_xll.cpp)
target_link_libraries(test_xll PRIVATE kernel32)
set_target_properties(test_xll PROPERTIES
    SUFFIX ".xll"
    LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/payloads/test_xll.def"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "tests: Configured (ipc_roundtrip, test_consumer, test_xll)")
