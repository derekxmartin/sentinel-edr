# akesoedr-cli: Console management tool (C++20)
cmake_minimum_required(VERSION 3.20)

add_executable(akesoedr-cli
    main.cpp
)

target_include_directories(akesoedr-cli PRIVATE ${CMAKE_SOURCE_DIR}/common)
set_target_properties(akesoedr-cli PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "akesoedr-cli"
)

set_target_properties(akesoedr-cli PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

message(STATUS "akesoedr-cli: Configured (CLI with command pipe client)")
