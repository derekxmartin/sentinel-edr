# sentinel-drv: Kernel-mode WDM minifilter driver
cmake_minimum_required(VERSION 3.20)

# Target Windows 10+ (WINVER 0x0A00)
set(WDK_WINVER "0x0A00" CACHE STRING "" FORCE)

wdk_add_driver(sentinel-drv
    main.c
    comms.c
    callbacks_process.c
)

target_include_directories(sentinel-drv PRIVATE ${CMAKE_SOURCE_DIR}/common)

# Link FltMgr.lib for minifilter API (FltRegisterFilter, FltCreateCommunicationPort, etc.)
target_link_libraries(sentinel-drv WDK::FLTMGR)

message(STATUS "sentinel-drv: Configured (kernel minifilter driver)")
