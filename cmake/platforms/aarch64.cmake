set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER    "aarch64-buildroot-linux-gnu-gcc")
set(CMAKE_CXX_COMPILER  "aarch64-buildroot-linux-gnu-g++")
set(CMAKE_AR            "aarch64-buildroot-linux-gnu-ar")
set(CMAKE_LINKER        "aarch64-buildroot-linux-gnu-g++")
set(CMAKE_LD            "aarch64-buildroot-linux-gnu-ld")

execute_process(COMMAND ${CMAKE_C_COMPILER} --print-sysroot
                OUTPUT_VARIABLE CMAKE_FIND_ROOT_PATH
                OUTPUT_STRIP_TRAILING_WHITESPACE)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)