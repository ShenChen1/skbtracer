cmake_minimum_required(VERSION 3.16)
project(skbtracer
    VERSION 0.1
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/platforms/host.cmake"
    CACHE FILEPATH "toolchain file")
message(STATUS "Toolchain file defaulted to '${CMAKE_TOOLCHAIN_FILE}'")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/utils")
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/package)

include(GNUInstallDirs)
include(arch)
include(compile)

get_target_arch()
get_cross_compile_prefix()

add_subdirectory(3rdparty)
add_subdirectory(src)