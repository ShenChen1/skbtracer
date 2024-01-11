# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(skbtracer)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/platforms/host.cmake"
    CACHE FILEPATH "toolchain file")
message(STATUS "Toolchain file defaulted to '${CMAKE_TOOLCHAIN_FILE}'")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/package)

include(GNUInstallDirs)
add_subdirectory(3rdparty)
add_subdirectory(bpf)
add_subdirectory(app)