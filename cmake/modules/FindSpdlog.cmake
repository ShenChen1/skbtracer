# - Try to find spdlog
# Once done this will define
#
#  spdlog_INCLUDE_DIRS - where to find spdlog/spdlog.h
#  spdlog_LIBRARIES    - List of libraries when using spdlog
#  spdlog_FOUND        - True if spdlog found.

set(spdlog_INCLUDE_DIRS "${PROJECT_BINARY_DIR}/3rdparty/spdlog/include")
set(spdlog_LIBRARIES "${PROJECT_BINARY_DIR}/3rdparty/spdlog/lib/libspdlog.a")
set(spdlog_FOUND TRUE)