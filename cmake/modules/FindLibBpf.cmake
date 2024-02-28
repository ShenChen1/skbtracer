# - Try to find libbpf
# Once done this will define
#
#  LIBBPF_FOUND - system has libbpf
#  LIBBPF_INCLUDE_DIRS - the libbpf include directory
#  LIBBPF_LIBRARIES - Link these to use libbpf

set(LIBBPF_INCLUDE_DIRS "${PROJECT_BINARY_DIR}/3rdparty/libbpf")
set(LIBBPF_LIBRARIES "${PROJECT_BINARY_DIR}/3rdparty/libbpf/libbpf.a")
set(LIBBPF_FOUND TRUE)