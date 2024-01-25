include(ExternalProject)

ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    ARCH=${CMAKE_SYSTEM_PROCESSOR}
    CROSS_COMPILE=${CROSS_COMPILE_PREFIX}
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

add_library(log OBJECT
  ${CMAKE_CURRENT_SOURCE_DIR}/log.c/src/log.c)
target_include_directories(log
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/log.c/src/)

add_library(uthash INTERFACE)
target_include_directories(uthash
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/uthash/src/)