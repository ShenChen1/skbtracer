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
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
)

ExternalProject_Add(spdlog
  PREFIX spdlog
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/spdlog
  CONFIGURE_COMMAND cmake -S${CMAKE_CURRENT_SOURCE_DIR}/spdlog -Bbuild
    -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/spdlog
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
  BUILD_COMMAND cmake --build build
  INSTALL_COMMAND cmake --install build
)

ExternalProject_Add(libpcap
  PREFIX libpcap
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libpcap
  CONFIGURE_COMMAND ./autogen.sh && ./configure
    --prefix=${CMAKE_CURRENT_BINARY_DIR}/libpcap
    --host=${CROSS_COMPILE}
    --enable-shared=no
  BUILD_COMMAND make clean install
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
)