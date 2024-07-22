project(bpf)

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/../../3rdparty/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/${ARCH}/vmlinux.h)
find_package(BpfObject REQUIRED)
bpf_object(skbtracer skbtracer.bpf.c)

add_library(skbtracer_skel OBJECT
    ${BPF_SKEL_FILE})
target_include_directories(skbtracer_skel
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_library(${PROJECT_NAME} STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/trace_helpers.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/uprobe_helpers.c)
target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/
    SYSTEM ${LIBPCAP_INCLUDE_DIRS}
    SYSTEM ${LIBBPF_INCLUDE_DIRS}
    SYSTEM ${spdlog_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}
    ${LIBPCAP_LIBRARIES}
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    ${LIBZ_LIBRARIES}
    ${spdlog_LIBRARIES})