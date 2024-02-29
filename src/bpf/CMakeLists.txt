set(BPFOBJECT_BPFTOOL_EXE ${PROJECT_BINARY_DIR}/3rdparty/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${PROJECT_SOURCE_DIR}/3rdparty/bcc/libbpf-tools/${ARCH}/vmlinux.h)

find_package(BpfObject REQUIRED)
bpf_object(${PROJECT_NAME} skbtracer.bpf.c)

add_library(${PROJECT_NAME}_skel OBJECT
    ${BPF_SKEL_FILE})

target_include_directories(${PROJECT_NAME}_skel
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME}_skel
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    ${LIBZ_LIBRARIES})