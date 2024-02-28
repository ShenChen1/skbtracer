set(BPFOBJECT_BPFTOOL_EXE ${PROJECT_BINARY_DIR}/3rdparty/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${PROJECT_SOURCE_DIR}/3rdparty/bcc/libbpf-tools/${ARCH}/vmlinux.h)

find_package(BpfObject REQUIRED)
bpf_object(${PROJECT_NAME} ${PROJECT_NAME}.bpf.c)

add_library(${PROJECT_NAME}_skel OBJECT
    ${BPF_SKEL_FILE})
target_include_directories(${PROJECT_NAME} PRIVATE
    ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES}
    ${LIBZ_LIBRARIES})