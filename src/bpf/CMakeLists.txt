set(BPFOBJECT_BPFTOOL_EXE ${PROJECT_BINARY_DIR}/3rdparty/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${PROJECT_SOURCE_DIR}/3rdparty/bcc/libbpf-tools/${ARCH}/vmlinux.h)

find_package(BpfObject REQUIRED)
# Build object skeleton and depend skeleton on libbpf build
bpf_object(${PROJECT_NAME} ${PROJECT_NAME}.bpf.c)
add_dependencies(${PROJECT_NAME}_skel libbpf-build bpftool-build)