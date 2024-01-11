set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/../3rdparty/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/bcc/libbpf-tools/${ARCH}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/../3rdparty/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/../3rdparty/libbpf/libbpf.a)

find_package(BpfObject REQUIRED)
# Build object skeleton and depend skeleton on libbpf build
bpf_object(skbtracer skbtracer.bpf.c)
add_dependencies(skbtracer_skel libbpf-build bpftool-build)