project(pcap2bpf)

add_library(${PROJECT_NAME} STATIC
    pcap2bpf.cpp
    bpf_convert.c)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/libbpf/include/linux/
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME}
    bpf
    utils)