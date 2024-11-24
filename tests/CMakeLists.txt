add_executable(test_pcap2bpf test_pcap2bpf.cpp)
target_link_libraries(test_pcap2bpf
    pcap2bpf
    bpf
    utils)
add_test(NAME test_pcap2bpf COMMAND test_pcap2bpf)
