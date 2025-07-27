add_executable(test_pcap2bpf test_pcap2bpf.cpp)
target_link_libraries(test_pcap2bpf
    pcap2bpf
    bpf
    utils)
add_test(NAME test_pcap2bpf COMMAND test_pcap2bpf)

add_executable(test_options test_options.cpp)
target_link_libraries(test_options
    cfg
    utils)
add_test(NAME test_options COMMAND test_options)

add_executable(test_output test_output.cpp)
target_link_libraries(test_output
    output
    bpf
    utils)
add_test(NAME test_output COMMAND test_output)


add_executable(test_trace test_trace.cpp)
target_link_libraries(test_trace
    trace
    pcap2bpf
    skbtracer_skel
    bpf
    utils)
add_test(NAME test_trace COMMAND test_trace)

foreach(test_target IN ITEMS test_pcap2bpf test_options test_output test_trace)
    target_compile_options(${test_target} PRIVATE -UNDEBUG)
endforeach()
