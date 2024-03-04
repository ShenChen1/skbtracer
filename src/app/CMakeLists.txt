add_executable(${PROJECT_NAME}
    main.cpp
    options.cpp)
target_link_libraries(${PROJECT_NAME}
    bpf
    symdb
    trace
    utils)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})