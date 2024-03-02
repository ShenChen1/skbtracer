add_executable(${PROJECT_NAME}
    main.cpp)
target_link_libraries(${PROJECT_NAME}
    ${PROJECT_NAME}_skel
    bpf
    symdb
    trace
    utils)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})