project(skbtracer)

add_executable(${PROJECT_NAME}
    main.cpp)
target_link_libraries(${PROJECT_NAME}
    ${PROJECT_NAME}_skel
    symdb
    trace
    utils)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../bpf)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})