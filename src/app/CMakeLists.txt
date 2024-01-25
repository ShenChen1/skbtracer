project(skbtracer)

add_executable(${PROJECT_NAME}
    main.c
    options.c)
target_link_libraries(${PROJECT_NAME}
    ${PROJECT_NAME}_skel
    symdb
    trace
    utils)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})