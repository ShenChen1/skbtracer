project(trace)

add_library(${PROJECT_NAME} OBJECT
    tracer.c)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME}
    log)