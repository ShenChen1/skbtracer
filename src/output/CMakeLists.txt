project(output)

add_library(${PROJECT_NAME} STATIC
    dev_cache.cpp
    meta_output.cpp
    time_output.cpp
    tuple_output.cpp
    output.cpp)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME}
    bpf
    cfg
    symdb
    utils)