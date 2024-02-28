project(symdb)

add_library(${PROJECT_NAME} OBJECT
    symdb.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/trace_helpers.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/uprobe_helpers.c)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${LIBBPF_INCLUDE_DIRS})

target_link_libraries(${PROJECT_NAME}
    ${LIBBPF_LIBRARIES})