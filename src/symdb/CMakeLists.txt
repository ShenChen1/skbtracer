project(symdb)

add_library(${PROJECT_NAME} OBJECT
    symdb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/trace_helpers.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/uprobe_helpers.c)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/bcc/libbpf-tools/)

target_link_libraries(${PROJECT_NAME}
    utils
    uthash)