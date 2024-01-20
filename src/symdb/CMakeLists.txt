project(symdb)

add_library(${PROJECT_NAME} OBJECT
    symdb.c)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME}
    log)