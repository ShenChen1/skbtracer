project(cfg)

add_library(${PROJECT_NAME} STATIC
    options.cpp)

target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})