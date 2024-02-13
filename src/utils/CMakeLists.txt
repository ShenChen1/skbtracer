project(utils)

add_library(${PROJECT_NAME} STATIC
    utils.cpp)
target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
#target_link_libraries(${PROJECT_NAME})
