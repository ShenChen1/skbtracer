project(utils)

add_library(${PROJECT_NAME} OBJECT
    utils.cpp)
target_include_directories(${PROJECT_NAME}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    SYSTEM ${LIBPCAP_INCLUDE_DIRS}
    SYSTEM ${spdlog_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}
    ${LIBPCAP_LIBRARIES}
    ${spdlog_LIBRARIES})
