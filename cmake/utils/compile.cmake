macro(get_cross_compile_prefix)
  execute_process(COMMAND basename ${CMAKE_C_COMPILER}
    COMMAND grep -e "-gcc" -e "-cc"
    OUTPUT_VARIABLE CROSS_COMPILE_output
    ERROR_VARIABLE CROSS_COMPILE_error
    RESULT_VARIABLE CROSS_COMPILE_result
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(${CROSS_COMPILE_result} EQUAL 0)
    string(REGEX REPLACE "-(gcc|cc)$" "" CROSS_COMPILE ${CROSS_COMPILE_output})
    set(CROSS_COMPILE_PREFIX ${CROSS_COMPILE}-)
    message(STATUS "Cross compiling with ${CROSS_COMPILE}")
  else()
    set(CROSS_COMPILE "")
    set(CROSS_COMPILE_PREFIX "")
  endif()
endmacro()

