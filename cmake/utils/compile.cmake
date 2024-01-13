macro(get_cross_compile_prefix)
  execute_process(COMMAND basename ${CMAKE_C_COMPILER}
    COMMAND sed -e "s/gcc//" -e "s/cc//"
    OUTPUT_VARIABLE CROSS_COMPILE_output
    ERROR_VARIABLE CROSS_COMPILE_error
    RESULT_VARIABLE CROSS_COMPILE_result
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(${CROSS_COMPILE_result} EQUAL 0)
    set(CROSS_COMPILE_PREFIX ${CROSS_COMPILE_output})
    message(STATUS "Cross compiling with ${CROSS_COMPILE_PREFIX}")
  else()
    set(CROSS_COMPILE_PREFIX "")
  endif()
endmacro()

