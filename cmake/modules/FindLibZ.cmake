# - Try to find libz
# Once done this will define
#
#  LIBZ_FOUND - system has libz
#  LIBZ_LIBRARIES - Link these to use libz

find_library(LIBZ_LIBRARIES
  NAMES
    z
  PATH_SUFFIXES
    libz
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBZ_FOUND to TRUE if all listed variables are TRUE
find_package_handle_standard_args(LibZ "Please install the libz package"
  LIBZ_LIBRARIES)

mark_as_advanced(LIBZ_LIBRARIES)