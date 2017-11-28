cmake_minimum_required (VERSION 2.6)
project (corkscrew)

set (VERSION_MAJOR 2)
set (VERSION_MINOR 1)
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
  )

include_directories("${PROJECT_BINARY_DIR}")

add_executable(corkscrew corkscrew.c md5.c)
# add_library(md5 md5.c)
target_link_libraries (corkscrew event)
