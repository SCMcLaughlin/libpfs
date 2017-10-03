
cmake_minimum_required(VERSION 2.6)

project(libpfs)

# Build options
add_definitions(-O2 -fomit-frame-pointer -std=c89 -fPIC)
# Warnings
add_definitions(-Wall -Wextra -Wredundant-decls -Wno-unused-result -Wno-strict-aliasing)

add_library(pfs SHARED pfs.c)

find_package(ZLIB)
if (ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
    target_link_libraries(pfs ${ZLIB_LIBRARIES})
endif()

install(TARGETS pfs DESTINATION lib)
install(FILES pfs.h DESTINATION include)
