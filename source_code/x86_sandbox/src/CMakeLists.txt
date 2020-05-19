# CMakeList.txt: ctf 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.5)


# 将源代码添加到此项目的可执行文件。
# 
# aux_source_directory(. DIR_ctf_SRCS)
add_compile_options(-std=c++11)
project(xctf_pwn CXX)


INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/src")
message("ctf ${CMAKE_BINARY_DIR}")
message("ctf ${CMAKE_SOURCE_DIR}")

add_executable(x86_sandbox "mian.cpp")
add_library(syscall STATIC "syscall.cpp")

SET(ctf_INCLUDE ${CMAKE_SOURCE_DIR}/include/)
message(STATUS "ctf_INCLUDE: ${ctf_INCLUDE}")
INCLUDE_DIRECTORIES("${ctf_INCLUDE}")
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/src")

find_library(LIB_PATH libunicorn.a "${CMAKE_SOURCE_DIR}/lib")
IF(NOT LIB_PATH)
MESSAGE(FATAL_ERROR "ctf: /lib/unicorn.lib dir not found")
ENDIF(NOT LIB_PATH) 

MESSAGE(STATUS ${LIB_PATH} " found")
find_package(Threads)
TARGET_LINK_LIBRARIES(x86_sandbox unicorn syscall ${CMAKE_THREAD_LIBS_INIT})

# TODO: 如有需要，请添加测试并安装目标。
