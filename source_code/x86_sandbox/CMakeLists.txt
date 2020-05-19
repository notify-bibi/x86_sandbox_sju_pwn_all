# CMakeList.txt: 顶层 CMake 项目文件，在此处执行全局配置
# 并包含子项目。
#
cmake_minimum_required (VERSION 3.5)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project ("xctf_pwn")

# 包含子项目。
aux_source_directory(. DIRSRCS)
LINK_DIRECTORIES("./lib")
add_subdirectory ("./src")