cmake_minimum_required(VERSION 3.8)
project(FileSend CXX)

set(CMAKE_CXX_STANDARD 17)
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS)
add_subdirectory(src)