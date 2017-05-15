cmake_minimum_required(VERSION 3.7)
project(DES)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES test/main.cpp src/DES.hpp src/fileDES.hpp)
add_executable(DES ${SOURCE_FILES})