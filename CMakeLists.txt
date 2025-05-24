cmake_minimum_required(VERSION 3.30)
project(mjar)

set(CMAKE_CXX_STANDARD 11)

add_library(mjar SHARED mjar.cpp aes.c pkcs7_padding.c)
include_directories(C:/Users/test/.jdks/temurin-1.8.0_442/include)
include_directories(C:/Users/test/.jdks/temurin-1.8.0_442/include/win32)
include_directories(C:/Users/test/.jdks/temurin-1.8.0_442/include/win32/bridge)
