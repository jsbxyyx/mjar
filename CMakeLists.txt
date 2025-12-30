cmake_minimum_required(VERSION 3.15)
project(mjar LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Java REQUIRED COMPONENTS Development)
find_package(JNI REQUIRED)

message(STATUS "Java: ${Java_JAVA_EXECUTABLE}")
message(STATUS "JNI include dirs: ${JNI_INCLUDE_DIRS}")
message(STATUS "JNI libraries: ${JNI_LIBRARIES}")

add_library(mjar SHARED
    mjar.cpp
    aes.c
    pkcs7_padding.c
    sha1.c
)

target_include_directories(mjar
    PRIVATE
        ${JNI_INCLUDE_DIRS}
)

target_link_libraries(mjar
    PRIVATE
        ${JNI_LIBRARIES}
)

set_target_properties(mjar PROPERTIES
    OUTPUT_NAME "mjar"
)
