cmake_minimum_required(VERSION 2.8)
project(simpletun C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe -std=c99")

include_directories("/usr/include")
include_directories("/opt/tongsuo/include")
link_directories("/opt/tongsuo/lib64")



add_executable(simpletun2 simpletun2.c)
target_link_libraries(simpletun2 pthread)

