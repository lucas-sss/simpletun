cmake_minimum_required(VERSION 2.8)
project(simpletun C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe -std=c99")

include_directories("/usr/include")
include_directories("/opt/tongsuo/include")
link_directories("/opt/tongsuo/lib64")

add_executable(simpletun simpletun.c)
target_link_libraries(simpletun)

add_executable(simpletun-ssl simpletun-ssl.c)
target_link_libraries(simpletun-ssl ssl crypto)

add_executable(simpletun2 simpletun2.c)
target_link_libraries(simpletun2 pthread ssl crypto)

add_executable(simpletun3 simpletun3.c)
target_link_libraries(simpletun3 pthread ssl crypto)

add_executable(mmapsocket mmapsocket.c)
target_link_libraries(mmapsocket)

add_executable(test test.c)
target_link_libraries(test pthread)

# 拷贝文件夹到指定的目录
add_custom_target(
  copy_certs ALL
  VERBATIM
  # COMMAND_EXPAND_LISTS
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/certs" "certs")
