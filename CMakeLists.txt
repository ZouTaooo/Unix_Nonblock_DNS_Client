cmake_minimum_required(VERSION 3.16)
project(Unix_Nonblock_DNS_Client)

set(CMAKE_CXX_STANDARD 11)

add_executable(Unix_Nonblock_DNS_Client main.cpp)
add_executable(TEST TEST.cpp)
target_link_libraries(Unix_Nonblock_DNS_Client /usr/local/lib/libuv.so)