cmake_minimum_required(VERSION 3.3)

project(PreFirewall)

add_definitions(-std=c++11)

set(SOURCE_FILES main.cpp)

add_executable(PreFirewallRun ${SOURCE_FILES})

add_subdirectory(cpp)
add_subdirectory(PreFirewallTests)
