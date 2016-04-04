cmake_minimum_required(VERSION 3.3)

add_definitions(-std=c++11)

add_subdirectory(PreFirewallSrc)
add_subdirectory(RuleWrappers)
add_subdirectory(AnomaliesResolverWrapper)

set(SOURCE_FILES
        PreFirewallNode.cpp)

add_executable(PreFirewallNode ${SOURCE_FILES})
