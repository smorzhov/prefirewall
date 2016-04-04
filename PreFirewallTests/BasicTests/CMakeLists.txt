include_directories(${googletest_SOURCE_DIR}/include ${googletest_SOURCE_DIR})

add_executable(runBasicTests
        IPv4AdressCheck.cpp
        ACLRuleCheck.cpp
        FirewallRuleCheck.cpp
        AlgorithmCheckFirewall.cpp
        AlgorithmCheckACL.cpp)

target_link_libraries(runBasicTests gtest gtest_main)
target_link_libraries(runBasicTests PreFirewallSrc)