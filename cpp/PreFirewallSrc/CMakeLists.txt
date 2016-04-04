cmake_minimum_required(VERSION 3.3)

project(PreFirewallSrc)

set(HEADER_FILES
        Algorithm/AnomaliesResolver.h
        IPAddresses/IPAddress.h
        IPAddresses/IPv4Address.h
        Rules/Rule.h
        Rules/FloodlightFirewallRule.h
        Rules/FloodlightACLRule.h
        )

set(SOURCE_FILES
        Algorithm/AnomaliesResolver.cpp
        IPAddresses/IPv4Address.cpp
        Rules/FloodlightFirewallRule.cpp
        Rules/FloodlightACLRule.cpp
        )

add_library(PreFirewallSrc STATIC ${SOURCE_FILES} ${HEADER_FILES})