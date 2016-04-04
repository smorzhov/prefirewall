cmake_minimum_required(VERSION 3.3)

project(RuleWrappers)

set(HEADER_FILES
        FloodlightACLRuleWrapper.h
        FloodlightFirewallRuleWrapper.h
        RuleWrapper.h
        )

set(SOURCE_FILES
        FloodlightACLRuleWrapper.cpp
        FloodlightFirewallRuleWrapper.cpp
        )

add_library(RuleWrappers STATIC ${SOURCE_FILES} ${HEADER_FILES})