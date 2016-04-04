cmake_minimum_required(VERSION 3.3)

project(AnomaliesResolverWrapper)

set(HEADER_FILES
        AnomaliesResolverWrapper.h
        )

set(SOURCE_FILES
        AnomaliesResolverWrapper.cpp
        )

add_library(AnomaliesResolverWrapper STATIC ${SOURCE_FILES} ${HEADER_FILES})