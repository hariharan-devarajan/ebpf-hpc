cmake_minimum_required(VERSION 3.4)
project(dftracer_ebpf LANGUAGES C)

set(DFT_EBPF_SRC dftracer_ebpf.c dftracer_ebpf.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(${PROJECT_NAME} SHARED ${DFT_EBPF_SRC})

add_executable(test test.c)