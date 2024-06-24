cmake_minimum_required(VERSION 3.4)
project(dftracer_ebpf LANGUAGES C CXX)

set(DFT_EBPF_SRC dftracer_ebpf.c dftracer_ebpf.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(${PROJECT_NAME} SHARED ${DFT_EBPF_SRC})

find_package(MPI COMPONENTS CXX REQUIRED)
include_directories(${MPI_CXX_INCLUDE_DIRS})
add_executable(df_tracer_test test.cpp)
target_link_libraries(df_tracer_test ${MPI_CXX_LIBRARIES})