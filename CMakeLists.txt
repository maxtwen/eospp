cmake_minimum_required(VERSION 3.13)
project(eos_signature_11)

set(CMAKE_CXX_STANDARD 11)

link_directories(${CMAKE_SOURCE_DIR}/libraries)
set(GCC_COVERAGE_COMPILE_FLAGS "-lcurlpp -lcurl -lcrypto")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")


add_executable(eos_signature_11 main.cpp)
