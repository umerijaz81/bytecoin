cmake_minimum_required(VERSION 3.10)
project(bytecoin-randomx-modes LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
add_subdirectory(../../vendor/randomx randomx EXCLUDE_FROM_ALL)
add_executable(randomx-mode-tests
    test_randomx_modes.cpp
    ../../src/crypto/RandomX.cpp)
target_include_directories(randomx-mode-tests PRIVATE
    ../../src
    ../../vendor/randomx/src)
target_link_libraries(randomx-mode-tests PRIVATE randomx Threads::Threads)
