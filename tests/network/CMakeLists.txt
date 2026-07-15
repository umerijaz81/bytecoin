cmake_minimum_required(VERSION 3.15)
project(bytecoin_network_privacy_tests LANGUAGES CXX)

add_executable(network-privacy-tests test_network_privacy.cpp)
target_include_directories(network-privacy-tests PRIVATE ../../src)
target_compile_features(network-privacy-tests PRIVATE cxx_std_14)

if(MSVC)
  target_compile_options(network-privacy-tests PRIVATE /W4 /WX)
else()
  target_compile_options(network-privacy-tests PRIVATE -Wall -Wextra -Werror -pedantic)
endif()
