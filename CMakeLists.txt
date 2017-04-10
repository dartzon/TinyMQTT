cmake_minimum_required(VERSION 2.6)

project(MQTT)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

list(APPEND CMAKE_CXX_FLAGS "-pthread -std=c++14 -fno-rtti -fno-exceptions ${CMAKE_CXX_FLAGS}")

subdirs(src)
