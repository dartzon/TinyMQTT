cmake_minimum_required(VERSION 3.0)
project(MQTT)

# Enable c, and c++ language
enable_language(C CXX)

include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckIncludeFiles)
include(ExternalProject)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_REQUIRED_INCLUDES cstdint)

###############################################################################
## File globbing
###############################################################################
file(GLOB_RECURSE MQTT_SRC src/*.cpp src/*.h)

###############################################################################
## Target definitions
###############################################################################
add_executable(mqtt ${MQTT_SRC})

target_compile_options(mqtt PUBLIC -pthread -std=c++14 -DBOOST_ALL_NO_LIB -DASIO_STANDALONE)

target_include_directories(mqtt PUBLIC src/)
target_include_directories(mqtt PRIVATE libs/asio/include/ libs/asio/include/asio/)

# list(APPEND CMAKE_CXX_FLAGS "-pthread -std=c++14 -fno-rtti -fno-exceptions -DBOOST_EXCEPTION_DISABLE -DBOOST_NO_EXCEPTION -DBOOST_NO_RTTI -DASIO_STANDALONE ${CMAKE_CXX_FLAGS}")
