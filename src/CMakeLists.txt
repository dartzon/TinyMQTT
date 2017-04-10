#include_directories(
#	/home/dartzon/Dev-Workspace/CPP/MQTT/libs/asio-1.10.6/include
#	include
#	src)

file(GLOB SOURCES "*.cpp")
add_executable(mqtt ${SOURCES})
