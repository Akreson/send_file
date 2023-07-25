set(This filesend)

add_executable(${This} main.cpp common.h)
if(WIN32)
  target_link_libraries(${This} ws2_32)
endif()