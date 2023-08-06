set(This filesend)

# file(GLOB SOURCES
#   ${PROJECT_SOURCE_DIR}/src/*.h
#   ${PROJECT_SOURCE_DIR}/src/*.cpp
# )

add_executable(${This})

target_sources(${This} PRIVATE
  common.h
  client.h
  server.h
  common.cpp
  client.cpp
  server.cpp
  main.cpp
)

add_link_options("/VERBOSE")
#add_executable(${This} main.cpp common.h)

if(WIN32)
  target_link_libraries(${This} ws2_32)
endif()
