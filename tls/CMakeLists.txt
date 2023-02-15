include_directories("${CMAKE_SOURCE_DIR}/src")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

#======================= BUILD MODE =========================

#set(BUILD_MODE RELEASE)
set(BUILD_MODE DEBUG)

if (${BUILD_MODE} STREQUAL DEBUG)
        set(CMAKE_BUILD_TYPE Debug)
        add_definitions(-DIS_RELEASE_BUILD=0)
else()
        add_definitions(-DIS_RELEASE_BUILD=1)
endif()

#============================================================

add_executable(client "client.c" )
add_executable(server "server.c" )


find_package(MbedTLS REQUIRED)
target_link_libraries(client PUBLIC 
                MbedTLS::mbedtls
                MbedTLS::mbedcrypto
                MbedTLS::mbedx509)

target_link_libraries(server PUBLIC 
MbedTLS::mbedtls
MbedTLS::mbedcrypto
MbedTLS::mbedx509)