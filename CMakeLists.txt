cmake_minimum_required(VERSION 3.10)
project(SigningExample)

# Specify the OpenSSL installation directory
set(OPENSSL_ROOT_DIR /usr/local//opt/homebrew/opt/openssl@3/include) # Adjust this path based on your brew prefix output
#include_directories(/usr/local//opt/homebrew/opt/openssl@3/include)

set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(signing_example main.cpp)
target_link_libraries(signing_example ${OPENSSL_LIBRARIES})
