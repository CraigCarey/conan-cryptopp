project(conan-cryptopp LANGUAGES C CXX)

cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# set(CMAKE_CXX_CLANG_TIDY 
#   clang-tidy;
#   -header-filter=.;
#   -checks=*;)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(NOT CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR} CACHE PATH "search path for find_package() installation files")
else()
    list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})
endif()
message(STATUS "CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH}")

find_package(cryptopp)

set(INTRO intro)
add_executable(${INTRO} main.cpp)
target_link_libraries(${INTRO} cryptopp-static)

set(ENC_FILE encrypt_file)
add_executable(${ENC_FILE} encrypt_file.cpp)
target_link_libraries(${ENC_FILE} cryptopp-static)

set(DEC_FILE decrypt_file)
add_executable(${DEC_FILE} decrypt_file.cpp)
target_link_libraries(${DEC_FILE} cryptopp-static)
