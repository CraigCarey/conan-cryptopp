project(conan-cryptopp LANGUAGES C CXX)

cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

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

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME} cryptopp-static)
