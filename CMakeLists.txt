cmake_minimum_required(VERSION 3.10)
project(LiBurn LANGUAGES CXX)
project(LiBurn VERSION 1.0)

set(CMAKE_GENERATOR ninja)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG_MODE")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG_MODE")

enable_language(CXX)
enable_testing()

add_subdirectory(LiBurn)
add_subdirectory(payload)
