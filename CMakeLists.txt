cmake_minimum_required(VERSION 3.12)
project(memrw)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options("-O3;-Wall;-Wextra;-Werror;-fconcepts;")

add_executable(memrw main.cpp)
