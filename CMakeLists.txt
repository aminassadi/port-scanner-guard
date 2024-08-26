cmake_minimum_required(VERSION 3.22.1)
project(pscannerguard LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

add_subdirectory(src)
add_subdirectory(test)

include_directories(../src/.output)
target_link_directories(${PROJECT_NAME} PRIVATE ../src/.output)
target_link_libraries(${PROJECT_NAME} PRIVATE libbpf.a elf z)