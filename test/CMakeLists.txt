project(pscannerguard_test LANGUAGES CXX)
set(SOURCE main.cpp)
list(APPEND SOURCE bpf_test.cpp)

add_executable(${PROJECT_NAME} ${SOURCE})

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE GTest::gtest_main)

include_directories(../src/.output)
target_link_directories(${PROJECT_NAME} PRIVATE ../src/.output)
target_link_libraries(${PROJECT_NAME} PRIVATE libbpf.a elf z)


enable_testing()
include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})