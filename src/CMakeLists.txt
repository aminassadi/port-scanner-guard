

add_custom_target(
    bpf_skeleton
    COMMAND ${CMAKE_COMMAND} -E echo "Generate bpf skeleton"
    COMMAND make
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/kern
)

set(SOURCE main.cpp)

add_executable(${PROJECT_NAME} ${SOURCE})
add_dependencies(${PROJECT_NAME}  bpf_skeleton)

include_directories(.output ../libbpf/include)
target_link_directories(${PROJECT_NAME} PRIVATE .output)
target_link_libraries(${PROJECT_NAME} PRIVATE libbpf.a elf z)
