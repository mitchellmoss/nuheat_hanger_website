cmake_minimum_required(VERSION 3.16)

project(nuheat_checkout_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(nuheat_checkout_server
  main.cpp
)

target_include_directories(nuheat_checkout_server
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(CURL REQUIRED)

target_link_libraries(nuheat_checkout_server
  PRIVATE
    CURL::libcurl
)

if (MSVC)
  target_compile_options(nuheat_checkout_server PRIVATE /W4 /permissive-)
else()
  target_compile_options(nuheat_checkout_server PRIVATE -Wall -Wextra -Wpedantic)
endif()
