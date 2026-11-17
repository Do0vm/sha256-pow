cmake_minimum_required(VERSION 3.16)
project(sha256_pow LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(POW_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
find_package(Threads REQUIRED)

add_library(pow src/sha256.cpp src/bitcoin.cpp)
target_include_directories(pow PUBLIC include)
target_link_libraries(pow PUBLIC Threads::Threads)
if(MSVC)
  target_compile_options(pow PUBLIC /W4 /permissive-)
else()
  target_compile_options(pow PUBLIC -Wall -Wextra -Wpedantic)
  if(POW_SANITIZE)
    target_compile_options(pow PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(pow PUBLIC -fsanitize=address,undefined)
  endif()
endif()

add_executable(pow_tests tests/test_sha256.cpp)
target_link_libraries(pow_tests PRIVATE pow)

add_executable(pow_mine examples/mine.cpp)
target_link_libraries(pow_mine PRIVATE pow)

enable_testing()
add_test(NAME sha256_bitcoin COMMAND pow_tests)
