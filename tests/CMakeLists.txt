# Stand-alone unit tests for the OBS-independent core (no libobs needed).
#   cmake -S tests -B build-tests && cmake --build build-tests && ctest --test-dir build-tests
cmake_minimum_required(VERSION 3.16)
project(obs-ytsucks-tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src/core")
add_library(pii-core STATIC
  "${CORE_DIR}/pii-matcher.cpp"
  "${CORE_DIR}/motion-tracker.cpp"
  "${CORE_DIR}/bands.cpp"
  "${CORE_DIR}/rect.cpp"
  "${CORE_DIR}/image.cpp"
)
target_include_directories(pii-core PUBLIC "${CORE_DIR}")
if(MSVC)
  target_compile_options(pii-core PRIVATE /W4 /WX)
else()
  target_compile_options(pii-core PRIVATE -Wall -Wextra -Werror)
endif()

add_executable(pii-core-tests test-main.cpp)
target_link_libraries(pii-core-tests PRIVATE pii-core)

enable_testing()
add_test(NAME pii-core-tests COMMAND pii-core-tests)
