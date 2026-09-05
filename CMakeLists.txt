#CMakeLists.txt
cmake_minimum_required(VERSION 3.24)
project(sha256_research_miner VERSION 0.1.0 LANGUAGES CXX)

execute_process(
  COMMAND git rev-parse --verify HEAD
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  OUTPUT_VARIABLE SRM_GIT_COMMIT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
execute_process(
  COMMAND git status --porcelain
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  OUTPUT_VARIABLE SRM_GIT_STATUS
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
if(SRM_GIT_COMMIT)
  set(SRM_CODE_VERSION "${SRM_GIT_COMMIT}")
  if(SRM_GIT_STATUS)
    string(APPEND SRM_CODE_VERSION "+working-tree")
  endif()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Portable LLVM-MinGW builds can run from any terminal without toolchain DLLs.
# MSVC and other platforms are unaffected.
if(MINGW)
  add_link_options(-static)
endif()

option(SRM_ENABLE_OPENCL "Build the optional OpenCL GPU backend" ON)
option(SRM_BUILD_TESTS "Build deterministic tests" ON)

include(FetchContent)

find_package(nlohmann_json 3.11 CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
  find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
  if(NLOHMANN_JSON_INCLUDE_DIR)
    add_library(nlohmann_json_headers INTERFACE)
    add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json_headers)
    target_include_directories(nlohmann_json_headers INTERFACE "${NLOHMANN_JSON_INCLUDE_DIR}")
  else()
    FetchContent_Declare(nlohmann_json
      URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
      URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d)
    FetchContent_MakeAvailable(nlohmann_json)
  endif()
endif()

find_path(ASIO_INCLUDE_DIR asio.hpp)
if(NOT ASIO_INCLUDE_DIR)
  FetchContent_Declare(asio
    URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-30-2.tar.gz)
  FetchContent_GetProperties(asio)
  if(NOT asio_POPULATED)
    FetchContent_Populate(asio)
  endif()
  set(ASIO_INCLUDE_DIR "${asio_SOURCE_DIR}/asio/include")
endif()

set(SRM_SOURCES
  src/config/config.cpp
  src/platform/windows_utf8.cpp
  src/checkpoint/state_store.cpp
  src/stratum/stratum_client.cpp
  src/stratum/stratum_message.cpp
  src/stratum/stratum_job.cpp
  src/bitcoin/coinbase.cpp
  src/bitcoin/merkle.cpp
  src/bitcoin/block_header.cpp
  src/bitcoin/difficulty.cpp
  src/crypto/sha256.cpp
  src/crypto/sha256d.cpp
  src/crypto/reduced_sha256.cpp
  src/mining/work_allocator.cpp
  src/mining/benchmark.cpp
  src/mining/cpu_miner.cpp
  src/mining/gpu_miner.cpp
  src/mining/mining_controller.cpp
  src/telemetry/telemetry.cpp
  src/logging/result_logger.cpp
  src/logging/best_pow_tracker.cpp)

add_library(srm_core ${SRM_SOURCES})
target_include_directories(srm_core PUBLIC include PRIVATE "${ASIO_INCLUDE_DIR}")
target_compile_definitions(srm_core PRIVATE ASIO_STANDALONE ASIO_NO_DEPRECATED)
target_link_libraries(srm_core PUBLIC nlohmann_json::nlohmann_json)

if(MSVC)
  target_compile_options(srm_core PRIVATE /W4 /permissive- /EHsc /utf-8)
  target_compile_definitions(srm_core PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
else()
  target_compile_options(srm_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
  target_link_libraries(srm_core PRIVATE ws2_32)
endif()

if(SRM_ENABLE_OPENCL)
  find_package(OpenCL QUIET)
  if(OpenCL_FOUND)
    target_compile_definitions(srm_core PUBLIC SRM_HAS_OPENCL=1 CL_TARGET_OPENCL_VERSION=120)
    target_link_libraries(srm_core PRIVATE OpenCL::OpenCL)
  else()
    message(STATUS "OpenCL SDK not found: building CPU backend and GPU diagnostics fallback")
  endif()
endif()

add_executable(sha256_research_miner src/main.cpp)
target_link_libraries(sha256_research_miner PRIVATE srm_core)

add_library(srm_header_space
  src/research/header_space.cpp
  src/research/header_space_opencl.cpp
  src/research/context_campaign.cpp
  src/research/context_phase2.cpp
  src/research/context_trajectory.cpp
  src/research/sha256d_whitebox.cpp
  src/research/sha256d_whitebox_campaign.cpp
  src/research/sha256d_whitebox_transfer.cpp)
find_package(Threads REQUIRED)
target_include_directories(srm_header_space PUBLIC include)
target_link_libraries(srm_header_space PUBLIC srm_core Threads::Threads)
if(SRM_CODE_VERSION)
  target_compile_definitions(srm_header_space PRIVATE SRM_CODE_VERSION="${SRM_CODE_VERSION}")
endif()
if(OpenCL_FOUND)
  target_link_libraries(srm_header_space PRIVATE OpenCL::OpenCL)
endif()
if(MSVC)
  target_compile_options(srm_header_space PRIVATE /W4 /permissive- /EHsc /utf-8)
  target_compile_definitions(srm_header_space PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
else()
  target_compile_options(srm_header_space PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(sha256_header_space src/header_space_main.cpp)
target_link_libraries(sha256_header_space PRIVATE srm_header_space nlohmann_json::nlohmann_json)

add_executable(sha256_context_analyzer src/context_analysis_main.cpp)
target_link_libraries(sha256_context_analyzer PRIVATE srm_header_space nlohmann_json::nlohmann_json)

add_executable(sha256_whitebox src/whitebox_main.cpp)
target_link_libraries(sha256_whitebox PRIVATE srm_header_space nlohmann_json::nlohmann_json)

add_custom_command(TARGET sha256_research_miner POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/kernels"
          "$<TARGET_FILE_DIR:sha256_research_miner>/kernels")

add_custom_command(TARGET sha256_header_space POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/kernels"
          "$<TARGET_FILE_DIR:sha256_header_space>/kernels")

add_custom_command(TARGET sha256_context_analyzer POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/kernels"
          "$<TARGET_FILE_DIR:sha256_context_analyzer>/kernels")

if(SRM_BUILD_TESTS)
  enable_testing()
  add_executable(srm_tests
    tests/test_main.cpp
    tests/test_sha256.cpp
    tests/test_sha256d.cpp
    tests/test_genesis_block.cpp
    tests/test_historical_block.cpp
    tests/test_merkle.cpp
    tests/test_target.cpp
    tests/test_stratum_parser.cpp
    tests/test_checkpoint.cpp
    tests/test_result_logger.cpp
    tests/test_best_pow.cpp
    tests/test_context_campaign.cpp
    tests/test_context_phase2.cpp
    tests/test_context_trajectory.cpp
    tests/test_config.cpp
    tests/test_gpu_selection.cpp
    tests/test_work_allocator.cpp
    tests/test_opencl_sha256d.cpp
    tests/test_header_space.cpp
    tests/test_sha256d_whitebox.cpp)
  target_link_libraries(srm_tests PRIVATE srm_core srm_header_space)
  target_include_directories(srm_tests PRIVATE tests)
  target_compile_definitions(srm_tests PRIVATE SRM_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  if(OpenCL_FOUND)
    target_link_libraries(srm_tests PRIVATE OpenCL::OpenCL)
  endif()
  add_test(NAME deterministic_reference_tests COMMAND srm_tests)

  add_executable(mock_stratum_server tests/mock_stratum_server.cpp)
  target_include_directories(mock_stratum_server PRIVATE include "${ASIO_INCLUDE_DIR}")
  target_compile_definitions(mock_stratum_server PRIVATE ASIO_STANDALONE ASIO_NO_DEPRECATED)
  target_link_libraries(mock_stratum_server PRIVATE srm_core nlohmann_json::nlohmann_json)
  if(WIN32)
    target_compile_definitions(mock_stratum_server PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(mock_stratum_server PRIVATE ws2_32)
    add_test(NAME mock_stratum_end_to_end
      COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
        -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_mock_integration.ps1"
        -Miner "$<TARGET_FILE:sha256_research_miner>"
        -Server "$<TARGET_FILE:mock_stratum_server>"
        -ProjectRoot "${CMAKE_CURRENT_SOURCE_DIR}")
    set_tests_properties(mock_stratum_end_to_end PROPERTIES TIMEOUT 25 RUN_SERIAL TRUE)
  endif()
endif()
