//tests\test_checkpoint.cpp
#include "checkpoint/state_store.h"
#include "test_support.h"

#include <chrono>
#include <filesystem>
#include <thread>

#ifdef _WIN32
#include <Windows.h>
#endif

TEST_CASE("checkpoint atomic replacement leaves valid JSON and no tmp") {
  const auto directory = std::filesystem::temp_directory_path() / "srm_checkpoint_test";
  std::filesystem::create_directories(directory);
  const auto path = directory / "state.json";
  srm::checkpoint::StateStore store(path);
  store.save({{"value", 1}});
  store.save({{"value", 2}, {"complete", true}});
  const auto loaded = store.load_or({});
  REQUIRE_EQ(loaded.at("value").get<int>(), 2);
  REQUIRE(loaded.at("complete").get<bool>());
  REQUIRE(!std::filesystem::exists(path.string() + ".tmp"));
  std::filesystem::remove(path);
  std::filesystem::remove(directory);
}

#ifdef _WIN32
TEST_CASE("checkpoint retries a transient Windows lock on its temporary file") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_checkpoint_retry_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  const auto path = directory / "state.json";
  auto temporary = path;
  temporary += ".tmp";
  const auto locked = CreateFileW(
      temporary.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL, nullptr);
  REQUIRE(locked != INVALID_HANDLE_VALUE);

  std::jthread unlocker([locked] {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CloseHandle(locked);
  });
  srm::checkpoint::StateStore(path).save({{"value", 7}});
  unlocker.join();
  REQUIRE_EQ(srm::checkpoint::StateStore(path).load_or({}).at("value").get<int>(), 7);
  std::filesystem::remove_all(directory);
}
#endif
