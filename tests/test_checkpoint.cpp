//tests\test_checkpoint.cpp
#include "checkpoint/state_store.h"
#include "test_support.h"

#include <filesystem>

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
