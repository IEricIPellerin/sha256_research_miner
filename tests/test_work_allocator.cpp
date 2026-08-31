#include "mining/work_allocator.h"
#include "test_support.h"

#include <filesystem>

TEST_CASE("allocator persists next nonce and never reacquires COMPLETE") {
  const auto directory = std::filesystem::temp_directory_path() / "srm_allocator_test";
  std::filesystem::create_directories(directory);
  const auto path = directory / "state.json";
  {
    srm::mining::WorkAllocator allocator(srm::checkpoint::StateStore(path), "historical_test");
    allocator.prepare_historical("header", 10, 20, 1, 64);
    const auto unit = allocator.acquire(srm::mining::WorkerKind::Cpu);
    REQUIRE(unit.has_value());
    allocator.update_progress(unit->id, 15, 5);
    allocator.checkpoint();
  }
  {
    srm::mining::WorkAllocator allocator(srm::checkpoint::StateStore(path), "historical_test");
    const auto resumed = allocator.acquire(srm::mining::WorkerKind::Cpu);
    REQUIRE(resumed.has_value());
    REQUIRE_EQ(resumed->nonce_next, 15ULL);
    allocator.complete(resumed->id);
    REQUIRE(!allocator.acquire(srm::mining::WorkerKind::Cpu).has_value());
    REQUIRE(allocator.prepare_historical("header", 10, 20, 1, 64));
    REQUIRE(!allocator.acquire(srm::mining::WorkerKind::Cpu).has_value());
  }
  std::filesystem::remove(path);
  std::filesystem::remove(directory);
}
