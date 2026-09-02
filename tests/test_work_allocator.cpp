//tests\test_work_allocator.cpp
#include "mining/work_allocator.h"
#include "test_support.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>
#include <vector>

namespace {

std::filesystem::path temporary_test_directory(const std::string& prefix) {
  return std::filesystem::temp_directory_path() /
      (prefix + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
}

}  // namespace

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

TEST_CASE("compatible live fingerprint resumes exact nonce progress") {
  const auto directory = temporary_test_directory("srm_live_resume_");
  std::filesystem::create_directories(directory);
  const auto path = directory / "state.json";
  {
    srm::mining::WorkAllocator allocator(srm::checkpoint::StateStore(path), "live");
    REQUIRE(!allocator.prepare_live_job(
        "job", std::string(64, '1'), "01020304", 4, "fingerprint", 1, false, 1));
    const auto unit = allocator.acquire(srm::mining::WorkerKind::Cpu);
    REQUIRE(unit.has_value());
    allocator.update_progress(unit->id, unit->nonce_start + 1234, 1234);
    allocator.checkpoint({{"counters", {{"hashes", 987654321ULL}}}});
  }
  {
    srm::mining::WorkAllocator allocator(srm::checkpoint::StateStore(path), "live");
    REQUIRE(allocator.prepare_live_job(
        "job", std::string(64, '1'), "01020304", 4, "fingerprint", 1, false, 2));
    const auto unit = allocator.acquire(srm::mining::WorkerKind::Cpu);
    REQUIRE(unit.has_value());
    REQUIRE_EQ(unit->nonce_next, unit->nonce_start + 1234);
    const auto snapshot = allocator.snapshot();
    REQUIRE_EQ(snapshot.at("hashes_tested").get<std::uint64_t>(), 1234ULL);
    REQUIRE_EQ(snapshot.at("counters").at("hashes").get<std::uint64_t>(), 987654321ULL);
  }
  std::filesystem::remove_all(directory);
}

TEST_CASE("incompatible live jobs compact restart state instead of accumulating history") {
  const auto directory = temporary_test_directory("srm_live_compaction_");
  std::filesystem::create_directories(directory);
  const auto path = directory / "state.json";
  constexpr unsigned job_changes = 2000;
  constexpr unsigned expected_units = 4;
  srm::mining::WorkAllocator allocator(srm::checkpoint::StateStore(path), "live");
  for (unsigned job = 0; job < job_changes; ++job) {
    REQUIRE(!allocator.prepare_live_job(
        "job-" + std::to_string(job), std::string(64, static_cast<char>('a' + job % 6)),
        "01020304", 4, "fingerprint-" + std::to_string(job), 3, true, job + 1));
    REQUIRE_EQ(allocator.units().size(), static_cast<std::size_t>(expected_units));
    if ((job + 1) % 50 == 0) {
      allocator.checkpoint({{"counters", {{"hashes", 123456789ULL}, {"shares", 17ULL}}}});
    }
  }
  allocator.checkpoint({{"counters", {{"hashes", 123456789ULL}, {"shares", 17ULL}}}});
  const auto state = srm::checkpoint::StateStore(path).load_or({});
  REQUIRE_EQ(state.at("work_units").size(), static_cast<std::size_t>(expected_units));
  REQUIRE_EQ(state.at("hashes_tested").get<std::uint64_t>(), 0ULL);
  REQUIRE_EQ(state.at("completed_ranges").size(), 0U);
  REQUIRE_EQ(state.at("counters").at("hashes").get<std::uint64_t>(), 123456789ULL);
  REQUIRE(std::filesystem::file_size(path) < 16384ULL);
  std::cout << "[INFO] live compaction: " << job_changes << " jobs -> "
            << state.at("work_units").size() << " work_units, "
            << std::filesystem::file_size(path) << " bytes\n";
  std::filesystem::remove_all(directory);
}

TEST_CASE("completed live extranonce groups stay bounded within one fingerprint") {
  const auto directory = temporary_test_directory("srm_live_extranonce_compaction_");
  std::filesystem::create_directories(directory);
  const auto path = directory / "state.json";
  srm::mining::WorkAllocator allocator(srm::checkpoint::StateStore(path), "live");
  allocator.prepare_live_job(
      "job", std::string(64, '3'), "01020304", 4, "fingerprint", 1, false, 1);
  for (unsigned group = 0; group < 1000; ++group) {
    const auto unit = allocator.acquire(srm::mining::WorkerKind::Cpu);
    REQUIRE(unit.has_value());
    allocator.complete(unit->id);
    REQUIRE_EQ(allocator.units().size(), 1U);
    if ((group + 1) % 100 == 0) allocator.checkpoint();
  }
  allocator.checkpoint();
  const auto state = srm::checkpoint::StateStore(path).load_or({});
  REQUIRE_EQ(state.at("work_units").size(), 1U);
  REQUIRE_EQ(state.at("next_extranonce2_counter").get<std::uint64_t>(), 1001ULL);
  REQUIRE_EQ(state.at("completed_ranges").size(), 0U);
  std::filesystem::remove_all(directory);
}

TEST_CASE("concurrent allocator checkpoints serialize one atomic save at a time") {
  const auto directory = temporary_test_directory("srm_allocator_concurrent_");
  std::filesystem::create_directories(directory);
  const auto path = directory / "state.json";
  srm::mining::WorkAllocator allocator(srm::checkpoint::StateStore(path), "live");
  allocator.prepare_live_job(
      "job", std::string(64, '2'), "01020304", 4, "fingerprint", 2, true, 1);

  std::atomic<unsigned> failures{0};
  std::vector<std::jthread> writers;
  for (unsigned writer = 0; writer < 8; ++writer) {
    writers.emplace_back([&, writer] {
      for (unsigned iteration = 0; iteration < 20; ++iteration) {
        try {
          allocator.checkpoint({{"writer", writer}, {"iteration", iteration}});
        } catch (...) {
          failures.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }
  writers.clear();
  REQUIRE_EQ(failures.load(), 0U);
  const auto state = srm::checkpoint::StateStore(path).load_or({});
  REQUIRE_EQ(state.at("work_units").size(), 3U);
  REQUIRE(!std::filesystem::exists(path.string() + ".tmp"));
  std::filesystem::remove_all(directory);
}
