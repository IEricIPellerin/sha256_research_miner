//tests\test_best_pow.cpp
#include "bitcoin/difficulty.h"
#include "logging/best_pow_tracker.h"
#include "logging/result_logger.h"
#include "test_support.h"

#include <chrono>
#include <filesystem>
#include <fstream>

namespace {

std::filesystem::path unique_directory(const std::string& name) {
  return std::filesystem::temp_directory_path() /
      (name + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
}

srm::mining::Solution pow_solution(const std::string& hash,
                                   const bool share,
                                   const bool network) {
  srm::mining::Solution value;
  value.hash = hash;
  value.network_target = std::string(63, '0') + "1";
  value.share_target = std::string(62, 'f') + "ff";
  value.detected_timestamp_utc = srm::logging::ResultLogger::utc_now();
  value.worker = "GPU";
  value.job_id = "job";
  value.work_fingerprint = std::string(64, 'a');
  value.prevhash = std::string(64, 'b');
  value.nbits = "03000001";
  value.nonce = "00000001";
  value.nonce_header_le = "01000000";
  value.header_hex = std::string(160, '0');
  value.share_candidate = share;
  value.network_candidate = network;
  return value;
}

}  // namespace

TEST_CASE("best PoW records initial, improved, non-share, network, and persistence") {
  const auto directory = unique_directory("srm_best_pow_");
  {
    srm::logging::BestPowTracker tracker(directory);
    auto initial = pow_solution(std::string(63, '0') + "2", false, false);
    REQUIRE(tracker.observe(initial, 100U, 1000U).is_record);
    REQUIRE(initial.personal_record);
    REQUIRE(!initial.share_candidate);
    REQUIRE(initial.hash_difficulty > 1.0);

    auto worse = pow_solution(std::string(63, '0') + "3", true, false);
    REQUIRE(!tracker.observe(worse, 200U, 2000U).is_record);

    auto network = pow_solution(std::string(63, '0') + "1", true, true);
    REQUIRE(tracker.observe(network, 300U, 3000U).is_record);
    REQUIRE(network.network_candidate);
  }
  {
    srm::logging::BestPowTracker reloaded(directory);
    REQUIRE_EQ(reloaded.best_hash(), std::string(63, '0') + "1");
    auto worse = pow_solution(std::string(63, '0') + "2", false, false);
    REQUIRE(!reloaded.observe(worse, 400U, 4000U).is_record);
  }
  std::ifstream records(directory / "statistics" / "best_pow_records.jsonl");
  std::string line;
  unsigned lines = 0;
  while (std::getline(records, line)) if (!line.empty()) ++lines;
  REQUIRE_EQ(lines, 2U);
  records.close();
  std::filesystem::remove_all(directory);
}

TEST_CASE("difficulty display is exact at difficulty one") {
  const auto target = srm::bitcoin::target_from_nbits("1d00ffff");
  REQUIRE_EQ(srm::bitcoin::difficulty_from_target(target), 1.0);
  srm::crypto::Digest digest{};
  for (std::size_t i = 0; i < digest.size(); ++i) digest[i] = target.big_endian[31U - i];
  REQUIRE_EQ(srm::bitcoin::difficulty_from_hash(digest), 1.0);
}

TEST_CASE("share retention removes only expired ordinary audit files") {
  const auto directory = unique_directory("srm_retention_");
  std::filesystem::create_directories(directory / "share_audit_recent");
  const auto recent = directory / "share_audit_recent" / "shares_recent.jsonl";
  const auto old = directory / "share_audit_recent" / "shares_old.jsonl";
  const auto legacy = directory / "share_audit_legacy.json";
  const auto block = directory / "block_candidate_protected.json";
  const auto archive = directory / "stratum_jobs.jsonl";
  for (const auto& path : {recent, old, legacy, block, archive}) {
    std::ofstream output(path);
    output << "{}\n";
  }
  const auto expired = std::filesystem::file_time_type::clock::now() - std::chrono::hours(48);
  std::filesystem::last_write_time(old, expired);
  std::filesystem::last_write_time(legacy, expired);
  std::filesystem::last_write_time(block, expired);
  std::filesystem::last_write_time(archive, expired);
  srm::logging::ResultLogger logger(directory, false, true, true, 24U, 10000.0);
  REQUIRE(!std::filesystem::exists(old));
  REQUIRE(!std::filesystem::exists(legacy));
  REQUIRE(std::filesystem::exists(recent));
  REQUIRE(std::filesystem::exists(block));
  REQUIRE(std::filesystem::exists(archive));
  std::filesystem::remove_all(directory);
}
