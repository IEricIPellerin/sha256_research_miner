//tests\test_result_logger.cpp
#include "bitcoin/block_header.h"
#include "bitcoin/difficulty.h"
#include "checkpoint/state_store.h"
#include "crypto/sha256d.h"
#include "logging/result_logger.h"
#include "stratum/stratum_job.h"
#include "test_support.h"

#include <chrono>
#include <filesystem>

namespace {

srm::mining::Solution make_solution(
    const srm::stratum::StratumJob& job,
    const std::string& extranonce1,
    const std::string& extranonce2,
    const std::uint32_t nonce,
    const bool network_candidate) {
  const auto built = srm::stratum::build_work(job, extranonce1, extranonce2, nonce);
  const auto digest = srm::crypto::sha256d(built.header);
  srm::mining::Solution solution;
  solution.job_id = job.job_id;
  solution.username = "bc1q-audit.worker";
  solution.extranonce1 = extranonce1;
  solution.extranonce2 = extranonce2;
  solution.extranonce2_size = 4;
  solution.clean_jobs = job.clean_jobs;
  solution.coinbase1 = job.coinbase1;
  solution.coinbase2 = job.coinbase2;
  solution.merkle_branches = job.merkle_branches;
  solution.work_fingerprint = "fixture-fingerprint";
  solution.version = job.version;
  solution.prevhash = job.prevhash;
  solution.merkle_root = srm::crypto::bitcoin_hash_hex(built.merkle_root);
  solution.ntime = job.ntime;
  solution.nbits = job.nbits;
  solution.nonce_value = nonce;
  solution.nonce = srm::bitcoin::stratum_nonce_hex(nonce);
  solution.nonce_header_le = srm::bitcoin::nonce_header_le_hex(built.header);
  solution.header_hex = srm::bitcoin::header_hex(built.header);
  solution.hash = srm::crypto::bitcoin_hash_hex(digest);
  solution.share_difficulty = 10000.0;
  solution.share_target = srm::bitcoin::target_hex(
      srm::bitcoin::share_target_from_difficulty(solution.share_difficulty));
  solution.network_target = srm::bitcoin::target_hex(
      srm::bitcoin::target_from_nbits(job.nbits));
  solution.detected_timestamp_utc = "2026-09-02T05:36:50.799Z";
  solution.submitted_timestamp_utc = "2026-09-02T05:36:50.800Z";
  solution.submission_status = "pending";
  solution.network_candidate = network_candidate;
  return solution;
}

}  // namespace

TEST_CASE("share audit alone reconstructs header submit nonce and exact server response") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_share_audit_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  srm::logging::ResultLogger logger(directory, false, true, true);
  const srm::stratum::StratumJob job{
      "audit-job",
      std::string(64, '0'),
      "01000000",
      "ffffffff",
      {std::string(64, '1'), std::string(64, '2')},
      "20000000",
      "1d00ffff",
      "65000000",
      true};

  auto rejected = make_solution(job, "01020304", "05060708", 0xc2608b15U, true);
  const auto block_candidate_path = logger.save_candidate(rejected);
  REQUIRE(std::filesystem::exists(block_candidate_path));
  const auto rejected_path = logger.save_share_audit(rejected);
  REQUIRE(std::filesystem::exists(rejected_path));
  rejected.submission_id = 100;
  rejected.accepted = false;
  rejected.response_timestamp_utc = "2026-09-02T05:36:50.900Z";
  rejected.submission_latency_us = 100000;
  rejected.submission_status = "rejected";
  rejected.server_response = nlohmann::json{
      {"id", 100}, {"error", nlohmann::json::array({23, "Above target", nullptr})},
      {"result", nullptr}};
  logger.update_candidate(rejected);
  logger.update_share_audit(rejected);

  auto accepted = make_solution(job, "01020304", "05060709", 0x5a5d5d8fU, false);
  const auto accepted_path = logger.save_share_audit(accepted);
  REQUIRE(rejected_path != accepted_path);
  accepted.submission_id = 101;
  accepted.accepted = true;
  accepted.response_timestamp_utc = "2026-09-02T07:08:59.248Z";
  accepted.submission_latency_us = 100000;
  accepted.submission_status = "accepted";
  accepted.server_response = nlohmann::json{{"id", 101}, {"error", nullptr}, {"result", true}};
  logger.update_share_audit(accepted);

  const auto audit = srm::checkpoint::StateStore(rejected_path).load_or({});
  REQUIRE_EQ(audit.at("schema_version").get<unsigned>(), 1U);
  REQUIRE_EQ(audit.at("stratum_job").at("coinbase1").get<std::string>(), job.coinbase1);
  REQUIRE_EQ(audit.at("stratum_job").at("coinbase2").get<std::string>(), job.coinbase2);
  REQUIRE_EQ(
      audit.at("stratum_job").at("merkle_branches").get<std::vector<std::string>>(),
      job.merkle_branches);
  REQUIRE_EQ(audit.at("stratum_job").at("extranonce1").get<std::string>(), "01020304");
  REQUIRE_EQ(audit.at("stratum_job").at("extranonce2").get<std::string>(), "05060708");
  REQUIRE_EQ(audit.at("nonce").at("uint32").get<std::uint32_t>(), 0xc2608b15U);
  REQUIRE_EQ(audit.at("nonce").at("stratum_hex").get<std::string>(), "c2608b15");
  REQUIRE_EQ(audit.at("nonce").at("header_little_endian_hex").get<std::string>(), "158b60c2");
  REQUIRE_EQ(audit.at("submission").at("nonce").get<std::string>(), "c2608b15");
  REQUIRE_EQ(audit.at("submission").at("accepted").get<bool>(), false);
  REQUIRE_EQ(audit.at("submission").at("server_response"), *rejected.server_response);
  REQUIRE(audit.dump().find("password") == std::string::npos);
  const auto block_candidate = srm::checkpoint::StateStore(block_candidate_path).load_or({});
  REQUIRE_EQ(block_candidate.at("nonce").get<std::string>(), "c2608b15");
  REQUIRE_EQ(block_candidate.at("nonce_header_le").get<std::string>(), "158b60c2");
  REQUIRE(block_candidate.at("network_candidate").get<bool>());

  const auto& stored_job = audit.at("stratum_job");
  const srm::stratum::StratumJob reconstructed_job{
      stored_job.at("job_id").get<std::string>(),
      stored_job.at("prevhash").get<std::string>(),
      stored_job.at("coinbase1").get<std::string>(),
      stored_job.at("coinbase2").get<std::string>(),
      stored_job.at("merkle_branches").get<std::vector<std::string>>(),
      stored_job.at("version").get<std::string>(),
      stored_job.at("nbits").get<std::string>(),
      stored_job.at("ntime").get<std::string>(),
      stored_job.at("clean_jobs").get<bool>()};
  const auto rebuilt = srm::stratum::build_work(
      reconstructed_job,
      stored_job.at("extranonce1").get<std::string>(),
      stored_job.at("extranonce2").get<std::string>(),
      audit.at("nonce").at("uint32").get<std::uint32_t>());
  REQUIRE_EQ(srm::bitcoin::header_hex(rebuilt.header), audit.at("work").at("header_hex").get<std::string>());
  REQUIRE_EQ(
      srm::crypto::bitcoin_hash_hex(srm::crypto::sha256d(rebuilt.header)),
      audit.at("work").at("hash_bitcoin_display").get<std::string>());

  const auto accepted_audit = srm::checkpoint::StateStore(accepted_path).load_or({});
  REQUIRE_EQ(accepted_audit.at("submission").at("submission_id").get<std::int64_t>(), 101);
  REQUIRE(accepted_audit.at("submission").at("accepted").get<bool>());
  REQUIRE_EQ(accepted_audit.at("nonce").at("stratum_hex").get<std::string>(), "5a5d5d8f");
  std::filesystem::remove_all(directory);
}

TEST_CASE("network candidate update does not depend on a share audit") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_block_candidate_without_audit_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  srm::logging::ResultLogger logger(directory, false, true, false);
  const srm::stratum::StratumJob job{
      "block-only-job",
      std::string(64, '0'),
      "01000000",
      "ffffffff",
      {},
      "20000000",
      "1d00ffff",
      "65000000",
      true};

  auto solution = make_solution(job, "01020304", "05060708", 0xc2608b15U, true);
  const auto block_candidate_path = logger.save_candidate(solution);
  REQUIRE(std::filesystem::exists(block_candidate_path));
  REQUIRE(logger.save_share_audit(solution).empty());
  REQUIRE(solution.share_audit_file.empty());

  solution.submission_id = 102;
  solution.accepted = true;
  solution.response_timestamp_utc = "2026-09-02T08:09:00.000Z";
  solution.submission_latency_us = 100000;
  solution.submission_status = "accepted";
  solution.server_response = nlohmann::json{{"id", 102}, {"error", nullptr}, {"result", true}};
  logger.update_candidate(solution);
  logger.update_share_audit(solution);

  const auto block_candidate = srm::checkpoint::StateStore(block_candidate_path).load_or({});
  REQUIRE_EQ(block_candidate.at("submission_status").get<std::string>(), "accepted");
  REQUIRE_EQ(block_candidate.at("submission_id").get<std::int64_t>(), 102);
  REQUIRE(block_candidate.at("accepted").get<bool>());
  REQUIRE_EQ(block_candidate.at("nonce").get<std::string>(), "c2608b15");
  std::filesystem::remove_all(directory);
}
