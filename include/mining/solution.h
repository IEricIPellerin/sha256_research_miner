//include\mining\solution.h
#pragma once

#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace srm::mining {

struct Solution {
  std::string job_id;
  std::string username;
  std::string extranonce1;
  std::string extranonce2;
  unsigned extranonce2_size{0};
  bool clean_jobs{false};
  std::string coinbase1;
  std::string coinbase2;
  std::vector<std::string> merkle_branches;
  std::string work_fingerprint;
  std::string version;
  std::string prevhash;
  std::string merkle_root;
  std::string ntime;
  std::string nbits;
  std::string nonce;
  std::uint32_t nonce_value{0};
  std::string nonce_header_le;
  std::string header_hex;
  std::string hash;
  std::string network_target;
  std::string share_target;
  double share_difficulty{0.0};
  double hash_difficulty{0.0};
  double network_difficulty{0.0};
  double network_difficulty_ratio{0.0};
  std::string worker;
  std::uint64_t total_hashes_at_detection{0};
  std::uint64_t uptime_ms_at_detection{0};
  std::string detected_timestamp_utc;
  std::string submitted_timestamp_utc;
  std::string response_timestamp_utc;
  std::string submission_status{"detected"};
  std::optional<std::int64_t> submission_id;
  std::optional<bool> accepted;
  std::uint64_t submission_latency_us{0};
  std::optional<nlohmann::json> server_response;
  std::optional<std::string> local_submission_error;
  bool network_candidate{false};
  bool share_candidate{true};
  bool personal_record{false};
  bool offline{false};
  std::filesystem::path result_file;
  std::filesystem::path share_audit_file;
};

}  // namespace srm::mining
