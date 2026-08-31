#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace srm::mining {

struct Solution {
  std::string job_id;
  std::string username;
  std::string extranonce1;
  std::string extranonce2;
  std::string version;
  std::string prevhash;
  std::string merkle_root;
  std::string ntime;
  std::string nbits;
  std::string nonce;
  std::string header_hex;
  std::string hash;
  std::string network_target;
  std::string share_target;
  std::string detected_timestamp_utc;
  std::string submitted_timestamp_utc;
  std::uint64_t submission_latency_us{0};
  std::optional<std::string> server_response;
  bool network_candidate{false};
  bool offline{false};
  std::filesystem::path result_file;
};

}  // namespace srm::mining

