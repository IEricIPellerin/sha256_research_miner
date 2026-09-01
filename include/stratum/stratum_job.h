//include\stratum\stratum_job.h
#pragma once

#include "bitcoin/block_header.h"
#include "crypto/sha256.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace srm::stratum {

struct StratumJob {
  std::string job_id;
  std::string prevhash;
  std::string coinbase1;
  std::string coinbase2;
  std::vector<std::string> merkle_branches;
  std::string version;
  std::string nbits;
  std::string ntime;
  bool clean_jobs{false};
};

struct BuiltWork {
  bitcoin::Header header;
  crypto::Digest merkle_root;
};

StratumJob parse_notify(const nlohmann::json& params);
BuiltWork build_work(const StratumJob& job,
                     const std::string& extranonce1,
                     const std::string& extranonce2,
                     std::uint32_t nonce = 0);

}  // namespace srm::stratum
