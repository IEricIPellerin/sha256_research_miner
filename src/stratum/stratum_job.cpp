//src\stratum\stratum_job.cpp
#include "stratum/stratum_job.h"

#include "bitcoin/coinbase.h"
#include "bitcoin/merkle.h"
#include "crypto/sha256.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace srm::stratum {
namespace {

void require_hex(const std::string& value, const char* name, const std::size_t exact_bytes = 0) {
  if (value.size() % 2 != 0 || !std::all_of(value.begin(), value.end(), [](const unsigned char c) { return std::isxdigit(c) != 0; })) {
    throw std::invalid_argument(std::string(name) + " must be even-length hexadecimal data");
  }
  if (exact_bytes != 0 && value.size() != exact_bytes * 2) {
    throw std::invalid_argument(std::string(name) + " has an invalid byte length");
  }
}

}  // namespace

StratumJob parse_notify(const nlohmann::json& params) {
  if (!params.is_array() || params.size() != 9) throw std::invalid_argument("mining.notify must contain exactly nine parameters");
  StratumJob job;
  job.job_id = params.at(0).get<std::string>();
  job.prevhash = params.at(1).get<std::string>();
  job.coinbase1 = params.at(2).get<std::string>();
  job.coinbase2 = params.at(3).get<std::string>();
  job.merkle_branches = params.at(4).get<std::vector<std::string>>();
  job.version = params.at(5).get<std::string>();
  job.nbits = params.at(6).get<std::string>();
  job.ntime = params.at(7).get<std::string>();
  job.clean_jobs = params.at(8).get<bool>();
  if (job.job_id.empty()) throw std::invalid_argument("mining.notify job_id is empty");
  require_hex(job.prevhash, "prevhash", 32);
  require_hex(job.coinbase1, "coinbase1");
  require_hex(job.coinbase2, "coinbase2");
  require_hex(job.version, "version", 4);
  require_hex(job.nbits, "nbits", 4);
  require_hex(job.ntime, "ntime", 4);
  for (const auto& branch : job.merkle_branches) require_hex(branch, "merkle branch", 32);
  return job;
}

BuiltWork build_work(const StratumJob& job,
                     const std::string& extranonce1,
                     const std::string& extranonce2,
                     const std::uint32_t nonce) {
  const auto coinbase = bitcoin::coinbase_hash(job.coinbase1, extranonce1, extranonce2, job.coinbase2);
  const auto merkle = bitcoin::build_merkle_root(coinbase, job.merkle_branches);
  return {bitcoin::build_stratum_header(job.version, job.prevhash, merkle, job.ntime, job.nbits, nonce), merkle};
}

}  // namespace srm::stratum

