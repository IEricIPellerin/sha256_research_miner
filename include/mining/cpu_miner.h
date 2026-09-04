//include\mining\cpu_miner.h
#pragma once

#include "bitcoin/difficulty.h"
#include "mining/work_allocator.h"
#include "stratum/stratum_job.h"
#include "telemetry/telemetry.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace srm::mining {

struct LiveMiningJob {
  stratum::StratumJob job;
  std::string extranonce1;
  bitcoin::Target256 share_target;
  bitcoin::Target256 network_target;
  double share_difficulty{0.0};
  unsigned extranonce2_size{0};
  std::string work_fingerprint;
  std::uint64_t generation{0};
};

struct Candidate {
  LiveMiningJob context;
  std::string extranonce2;
  bitcoin::Header header;
  crypto::Digest merkle_root;
  crypto::Digest digest;
  std::uint32_t nonce{0};
  bool share_candidate{true};
  bool network_candidate{false};
  std::string worker{"CPU"};
};

class CpuMiner {
 public:
  using CandidateHandler = std::function<void(Candidate)>;

  CpuMiner(WorkAllocator& allocator,
           telemetry::Telemetry& telemetry,
           std::atomic<std::uint64_t>& active_generation,
           CandidateHandler handler);
  ~CpuMiner();

  void start(const LiveMiningJob& job, unsigned threads);
  void stop();

 private:
  void worker(std::stop_token token, LiveMiningJob job);

  WorkAllocator& allocator_;
  telemetry::Telemetry& telemetry_;
  std::atomic<std::uint64_t>& active_generation_;
  CandidateHandler handler_;
  std::vector<std::jthread> workers_;
};

}  // namespace srm::mining
