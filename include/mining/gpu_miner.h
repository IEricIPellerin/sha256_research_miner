#pragma once

#include "mining/cpu_miner.h"

#include <filesystem>
#include <string>

namespace srm::mining {

struct GpuInfo {
  bool available{false};
  std::string platform;
  std::string name;
  std::string vendor;
  std::string driver;
  std::uint32_t compute_units{0};
  std::uint64_t global_memory{0};
  std::size_t max_workgroup_size{0};
};

class GpuMiner {
 public:
  GpuMiner(WorkAllocator& allocator,
           telemetry::Telemetry& telemetry,
           std::atomic<std::uint64_t>& active_generation,
           CpuMiner::CandidateHandler handler,
           std::filesystem::path kernel_path,
           std::filesystem::path profile_path);
  ~GpuMiner();

  GpuInfo detect();
  void start(const LiveMiningJob& job, bool auto_tune);
  void stop();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace srm::mining

