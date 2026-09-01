//include\mining\gpu_miner.h
#pragma once

#include "bitcoin/block_header.h"
#include "mining/cpu_miner.h"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace srm::mining {

struct GpuInfo {
  bool available{false};
  std::size_t index{0};
  std::size_t platform_index{0};
  std::size_t device_index{0};
  std::string platform;
  std::string name;
  std::string board_name;
  std::string vendor;
  std::string driver;
  std::uint32_t compute_units{0};
  std::uint64_t global_memory{0};
  std::size_t max_workgroup_size{0};
};

struct GpuBenchmarkSample {
  std::size_t local_work_size{0};
  std::size_t global_work_size{0};
  std::uint64_t batch_size{0};
  std::uint64_t hashes{0};
  double seconds{0.0};
  double hash_rate{0.0};
};

struct GpuBenchmarkResult {
  GpuInfo device;
  bool validated{false};
  std::vector<GpuBenchmarkSample> samples;
  GpuBenchmarkSample best;
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

  std::vector<GpuInfo> enumerate() const;
  static std::size_t select_device_index(const std::vector<GpuInfo>& devices,
                                         const std::string& platform_selector,
                                         const std::string& device_selector);
  GpuInfo detect(const std::string& platform_selector = "auto",
                 const std::string& device_selector = "auto");
  GpuBenchmarkResult benchmark(const bitcoin::Header& header,
                               const std::string& platform_selector,
                               const std::string& device_selector,
                               bool auto_tune,
                               unsigned warmup_ms,
                               unsigned measurement_ms);
  void start(const LiveMiningJob& job, bool auto_tune);
  void stop();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace srm::mining
