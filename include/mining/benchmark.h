//include\mining\benchmark.h
#pragma once

#include "bitcoin/block_header.h"

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace srm::mining {

struct CpuBenchmarkSample {
  unsigned threads{0};
  std::uint64_t hashes{0};
  double seconds{0.0};
  double hash_rate{0.0};
};

struct CpuBenchmarkResult {
  std::vector<CpuBenchmarkSample> samples;
  CpuBenchmarkSample best;
};

CpuBenchmarkResult benchmark_cpu_sha256d(const bitcoin::Header& header,
                                         const std::vector<unsigned>& thread_counts,
                                         unsigned warmup_ms,
                                         unsigned measurement_ms,
                                         std::atomic_bool& stop_requested);

std::string format_hash_rate(double hashes_per_second);

}  // namespace srm::mining
