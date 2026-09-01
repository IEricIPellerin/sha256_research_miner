//src\mining\benchmark.cpp
#include "mining/benchmark.h"

#include "bitcoin/block_header.h"
#include "crypto/sha256d.h"

#include <algorithm>
#include <barrier>
#include <chrono>
#include <functional>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <thread>

namespace srm::mining {
namespace {

std::atomic<std::uint64_t> benchmark_sink{0};

bool wait_for(const std::chrono::milliseconds duration, std::atomic_bool& interrupted) {
  const auto deadline = std::chrono::steady_clock::now() + duration;
  while (!interrupted.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    std::this_thread::sleep_for(std::min(remaining, std::chrono::milliseconds(10)));
  }
  return !interrupted.load(std::memory_order_acquire);
}

CpuBenchmarkSample measure_cpu(const bitcoin::Header& base,
                               const unsigned thread_count,
                               const unsigned warmup_ms,
                               const unsigned measurement_ms,
                               std::atomic_bool& interrupted) {
  constexpr std::uint32_t check_batch = 256;
  std::barrier ready(static_cast<std::ptrdiff_t>(thread_count + 1));
  std::barrier measurement_start(static_cast<std::ptrdiff_t>(thread_count + 1));
  std::atomic_bool stop_measurement{false};
  std::vector<std::uint64_t> counts(thread_count, 0);
  std::vector<std::uint64_t> checksums(thread_count, 0);
  std::vector<std::jthread> workers;
  workers.reserve(thread_count);

  for (unsigned index = 0; index < thread_count; ++index) {
    workers.emplace_back([&, index](const std::stop_token token) {
      auto header = base;
      auto nonce = static_cast<std::uint32_t>(index * 0x01000000U);
      std::uint64_t checksum = 0;
      ready.arrive_and_wait();
      while (!token.stop_requested() && !interrupted.load(std::memory_order_relaxed) &&
             !stop_measurement.load(std::memory_order_relaxed)) {
        for (std::uint32_t i = 0; i < check_batch; ++i) {
          bitcoin::set_nonce(header, nonce++);
          const auto digest = crypto::sha256d(header);
          checksum ^= static_cast<std::uint64_t>(digest[(nonce + index) & 31U]) << ((nonce & 7U) * 8U);
        }
      }
      measurement_start.arrive_and_wait();
      std::uint64_t measured = 0;
      while (stop_measurement.load(std::memory_order_acquire) &&
             !interrupted.load(std::memory_order_relaxed)) std::this_thread::yield();
      while (!token.stop_requested() && !interrupted.load(std::memory_order_relaxed) &&
             !stop_measurement.load(std::memory_order_relaxed)) {
        for (std::uint32_t i = 0; i < check_batch; ++i) {
          bitcoin::set_nonce(header, nonce++);
          const auto digest = crypto::sha256d(header);
          checksum ^= static_cast<std::uint64_t>(digest[(nonce + index) & 31U]) << ((nonce & 7U) * 8U);
        }
        measured += check_batch;
      }
      counts[index] = measured;
      checksums[index] = checksum;
    });
  }

  ready.arrive_and_wait();
  wait_for(std::chrono::milliseconds(warmup_ms), interrupted);
  stop_measurement.store(true, std::memory_order_release);
  measurement_start.arrive_and_wait();
  stop_measurement.store(false, std::memory_order_release);
  const auto before = std::chrono::steady_clock::now();
  wait_for(std::chrono::milliseconds(measurement_ms), interrupted);
  stop_measurement.store(true, std::memory_order_release);
  const auto after = std::chrono::steady_clock::now();
  workers.clear();
  const auto seconds = std::chrono::duration<double>(after - before).count();
  const auto hashes = std::accumulate(counts.begin(), counts.end(), std::uint64_t{0});
  const auto checksum = std::accumulate(checksums.begin(), checksums.end(), std::uint64_t{0}, std::bit_xor<>{});
  benchmark_sink.fetch_xor(checksum, std::memory_order_relaxed);
  return {thread_count, hashes, seconds, seconds > 0.0 ? static_cast<double>(hashes) / seconds : 0.0};
}

}  // namespace

CpuBenchmarkResult benchmark_cpu_sha256d(const bitcoin::Header& header,
                                         const std::vector<unsigned>& thread_counts,
                                         const unsigned warmup_ms,
                                         const unsigned measurement_ms,
                                         std::atomic_bool& stop_requested) {
  CpuBenchmarkResult result;
  for (const auto threads : thread_counts) {
    if (stop_requested.load(std::memory_order_acquire)) break;
    auto sample = measure_cpu(header, threads, warmup_ms, measurement_ms, stop_requested);
    result.samples.push_back(sample);
    if (sample.hash_rate > result.best.hash_rate) result.best = sample;
  }
  return result;
}

std::string format_hash_rate(const double hashes_per_second) {
  std::ostringstream output;
  output << std::fixed << std::setprecision(2);
  if (hashes_per_second >= 1e9) output << hashes_per_second / 1e9 << " GH/s";
  else if (hashes_per_second >= 1e6) output << hashes_per_second / 1e6 << " MH/s";
  else if (hashes_per_second >= 1e3) output << hashes_per_second / 1e3 << " kH/s";
  else output << hashes_per_second << " H/s";
  return output.str();
}

}  // namespace srm::mining
