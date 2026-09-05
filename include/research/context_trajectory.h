#pragma once

#include "crypto/reduced_sha256.h"
#include "research/context_campaign.h"
#include "research/header_space.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace srm::research::context_trajectory {

inline constexpr unsigned kProductionThresholdBits = 20U;
inline constexpr std::size_t kInitialSparseCapacity = 8192U;
inline constexpr std::size_t kInputOrderPermutations = 200U;
inline constexpr std::size_t kBootstrapReplicates = 400U;

struct Request {
  std::uint64_t bje_count{0};
  std::uint64_t seed{0x5452414a454354ULL};
  std::size_t gpu_workers{1U};
};

struct GpuBjeWorkItem {
  std::string block_id;
  bitcoin::Header header{};
};

struct GpuBjeScanResult {
  std::string block_id;
  header_space::SparseHitResult scan;
};

struct GpuWorkloadResult {
  std::vector<GpuBjeScanResult> results;
  header_space::GpuDeviceInfo device;
  std::size_t gpu_workers{0U};
  double setup_seconds{0.0};
  double scan_wall_seconds{0.0};
};

using GpuCompletionHandler =
    std::function<void(std::size_t, GpuBjeScanResult&)>;

struct ThroughputBenchmarkOptions {
  std::size_t bje_count{0U};
  std::size_t gpu_workers{1U};
  std::uint64_t nonce_count{header_space::kNonceSpaceSize};
};

struct CpuNoncePartition {
  std::uint64_t nonce_start{0U};
  std::uint64_t nonce_count{0U};
};

struct PlannedBje {
  context_campaign::ArchivedContext context;
  std::string extranonce2;
  std::string block_id;
  std::string partition;
  std::string header_prefix_hex;
  std::string merkle_root;
};

struct Plan {
  Request request;
  context_campaign::BenchmarkResult benchmark;
  std::vector<PlannedBje> blocks;
  std::vector<std::string> warnings;
  std::uint64_t total_hashes{0};
  double estimated_seconds{0.0};
  std::uint64_t estimated_storage_bytes{0};
};

struct YHit {
  std::uint32_t nonce{0};
  header_space::PowValue y{};
};

struct SelectedBjen {
  std::string cohort;
  std::optional<std::size_t> y_rank;
  YHit hit;
};

struct RoundFeatures {
  unsigned global_round{0};
  unsigned sha_pass{0};
  unsigned compression_index{0};
  unsigned local_round{0};
  std::vector<double> values;
};

// Compact sufficient statistics for one (prevhash, comparison, round,
// feature) cell. Keeping only sums and a count avoids retaining one string and
// one heap-backed object per contributing BJE.
struct PrevhashEffectAccumulator {
  double sum_rank_biserial{0.0};
  double sum_ks{0.0};
  std::size_t count{0};
};

struct AggregateEffectSummary {
  std::size_t prevhash_count{0};
  std::size_t bje_count{0};
  double mean_rank_biserial{0.0};
  double median_rank_biserial{0.0};
  double bootstrap_ci_low{0.0};
  double bootstrap_ci_high{0.0};
  double mean_ks{0.0};
};

void accumulate_effect(PrevhashEffectAccumulator& accumulator,
                       double rank_biserial,
                       double ks);
AggregateEffectSummary aggregate_prevhash_effects(
    const std::vector<PrevhashEffectAccumulator>& accumulators,
    std::uint64_t bootstrap_seed);

Plan make_plan(const std::vector<context_campaign::ArchivedContext>& archive,
               Request request,
               context_campaign::BenchmarkResult benchmark);
nlohmann::json plan_preview_json(const Plan& plan);
std::filesystem::path create_campaign(const Plan& plan,
                                      const std::filesystem::path& output_root,
                                      const std::filesystem::path& archive_source,
                                      const std::filesystem::path& kernel_source,
                                      const std::string& campaign_id = {});

std::vector<YHit> reconstruct_and_sort(const bitcoin::Header& header,
                                       const std::vector<std::uint32_t>& nonces,
                                       unsigned threshold_bits,
                                       bool require_threshold = true);
void sort_y_hits(std::vector<YHit>& hits);
std::vector<SelectedBjen> select_cohorts(const bitcoin::Header& header,
                                        const std::vector<YHit>& sorted_t20,
                                        std::uint64_t seed,
                                        const std::string& block_id,
                                        std::size_t t20_control_count = 256U,
                                        std::size_t random_control_count = 256U);

const std::vector<std::string>& trajectory_feature_names();
std::vector<RoundFeatures> extract_trajectory_features(
    const crypto::ReducedSha256dTrace& trace);

void write_capture_atomic(const std::filesystem::path& path,
                          const std::vector<std::uint32_t>& sorted_nonces);
std::vector<std::uint32_t> read_capture(const std::filesystem::path& path);
std::string file_sha256(const std::filesystem::path& path);
bool capture_is_complete(const std::filesystem::path& campaign_directory,
                         const nlohmann::json& block);

namespace detail {

void run_bounded_workers(
    std::size_t task_count,
    std::size_t worker_count,
    const std::function<void(std::size_t, std::size_t)>& task,
    const std::function<void(std::size_t)>& on_completion = {});

}  // namespace detail

GpuWorkloadResult run_gpu_workload(
    const std::vector<GpuBjeWorkItem>& items,
    const std::filesystem::path& kernel,
    const std::string& device,
    std::size_t local_size,
    std::size_t gpu_workers,
    std::uint64_t nonce_start,
    std::uint64_t nonce_count,
    unsigned threshold_bits,
    std::size_t initial_capacity,
    const GpuCompletionHandler& on_completion = {});
nlohmann::json trajectory_throughput_benchmark(
    const std::filesystem::path& campaign_directory,
    const std::filesystem::path& kernel,
    const std::string& device,
    std::size_t local_size,
    ThroughputBenchmarkOptions options);
std::vector<CpuNoncePartition> partition_cpu_nonce_range(
    std::uint64_t nonce_count,
    std::size_t threads);
nlohmann::json trajectory_cpu_benchmark(std::size_t threads,
                                        std::uint64_t nonce_count);

int resume_campaign(const std::filesystem::path& campaign_directory,
                    const std::filesystem::path& kernel,
                    const std::string& device,
                    std::size_t local_size,
                    std::size_t gpu_workers = 1U);
nlohmann::json analyze_campaign(const std::filesystem::path& campaign_directory);
std::filesystem::path export_bje(const std::filesystem::path& campaign_directory,
                                 const std::string& block_id);
std::filesystem::path trace_bjen(const std::filesystem::path& campaign_directory,
                                 const std::string& block_id,
                                 std::uint32_t nonce);
nlohmann::json run_smoke(const context_campaign::ArchivedContext& context,
                         const std::filesystem::path& kernel,
                         const std::string& device,
                         std::size_t local_size,
                         std::uint64_t nonce_count = (std::uint64_t{1} << 20U),
                         unsigned threshold_bits = 10U);

}  // namespace srm::research::context_trajectory
