#pragma once

#include "crypto/reduced_sha256.h"
#include "research/context_campaign.h"
#include "research/header_space.h"

#include <cstdint>
#include <filesystem>
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

int resume_campaign(const std::filesystem::path& campaign_directory,
                    const std::filesystem::path& kernel,
                    const std::string& device,
                    std::size_t local_size);
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
