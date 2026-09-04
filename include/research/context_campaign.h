//include\research\context_campaign.h
#pragma once

#include "research/header_space.h"
#include "stratum/stratum_job.h"

#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace srm::research::context_campaign {

struct ArchivedContext {
  stratum::StratumJob job;
  std::string received_timestamp_utc;
  std::string extranonce1;
  unsigned extranonce2_size{0};
  std::string work_fingerprint;
};

struct CampaignRequest {
  std::string profile{"CUSTOM"};
  std::uint64_t seed{0x534841323536ULL};
  std::optional<std::uint64_t> total_blocks;
  std::optional<double> time_budget_minutes;
  std::size_t prevhash_count{0};
  std::size_t context_count{0};
  std::optional<std::size_t> blocks_per_context;
  double discovery_fraction{0.60};
  double validation_fraction{0.20};
  double holdout_fraction{0.20};
};

struct BenchmarkResult {
  std::string backend;
  std::string device;
  std::uint64_t hashes{0};
  double seconds{0.0};
  double hashes_per_second{0.0};
};

struct PlannedContext {
  ArchivedContext context;
  std::string partition;
  std::vector<std::string> extranonce2_values;
};

struct CampaignPlan {
  CampaignRequest request;
  BenchmarkResult benchmark;
  std::vector<PlannedContext> contexts;
  std::uint64_t total_blocks{0};
  std::uint64_t total_hashes{0};
  double estimated_seconds{0.0};
  std::uint64_t estimated_disk_bytes{0};
  std::vector<std::string> warnings;
};

std::vector<ArchivedContext> load_archive(const std::filesystem::path& archive,
                                          std::size_t* rejected_lines = nullptr);
BenchmarkResult benchmark(const ArchivedContext& context,
                          const std::filesystem::path& kernel,
                          const std::string& device,
                          std::uint64_t nonce_count,
                          std::uint64_t zone_size,
                          std::size_t batch_zones,
                          std::size_t local_size);
CampaignPlan make_plan(const std::vector<ArchivedContext>& archive,
                       CampaignRequest request,
                       BenchmarkResult benchmark);
nlohmann::json plan_preview_json(const CampaignPlan& plan);
nlohmann::json pre_scan_features(const ArchivedContext& context,
                                 const std::string& extranonce2,
                                 const std::string& block_id,
                                 const std::string& partition);
std::string block_id(const ArchivedContext& context, const std::string& extranonce2);
std::vector<std::string> sample_extranonce2(std::uint64_t seed,
                                            const std::string& work_fingerprint,
                                            unsigned size,
                                            std::size_t count);
double quality_bits(const header_space::PowValue& value);

std::filesystem::path create_campaign(const CampaignPlan& plan,
                                      const std::filesystem::path& output_root,
                                      const std::filesystem::path& archive_source,
                                      const std::string& campaign_id = {});
int run_campaign(const std::filesystem::path& campaign_directory,
                 const std::filesystem::path& kernel,
                 const std::string& device,
                 std::uint64_t zone_size,
                 std::size_t batch_zones,
                 std::size_t local_size);
int run_smoke(const CampaignPlan& plan,
              const std::filesystem::path& output_root,
              const std::filesystem::path& kernel,
              const std::string& device,
              std::uint64_t nonce_count,
              std::uint64_t zone_size,
              std::size_t batch_zones,
              std::size_t local_size);
nlohmann::json analyze_campaign(const std::filesystem::path& campaign_directory,
                                bool finalize_holdout);
std::vector<std::string> recover_completed_blocks(const std::filesystem::path& labels_path);

}  // namespace srm::research::context_campaign
