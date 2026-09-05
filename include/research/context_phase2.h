#pragma once

#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace srm::research::context_phase2 {

inline constexpr std::uint64_t kDefaultSeed = 0x5048415345324155ULL;
inline constexpr unsigned kSchemaVersion = 1U;

struct Options {
  std::string expected_campaign_id{"ctx_20260904_165537_41323536"};
  std::uint64_t seed{kDefaultSeed};
  std::size_t outer_folds{8U};
  std::size_t bootstrap_replicates{200U};
  std::size_t permutation_replicates{200U};
  std::size_t selected_feature_count{32U};
  bool check_only{false};
};

struct CarrySummary {
  unsigned carry_count{};
  unsigned maximum_chain{};
  unsigned chain_count{};
  std::uint32_t carry_mask{};
  std::uint64_t maximum_carry_value{};
};

// Bit-column audit for deterministic unsigned additions modulo 2^32.
CarrySummary fixed_addition_carries(
    const std::vector<std::uint32_t>& operands);

// Exact E[number of carry-ins at bits 1..31] when adding a fixed uint32
// constant to a uniformly distributed uint32 word.
double expected_uniform_addend_carries(std::uint32_t fixed);

// Public deterministic helpers are intentionally small so permanent tests can
// exercise leakage and fold invariants without running a scientific analysis.
nlohmann::json derive_self_features(const nlohmann::json& source_feature);
std::string deterministic_context_reference(
    const std::vector<nlohmann::json>& source_features);
std::vector<std::size_t> grouped_fold_assignment(
    const std::vector<std::string>& groups,
    std::size_t fold_count,
    std::uint64_t seed);
std::vector<std::size_t> intra_context_topk_selection(
    const std::vector<std::string>& contexts,
    const std::vector<double>& scores,
    double fraction,
    bool descending = true);

// Validates source completeness and the discovery-only barrier. check_only
// performs all source/feature checks but writes no files and runs no statistics.
nlohmann::json run(const std::filesystem::path& campaign_directory,
                   const Options& options = {});

}  // namespace srm::research::context_phase2
