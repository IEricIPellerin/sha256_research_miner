#include "research/context_phase2.h"

#include "crypto/reduced_sha256.h"
#include "crypto/sha256.h"
#include "research/sha256d_whitebox.h"
#include "test_support.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <set>
#include <sstream>

namespace phase2 = srm::research::context_phase2;
namespace whitebox = srm::research::whitebox;

namespace {

constexpr const char* kGenesisHeader =
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c";

std::uint32_t read_be32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
         (static_cast<std::uint32_t>(bytes[1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2]) << 8U) |
         bytes[3];
}

nlohmann::json source_feature(const std::string& id,
                              const std::string& partition,
                              const std::string& context,
                              const std::string& prevhash,
                              const std::uint64_t extranonce) {
  auto header = srm::crypto::from_hex(kGenesisHeader);
  header[68] = static_cast<std::uint8_t>(extranonce >> 24U);
  header[69] = static_cast<std::uint8_t>(extranonce >> 16U);
  header[70] = static_cast<std::uint8_t>(extranonce >> 8U);
  header[71] = static_cast<std::uint8_t>(extranonce);
  const std::span<const std::uint8_t> prefix(header.data(), 76U);
  const auto compact = whitebox::build_prescan_compression1(prefix);
  nlohmann::json words = nlohmann::json::array();
  for (std::size_t i = 0; i < 19U; ++i) words.push_back(read_be32(header.data() + i * 4U));
  std::ostringstream ex;
  ex << std::hex << std::setfill('0') << std::setw(16) << extranonce;
  return {
      {"schema_version", 1}, {"block_id", id}, {"partition", partition},
      {"feature_stage", "PRE_SCAN"}, {"post_scan_fields_present", false},
      {"work_fingerprint", context}, {"prevhash", prevhash},
      {"extranonce2", ex.str()}, {"extranonce2_size", 8},
      {"derived", {
          {"header_prefix_76_bytes_hex", srm::crypto::to_hex(prefix)},
          {"header_words_be", words},
          {"merkle_root", std::string(64, '0')},
          {"sha256_first_chunk_midstate_words", compact.midstate}}}};
}

nlohmann::json label(const std::string& id, const std::string& partition,
                     const std::string& context, const std::string& prevhash,
                     const double quality) {
  nlohmann::json tails = nlohmann::json::object();
  for (const auto bits : {26U, 28U, 30U, 32U, 34U, 36U, 38U}) {
    tails["leading_zero_" + std::to_string(bits)] =
        static_cast<std::uint64_t>(quality) % (bits - 23U);
  }
  return {
      {"schema_version", 1}, {"campaign_id", "phase2-test"},
      {"block_id", id}, {"partition", partition}, {"complete", true},
      {"label_stage", "POST_SCAN"}, {"work_fingerprint", context},
      {"prevhash_group", prevhash},
      {"quality", {{"quality_bits", quality},
                   {"best_difficulty", std::exp(quality / 10.0)},
                   {"tail_counts", tails}}}};
}

std::filesystem::path fixture(const std::string& suffix,
                              const double holdout_quality = 999999.0,
                              const bool swap_first_context_targets = false) {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_phase2_" + suffix + "_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  {
    std::ofstream output(directory / "manifest.json", std::ios::binary);
    output << R"({"schema_version":1,"campaign_id":"phase2-test","created_at_utc":"2026-09-04T00:00:00.000Z"})";
  }
  struct Item { std::string id, partition, context, prevhash; double quality; };
  std::vector<Item> items{
      {"d00", "discovery", "c0", "p0", 30.0},
      {"d01", "discovery", "c0", "p0", 31.0},
      {"d10", "discovery", "c1", "p0", 32.0},
      {"d11", "discovery", "c1", "p0", 34.0},
      {"d20", "discovery", "c2", "p1", 33.0},
      {"d21", "discovery", "c2", "p1", 38.0},
      {"d30", "discovery", "c3", "p1", 35.0},
      {"d31", "discovery", "c3", "p1", 36.0},
      {"validation-secret", "validation", "cv", "pv", 1.0e100},
      {"holdout-secret", "holdout", "ch", "ph", holdout_quality}};
  if (swap_first_context_targets) {
    std::swap(items[0].quality, items[1].quality);
  }
  {
    std::ofstream output(directory / "features.jsonl", std::ios::binary);
    std::uint64_t ex = 1U;
    for (const auto& item : items) {
      output << source_feature(item.id, item.partition, item.context,
                               item.prevhash, ex++).dump() << '\n';
    }
  }
  {
    std::ofstream output(directory / "block_labels.jsonl", std::ios::binary);
    for (const auto& item : items) {
      auto value = label(item.id, item.partition, item.context,
                         item.prevhash, item.quality);
      if (item.partition != "discovery") {
        value["quality"] = "must never be accessed by Phase 2A";
      }
      output << value.dump() << '\n';
    }
  }
  {
    std::ofstream output(directory / "checkpoint.json", std::ios::binary);
    output << R"({"campaign_id":"phase2-test","status":"COMPLETE","completed_blocks":10})";
  }
  {
    std::ofstream output(directory / "analysis_summary.json", std::ios::binary);
    output << R"({"campaign_id":"phase2-test","holdout_finalized":false})";
  }
  {
    std::ofstream output(directory / "report.md", std::ios::binary);
    output << "# frozen source report\n";
  }
  return directory;
}

std::string read_all(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::map<std::string, std::pair<std::string, std::string>> rank_prediction_cells(
    const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::string line;
  std::getline(input, line);
  std::map<std::string, std::pair<std::string, std::string>> result;
  while (std::getline(input, line)) {
    std::istringstream row(line);
    std::vector<std::string> cells;
    std::string cell;
    while (std::getline(row, cell, ',')) cells.push_back(cell);
    REQUIRE(cells.size() >= 6U);
    result[cells[0]] = {cells[4], cells[5]};
  }
  return result;
}

}  // namespace

TEST_CASE("Phase 2 pre-nonce rounds and schedule boundary match full white-box traces") {
  auto header = srm::crypto::from_hex(kGenesisHeader);
  const auto compact = whitebox::build_prescan_compression1(
      std::span<const std::uint8_t>(header.data(), 76U));
  const auto full = srm::crypto::trace_reduced_sha256d(header, 64U);
  for (std::size_t round = 0; round < 3U; ++round) {
    const auto& expected = full.first_sha.rounds.at(64U + round);
    const auto& actual = compact.rounds[round];
    REQUIRE_EQ(actual.w, expected.w);
    REQUIRE_EQ(actual.temp1, expected.temp1);
    REQUIRE_EQ(actual.temp2, expected.temp2);
    REQUIRE_EQ(actual.before[0], expected.a_before);
    REQUIRE_EQ(actual.before[7], expected.h_before);
    REQUIRE_EQ(actual.after[0], expected.a_after);
    REQUIRE_EQ(actual.after[7], expected.h_after);
  }
  REQUIRE(compact.w16_nonce_independent);
  REQUIRE(compact.w17_nonce_independent);
  REQUIRE(compact.w18_nonce_dependent);

  for (const auto nonce_word : {0U, 1U, 0x12345678U, 0xffffffffU}) {
    header[76] = static_cast<std::uint8_t>(nonce_word >> 24U);
    header[77] = static_cast<std::uint8_t>(nonce_word >> 16U);
    header[78] = static_cast<std::uint8_t>(nonce_word >> 8U);
    header[79] = static_cast<std::uint8_t>(nonce_word);
    const auto trace = srm::crypto::trace_reduced_sha256d(header, 64U);
    REQUIRE_EQ(trace.first_sha.rounds.at(67U).temp1,
               compact.round3_c3 + nonce_word);
    REQUIRE_EQ(trace.first_sha.rounds.at(80U).w, compact.w16);
    REQUIRE_EQ(trace.first_sha.rounds.at(81U).w, compact.w17);
  }
}

TEST_CASE("Phase 2 carry summaries and uniform-addend formula are exact") {
  const auto summary = phase2::fixed_addition_carries({0xffffffffU, 1U});
  REQUIRE_EQ(summary.carry_count, 32U);
  REQUIRE_EQ(summary.maximum_chain, 32U);
  REQUIRE_EQ(summary.chain_count, 1U);
  REQUIRE_EQ(summary.carry_mask, 0xffffffffU);

  for (unsigned fixed = 0U; fixed < 256U; ++fixed) {
    double enumerated = 0.0;
    for (unsigned addend = 0U; addend < 256U; ++addend) {
      unsigned carry = 0U;
      for (unsigned bit = 0U; bit < 7U; ++bit) {
        const auto column = ((fixed >> bit) & 1U) +
                            ((addend >> bit) & 1U) + carry;
        carry = column >> 1U;
        enumerated += carry;
      }
    }
    enumerated /= 256.0;
    double formula = 0.0;
    for (unsigned bit = 1U; bit < 8U; ++bit) {
      formula += static_cast<double>(fixed & ((1U << bit) - 1U)) /
                 static_cast<double>(1U << bit);
    }
    REQUIRE(std::abs(enumerated - formula) < 1e-12);
  }
}

TEST_CASE("Phase 2 features and contextual references cannot depend on POST_SCAN labels") {
  const auto source = source_feature("candidate", "discovery", "context", "prevhash", 7U);
  const auto first = phase2::derive_self_features(source);
  auto unrelated_label = label("candidate", "discovery", "context", "prevhash", 1.0);
  unrelated_label["quality"]["quality_bits"] = 1.0e200;
  const auto second = phase2::derive_self_features(source);
  REQUIRE_EQ(first, second);

  auto a = source_feature("a", "discovery", "context", "prevhash", 1U);
  auto b = source_feature("b", "discovery", "context", "prevhash", 2U);
  std::vector<nlohmann::json> candidates{a, b};
  const auto reference = phase2::deterministic_context_reference(candidates);
  candidates[0]["quality_bits"] = -999999.0;
  candidates[1]["quality_bits"] = 999999.0;
  REQUIRE_EQ(phase2::deterministic_context_reference(candidates), reference);
}

TEST_CASE("Phase 2 operational top-k selects independently inside every context") {
  const std::vector<std::string> contexts{
      "A", "A", "A", "A", "B", "B", "B", "B"};
  const std::vector<double> different_scales{
      1000.0, 900.0, 800.0, 700.0, 1.0, 0.9, 0.8, 0.7};
  const auto quarter = phase2::intra_context_topk_selection(
      contexts, different_scales, 0.25, true);
  REQUIRE_EQ(quarter.size(), 2U);
  REQUIRE(std::find(quarter.begin(), quarter.end(), 0U) != quarter.end());
  REQUIRE(std::find(quarter.begin(), quarter.end(), 4U) != quarter.end());

  std::map<std::string, std::size_t> owners;
  for (const auto index : quarter) ++owners[contexts[index]];
  REQUIRE_EQ(owners["A"], 1U);
  REQUIRE_EQ(owners["B"], 1U);
  REQUIRE(std::find(quarter.begin(), quarter.end(), 1U) == quarter.end());

  const std::vector<std::string> unequal_contexts{"A", "A", "A", "A", "B", "B"};
  const std::vector<double> scores{6, 5, 4, 3, 2, 1};
  const auto half = phase2::intra_context_topk_selection(
      unequal_contexts, scores, 0.5, true);
  std::map<std::string, std::size_t> half_counts;
  for (const auto index : half) ++half_counts[unequal_contexts[index]];
  REQUIRE_EQ(half_counts["A"], 2U);
  REQUIRE_EQ(half_counts["B"], 1U);
}

TEST_CASE("Phase 2 full fixture excludes validation and holdout and records train-only CV provenance") {
  const auto directory = fixture("guards");
  phase2::Options options;
  options.expected_campaign_id = "phase2-test";
  options.outer_folds = 2U;
  options.bootstrap_replicates = 2U;
  options.permutation_replicates = 2U;
  options.selected_feature_count = 4U;
  const auto audit = phase2::run(directory, options);
  REQUIRE_EQ(audit.at("discovery_rows_used").get<std::size_t>(), 8U);
  REQUIRE_EQ(audit.at("validation_rows_used").get<std::size_t>(), 0U);
  REQUIRE_EQ(audit.at("holdout_rows_used").get<std::size_t>(), 0U);
  const auto output = directory / "phase2_discovery_v1";
  const auto derived = read_all(output / "derived_features_discovery.jsonl");
  REQUIRE(derived.find("validation-secret") == std::string::npos);
  REQUIRE(derived.find("holdout-secret") == std::string::npos);
  REQUIRE(std::filesystem::exists(output / "intra_context_feature_summary.csv"));
  REQUIRE(std::filesystem::exists(output / "topk_lift_intra_context.csv"));
  REQUIRE(std::filesystem::exists(output / "grouped_cv_rank_predictions.csv"));
  const auto rank_predictions = read_all(output / "grouped_cv_rank_predictions.csv");
  REQUIRE(rank_predictions.find("validation-secret") == std::string::npos);
  REQUIRE(rank_predictions.find("holdout-secret") == std::string::npos);
  const auto primary_topk = read_all(output / "topk_lift_intra_context.csv");
  REQUIRE(primary_topk.find("baseline.random_deterministic") != std::string::npos);
  const auto cv = nlohmann::json::parse(
      read_all(output / "grouped_cv_rank_summary.json"));
  REQUIRE_EQ(cv.at("role").get<std::string>(), "PRIMARY_OPERATIONAL");
  REQUIRE_EQ(cv.at("target").get<std::string>(), "context_quality_score");
  REQUIRE_EQ(cv.at("feature_selection_statistic").get<std::string>(),
             "absolute mean prevhash of context-level Spearman, train-only");
  REQUIRE(!cv.at("sanity_baseline_admissible").get<bool>());
  for (const auto& fold : cv.at("folds")) {
    const auto train = fold.at("train_prevhashes").get<std::set<std::string>>();
    const auto test = fold.at("test_prevhashes").get<std::set<std::string>>();
    std::vector<std::string> overlap;
    std::set_intersection(train.begin(), train.end(), test.begin(), test.end(),
                          std::back_inserter(overlap));
    REQUIRE(overlap.empty());
    REQUIRE_EQ(fold.at("normalization").at("scope").get<std::string>(),
               "outer_train_only");
    REQUIRE_EQ(fold.at("feature_selection").at("scope").get<std::string>(),
               "outer_train_only");
    REQUIRE_EQ(fold.at("feature_selection").at("statistic").get<std::string>(),
               "absolute mean prevhash of context-level Spearman");
    REQUIRE_EQ(fold.at("normalization").at("fitted_row_count").get<std::size_t>(),
               fold.at("train_rows").get<std::size_t>());
    REQUIRE_EQ(fold.at("test_target_rows_used_for_training").get<std::size_t>(), 0U);
    for (const auto& name : fold.at("selected_features")) {
      REQUIRE(name.get<std::string>().rfind("baseline.", 0U) != 0U);
    }
  }
  const auto permutation = nlohmann::json::parse(
      read_all(output / "permutation_summary.json"));
  REQUIRE_EQ(permutation.at("multiple_selection_adjustment").get<std::string>(),
             "none; post-selection values are exploratory and unadjusted");
  for (const auto& result : permutation.at("results")) {
    REQUIRE(result.at("feature").get<std::string>().rfind("baseline.", 0U) != 0U);
    REQUIRE_EQ(result.at("status").get<std::string>(),
               "POST_SELECTION_EXPLORATORY_UNADJUSTED_NOT_EVIDENCE");
  }
  std::filesystem::remove_all(directory);
}

TEST_CASE("Phase 2 scientific artifacts are deterministic for an identical seed") {
  const auto first = fixture("determinism_a");
  const auto second = fixture("determinism_b");
  phase2::Options options;
  options.expected_campaign_id = "phase2-test";
  options.outer_folds = 2U;
  options.bootstrap_replicates = 2U;
  options.permutation_replicates = 2U;
  options.selected_feature_count = 4U;
  (void)phase2::run(first, options);
  (void)phase2::run(second, options);
  for (const auto& entry : std::filesystem::directory_iterator(first / "phase2_discovery_v1")) {
    const auto peer = second / "phase2_discovery_v1" / entry.path().filename();
    REQUIRE_EQ(read_all(entry.path()), read_all(peer));
  }
  std::filesystem::remove_all(first);
  std::filesystem::remove_all(second);
}

TEST_CASE("Phase 2 rank model never trains on the target of its outer test prevhash") {
  const auto original = fixture("test_target_original");
  const auto perturbed = fixture("test_target_perturbed", 999999.0, true);
  phase2::Options options;
  options.expected_campaign_id = "phase2-test";
  options.outer_folds = 2U;
  options.bootstrap_replicates = 1U;
  options.permutation_replicates = 1U;
  options.selected_feature_count = 4U;
  (void)phase2::run(original, options);
  (void)phase2::run(perturbed, options);
  const auto original_predictions = rank_prediction_cells(
      original / "phase2_discovery_v1" / "grouped_cv_rank_predictions.csv");
  const auto perturbed_predictions = rank_prediction_cells(
      perturbed / "phase2_discovery_v1" / "grouped_cv_rank_predictions.csv");
  for (const auto& id : {"d00", "d01"}) {
    REQUIRE(original_predictions.at(id).first !=
            perturbed_predictions.at(id).first);
    REQUIRE_EQ(original_predictions.at(id).second,
               perturbed_predictions.at(id).second);
  }
  std::filesystem::remove_all(original);
  std::filesystem::remove_all(perturbed);
}

TEST_CASE("Phase 2 dry-run writes no artifacts") {
  const auto directory = fixture("dry_run");
  phase2::Options options;
  options.expected_campaign_id = "phase2-test";
  options.outer_folds = 2U;
  options.check_only = true;
  const auto audit = phase2::run(directory, options);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "DRY_RUN_CHECK_PASSED");
  REQUIRE_EQ(audit.at("artifacts_written").get<unsigned>(), 0U);
  REQUIRE(!std::filesystem::exists(directory / "phase2_discovery_v1"));
  std::filesystem::remove_all(directory);
}
