//tests\test_context_campaign.cpp
#include "research/context_campaign.h"
#include "bitcoin/block_header.h"
#include "test_support.h"

#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>

namespace cc = srm::research::context_campaign;

namespace {

cc::ArchivedContext context(const char marker, const std::string& prevhash) {
  cc::ArchivedContext value;
  value.job = {std::string("job-") + marker, prevhash, "00", "", {},
               "20000000", "207fffff", "65000000", true};
  value.received_timestamp_utc = "2026-09-04T00:00:00.000Z";
  value.extranonce1 = "01020304";
  value.extranonce2_size = 8;
  value.work_fingerprint = std::string(64, marker);
  return value;
}

cc::BenchmarkResult speed() {
  return {"TEST", "CPU", 1000U, 1.0, 1.0e9};
}

nlohmann::json feature(const std::string& id, const double static_score) {
  return {{"block_id", id}, {"feature_stage", "PRE_SCAN"},
          {"post_scan_fields_present", false},
          {"derived", {{"extranonce2_sha256", std::string(64, id.front())},
                       {"header_prefix_hamming_weight", static_score}}},
          {"cost", {{"reconstruction_and_feature_seconds", 0.001}}}};
}

nlohmann::json label(const std::string& id,
                     const std::string& partition,
                     const double quality,
                     const std::uint64_t tail_hits) {
  nlohmann::json tails = nlohmann::json::object();
  for (const auto bits : srm::research::header_space::kThresholdBits) {
    tails["leading_zero_" + std::to_string(bits)] = tail_hits;
  }
  return {{"block_id", id}, {"complete", true}, {"partition", partition},
          {"work_fingerprint", std::string(64, id.front())},
          {"prevhash_group", std::string(64, partition.front())},
          {"extranonce2", "0000000000000000"},
          {"quality", {{"quality_bits", quality}, {"best_difficulty", quality},
                       {"tail_counts", std::move(tails)}}},
          {"scan", {{"nonce_count", 4294967296ULL}, {"elapsed_seconds", 2.0}}}};
}

void write_analysis_fixture(const std::filesystem::path& directory,
                            const double holdout_quality,
                            const std::uint64_t holdout_tails) {
  {
    std::ofstream output(directory / "features.jsonl", std::ios::binary | std::ios::trunc);
    output << feature("d", 10.0).dump() << '\n';
    output << feature("e", 20.0).dump() << '\n';
    output << feature("f", 30.0).dump() << '\n';
  }
  {
    std::ofstream output(directory / "block_labels.jsonl", std::ios::binary | std::ios::trunc);
    output << label("d", "discovery", 31.0, 1U).dump() << '\n';
    output << label("e", "validation", 32.0, 2U).dump() << '\n';
    output << label("f", "holdout", holdout_quality, holdout_tails).dump() << '\n';
  }
}

std::string read_all(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

}  // namespace

TEST_CASE("quality_bits uses the complete uint256 mantissa") {
  srm::research::header_space::PowValue first{};
  first[0] = 1U;
  REQUIRE(std::abs(cc::quality_bits(first) - 32.0) < 1e-12);

  auto second = first;
  second[1] = 0x80000000U;
  REQUIRE(std::abs(cc::quality_bits(second) - (32.0 - std::log2(1.5))) < 1e-12);
  REQUIRE(cc::quality_bits(second) < cc::quality_bits(first));

  const srm::research::header_space::PowValue witness{
      0x00000000U, 0x2ba6d6beU, 0x2eae6f91U, 0x32cc12d9U,
      0xcd473f6eU, 0x424e717cU, 0x7e0ebdcdU, 0x51cd5081U};
  REQUIRE(std::abs(cc::quality_bits(witness) - 34.55203359505532) < 1e-12);
}

TEST_CASE("context sampling is reproducible, width-correct, and unique") {
  const auto first = cc::sample_extranonce2(42U, std::string(64, 'a'), 8U, 128U);
  const auto second = cc::sample_extranonce2(42U, std::string(64, 'a'), 8U, 128U);
  REQUIRE_EQ(first, second);
  std::set<std::string> unique(first.begin(), first.end());
  REQUIRE_EQ(unique.size(), first.size());
  for (const auto& value : first) REQUIRE_EQ(value.size(), 16U);
}

TEST_CASE("campaign sizing supports exact total, time budget, and per-context layout") {
  const std::vector<cc::ArchivedContext> archive{
      context('a', std::string(64, '1')), context('b', std::string(64, '2')),
      context('c', std::string(64, '3')), context('d', std::string(64, '1'))};
  cc::CampaignRequest exact;
  exact.total_blocks = 11U;
  exact.prevhash_count = 3U;
  exact.context_count = 4U;
  const auto exact_plan = cc::make_plan(archive, exact, speed());
  REQUIRE_EQ(exact_plan.total_blocks, 11U);
  REQUIRE_EQ(exact_plan.contexts.size(), 4U);

  cc::CampaignRequest timed;
  timed.time_budget_minutes = 1.0;
  timed.prevhash_count = 3U;
  timed.context_count = 3U;
  const auto timed_plan = cc::make_plan(archive, timed, speed());
  REQUIRE_EQ(timed_plan.total_blocks, 13U);

  cc::CampaignRequest layout;
  layout.blocks_per_context = 7U;
  layout.prevhash_count = 3U;
  layout.context_count = 3U;
  const auto layout_plan = cc::make_plan(archive, layout, speed());
  REQUIRE_EQ(layout_plan.total_blocks, 21U);
  for (const auto& selected : layout_plan.contexts) REQUIRE_EQ(selected.extranonce2_values.size(), 7U);
}

TEST_CASE("context selection is temporally stratified within each prevhash and reproducible") {
  std::vector<cc::ArchivedContext> archive;
  for (unsigned i = 0; i < 9U; ++i) {
    auto value = context(static_cast<char>('a' + i), std::string(64, '1'));
    value.received_timestamp_utc = "2026-09-04T00:00:0" + std::to_string(i) + ".000Z";
    archive.push_back(std::move(value));
  }
  cc::CampaignRequest request;
  request.total_blocks = 3U;
  request.prevhash_count = 1U;
  request.context_count = 3U;
  request.seed = 12345U;
  const auto first = cc::make_plan(archive, request, speed());
  const auto second = cc::make_plan(archive, request, speed());
  REQUIRE_EQ(first.contexts.size(), 3U);
  REQUIRE_EQ(first.contexts[0].context.work_fingerprint,
             second.contexts[0].context.work_fingerprint);
  REQUIRE_EQ(first.contexts[1].context.work_fingerprint,
             second.contexts[1].context.work_fingerprint);
  REQUIRE_EQ(first.contexts[2].context.work_fingerprint,
             second.contexts[2].context.work_fingerprint);
  REQUIRE(first.contexts[0].context.work_fingerprint.front() >= 'a' &&
          first.contexts[0].context.work_fingerprint.front() <= 'c');
  REQUIRE(first.contexts[1].context.work_fingerprint.front() >= 'd' &&
          first.contexts[1].context.work_fingerprint.front() <= 'f');
  REQUIRE(first.contexts[2].context.work_fingerprint.front() >= 'g' &&
          first.contexts[2].context.work_fingerprint.front() <= 'i');
}

TEST_CASE("configured partition fractions are applied and must sum to one") {
  std::vector<cc::ArchivedContext> archive;
  for (unsigned i = 0; i < 8U; ++i) {
    archive.push_back(context(static_cast<char>('a' + i),
                              std::string(64, static_cast<char>('1' + i))));
  }
  cc::CampaignRequest request;
  request.total_blocks = 8U;
  request.prevhash_count = 8U;
  request.context_count = 8U;
  request.discovery_fraction = 0.25;
  request.validation_fraction = 0.25;
  request.holdout_fraction = 0.50;
  const auto plan = cc::make_plan(archive, request, speed());
  std::map<std::string, std::size_t> counts;
  for (const auto& selected : plan.contexts) ++counts[selected.partition];
  REQUIRE_EQ(counts["discovery"], 2U);
  REQUIRE_EQ(counts["validation"], 2U);
  REQUIRE_EQ(counts["holdout"], 4U);

  request.holdout_fraction = 0.40;
  bool rejected = false;
  try {
    (void)cc::make_plan(archive, request, speed());
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  REQUIRE(rejected);
}

TEST_CASE("campaign partitions never share a prevhash and pre-scan features contain no labels") {
  const std::vector<cc::ArchivedContext> archive{
      context('a', std::string(64, '1')), context('b', std::string(64, '2')),
      context('c', std::string(64, '3')), context('d', std::string(64, '1'))};
  cc::CampaignRequest request;
  request.total_blocks = 12U;
  request.prevhash_count = 3U;
  request.context_count = 4U;
  request.seed = 7U;
  const auto plan = cc::make_plan(archive, request, speed());
  std::map<std::string, std::string> owners;
  for (const auto& selected : plan.contexts) {
    const auto [found, inserted] = owners.emplace(selected.context.job.prevhash, selected.partition);
    REQUIRE(inserted || found->second == selected.partition);
    const auto ex = selected.extranonce2_values.front();
    const auto id = cc::block_id(selected.context, ex);
    const auto features = cc::pre_scan_features(selected.context, ex, id, selected.partition);
    REQUIRE_EQ(features.at("feature_stage").get<std::string>(), "PRE_SCAN");
    REQUIRE(!features.at("post_scan_fields_present").get<bool>());
    REQUIRE(features.dump().find("minimum_pow_value") == std::string::npos);
  }
  REQUIRE_EQ(owners.size(), 3U);
}

TEST_CASE("Stratum archive rejects incomplete contexts and reconstructs replayable work") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_context_archive_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  const auto path = directory / "jobs.jsonl";
  const auto valid = context('a', std::string(64, '1'));
  nlohmann::json line = {
      {"event", "mining.notify"}, {"received_timestamp_utc", valid.received_timestamp_utc},
      {"work_fingerprint", valid.work_fingerprint},
      {"subscription", {{"available", true}, {"extranonce1", valid.extranonce1},
                        {"extranonce2_size", valid.extranonce2_size}}},
      {"stratum_job", {{"job_id", valid.job.job_id}, {"prevhash", valid.job.prevhash},
                       {"coinbase1", valid.job.coinbase1}, {"coinbase2", valid.job.coinbase2},
                       {"merkle_branches", valid.job.merkle_branches}, {"version", valid.job.version},
                       {"nbits", valid.job.nbits}, {"ntime", valid.job.ntime},
                       {"clean_jobs", valid.job.clean_jobs}}}};
  {
    std::ofstream output(path);
    output << line.dump() << '\n';
    line["subscription"].erase("extranonce1");
    output << line.dump() << '\n';
  }
  std::size_t rejected = 0;
  const auto loaded = cc::load_archive(path, &rejected);
  REQUIRE_EQ(loaded.size(), 1U);
  REQUIRE_EQ(rejected, 1U);
  const auto built = srm::stratum::build_work(loaded.front().job, loaded.front().extranonce1,
                                               std::string(16, '0'), 0U);
  REQUIRE_EQ(srm::bitcoin::header_hex(built.header).size(), 160U);
  std::filesystem::remove_all(directory);
}

TEST_CASE("checkpoint recovery de-duplicates completed B(J,e) identifiers") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_context_resume_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  const auto path = directory / "block_labels.jsonl";
  {
    std::ofstream output(path);
    output << R"({"block_id":"a","complete":true})" << '\n';
    output << R"({"block_id":"a","complete":true})" << '\n';
    output << R"({"block_id":"b","complete":false})" << '\n';
  }
  const auto recovered = cc::recover_completed_blocks(path);
  REQUIRE_EQ(recovered.size(), 1U);
  REQUIRE_EQ(recovered.front(), "a");
  std::filesystem::remove_all(directory);
}

TEST_CASE("sealed holdout is opaque until explicit immutable finalization") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_context_holdout_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  {
    std::ofstream output(directory / "manifest.json", std::ios::binary);
    output << R"({"schema_version":1,"campaign_id":"holdout-test"})";
  }
  write_analysis_fixture(directory, 1000000.0, 999999999U);
  const auto sealed_before = cc::analyze_campaign(directory, false);
  const auto file_before = read_all(directory / "analysis_summary.json");
  REQUIRE_EQ(sealed_before.at("corpus").at("complete_blocks").get<std::size_t>(), 2U);
  REQUIRE(!sealed_before.at("holdout").at("opened").get<bool>());
  REQUIRE(!std::filesystem::exists(directory / "holdout_evaluation.json"));

  write_analysis_fixture(directory, 1.0e300, 9999999999ULL);
  const auto sealed_after = cc::analyze_campaign(directory, false);
  const auto file_after = read_all(directory / "analysis_summary.json");
  REQUIRE_EQ(sealed_before, sealed_after);
  REQUIRE_EQ(file_before, file_after);
  REQUIRE(!std::filesystem::exists(directory / "holdout_evaluation.json"));

  const auto opened = cc::analyze_campaign(directory, true);
  REQUIRE(opened.at("holdout").at("opened").get<bool>());
  REQUIRE_EQ(opened.at("corpus").at("complete_blocks").get<std::size_t>(), 3U);
  const auto evaluation_path = directory / "holdout_evaluation.json";
  REQUIRE(std::filesystem::exists(evaluation_path));
  const auto evaluation = nlohmann::json::parse(read_all(evaluation_path));
  REQUIRE_EQ(evaluation.at("campaign_id").get<std::string>(), "holdout-test");
  REQUIRE(evaluation.contains("finalized_at_utc"));
  REQUIRE(evaluation.contains("policy"));
  const auto immutable = read_all(evaluation_path);

  write_analysis_fixture(directory, 2.0e300, 1U);
  (void)cc::analyze_campaign(directory, true);
  REQUIRE_EQ(read_all(evaluation_path), immutable);
  std::filesystem::remove_all(directory);
}

TEST_CASE("holdout finalization rejects a stale artifact without campaign identity") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_context_stale_holdout_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  {
    std::ofstream output(directory / "manifest.json", std::ios::binary);
    output << R"({"schema_version":1,"campaign_id":"current-campaign"})";
  }
  write_analysis_fixture(directory, 100.0, 1U);
  {
    std::ofstream output(directory / "holdout_evaluation.json", std::ios::binary);
    output << R"({"schema_version":1,"finalized_at_utc":"old","policy":"foreign legacy"})";
  }
  bool rejected = false;
  try {
    (void)cc::analyze_campaign(directory, true);
  } catch (const std::runtime_error& error) {
    rejected = std::string(error.what()).find("no campaign_id") != std::string::npos;
  }
  REQUIRE(rejected);
  std::filesystem::remove_all(directory);
}

TEST_CASE("holdout finalization rejects an artifact from another campaign") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_context_foreign_holdout_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  {
    std::ofstream output(directory / "manifest.json", std::ios::binary);
    output << R"({"schema_version":1,"campaign_id":"current-campaign"})";
  }
  write_analysis_fixture(directory, 100.0, 1U);
  {
    std::ofstream output(directory / "holdout_evaluation.json", std::ios::binary);
    output << R"({"schema_version":1,"campaign_id":"different-campaign","finalized_at_utc":"old","policy":"foreign"})";
  }
  bool rejected = false;
  try {
    (void)cc::analyze_campaign(directory, true);
  } catch (const std::runtime_error& error) {
    rejected = std::string(error.what()).find("different-campaign") != std::string::npos;
  }
  REQUIRE(rejected);
  std::filesystem::remove_all(directory);
}

TEST_CASE("holdout finalization preserves an immutable artifact from the same campaign") {
  const auto directory = std::filesystem::temp_directory_path() /
      ("srm_context_current_holdout_" + std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(directory);
  {
    std::ofstream output(directory / "manifest.json", std::ios::binary);
    output << R"({"schema_version":1,"campaign_id":"current-campaign"})";
  }
  write_analysis_fixture(directory, 100.0, 1U);
  const auto immutable = std::string(
      R"({"schema_version":1,"campaign_id":"current-campaign","finalized_at_utc":"frozen","policy":"frozen","marker":42})");
  {
    std::ofstream output(directory / "holdout_evaluation.json", std::ios::binary);
    output << immutable;
  }
  {
    std::ofstream output(directory / "analysis_summary.json", std::ios::binary);
    output << R"({"campaign_id":"current-campaign","frozen":true})";
  }
  const auto frozen_summary = read_all(directory / "analysis_summary.json");
  (void)cc::analyze_campaign(directory, true);
  REQUIRE_EQ(read_all(directory / "holdout_evaluation.json"), immutable);
  REQUIRE_EQ(read_all(directory / "analysis_summary.json"), frozen_summary);
  std::filesystem::remove_all(directory);
}
