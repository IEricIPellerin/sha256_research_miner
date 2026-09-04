//tests\test_context_campaign.cpp
#include "research/context_campaign.h"
#include "bitcoin/block_header.h"
#include "test_support.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>

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

}  // namespace

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
