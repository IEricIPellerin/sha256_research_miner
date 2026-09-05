#include "research/context_trajectory.h"
#include "checkpoint/state_store.h"
#include "crypto/sha256d.h"
#include "test_support.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <map>
#include <numeric>
#include <random>
#include <set>

namespace trajectory = srm::research::context_trajectory;
namespace hs = srm::research::header_space;
namespace cc = srm::research::context_campaign;

namespace {

std::string hex64(const unsigned value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result(64U, '0');
  result[62] = digits[(value >> 4U) & 15U];
  result[63] = digits[value & 15U];
  return result;
}

cc::ArchivedContext fake_context(const unsigned group, const unsigned context = 0U) {
  cc::ArchivedContext result;
  result.job.job_id = "job-" + std::to_string(group) + '-' + std::to_string(context);
  result.job.prevhash = hex64(group + 1U);
  result.job.coinbase1 = "01000000";
  result.job.coinbase2 = "";
  result.job.version = "20000000";
  result.job.nbits = "1d00ffff";
  result.job.ntime = "495fab29";
  result.received_timestamp_utc = "2026-01-01T00:00:" + std::to_string(context) + "Z";
  result.extranonce1 = "01020304";
  result.extranonce2_size = 4U;
  result.work_fingerprint = hex64(32U + group * 4U + context);
  return result;
}

std::vector<cc::ArchivedContext> fake_archive(const unsigned groups,
                                               const unsigned contexts_per_group = 2U) {
  std::vector<cc::ArchivedContext> result;
  for (unsigned group = 0; group < groups; ++group)
    for (unsigned context = 0; context < contexts_per_group; ++context)
      result.push_back(fake_context(group, context));
  return result;
}

cc::BenchmarkResult benchmark() {
  return {"TEST", "deterministic", 1000000U, 1.0, 1000000.0};
}

std::filesystem::path unique_temp(const std::string& stem) {
  return std::filesystem::temp_directory_path() /
      (stem + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
}

std::map<std::string, std::string> directory_snapshot(
    const std::filesystem::path& root) {
  std::map<std::string, std::string> result;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
    if (!entry.is_regular_file()) continue;
    result.emplace(std::filesystem::relative(entry.path(), root).generic_string(),
                   trajectory::file_sha256(entry.path()));
  }
  return result;
}

bool throws_with(const std::function<void()>& function, const std::string& text) {
  try { function(); }
  catch (const std::exception& error) { return std::string(error.what()).find(text) != std::string::npos; }
  return false;
}

}  // namespace

TEST_CASE("T20 is the exact strict canonical PoW boundary") {
  hs::PowValue below{};
  below[0] = 0x00000fffU;
  for (std::size_t i = 1; i < below.size(); ++i) below[i] = 0xffffffffU;
  hs::PowValue boundary{};
  boundary[0] = 0x00001000U;
  REQUIRE(hs::below_power_of_two_threshold(below, 20U));
  REQUIRE(!hs::below_power_of_two_threshold(boundary, 20U));
  REQUIRE_EQ(hs::leading_zero_bits(below), 20U);
}

TEST_CASE("PowValue conversion preserves Bitcoin numeric endian order") {
  srm::crypto::Digest raw{};
  raw[31] = 0x12U; raw[30] = 0x34U; raw[29] = 0x56U; raw[28] = 0x78U;
  raw[27] = 0x9aU; raw[26] = 0xbcU; raw[25] = 0xdeU; raw[24] = 0xf0U;
  const auto value = hs::pow_value(raw);
  REQUIRE_EQ(value[0], 0x12345678U);
  REQUIRE_EQ(value[1], 0x9abcdef0U);
  REQUIRE(hs::below_power_of_two_threshold(hs::PowValue{}, 256U));
}

TEST_CASE("CPU sparse capture reports overflow and complete retry loses no hit") {
  const auto header = hs::genesis_header();
  const auto one_shot = hs::scan_sparse_hits_cpu(header, 0U, 4096U, 4U, 1U);
  REQUIRE(one_shot.overflow);
  REQUIRE(one_shot.total_hit_count > one_shot.captured_count);
  const auto complete = hs::scan_sparse_hits_cpu_complete(header, 0U, 4096U, 4U, 1U);
  REQUIRE(!complete.overflow);
  REQUIRE_EQ(complete.total_hit_count, complete.nonces.size());
  REQUIRE(complete.overflow_retries > 0U);
  auto unique = complete.nonces;
  std::sort(unique.begin(), unique.end());
  REQUIRE(std::adjacent_find(unique.begin(), unique.end()) == unique.end());
  REQUIRE_EQ(trajectory::reconstruct_and_sort(header, unique, 4U, true).size(), unique.size());
}

TEST_CASE("GPU sparse capture exactly matches CPU when OpenCL GPU is available") {
  if (!hs::opencl_compiled() || hs::enumerate_gpu_devices().empty()) return;
  const auto header = hs::genesis_header();
  const auto cpu = hs::scan_sparse_hits_cpu_complete(header, 0x12340000U, 16384U, 8U, 8U);
  hs::GpuScanner scanner("auto", std::filesystem::path(SRM_SOURCE_DIR) / "kernels" / "header_space_map.cl", 64U);
  const auto gpu = scanner.scan_sparse_hits_complete(header, 0x12340000U, 16384U, 8U, 8U);
  auto left = cpu.nonces, right = gpu.nonces;
  std::sort(left.begin(), left.end()); std::sort(right.begin(), right.end());
  REQUIRE_EQ(left, right);
  REQUIRE_EQ(gpu.total_hit_count, cpu.total_hit_count);
  REQUIRE(!gpu.overflow);
}

TEST_CASE("bounded worker pool propagates worker exceptions to its coordinator") {
  std::atomic<std::size_t> completed{0U};
  REQUIRE(throws_with([&] {
    trajectory::detail::run_bounded_workers(32U, 4U,
        [&](const std::size_t, const std::size_t task) {
          if (task == 3U) throw std::runtime_error("synthetic worker failure");
          ++completed;
        });
  }, "synthetic worker failure"));
  REQUIRE(completed.load() < 32U);
}

TEST_CASE("CPU nonce partitions have exact coverage without holes or overlaps") {
  constexpr std::uint64_t nonce_count = 1009U;
  for (const auto threads : {1U, 2U, 4U, 8U, 16U, 32U}) {
    const auto partitions = trajectory::partition_cpu_nonce_range(
        nonce_count, threads);
    REQUIRE_EQ(partitions.size(), threads);
    std::uint64_t cursor = 0U;
    for (const auto& partition : partitions) {
      REQUIRE_EQ(partition.nonce_start, cursor);
      REQUIRE(partition.nonce_count > 0U);
      cursor += partition.nonce_count;
    }
    REQUIRE_EQ(cursor, nonce_count);
  }
  const auto result = trajectory::trajectory_cpu_benchmark(4U, 4096U);
  REQUIRE_EQ(result.at("threads").get<std::size_t>(), 4U);
  REQUIRE_EQ(result.at("nonce_count").get<std::uint64_t>(), 4096U);
  REQUIRE(result.at("exact_partition_coverage").get<bool>());
  REQUIRE(!result.at("scientific_ground_truth").get<bool>());
}

TEST_CASE("GPU workers one two and four return the same complete BJE nonce sets") {
  if (!hs::opencl_compiled() || hs::enumerate_gpu_devices().empty()) return;
  std::vector<trajectory::GpuBjeWorkItem> items;
  for (std::size_t i = 0U; i < 3U; ++i) {
    auto header = hs::genesis_header();
    header[68] ^= static_cast<std::uint8_t>(i + 1U);
    items.push_back({"parallel-bje-" + std::to_string(i), header});
  }
  const auto kernel = std::filesystem::path(SRM_SOURCE_DIR) /
      "kernels" / "header_space_map.cl";
  const auto run = [&](const std::size_t workers) {
    return trajectory::run_gpu_workload(items, kernel, "auto", 64U,
        workers, 0U, 65536U, 10U, 128U);
  };
  const auto canonical = [&](const trajectory::GpuWorkloadResult& workload) {
    std::map<std::string, std::vector<std::uint32_t>> sets;
    REQUIRE_EQ(workload.results.size(), items.size());
    for (std::size_t i = 0U; i < workload.results.size(); ++i) {
      const auto& result = workload.results[i];
      REQUIRE_EQ(result.block_id, items[i].block_id);
      auto nonces = result.scan.nonces;
      std::sort(nonces.begin(), nonces.end());
      REQUIRE(std::adjacent_find(nonces.begin(), nonces.end()) == nonces.end());
      REQUIRE_EQ(trajectory::reconstruct_and_sort(
          items[i].header, nonces, 10U, true).size(), nonces.size());
      REQUIRE(sets.emplace(result.block_id, std::move(nonces)).second);
    }
    REQUIRE_EQ(sets.size(), items.size());
    return sets;
  };
  const auto one = canonical(run(1U));
  const auto two = canonical(run(2U));
  const auto four = canonical(run(4U));
  REQUIRE_EQ(one, two);
  REQUIRE_EQ(one, four);
}

TEST_CASE("trajectory throughput benchmark leaves its frozen campaign byte-identical") {
  if (!hs::opencl_compiled() || hs::enumerate_gpu_devices().empty()) return;
  const auto root = unique_temp("srm_trajectory_throughput_readonly");
  std::filesystem::create_directories(root);
  const auto archive_path = root / "archive.jsonl";
  { std::ofstream output(archive_path); output << "frozen test archive\n"; }
  const auto kernel = std::filesystem::path(SRM_SOURCE_DIR) /
      "kernels" / "header_space_map.cl";
  const auto plan = trajectory::make_plan(
      fake_archive(4U), {2U, 42U, 2U}, benchmark());
  const auto campaign = trajectory::create_campaign(
      plan, root, archive_path, kernel, "traj_throughput_readonly");
  const auto manifest = srm::checkpoint::StateStore(campaign / "manifest.json")
      .load_or(nlohmann::json());
  const auto before = directory_snapshot(campaign);
  const auto result = trajectory::trajectory_throughput_benchmark(
      campaign, kernel, "auto", 64U, {2U, 2U, 4096U});
  const auto after = directory_snapshot(campaign);
  REQUIRE_EQ(before, after);
  REQUIRE_EQ(result.at("bje_count").get<std::size_t>(), 2U);
  REQUIRE_EQ(result.at("gpu_workers").get<std::size_t>(), 2U);
  REQUIRE_EQ(result.at("first_block_id").get<std::string>(),
             manifest.at("blocks").at(0U).at("block_id").get<std::string>());
  REQUIRE_EQ(result.at("last_block_id").get<std::string>(),
             manifest.at("blocks").at(1U).at("block_id").get<std::string>());
  REQUIRE_EQ(result.at("ordered_block_ids_sha256").get<std::string>().size(), 64U);
  REQUIRE(result.at("exact_cpu_verification").get<bool>());
  REQUIRE(!result.at("scientific_ground_truth").get<bool>());
  std::filesystem::remove_all(root);
}

TEST_CASE("Y sorting is numeric with deterministic nonce tie break") {
  hs::PowValue a{}, b{};
  a[7] = 4U; b[7] = 5U;
  std::vector<trajectory::YHit> hits{{9U, b}, {7U, a}, {3U, a}};
  trajectory::sort_y_hits(hits);
  REQUIRE_EQ(hits[0].nonce, 3U);
  REQUIRE_EQ(hits[1].nonce, 7U);
  REQUIRE_EQ(hits[2].nonce, 9U);
}

TEST_CASE("trajectory cohorts have exact ranks and deterministic non-T20 controls") {
  std::vector<trajectory::YHit> sorted;
  for (std::uint32_t i = 0; i < 600U; ++i) {
    hs::PowValue y{}; y[7] = i + 1U;
    sorted.push_back({i, y});
  }
  const auto first = trajectory::select_cohorts(hs::genesis_header(), sorted, 77U, "block");
  const auto second = trajectory::select_cohorts(hs::genesis_header(), sorted, 77U, "block");
  REQUIRE_EQ(first.size(), 768U);
  REQUIRE_EQ(second.size(), first.size());
  std::map<std::string, std::size_t> counts;
  for (std::size_t i = 0; i < first.size(); ++i) {
    ++counts[first[i].cohort];
    REQUIRE_EQ(first[i].cohort, second[i].cohort);
    REQUIRE_EQ(first[i].hit.nonce, second[i].hit.nonce);
    if (first[i].cohort == "RANDOM_CONTROL") {
      REQUIRE(!first[i].y_rank.has_value());
      REQUIRE(!hs::below_power_of_two_threshold(first[i].hit.y, 20U));
    }
  }
  REQUIRE_EQ(counts["EXTREME"], 16U);
  REQUIRE_EQ(counts["VERY_GOOD"], 48U);
  REQUIRE_EQ(counts["GOOD"], 192U);
  REQUIRE_EQ(counts["T20_CONTROL"], 256U);
  REQUIRE_EQ(counts["RANDOM_CONTROL"], 256U);
}

TEST_CASE("BJE selection is exact deterministic diverse and seed-sensitive") {
  const auto archive = fake_archive(20U, 3U);
  const auto first = trajectory::make_plan(archive, {16U, 123U}, benchmark());
  const auto repeat = trajectory::make_plan(archive, {16U, 123U}, benchmark());
  const auto changed = trajectory::make_plan(archive, {16U, 124U}, benchmark());
  REQUIRE_EQ(first.blocks.size(), 16U);
  std::set<std::string> groups, identities, repeated, changed_ids;
  for (const auto& block : first.blocks) { groups.insert(block.context.job.prevhash); identities.insert(block.block_id); }
  for (const auto& block : repeat.blocks) repeated.insert(block.block_id);
  for (const auto& block : changed.blocks) changed_ids.insert(block.block_id);
  REQUIRE_EQ(groups.size(), 8U);
  REQUIRE_EQ(identities, repeated);
  REQUIRE(identities != changed_ids);
}

TEST_CASE("trajectory partitions never split a complete prevhash") {
  const auto plan = trajectory::make_plan(fake_archive(40U), {128U, 998U}, benchmark());
  std::map<std::string, std::string> owners;
  for (const auto& block : plan.blocks) {
    const auto found = owners.find(block.context.job.prevhash);
    REQUIRE(found == owners.end() || found->second == block.partition);
    owners[block.context.job.prevhash] = block.partition;
  }
  REQUIRE_EQ(plan.blocks.size(), 128U);
}

TEST_CASE("frozen trajectory manifest is independent from later archive appends") {
  const auto root = unique_temp("srm_trajectory_frozen");
  std::filesystem::create_directories(root);
  const auto archive_path = root / "archive.jsonl";
  { std::ofstream output(archive_path); output << "initial\n"; }
  const auto plan = trajectory::make_plan(fake_archive(8U), {8U, 42U}, benchmark());
  const auto campaign = trajectory::create_campaign(plan, root, archive_path,
      std::filesystem::path(SRM_SOURCE_DIR) / "kernels" / "header_space_map.cl", "traj_test_frozen");
  const auto before = srm::checkpoint::StateStore(campaign / "manifest.json").load_or({});
  { std::ofstream output(archive_path, std::ios::app); output << "later\n"; }
  const auto after = srm::checkpoint::StateStore(campaign / "manifest.json").load_or({});
  REQUIRE_EQ(before.at("blocks"), after.at("blocks"));
  REQUIRE_EQ(before.at("planned_bje").get<std::size_t>(), 8U);
  std::filesystem::remove_all(root);
}

TEST_CASE("capture completeness requires checksum and rejects corruption") {
  const auto root = unique_temp("srm_trajectory_checksum");
  std::filesystem::create_directories(root / "captures");
  const auto id = std::string(64U, 'a');
  const auto path = root / "captures" / (id + ".t20.bin");
  trajectory::write_capture_atomic(path, {1U, 9U, 27U});
  const nlohmann::json block{{"block_id", id}, {"partition", "discovery"}};
  srm::checkpoint::StateStore(root / "captures" / (id + ".json")).save({
      {"block_id", id}, {"partition", "discovery"},
      {"status", "COMPLETE"}, {"scan_complete", true}, {"overflow", false},
      {"cpu_verification_complete", true}, {"duplicate_count", 0},
      {"nonce_count", hs::kNonceSpaceSize}, {"threshold_bits", 20},
      {"observed_t20_count", 3}, {"cpu_verification_count", 3},
      {"total_hit_count", 3}, {"captured_count", 3},
      {"capture_sha256", trajectory::file_sha256(path)}});
  REQUIRE(trajectory::capture_is_complete(root, block));
  { std::ofstream output(path, std::ios::binary | std::ios::app); output.put('x'); }
  REQUIRE(!trajectory::capture_is_complete(root, block));
  std::filesystem::remove_all(root);
}

TEST_CASE("resume does not rescan a checksum-valid complete BJE") {
  const auto root = unique_temp("srm_trajectory_resume");
  std::filesystem::create_directories(root / "captures");
  std::filesystem::create_directories(root / "analysis_discovery_v1");
  const auto id = std::string(64U, 'b');
  const auto binary = root / "captures" / (id + ".t20.bin");
  trajectory::write_capture_atomic(binary, {5U, 17U});
  const nlohmann::json block{{"block_id", id}, {"partition", "validation"}};
  srm::checkpoint::StateStore(root / "captures" / (id + ".json")).save({
      {"block_id", id}, {"partition", "validation"}, {"status", "COMPLETE"},
      {"scan_complete", true}, {"overflow", false}, {"cpu_verification_complete", true},
      {"duplicate_count", 0}, {"nonce_count", hs::kNonceSpaceSize}, {"threshold_bits", 20},
      {"observed_t20_count", 2}, {"cpu_verification_count", 2}, {"total_hit_count", 2},
      {"captured_count", 2}, {"elapsed_seconds", 1.0}, {"cpu_verify_seconds", 0.1},
      {"overflow_retries", 0}, {"capture_sha256", trajectory::file_sha256(binary)}});
  srm::checkpoint::StateStore(root / "manifest.json").save({
      {"experiment", "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY"}, {"campaign_id", "traj_resume"},
      {"capture", {{"threshold_bits", 20}}}, {"planned_bje", 1},
      {"plan_preview", {{"estimated_seconds", 1.0}}},
      {"blocks", nlohmann::json::array({block})}});
  srm::checkpoint::StateStore(root / "checkpoint.json").save({
      {"status", "COMPLETE"}, {"checkpoint_count", 1}});
  const auto checksum = trajectory::file_sha256(binary);
  REQUIRE_EQ(trajectory::resume_campaign(root, root / "no-kernel.cl", "no-device", 64U), 0);
  REQUIRE_EQ(trajectory::file_sha256(binary), checksum);
  REQUIRE(!std::filesystem::exists(std::filesystem::path(binary.string() + ".invalid")));
  std::filesystem::remove_all(root);
}

TEST_CASE("incomplete resume rejects a changed frozen kernel before GPU access") {
  const auto root = unique_temp("srm_trajectory_kernel_guard");
  std::filesystem::create_directories(root);
  const auto kernel_a = root / "kernel_a.cl";
  const auto kernel_b = root / "kernel_b.cl";
  { std::ofstream output(kernel_a); output << "kernel A\n"; }
  { std::ofstream output(kernel_b); output << "kernel B\n"; }
  const auto id = std::string(64U, 'c');
  srm::checkpoint::StateStore(root / "manifest.json").save({
      {"experiment", "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY"}, {"campaign_id", "traj_kernel_guard"},
      {"capture", {{"threshold_bits", 20}}}, {"planned_bje", 1},
      {"kernel", {{"sha256", trajectory::file_sha256(kernel_a)}}},
      {"blocks", nlohmann::json::array({{{"block_id", id}, {"partition", "validation"}}})}});
  srm::checkpoint::StateStore(root / "checkpoint.json").save({{"status", "RUNNING"}});
  REQUIRE(throws_with([&] {
    (void)trajectory::resume_campaign(root, kernel_b, "GPU must not be opened", 64U);
  }, "OpenCL kernel SHA-256 differs from frozen manifest"));
  std::filesystem::remove_all(root);
}

TEST_CASE("compact prevhash effects equal the legacy BJE grouped definition") {
  struct LegacyEffect { std::size_t prevhash; double rank; double ks; };
  const std::vector<LegacyEffect> legacy{
      {0U, 0.2, 0.1}, {0U, 0.4, 0.3},
      {1U, -0.5, 0.4},
      {2U, 0.1, 0.2}, {2U, 0.7, 0.6}, {2U, 0.4, 0.1}};
  std::vector<trajectory::PrevhashEffectAccumulator> compact(3U);
  for (const auto& effect : legacy)
    trajectory::accumulate_effect(compact[effect.prevhash], effect.rank, effect.ks);
  const std::uint64_t seed = 0x12345678U;
  const auto observed = trajectory::aggregate_prevhash_effects(compact, seed);

  std::vector<double> legacy_rank, legacy_ks;
  for (std::size_t prevhash = 0; prevhash < compact.size(); ++prevhash) {
    double sum_rank = 0.0, sum_ks = 0.0;
    std::size_t count = 0U;
    for (const auto& effect : legacy) if (effect.prevhash == prevhash) {
      sum_rank += effect.rank; sum_ks += effect.ks; ++count;
    }
    legacy_rank.push_back(sum_rank / count);
    legacy_ks.push_back(sum_ks / count);
  }
  const auto legacy_mean = [](const std::vector<double>& values) {
    return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
  };
  auto sorted_rank = legacy_rank;
  std::sort(sorted_rank.begin(), sorted_rank.end());
  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<std::size_t> choose(0U, legacy_rank.size() - 1U);
  std::vector<double> bootstrap;
  for (std::size_t replicate = 0; replicate < trajectory::kBootstrapReplicates; ++replicate) {
    double sum = 0.0;
    for (std::size_t i = 0; i < legacy_rank.size(); ++i) sum += legacy_rank[choose(rng)];
    bootstrap.push_back(sum / legacy_rank.size());
  }
  std::sort(bootstrap.begin(), bootstrap.end());
  REQUIRE_EQ(observed.prevhash_count, 3U);
  REQUIRE_EQ(observed.bje_count, legacy.size());
  REQUIRE(std::abs(observed.mean_rank_biserial - legacy_mean(legacy_rank)) < 1e-15);
  REQUIRE(std::abs(observed.median_rank_biserial - sorted_rank[1]) < 1e-15);
  REQUIRE(std::abs(observed.mean_ks - legacy_mean(legacy_ks)) < 1e-15);
  REQUIRE_EQ(observed.bootstrap_ci_low,
      bootstrap[static_cast<std::size_t>(0.025 * (bootstrap.size() - 1U))]);
  REQUIRE_EQ(observed.bootstrap_ci_high,
      bootstrap[static_cast<std::size_t>(0.975 * (bootstrap.size() - 1U))]);
}

TEST_CASE("validation and holdout BJE export and trace are sealed") {
  for (const auto* partition : {"validation", "holdout"}) {
    const auto root = unique_temp(std::string("srm_trajectory_guard_") + partition);
    std::filesystem::create_directories(root);
    const auto id = std::string(64U, partition[0]);
    srm::checkpoint::StateStore(root / "manifest.json").save({
        {"experiment", "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY"},
        {"blocks", nlohmann::json::array({{{"block_id", id}, {"partition", partition}}})}});
    REQUIRE(throws_with([&] { (void)trajectory::export_bje(root, id); }, "sealed"));
    REQUIRE(throws_with([&] { (void)trajectory::trace_bjen(root, id, 0U); }, "sealed"));
    std::filesystem::remove_all(root);
  }
}

TEST_CASE("trajectory analysis reads discovery only and leaves sealed partitions untouched") {
  const auto root = unique_temp("srm_trajectory_analysis_sealed");
  std::filesystem::create_directories(root);
  const auto val = nlohmann::json{{"block_id", std::string(64U, 'v')}, {"partition", "validation"}};
  const auto hold = nlohmann::json{{"block_id", std::string(64U, 'h')}, {"partition", "holdout"}};
  srm::checkpoint::StateStore(root / "manifest.json").save({
      {"experiment", "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY"}, {"campaign_id", "traj_sealed"},
      {"seed", 1}, {"blocks", nlohmann::json::array({val, hold})}});
  srm::checkpoint::StateStore(root / "checkpoint.json").save({{"status", "COMPLETE"}});
  const auto summary = trajectory::analyze_campaign(root);
  REQUIRE_EQ(summary.at("analyzed_bje").get<std::size_t>(), 0U);
  REQUIRE(!summary.at("validation_opened").get<bool>());
  REQUIRE(!summary.at("holdout_opened").get<bool>());
  REQUIRE(std::filesystem::exists(root / "analysis_discovery_v1" / "selected_bjen.csv"));
  const auto schema = srm::checkpoint::StateStore(
      root / "analysis_discovery_v1" / "trajectory_feature_schema.json").load_or({});
  std::map<std::string, std::string> families;
  for (const auto& feature : schema.at("features")) {
    families.emplace(feature.at("name").get<std::string>(),
                     feature.at("family").get<std::string>());
  }
  std::size_t exact_carry_count = 0U;
  for (const auto* addition : {"T1", "T2", "new_e", "new_a"}) {
    for (const auto* suffix : {"carry_count", "maximum_chain", "chain_count", "carry_mask_popcount"}) {
      REQUIRE_EQ(families.at(std::string(addition) + '_' + suffix), "EXACT_CARRIES");
      ++exact_carry_count;
    }
  }
  REQUIRE_EQ(exact_carry_count, 16U);
  std::filesystem::remove_all(root);
}

TEST_CASE("white-box trajectory replay maps exactly 192 global rounds and reproduces Y") {
  auto header = hs::genesis_header();
  const auto expected = hs::pow_value(srm::crypto::sha256d(header));
  const auto trace = srm::crypto::trace_reduced_sha256d(header, 64U);
  const auto features = trajectory::extract_trajectory_features(trace);
  REQUIRE_EQ(features.size(), 192U);
  REQUIRE_EQ(features.front().global_round, 0U);
  REQUIRE_EQ(features[63].sha_pass, 1U);
  REQUIRE_EQ(features[64].compression_index, 1U);
  REQUIRE_EQ(features[127].global_round, 127U);
  REQUIRE_EQ(features[128].sha_pass, 2U);
  REQUIRE_EQ(features.back().global_round, 191U);
  REQUIRE_EQ(features.back().local_round, 63U);
  REQUIRE_EQ(features.front().values.size(), trajectory::trajectory_feature_names().size());
  REQUIRE_EQ(hs::pow_value(trace.digest), expected);
}
