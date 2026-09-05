#include "research/context_trajectory.h"

#include "checkpoint/state_store.h"
#include "crypto/sha256.h"
#include "crypto/sha256d.h"
#include "logging/result_logger.h"
#include "research/sha256d_whitebox.h"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace srm::research::context_trajectory {
namespace {

constexpr std::array<std::uint32_t, 64> kSha256Constants{
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};

void require(const bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

std::uint64_t derived_seed(const std::uint64_t seed, const std::string& text) {
  const auto material = std::to_string(seed) + ":" + text;
  const auto digest = crypto::sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(material.data()), material.size()));
  std::uint64_t result = 0;
  for (std::size_t i = 0; i < 8U; ++i) result = (result << 8U) | digest[i];
  return result;
}

std::string utc_compact() {
  const auto now = std::chrono::system_clock::now();
  const auto value = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &value);
#else
  gmtime_r(&value, &utc);
#endif
  std::ostringstream output;
  output << std::put_time(&utc, "%Y%m%d_%H%M%S");
  return output.str();
}

std::string hex_u64(const std::uint64_t value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0') << std::setw(16) << value;
  return output.str();
}

std::string hex_u32(const std::uint32_t value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0') << std::setw(8) << value;
  return output.str();
}

std::uint32_t read_le32(const std::uint8_t* bytes) {
  return static_cast<std::uint32_t>(bytes[0]) |
      (static_cast<std::uint32_t>(bytes[1]) << 8U) |
      (static_cast<std::uint32_t>(bytes[2]) << 16U) |
      (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

nlohmann::json archived_json(const context_campaign::ArchivedContext& context) {
  const auto& job = context.job;
  return {{"received_timestamp_utc", context.received_timestamp_utc},
          {"work_fingerprint", context.work_fingerprint},
          {"subscription", {{"extranonce1", context.extranonce1},
                            {"extranonce2_size", context.extranonce2_size}}},
          {"stratum_job", {{"job_id", job.job_id}, {"prevhash", job.prevhash},
                           {"coinbase1", job.coinbase1}, {"coinbase2", job.coinbase2},
                           {"merkle_branches", job.merkle_branches}, {"version", job.version},
                           {"nbits", job.nbits}, {"ntime", job.ntime},
                           {"clean_jobs", job.clean_jobs}}}};
}

context_campaign::ArchivedContext context_from_json(const nlohmann::json& value) {
  context_campaign::ArchivedContext result;
  const auto& job = value.at("stratum_job");
  result.job = stratum::parse_notify(nlohmann::json::array({
      job.at("job_id"), job.at("prevhash"), job.at("coinbase1"), job.at("coinbase2"),
      job.at("merkle_branches"), job.at("version"), job.at("nbits"), job.at("ntime"),
      job.at("clean_jobs")}));
  result.received_timestamp_utc = value.value("received_timestamp_utc", "");
  result.work_fingerprint = value.at("work_fingerprint").get<std::string>();
  result.extranonce1 = value.at("subscription").at("extranonce1").get<std::string>();
  result.extranonce2_size = value.at("subscription").at("extranonce2_size").get<unsigned>();
  return result;
}

bitcoin::Header block_header(const nlohmann::json& block) {
  auto bytes = crypto::from_hex(block.at("header_prefix_76_bytes_hex").get<std::string>());
  require(bytes.size() == 76U, "frozen header prefix is not 76 bytes");
  bitcoin::Header header{};
  std::copy(bytes.begin(), bytes.end(), header.begin());
  bitcoin::set_nonce(header, 0U);
  return header;
}

const nlohmann::json& find_block(const nlohmann::json& manifest,
                                 const std::string& block_id) {
  for (const auto& block : manifest.at("blocks")) {
    if (block.at("block_id").get<std::string>() == block_id) return block;
  }
  throw std::invalid_argument("unknown trajectory block_id: " + block_id);
}

void require_discovery(const nlohmann::json& block, const char* operation) {
  const auto partition = block.at("partition").get<std::string>();
  if (partition != "discovery") {
    throw std::invalid_argument(std::string(operation) + " refuses partition " + partition +
                                "; validation and holdout are sealed");
  }
}

void csv_field(std::ostream& output, const std::string& field) {
  const bool quote = field.find_first_of(",\"\r\n") != std::string::npos;
  if (!quote) { output << field; return; }
  output << '"';
  for (const auto c : field) output << (c == '"' ? "\"\"" : std::string(1, c));
  output << '"';
}

void csv_row(std::ostream& output, const std::vector<std::string>& fields) {
  for (std::size_t i = 0; i < fields.size(); ++i) {
    if (i) output << ',';
    csv_field(output, fields[i]);
  }
  output << '\n';
}

double quality_bits(const header_space::PowValue& value) {
  return context_campaign::quality_bits(value);
}

double normalized_word(const std::uint32_t value) {
  return static_cast<double>(value) / static_cast<double>(0xffffffffU);
}

unsigned transitions(const std::uint32_t value) {
  return std::popcount((value ^ (value >> 1U)) & 0x7fffffffU);
}

struct CarryFeatures { unsigned count{}, maximum_chain{}, chain_count{}, mask_popcount{}; };

CarryFeatures carry_features(const std::initializer_list<std::uint32_t> operands) {
  std::uint64_t carry = 0;
  bool in_chain = false;
  unsigned chain = 0;
  CarryFeatures result;
  for (unsigned bit = 0; bit < 32U; ++bit) {
    std::uint64_t column = carry;
    for (const auto operand : operands) column += (operand >> bit) & 1U;
    carry = column >> 1U;
    if (carry != 0U) {
      ++result.count;
      ++result.mask_popcount;
      if (!in_chain) { in_chain = true; ++result.chain_count; chain = 0; }
      ++chain;
      result.maximum_chain = std::max(result.maximum_chain, chain);
    } else {
      in_chain = false;
      chain = 0;
    }
  }
  return result;
}

void add_word_features(std::vector<double>& values, const std::uint32_t word) {
  values.push_back(normalized_word(word));
  values.push_back(static_cast<double>(std::popcount(word)));
  values.push_back(static_cast<double>(transitions(word)));
}

void add_carry_features(std::vector<double>& values, const CarryFeatures& carry) {
  values.push_back(carry.count);
  values.push_back(carry.maximum_chain);
  values.push_back(carry.chain_count);
  values.push_back(carry.mask_popcount);
}

std::vector<std::uint32_t> unique_sorted(std::vector<std::uint32_t> values,
                                         std::size_t* duplicates = nullptr) {
  std::sort(values.begin(), values.end());
  const auto original = values.size();
  values.erase(std::unique(values.begin(), values.end()), values.end());
  if (duplicates) *duplicates = original - values.size();
  return values;
}

void write_text_exclusive(const std::filesystem::path& path, const std::string& data) {
  if (std::filesystem::exists(path)) throw std::runtime_error("immutable output already exists: " + path.string());
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("cannot create " + path.string());
  output << data;
  if (!output) throw std::runtime_error("cannot finish " + path.string());
}

void write_nonce_file(const std::filesystem::path& path,
                      const std::vector<std::uint32_t>& sorted_nonces) {
  if (!std::is_sorted(sorted_nonces.begin(), sorted_nonces.end()) ||
      std::adjacent_find(sorted_nonces.begin(), sorted_nonces.end()) != sorted_nonces.end()) {
    throw std::invalid_argument("capture nonces must be unique and numeric ascending");
  }
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("cannot create capture " + path.string());
  for (const auto nonce : sorted_nonces) {
    const std::array<char, 4> bytes{static_cast<char>(nonce), static_cast<char>(nonce >> 8U),
                                    static_cast<char>(nonce >> 16U), static_cast<char>(nonce >> 24U)};
    output.write(bytes.data(), bytes.size());
  }
  output.flush();
  if (!output) throw std::runtime_error("cannot flush capture " + path.string());
}

std::string code_version() {
#ifdef SRM_CODE_VERSION
  return SRM_CODE_VERSION;
#else
  return "unavailable";
#endif
}

}  // namespace

Plan make_plan(const std::vector<context_campaign::ArchivedContext>& archive,
               Request request,
               context_campaign::BenchmarkResult benchmark) {
  if (request.bje_count == 0U) throw std::invalid_argument("--bje must be a positive integer");
  if (request.bje_count > std::numeric_limits<std::uint64_t>::max() /
                              header_space::kNonceSpaceSize) {
    throw std::invalid_argument("--bje is too large to represent planned hashes exactly");
  }
  if (archive.empty()) throw std::invalid_argument("cannot select BJE from an empty archive");
  std::map<std::string, std::vector<const context_campaign::ArchivedContext*>> grouped;
  for (const auto& context : archive) grouped[context.job.prevhash].push_back(&context);
  for (auto& [unused, contexts] : grouped) {
    std::stable_sort(contexts.begin(), contexts.end(), [](const auto* left, const auto* right) {
      if (left->received_timestamp_utc != right->received_timestamp_utc)
        return left->received_timestamp_utc < right->received_timestamp_utc;
      return left->work_fingerprint < right->work_fingerprint;
    });
  }
  std::vector<std::string> prevhashes;
  for (const auto& [prevhash, unused] : grouped) prevhashes.push_back(prevhash);
  std::mt19937_64 rng(request.seed);
  std::shuffle(prevhashes.begin(), prevhashes.end(), rng);
  const auto ideal_groups = request.bje_count <= 16U
      ? (request.bje_count + 1U) / 2U
      : (request.bje_count + 7U) / 8U;
  const auto wanted_groups = static_cast<std::size_t>(std::min<std::uint64_t>(
      prevhashes.size(), std::max<std::uint64_t>(1U, ideal_groups)));
  prevhashes.resize(wanted_groups);

  Plan plan;
  plan.request = request;
  plan.benchmark = std::move(benchmark);
  if (wanted_groups < ideal_groups) {
    plan.warnings.push_back("archive diversity is below the ideal prevhash target; exact N is retained and spread over available groups");
  }
  std::vector<std::size_t> quotas(wanted_groups, 0U);
  for (std::uint64_t i = 0; i < request.bje_count; ++i) ++quotas[static_cast<std::size_t>(i % wanted_groups)];

  struct Pending { PlannedBje block; std::size_t group_index{}; };
  std::vector<Pending> pending;
  for (std::size_t group_index = 0; group_index < wanted_groups; ++group_index) {
    const auto& contexts = grouped.at(prevhashes[group_index]);
    std::vector<std::size_t> per_context(contexts.size(), 0U);
    for (std::size_t i = 0; i < quotas[group_index]; ++i) ++per_context[i % contexts.size()];
    for (std::size_t context_index = 0; context_index < contexts.size(); ++context_index) {
      if (per_context[context_index] == 0U) continue;
      const auto* context = contexts[context_index];
      const auto extranonces = context_campaign::sample_extranonce2(
          request.seed, context->work_fingerprint, context->extranonce2_size,
          per_context[context_index]);
      for (const auto& extranonce2 : extranonces) {
        const auto work = stratum::build_work(context->job, context->extranonce1, extranonce2, 0U);
        Pending item;
        item.group_index = group_index;
        item.block.context = *context;
        item.block.extranonce2 = extranonce2;
        item.block.block_id = context_campaign::block_id(*context, extranonce2);
        item.block.header_prefix_hex = crypto::to_hex(
            std::span<const std::uint8_t>(work.header.data(), 76U));
        item.block.merkle_root = crypto::bitcoin_hash_hex(work.merkle_root);
        pending.push_back(std::move(item));
      }
    }
  }
  require(pending.size() == request.bje_count, "BJE selector failed to retain exact requested N");

  // Whole-prevhash deterministic weighted assignment. The group BJE count is
  // the indivisible unit, while deficits target 50/25/25.
  std::vector<std::size_t> group_order(wanted_groups);
  std::iota(group_order.begin(), group_order.end(), 0U);
  std::mt19937_64 partition_rng(derived_seed(request.seed, "trajectory-partitions"));
  std::shuffle(group_order.begin(), group_order.end(), partition_rng);
  const std::array<double, 3> fractions{0.50, 0.25, 0.25};
  const std::array<std::string, 3> names{"discovery", "validation", "holdout"};
  std::array<std::uint64_t, 3> assigned{};
  std::vector<std::string> group_partition(wanted_groups);
  for (const auto group : group_order) {
    std::size_t best = 0U;
    double best_deficit = -std::numeric_limits<double>::infinity();
    for (std::size_t p = 0; p < names.size(); ++p) {
      const auto deficit = fractions[p] * static_cast<double>(request.bje_count) - assigned[p];
      if (deficit > best_deficit) { best_deficit = deficit; best = p; }
    }
    group_partition[group] = names[best];
    assigned[best] += quotas[group];
  }
  for (auto& item : pending) {
    item.block.partition = group_partition[item.group_index];
    plan.blocks.push_back(std::move(item.block));
  }
  std::stable_sort(plan.blocks.begin(), plan.blocks.end(), [](const auto& left, const auto& right) {
    if (left.partition != right.partition) return left.partition < right.partition;
    if (left.context.job.prevhash != right.context.job.prevhash)
      return left.context.job.prevhash < right.context.job.prevhash;
    return left.block_id < right.block_id;
  });
  plan.total_hashes = request.bje_count * header_space::kNonceSpaceSize;
  plan.estimated_seconds = plan.benchmark.hashes_per_second > 0.0
      ? static_cast<double>(plan.total_hashes) / plan.benchmark.hashes_per_second : 0.0;
  plan.estimated_storage_bytes = request.bje_count * (4096U * 4U + 8192U);
  return plan;
}

nlohmann::json plan_preview_json(const Plan& plan) {
  std::map<std::string, std::size_t> by_prevhash, by_context, partitions;
  for (const auto& block : plan.blocks) {
    ++by_prevhash[block.context.job.prevhash];
    ++by_context[block.context.work_fingerprint];
    ++partitions[block.partition];
  }
  const auto extrema = [](const auto& counts) {
    std::size_t low = std::numeric_limits<std::size_t>::max(), high = 0U;
    for (const auto& [unused, count] : counts) { low = std::min(low, count); high = std::max(high, count); }
    return std::pair{counts.empty() ? 0U : low, high};
  };
  const auto [prev_low, prev_high] = extrema(by_prevhash);
  const auto [context_low, context_high] = extrema(by_context);
  return {{"requested_bje", plan.request.bje_count}, {"seed", plan.request.seed},
          {"distinct_prevhashes", by_prevhash.size()}, {"stratum_contexts", by_context.size()},
          {"bje_per_prevhash_min", prev_low}, {"bje_per_prevhash_max", prev_high},
          {"bje_per_context_min", context_low}, {"bje_per_context_max", context_high},
          {"total_hashes", plan.total_hashes}, {"estimated_seconds", plan.estimated_seconds},
          {"estimated_storage_bytes", plan.estimated_storage_bytes},
          {"threshold", "T20"}, {"threshold_bits", kProductionThresholdBits},
          {"partitions", partitions}, {"benchmark", {{"backend", plan.benchmark.backend},
              {"device", plan.benchmark.device}, {"hashes_per_second", plan.benchmark.hashes_per_second}}},
          {"warnings", plan.warnings}};
}

std::filesystem::path create_campaign(const Plan& plan,
                                      const std::filesystem::path& output_root,
                                      const std::filesystem::path& archive_source,
                                      const std::filesystem::path& kernel_source,
                                      const std::string& requested_id) {
  require(plan.blocks.size() == plan.request.bje_count, "trajectory plan is not exact N");
  const auto id = requested_id.empty()
      ? "traj_" + utc_compact() + "_" + hex_u64(plan.request.seed).substr(8U)
      : requested_id;
  const auto directory = output_root / id;
  if (std::filesystem::exists(directory)) throw std::runtime_error("trajectory campaign already exists: " + directory.string());
  std::filesystem::create_directories(directory / "captures");
  nlohmann::json blocks = nlohmann::json::array();
  for (const auto& selected : plan.blocks) {
    auto frozen = archived_json(selected.context);
    frozen["block_id"] = selected.block_id;
    frozen["partition"] = selected.partition;
    frozen["extranonce2"] = selected.extranonce2;
    frozen["header_prefix_76_bytes_hex"] = selected.header_prefix_hex;
    frozen["merkle_root"] = selected.merkle_root;
    blocks.push_back(std::move(frozen));
  }
  const auto manifest = nlohmann::json{
      {"schema_version", 1}, {"experiment", "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY"},
      {"campaign_id", id}, {"created_at_utc", logging::ResultLogger::utc_now()},
      {"code_version", code_version()}, {"seed", plan.request.seed},
      {"archive", {{"path", std::filesystem::absolute(archive_source).string()},
                   {"sha256", file_sha256(archive_source)}, {"frozen_at_creation", true}}},
      {"planned_bje", plan.request.bje_count}, {"planned_hashes", plan.total_hashes},
      {"selection_policy", "seeded maximum prevhash diversity; balanced contexts; stratified extranonce2; no Phase 2 score"},
      {"partitions", {{"unit", "complete_prevhash"}, {"discovery_fraction", 0.50},
                      {"validation_fraction", 0.25}, {"holdout_fraction", 0.25},
                      {"validation_sealed", true}, {"holdout_sealed", true}}},
      {"capture", {{"threshold", "T20"}, {"threshold_bits", 20},
                   {"predicate", "Y < 2^236"}, {"expected_hits_per_complete_bje", 4096},
                   {"nonce_start", 0}, {"nonce_count", header_space::kNonceSpaceSize},
                   {"record", "uint32 nonce only"}, {"record_endian", "little-endian"},
                   {"order", "numeric nonce ascending, never Y order"},
                   {"initial_capacity", kInitialSparseCapacity},
                   {"overflow_policy", "reject and rescan with doubled capacity until complete"}}},
      {"cohorts", {{"EXTREME", "Y ranks 1..16"}, {"VERY_GOOD", "Y ranks 17..64"},
                   {"GOOD", "Y ranks 65..256"},
                   {"T20_CONTROL", "256 deterministic without replacement from ranks 257..end"},
                   {"RANDOM_CONTROL", "256 deterministic unique non-T20 from same BJE"}}},
      {"analysis", {{"scope", "discovery_only"}, {"status", "exploratory_not_validated"},
                    {"input_order_permutations", kInputOrderPermutations},
                    {"bootstrap_replicates", kBootstrapReplicates},
                    {"bootstrap_unit", "complete_prevhash"}}},
      {"kernel", {{"path", std::filesystem::absolute(kernel_source).string()},
                  {"sha256", file_sha256(kernel_source)}}},
      {"benchmark", {{"backend", plan.benchmark.backend}, {"device", plan.benchmark.device},
                     {"hashes", plan.benchmark.hashes}, {"seconds", plan.benchmark.seconds},
                     {"hashes_per_second", plan.benchmark.hashes_per_second}}},
      {"plan_preview", plan_preview_json(plan)}, {"blocks", blocks}};
  checkpoint::StateStore(directory / "manifest.json").save(manifest);
  checkpoint::StateStore(directory / "checkpoint.json").save({
      {"schema_version", 1}, {"campaign_id", id}, {"status", "PLANNED"},
      {"completed_bje", 0}, {"total_bje", plan.request.bje_count}, {"checkpoint_count", 0}});
  checkpoint::StateStore(directory / "audit.json").save({
      {"schema_version", 1}, {"campaign_id", id}, {"phase2_outputs_modified", false},
      {"phase2_scores_used_for_selection", false}, {"validation_opened", false},
      {"holdout_opened", false}, {"scientific_status", "DISCOVERY_EXPLORATORY_NOT_VALIDATED"}});
  write_text_exclusive(directory / "report.md",
      "# Phase 3 — POST_SCAN Y-SORT / TRAJECTORY\n\n"
      "Campagne planifiée. La capture conserve uniquement les nonces T20; aucun tableau des 2^32 hashes n'est écrit.\n\n"
      "Validation et holdout restent scellés pour l'analyse.\n");
  return directory;
}

std::vector<YHit> reconstruct_and_sort(const bitcoin::Header& input,
                                       const std::vector<std::uint32_t>& nonces,
                                       const unsigned threshold_bits,
                                       const bool require_threshold) {
  std::unordered_set<std::uint32_t> unique;
  std::vector<YHit> result;
  result.reserve(nonces.size());
  auto header = input;
  for (const auto nonce : nonces) {
    if (!unique.insert(nonce).second) throw std::runtime_error("duplicate nonce in sparse capture");
    bitcoin::set_nonce(header, nonce);
    const auto y = header_space::pow_value(crypto::sha256d(header));
    if (require_threshold && !header_space::below_power_of_two_threshold(y, threshold_bits)) {
      throw std::runtime_error("CPU verification rejected a sparse hit");
    }
    result.push_back({nonce, y});
  }
  sort_y_hits(result);
  return result;
}

void sort_y_hits(std::vector<YHit>& result) {
  std::stable_sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
    if (left.y != right.y) return left.y < right.y;
    return left.nonce < right.nonce;
  });
}

std::vector<SelectedBjen> select_cohorts(const bitcoin::Header& header,
                                        const std::vector<YHit>& sorted_t20,
                                        const std::uint64_t seed,
                                        const std::string& block_id,
                                        const std::size_t t20_control_count,
                                        const std::size_t random_control_count) {
  if (sorted_t20.size() < 256U) return {};
  std::vector<SelectedBjen> selected;
  const auto append_range = [&](const std::string& cohort, const std::size_t first, const std::size_t last) {
    for (auto rank = first; rank <= last && rank <= sorted_t20.size(); ++rank)
      selected.push_back({cohort, rank, sorted_t20[rank - 1U]});
  };
  append_range("EXTREME", 1U, 16U);
  append_range("VERY_GOOD", 17U, 64U);
  append_range("GOOD", 65U, 256U);
  std::vector<std::size_t> candidates(sorted_t20.size() - 256U);
  std::iota(candidates.begin(), candidates.end(), 257U);
  std::mt19937_64 control_rng(derived_seed(seed, block_id + ":T20_CONTROL"));
  std::shuffle(candidates.begin(), candidates.end(), control_rng);
  const auto control_n = std::min(t20_control_count, candidates.size());
  for (std::size_t i = 0; i < control_n; ++i) {
    const auto rank = candidates[i];
    selected.push_back({"T20_CONTROL", rank, sorted_t20[rank - 1U]});
  }
  std::unordered_set<std::uint32_t> used;
  std::mt19937_64 random_rng(derived_seed(seed, block_id + ":RANDOM_CONTROL"));
  auto mutable_header = header;
  while (used.size() < random_control_count) {
    const auto nonce = static_cast<std::uint32_t>(random_rng());
    if (!used.insert(nonce).second) continue;
    bitcoin::set_nonce(mutable_header, nonce);
    const auto y = header_space::pow_value(crypto::sha256d(mutable_header));
    if (header_space::below_power_of_two_threshold(y, kProductionThresholdBits)) {
      used.erase(nonce);
      continue;
    }
    selected.push_back({"RANDOM_CONTROL", std::nullopt, {nonce, y}});
  }
  return selected;
}

const std::vector<std::string>& trajectory_feature_names() {
  static const std::vector<std::string> names = [] {
    std::vector<std::string> result;
    const std::array<std::string, 8> states{"a", "b", "c", "d", "e", "f", "g", "h"};
    const std::array<std::string, 7> round{"W", "Sigma0", "Sigma1", "Ch", "Maj", "T1", "T2"};
    const std::array<std::string, 3> word_suffix{"normalized", "popcount", "bit_transitions"};
    for (const auto& state : states) for (const auto& suffix : word_suffix) result.push_back("state_" + state + "_before_" + suffix);
    for (const auto& variable : round) for (const auto& suffix : word_suffix) result.push_back(variable + "_" + suffix);
    const std::array<std::string, 4> additions{"T1", "T2", "new_e", "new_a"};
    const std::array<std::string, 4> carry_suffix{"carry_count", "maximum_chain", "chain_count", "carry_mask_popcount"};
    for (const auto& addition : additions) for (const auto& suffix : carry_suffix) result.push_back(addition + "_" + suffix);
    return result;
  }();
  return names;
}

std::vector<RoundFeatures> extract_trajectory_features(const crypto::ReducedSha256dTrace& trace) {
  require(trace.first_sha.rounds.size() == 128U && trace.second_sha.rounds.size() == 64U,
          "trajectory replay must contain exactly 192 rounds");
  std::vector<RoundFeatures> result;
  result.reserve(192U);
  const auto append = [&](const crypto::Sha256RoundTrace& round, const unsigned global,
                          const unsigned pass, const unsigned compression) {
    RoundFeatures item;
    item.global_round = global;
    item.sha_pass = pass;
    item.compression_index = compression;
    item.local_round = round.round_index;
    item.values.reserve(trajectory_feature_names().size());
    for (const auto state : {round.a_before, round.b_before, round.c_before, round.d_before,
                             round.e_before, round.f_before, round.g_before, round.h_before})
      add_word_features(item.values, state);
    for (const auto variable : {round.w, round.sum0, round.sum1, round.choice,
                                round.majority, round.temp1, round.temp2})
      add_word_features(item.values, variable);
    const auto k = kSha256Constants[round.round_index];
    add_carry_features(item.values, carry_features({round.h_before, round.sum1, round.choice, k, round.w}));
    add_carry_features(item.values, carry_features({round.sum0, round.majority}));
    add_carry_features(item.values, carry_features({round.d_before, round.temp1}));
    add_carry_features(item.values, carry_features({round.temp1, round.temp2}));
    require(item.values.size() == trajectory_feature_names().size(), "trajectory feature schema mismatch");
    result.push_back(std::move(item));
  };
  for (std::size_t i = 0; i < trace.first_sha.rounds.size(); ++i)
    append(trace.first_sha.rounds[i], static_cast<unsigned>(i), 1U, static_cast<unsigned>(i / 64U));
  for (std::size_t i = 0; i < trace.second_sha.rounds.size(); ++i)
    append(trace.second_sha.rounds[i], static_cast<unsigned>(128U + i), 2U, 0U);
  return result;
}

void write_capture_atomic(const std::filesystem::path& path,
                          const std::vector<std::uint32_t>& sorted_nonces) {
  std::filesystem::create_directories(path.parent_path());
  const auto temporary = std::filesystem::path(path.string() + ".tmp");
  if (std::filesystem::exists(path)) throw std::runtime_error("capture already exists: " + path.string());
  write_nonce_file(temporary, sorted_nonces);
  std::filesystem::rename(temporary, path);
}

std::vector<std::uint32_t> read_capture(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot open sparse capture " + path.string());
  input.seekg(0, std::ios::end);
  const auto size = input.tellg();
  if (size < 0 || size % 4 != 0) throw std::runtime_error("invalid sparse capture byte length");
  input.seekg(0);
  std::vector<std::uint32_t> result(static_cast<std::size_t>(size) / 4U);
  for (auto& nonce : result) {
    std::array<unsigned char, 4> bytes{};
    input.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    nonce = static_cast<std::uint32_t>(bytes[0]) |
        (static_cast<std::uint32_t>(bytes[1]) << 8U) |
        (static_cast<std::uint32_t>(bytes[2]) << 16U) |
        (static_cast<std::uint32_t>(bytes[3]) << 24U);
  }
  if (!input) throw std::runtime_error("truncated sparse capture");
  return result;
}

std::string file_sha256(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot checksum " + path.string());
  const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)),
                                        std::istreambuf_iterator<char>());
  return crypto::digest_hex(crypto::sha256(bytes));
}

bool capture_is_complete(const std::filesystem::path& campaign_directory,
                         const nlohmann::json& block) {
  try {
    const auto id = block.at("block_id").get<std::string>();
    const auto binary = campaign_directory / "captures" / (id + ".t20.bin");
    const auto metadata_path = campaign_directory / "captures" / (id + ".json");
    if (!std::filesystem::exists(binary) || !std::filesystem::exists(metadata_path)) return false;
    const auto metadata = checkpoint::StateStore(metadata_path).load_or(nlohmann::json());
    if (metadata.value("status", "") != "COMPLETE" ||
        !metadata.value("scan_complete", false) || metadata.value("overflow", true) ||
        !metadata.value("cpu_verification_complete", false) ||
        metadata.value("duplicate_count", 1U) != 0U ||
        metadata.value("nonce_count", 0ULL) != header_space::kNonceSpaceSize ||
        metadata.value("threshold_bits", 0U) != kProductionThresholdBits) return false;
    if (metadata.value("block_id", "") != id ||
        metadata.value("partition", "") != block.value("partition", "") ||
        metadata.value("cpu_verification_count", 0U) != metadata.value("observed_t20_count", 1U) ||
        metadata.value("total_hit_count", 0U) != metadata.value("observed_t20_count", 1U) ||
        metadata.value("captured_count", 0U) != metadata.value("observed_t20_count", 1U)) return false;
    const auto nonces = read_capture(binary);
    if (nonces.size() != metadata.at("observed_t20_count").get<std::size_t>() ||
        !std::is_sorted(nonces.begin(), nonces.end()) ||
        std::adjacent_find(nonces.begin(), nonces.end()) != nonces.end()) return false;
    return file_sha256(binary) == metadata.at("capture_sha256").get<std::string>();
  } catch (const std::exception&) {
    return false;
  }
}

namespace {

void quarantine_if_present(const std::filesystem::path& path) {
  if (!std::filesystem::exists(path)) return;
  auto destination = std::filesystem::path(path.string() + ".invalid");
  for (unsigned suffix = 1U; std::filesystem::exists(destination); ++suffix)
    destination = std::filesystem::path(path.string() + ".invalid." + std::to_string(suffix));
  std::filesystem::rename(path, destination);
}

void append_report(const std::filesystem::path& directory, const std::string& text) {
  std::ofstream output(directory / "report.md", std::ios::binary | std::ios::app);
  if (!output) throw std::runtime_error("cannot append trajectory report");
  output << text;
  if (!output) throw std::runtime_error("cannot flush trajectory report");
}

void refresh_capture_summary(const std::filesystem::path& directory,
                             const nlohmann::json& manifest) {
  auto captures = nlohmann::json::array();
  std::uint64_t sparse_hits = 0U;
  double scan_seconds = 0.0, verify_seconds = 0.0;
  for (const auto& block : manifest.at("blocks")) {
    if (!capture_is_complete(directory, block)) continue;
    const auto id = block.at("block_id").get<std::string>();
    const auto metadata = checkpoint::StateStore(directory / "captures" / (id + ".json"))
        .load_or(nlohmann::json());
    sparse_hits += metadata.at("observed_t20_count").get<std::uint64_t>();
    scan_seconds += metadata.at("elapsed_seconds").get<double>();
    verify_seconds += metadata.at("cpu_verify_seconds").get<double>();
    captures.push_back({{"block_id", id}, {"partition", block.at("partition")},
                        {"observed_t20_count", metadata.at("observed_t20_count")},
                        {"scan_seconds", metadata.at("elapsed_seconds")},
                        {"cpu_verify_seconds", metadata.at("cpu_verify_seconds")},
                        {"overflow_retries", metadata.at("overflow_retries")},
                        {"capture_sha256", metadata.at("capture_sha256")}});
  }
  const auto baseline_seconds = manifest.at("plan_preview").value("estimated_seconds", 0.0);
  const nlohmann::json overhead = baseline_seconds > 0.0
      ? nlohmann::json(scan_seconds / baseline_seconds - 1.0)
      : nlohmann::json(nullptr);
  checkpoint::StateStore(directory / "capture_summary.json").save({
      {"schema_version", 1}, {"campaign_id", manifest.at("campaign_id")},
      {"complete_captures", captures.size()}, {"sparse_hit_count", sparse_hits},
      {"scan_seconds", scan_seconds}, {"cpu_verify_seconds", verify_seconds},
      {"baseline_estimated_seconds", baseline_seconds}, {"sparse_overhead_ratio", overhead},
      {"captures", captures}});
}

}  // namespace

int resume_campaign(const std::filesystem::path& directory,
                    const std::filesystem::path& kernel,
                    const std::string& device,
                    const std::size_t local_size) {
  const auto manifest = checkpoint::StateStore(directory / "manifest.json").load_or(nlohmann::json());
  require(manifest.value("experiment", "") == "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY",
          "not a Phase 3 trajectory campaign");
  require(manifest.at("capture").at("threshold_bits").get<unsigned>() == kProductionThresholdBits,
          "scientific trajectory campaign threshold must remain fixed at T20");
  auto checkpoint_value = checkpoint::StateStore(directory / "checkpoint.json").load_or(nlohmann::json::object());
  std::uint64_t checkpoint_count = checkpoint_value.value("checkpoint_count", 0ULL);
  std::size_t completed = 0U;
  for (const auto& block : manifest.at("blocks")) if (capture_is_complete(directory, block)) ++completed;
  const auto total = manifest.at("planned_bje").get<std::size_t>();
  std::unique_ptr<header_space::GpuScanner> scanner;
  if (completed < total) scanner = std::make_unique<header_space::GpuScanner>(device, kernel, local_size);
  for (const auto& block : manifest.at("blocks")) {
    if (capture_is_complete(directory, block)) continue;
    const auto id = block.at("block_id").get<std::string>();
    const auto binary = directory / "captures" / (id + ".t20.bin");
    const auto metadata_path = directory / "captures" / (id + ".json");
    quarantine_if_present(binary);
    quarantine_if_present(metadata_path);
    quarantine_if_present(std::filesystem::path(binary.string() + ".tmp"));
    auto header = block_header(block);
    const auto scan = scanner->scan_sparse_hits_complete(
        header, 0U, header_space::kNonceSpaceSize, kProductionThresholdBits,
        kInitialSparseCapacity);
    require(!scan.overflow && scan.total_hit_count == scan.nonces.size(),
            "unresolved sparse overflow refused");
    std::size_t duplicates = 0U;
    auto nonces = unique_sorted(scan.nonces, &duplicates);
    require(duplicates == 0U, "duplicate nonce returned by sparse GPU capture");
    const auto temporary = std::filesystem::path(binary.string() + ".tmp");
    write_nonce_file(temporary, nonces);
    const auto verify_started = std::chrono::steady_clock::now();
    const auto reconstructed = reconstruct_and_sort(header, nonces, kProductionThresholdBits, true);
    require(reconstructed.size() == scan.total_hit_count, "CPU verification count mismatch");
    const auto verify_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - verify_started).count();
    const auto checksum = file_sha256(temporary);
    std::filesystem::rename(temporary, binary);
    const auto expected = 4096.0;
    const auto z = (static_cast<double>(nonces.size()) - expected) / std::sqrt(expected);
    const auto metadata = nlohmann::json{
        {"schema_version", 1}, {"campaign_id", manifest.at("campaign_id")},
        {"block_id", id}, {"partition", block.at("partition")},
        {"prevhash", block.at("stratum_job").at("prevhash")},
        {"work_fingerprint", block.at("work_fingerprint")},
        {"job_id", block.at("stratum_job").at("job_id")},
        {"extranonce1", block.at("subscription").at("extranonce1")},
        {"extranonce2", block.at("extranonce2")},
        {"extranonce2_size", block.at("subscription").at("extranonce2_size")},
        {"version", block.at("stratum_job").at("version")},
        {"nbits", block.at("stratum_job").at("nbits")},
        {"ntime", block.at("stratum_job").at("ntime")},
        {"merkle_root", block.at("merkle_root")},
        {"header_prefix_76_bytes_hex", block.at("header_prefix_76_bytes_hex")},
        {"nonce_start", 0}, {"nonce_count", header_space::kNonceSpaceSize},
        {"scan_complete", true}, {"gpu_device", {{"name", scan.device.name},
            {"board_name", scan.device.board_name}, {"vendor", scan.device.vendor},
            {"driver", scan.device.driver}, {"compute_units", scan.device.compute_units}}},
        {"elapsed_seconds", scan.elapsed_seconds}, {"kernel_seconds", scan.kernel_seconds},
        {"hash_rate_hps", scan.elapsed_seconds > 0.0
            ? static_cast<double>(header_space::kNonceSpaceSize) / scan.elapsed_seconds : 0.0},
        {"threshold", "T20"}, {"threshold_bits", kProductionThresholdBits},
        {"expected_hits", 4096}, {"observed_t20_count", nonces.size()},
        {"total_hit_count", scan.total_hit_count}, {"captured_count", scan.captured_count},
        {"count_z_score", z}, {"sparse_buffer_capacity", scan.capacity},
        {"overflow_retries", scan.overflow_retries}, {"overflow", false},
        {"cpu_verification_count", reconstructed.size()}, {"cpu_verify_seconds", verify_seconds},
        {"cpu_verification_complete", true}, {"duplicate_count", duplicates},
        {"capture_record_endian", "little-endian"}, {"capture_order", "nonce_numeric_ascending"},
        {"capture_sha256", checksum}, {"status", "COMPLETE"}};
    checkpoint::StateStore(metadata_path).save(metadata);
    ++completed;
    ++checkpoint_count;
    checkpoint::StateStore(directory / "checkpoint.json").save({
        {"schema_version", 1}, {"campaign_id", manifest.at("campaign_id")},
        {"status", completed == total ? "COMPLETE" : "RUNNING"},
        {"completed_bje", completed}, {"total_bje", total},
        {"checkpoint_count", checkpoint_count}, {"last_completed_block_id", id},
        {"updated_at_utc", logging::ResultLogger::utc_now()}});
    refresh_capture_summary(directory, manifest);
    std::cout << "[TRAJECTORY] BJE " << completed << '/' << total
              << "  T20=" << nonces.size() << "  retries=" << scan.overflow_retries
              << "  " << std::fixed << std::setprecision(3)
              << (scan.elapsed_seconds > 0.0 ? header_space::kNonceSpaceSize / scan.elapsed_seconds / 1e9 : 0.0)
              << " GH/s\n" << std::flush;
  }
  refresh_capture_summary(directory, manifest);
  append_report(directory, "\n## Capture terminée\n\nTous les BJE planifiés disposent d'une capture T20 vérifiée CPU et protégée par SHA-256.\n");
  if (!std::filesystem::exists(directory / "analysis_discovery_v1")) {
    (void)analyze_campaign(directory);
  }
  return completed == total ? 0 : 2;
}

namespace {

double mean(const std::vector<double>& values) {
  return values.empty() ? 0.0 : std::accumulate(values.begin(), values.end(), 0.0) / values.size();
}

double median(std::vector<double> values) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  const auto middle = values.size() / 2U;
  return values.size() % 2U ? values[middle] : (values[middle - 1U] + values[middle]) / 2.0;
}

double pearson(const std::vector<double>& left, const std::vector<double>& right) {
  if (left.size() != right.size() || left.size() < 2U) return 0.0;
  const auto ml = mean(left), mr = mean(right);
  double ll = 0.0, rr = 0.0, lr = 0.0;
  for (std::size_t i = 0; i < left.size(); ++i) {
    const auto dl = left[i] - ml, dr = right[i] - mr;
    ll += dl * dl; rr += dr * dr; lr += dl * dr;
  }
  return ll > 0.0 && rr > 0.0 ? lr / std::sqrt(ll * rr) : 0.0;
}

std::vector<double> ranks(const std::vector<double>& values) {
  std::vector<std::size_t> order(values.size());
  std::iota(order.begin(), order.end(), 0U);
  std::stable_sort(order.begin(), order.end(), [&](const auto a, const auto b) { return values[a] < values[b]; });
  std::vector<double> result(values.size());
  for (std::size_t begin = 0; begin < order.size();) {
    auto end = begin + 1U;
    while (end < order.size() && values[order[end]] == values[order[begin]]) ++end;
    const auto rank = (static_cast<double>(begin + 1U) + static_cast<double>(end)) / 2.0;
    for (auto i = begin; i < end; ++i) result[order[i]] = rank;
    begin = end;
  }
  return result;
}

double spearman_sequence(const std::vector<std::uint32_t>& values) {
  std::vector<double> index(values.size()), numeric(values.size());
  for (std::size_t i = 0; i < values.size(); ++i) { index[i] = static_cast<double>(i); numeric[i] = values[i]; }
  return pearson(ranks(index), ranks(numeric));
}

std::array<double, 6> order_metrics(const std::vector<std::uint32_t>& values) {
  if (values.size() < 2U) return {};
  double absolute = 0.0, circular = 0.0, pop = 0.0, prefix = 0.0, suffix = 0.0;
  for (std::size_t i = 1; i < values.size(); ++i) {
    const auto a = values[i - 1U], b = values[i];
    const auto delta = a > b ? static_cast<std::uint64_t>(a) - b : static_cast<std::uint64_t>(b) - a;
    const auto x = a ^ b;
    absolute += static_cast<double>(delta);
    circular += static_cast<double>(std::min(delta, header_space::kNonceSpaceSize - delta));
    pop += std::popcount(x);
    prefix += std::countl_zero(x);
    suffix += std::countr_zero(x);
  }
  const auto denominator = static_cast<double>(values.size() - 1U);
  return {absolute / denominator, circular / denominator, pop / denominator,
          prefix / denominator, suffix / denominator, spearman_sequence(values)};
}

double rank_biserial(const std::vector<double>& a, const std::vector<double>& b) {
  if (a.empty() || b.empty()) return 0.0;
  struct Item { double value; bool in_a; };
  std::vector<Item> joined;
  joined.reserve(a.size() + b.size());
  for (const auto value : a) joined.push_back({value, true});
  for (const auto value : b) joined.push_back({value, false});
  std::stable_sort(joined.begin(), joined.end(), [](const auto& left, const auto& right) { return left.value < right.value; });
  double rank_sum_a = 0.0;
  for (std::size_t begin = 0; begin < joined.size();) {
    auto end = begin + 1U;
    while (end < joined.size() && joined[end].value == joined[begin].value) ++end;
    const auto rank = (static_cast<double>(begin + 1U) + static_cast<double>(end)) / 2.0;
    for (auto i = begin; i < end; ++i) if (joined[i].in_a) rank_sum_a += rank;
    begin = end;
  }
  const auto na = static_cast<double>(a.size()), nb = static_cast<double>(b.size());
  const auto u = rank_sum_a - na * (na + 1.0) / 2.0;
  return 2.0 * u / (na * nb) - 1.0;
}

double ks_distance(std::vector<double> a, std::vector<double> b) {
  if (a.empty() || b.empty()) return 0.0;
  std::sort(a.begin(), a.end()); std::sort(b.begin(), b.end());
  std::size_t ia = 0U, ib = 0U;
  double maximum = 0.0;
  while (ia < a.size() || ib < b.size()) {
    const auto next_a = ia < a.size() ? a[ia] : std::numeric_limits<double>::infinity();
    const auto next_b = ib < b.size() ? b[ib] : std::numeric_limits<double>::infinity();
    const auto value = std::min(next_a, next_b);
    while (ia < a.size() && a[ia] <= value) ++ia;
    while (ib < b.size() && b[ib] <= value) ++ib;
    maximum = std::max(maximum, std::abs(static_cast<double>(ia) / a.size() -
                                         static_cast<double>(ib) / b.size()));
  }
  return maximum;
}

struct BjeEffect { std::string prevhash; double rank_biserial{}, ks{}; };

struct AggregateEffect {
  std::size_t prevhash_count{}, bje_count{};
  double mean_rank{}, median_rank{}, ci_low{}, ci_high{}, mean_ks{};
};

AggregateEffect aggregate_effects(const std::vector<BjeEffect>& effects,
                                  const std::uint64_t seed) {
  std::map<std::string, std::vector<BjeEffect>> grouped;
  for (const auto& effect : effects) grouped[effect.prevhash].push_back(effect);
  std::vector<double> per_prevhash_rank, per_prevhash_ks;
  for (const auto& [unused, group] : grouped) {
    std::vector<double> ranks_value, ks_value;
    for (const auto& effect : group) { ranks_value.push_back(effect.rank_biserial); ks_value.push_back(effect.ks); }
    per_prevhash_rank.push_back(mean(ranks_value));
    per_prevhash_ks.push_back(mean(ks_value));
  }
  AggregateEffect result;
  result.prevhash_count = grouped.size();
  result.bje_count = effects.size();
  result.mean_rank = mean(per_prevhash_rank);
  result.median_rank = median(per_prevhash_rank);
  result.mean_ks = mean(per_prevhash_ks);
  if (per_prevhash_rank.empty()) return result;
  std::mt19937_64 rng(seed);
  std::vector<double> bootstrap;
  bootstrap.reserve(kBootstrapReplicates);
  std::uniform_int_distribution<std::size_t> choose(0U, per_prevhash_rank.size() - 1U);
  for (std::size_t replicate = 0; replicate < kBootstrapReplicates; ++replicate) {
    double sum = 0.0;
    for (std::size_t i = 0; i < per_prevhash_rank.size(); ++i) sum += per_prevhash_rank[choose(rng)];
    bootstrap.push_back(sum / per_prevhash_rank.size());
  }
  std::sort(bootstrap.begin(), bootstrap.end());
  result.ci_low = bootstrap[static_cast<std::size_t>(0.025 * (bootstrap.size() - 1U))];
  result.ci_high = bootstrap[static_cast<std::size_t>(0.975 * (bootstrap.size() - 1U))];
  return result;
}

nlohmann::json feature_schema_json() {
  auto features = nlohmann::json::array();
  for (const auto& name : trajectory_feature_names()) {
    std::string family = name.rfind("state_", 0U) == 0U ? "STATE_BEFORE" :
        (name.find("carry_") != std::string::npos || name.find("chain_") != std::string::npos
          ? "EXACT_CARRIES" : "ROUND_VARIABLE");
    features.push_back({{"name", name}, {"family", family},
                        {"normalization", name.find("normalized") != std::string::npos
                            ? "uint32 / 4294967295" : "none"}});
  }
  return {{"schema_version", 1}, {"round_count", 192},
          {"global_round_mapping", {{"0..63", "first SHA-256 compression 0"},
                                    {"64..127", "first SHA-256 compression 1"},
                                    {"128..191", "second SHA-256 compression 0"}}},
          {"bit_transitions", "popcount((x XOR (x >> 1)) AND 0x7fffffff)"},
          {"carry_model", "exact integer bit-column carry; mask set when carry_out is nonzero"},
          {"features", features}};
}

}  // namespace

nlohmann::json analyze_campaign(const std::filesystem::path& directory) {
  const auto analysis_started = std::chrono::steady_clock::now();
  const auto manifest = checkpoint::StateStore(directory / "manifest.json").load_or(nlohmann::json());
  require(manifest.value("experiment", "") == "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY",
          "not a Phase 3 trajectory campaign");
  const auto campaign_checkpoint = checkpoint::StateStore(directory / "checkpoint.json")
      .load_or(nlohmann::json::object());
  require(campaign_checkpoint.value("status", "") == "COMPLETE",
          "trajectory-analyze requires all planned captures complete; validation and holdout remain sealed");
  const auto analysis = directory / "analysis_discovery_v1";
  if (std::filesystem::exists(analysis)) throw std::runtime_error("immutable analysis_discovery_v1 already exists");
  std::filesystem::create_directories(analysis);
  checkpoint::StateStore(analysis / "trajectory_feature_schema.json").save(feature_schema_json());
  std::ofstream selected_csv(analysis / "selected_bjen.csv", std::ios::binary);
  std::ofstream order_csv(analysis / "input_y_order_summary.csv", std::ios::binary);
  require(static_cast<bool>(selected_csv) && static_cast<bool>(order_csv), "cannot create discovery CSV outputs");
  csv_row(selected_csv, {"campaign_id", "block_id", "prevhash", "work_fingerprint", "extranonce2",
      "cohort", "y_rank", "nonce_uint32", "nonce_hex", "y_hex", "leading_zero_bits", "quality_bits"});
  csv_row(order_csv, {"campaign_id", "block_id", "prevhash", "metric", "observed", "null_mean",
      "null_sd", "z_score", "permutation_p_two_sided", "permutations"});
  const auto& names = trajectory_feature_names();
  constexpr std::size_t comparison_count = 5U, round_count = 192U;
  const std::array<std::string, comparison_count> comparison_names{
      "EXTREME_vs_RANDOM_CONTROL", "VERY_GOOD_vs_RANDOM_CONTROL", "GOOD_vs_RANDOM_CONTROL",
      "T20_CONTROL_vs_RANDOM_CONTROL", "EXTREME_vs_T20_CONTROL"};
  const std::array<std::pair<std::size_t, std::size_t>, comparison_count> comparison_groups{
      std::pair{0U,4U}, std::pair{1U,4U}, std::pair{2U,4U}, std::pair{3U,4U}, std::pair{0U,3U}};
  const std::unordered_map<std::string, std::size_t> cohort_index{
      {"EXTREME",0U}, {"VERY_GOOD",1U}, {"GOOD",2U}, {"T20_CONTROL",3U}, {"RANDOM_CONTROL",4U}};
  std::vector<std::vector<BjeEffect>> effects(comparison_count * round_count * names.size());
  nlohmann::json anomalies = nlohmann::json::array();
  nlohmann::json order_aggregate = nlohmann::json::array();
  struct OrderEntry { std::string prevhash; double observed{}, null_mean{}; };
  std::array<std::vector<OrderEntry>, 6> order_entries;
  const auto seed = manifest.at("seed").get<std::uint64_t>();
  std::size_t analyzed_bje = 0U, selected_bjen_count = 0U;
  const std::array<std::string, 6> metric_names{"mean_abs_nonce_delta", "mean_circular_nonce_distance",
      "mean_xor_popcount", "mean_common_prefix_bits", "mean_common_suffix_bits", "spearman_y_rank_vs_nonce"};
  for (const auto& block : manifest.at("blocks")) {
    if (block.at("partition").get<std::string>() != "discovery") continue;
    require(capture_is_complete(directory, block), "discovery capture is incomplete or invalid: " + block.at("block_id").get<std::string>());
    const auto id = block.at("block_id").get<std::string>();
    const auto prevhash = block.at("stratum_job").at("prevhash").get<std::string>();
    auto header = block_header(block);
    const auto nonces = read_capture(directory / "captures" / (id + ".t20.bin"));
    const auto sorted = reconstruct_and_sort(header, nonces, kProductionThresholdBits, true);
    std::vector<std::uint32_t> y_order;
    y_order.reserve(sorted.size());
    for (const auto& hit : sorted) y_order.push_back(hit.nonce);
    const auto observed = order_metrics(y_order);
    std::array<std::vector<double>, 6> null_values;
    std::mt19937_64 permutation_rng(derived_seed(seed, id + ":Y_ORDER"));
    auto permuted = y_order;
    for (std::size_t replicate = 0; replicate < kInputOrderPermutations; ++replicate) {
      std::shuffle(permuted.begin(), permuted.end(), permutation_rng);
      const auto metrics = order_metrics(permuted);
      for (std::size_t metric = 0; metric < metrics.size(); ++metric) null_values[metric].push_back(metrics[metric]);
    }
    for (std::size_t metric = 0; metric < observed.size(); ++metric) {
      const auto null_mean = mean(null_values[metric]);
      double variance = 0.0;
      for (const auto value : null_values[metric]) variance += (value - null_mean) * (value - null_mean);
      const auto sd = null_values[metric].size() > 1U ? std::sqrt(variance / (null_values[metric].size() - 1U)) : 0.0;
      std::size_t extreme = 0U;
      for (const auto value : null_values[metric])
        if (std::abs(value - null_mean) >= std::abs(observed[metric] - null_mean)) ++extreme;
      const auto p = static_cast<double>(extreme + 1U) / (null_values[metric].size() + 1U);
      csv_row(order_csv, {manifest.at("campaign_id").get<std::string>(), id, prevhash, metric_names[metric],
          std::to_string(observed[metric]), std::to_string(null_mean), std::to_string(sd),
          std::to_string(sd > 0.0 ? (observed[metric] - null_mean) / sd : 0.0), std::to_string(p),
          std::to_string(kInputOrderPermutations)});
      order_aggregate.push_back({{"block_id", id}, {"prevhash", prevhash}, {"metric", metric_names[metric]},
                                 {"observed", observed[metric]}, {"null_mean", null_mean}, {"p_two_sided", p}});
      order_entries[metric].push_back({prevhash, observed[metric], null_mean});
    }
    if (sorted.size() < 256U) {
      anomalies.push_back({{"block_id", id}, {"status", "EXCLUDED_INSUFFICIENT_T20"},
                           {"observed_t20_count", sorted.size()}, {"minimum_required", 256}});
      continue;
    }
    const auto selected = select_cohorts(header, sorted, seed, id);
    if (sorted.size() < 512U) {
      anomalies.push_back({{"block_id", id}, {"status", "ADAPTED_T20_CONTROL"},
                           {"observed_t20_count", sorted.size()},
                           {"available_t20_control", sorted.size() - 256U}});
    }
    std::vector<std::vector<std::vector<double>>> values(
        5U, std::vector<std::vector<double>>(round_count * names.size()));
    for (const auto& specimen : selected) {
      const auto cohort = cohort_index.at(specimen.cohort);
      bitcoin::set_nonce(header, specimen.hit.nonce);
      const auto trace = crypto::trace_reduced_sha256d(header, 64U);
      require(header_space::pow_value(trace.digest) == specimen.hit.y,
              "white-box replay does not reproduce selected Y");
      const auto features = extract_trajectory_features(trace);
      for (const auto& round : features)
        for (std::size_t feature = 0; feature < names.size(); ++feature)
          values[cohort][round.global_round * names.size() + feature].push_back(round.values[feature]);
      csv_row(selected_csv, {manifest.at("campaign_id").get<std::string>(), id, prevhash,
          block.at("work_fingerprint").get<std::string>(), block.at("extranonce2").get<std::string>(),
          specimen.cohort, specimen.y_rank ? std::to_string(*specimen.y_rank) : "",
          std::to_string(specimen.hit.nonce), hex_u32(specimen.hit.nonce),
          header_space::pow_value_hex(specimen.hit.y),
          std::to_string(header_space::leading_zero_bits(specimen.hit.y)),
          std::to_string(quality_bits(specimen.hit.y))});
      ++selected_bjen_count;
    }
    for (std::size_t comparison = 0; comparison < comparison_count; ++comparison) {
      const auto [left, right] = comparison_groups[comparison];
      for (std::size_t round = 0; round < round_count; ++round) {
        for (std::size_t feature = 0; feature < names.size(); ++feature) {
          const auto cell = round * names.size() + feature;
          if (values[left][cell].empty() || values[right][cell].empty()) continue;
          effects[(comparison * round_count + round) * names.size() + feature].push_back(
              {prevhash, rank_biserial(values[left][cell], values[right][cell]),
               ks_distance(values[left][cell], values[right][cell])});
        }
      }
    }
    ++analyzed_bje;
  }
  selected_csv.close(); order_csv.close();
  auto order_global = nlohmann::json::array();
  for (std::size_t metric = 0; metric < metric_names.size(); ++metric) {
    std::map<std::string, std::vector<OrderEntry>> grouped;
    for (const auto& entry : order_entries[metric]) grouped[entry.prevhash].push_back(entry);
    std::vector<double> observed_by_prevhash, null_by_prevhash;
    std::vector<BjeEffect> differences;
    for (const auto& [prevhash, entries] : grouped) {
      std::vector<double> observed_values, null_values;
      for (const auto& entry : entries) {
        observed_values.push_back(entry.observed);
        null_values.push_back(entry.null_mean);
      }
      observed_by_prevhash.push_back(mean(observed_values));
      null_by_prevhash.push_back(mean(null_values));
      differences.push_back({prevhash, mean(observed_values) - mean(null_values), 0.0});
    }
    const auto aggregate = aggregate_effects(differences,
        derived_seed(seed, "Y_ORDER_GLOBAL:" + metric_names[metric]));
    order_global.push_back({{"metric", metric_names[metric]}, {"prevhash_count", grouped.size()},
        {"bje_count", order_entries[metric].size()}, {"mean_observed_by_prevhash", mean(observed_by_prevhash)},
        {"mean_null_by_prevhash", mean(null_by_prevhash)},
        {"mean_observed_minus_null", aggregate.mean_rank},
        {"bootstrap_ci_low", aggregate.ci_low}, {"bootstrap_ci_high", aggregate.ci_high},
        {"bootstrap_unit", "complete_prevhash"}});
  }
  checkpoint::StateStore(analysis / "input_y_order_summary.json").save({
      {"schema_version", 1}, {"scope", "DISCOVERY_EXPLORATORY_NOT_VALIDATED"},
      {"partition_unit", "complete_prevhash"}, {"permutations_per_bje", kInputOrderPermutations},
      {"bje_metrics", order_aggregate}, {"global_by_prevhash", order_global}});
  checkpoint::StateStore(analysis / "anomalies.json").save(anomalies);

  std::ofstream contrast_csv(analysis / "round_contrasts.csv", std::ios::binary);
  std::ofstream maxima_csv(analysis / "round_max_effect_descriptive.csv", std::ios::binary);
  require(static_cast<bool>(contrast_csv) && static_cast<bool>(maxima_csv), "cannot create contrast outputs");
  csv_row(contrast_csv, {"global_round", "sha_pass", "compression_index", "local_round", "feature",
      "comparison", "prevhash_count", "bje_count", "mean_rank_biserial", "median_rank_biserial",
      "bootstrap_ci_low", "bootstrap_ci_high", "mean_ks"});
  csv_row(maxima_csv, {"global_round", "sha_pass", "compression_index", "local_round", "comparison",
      "max_abs_feature", "mean_rank_biserial", "multiple_looks_status"});
  for (std::size_t comparison = 0; comparison < comparison_count; ++comparison) {
    for (std::size_t round = 0; round < round_count; ++round) {
      double maximum_abs = -1.0, maximum_value = 0.0;
      std::string maximum_feature;
      for (std::size_t feature = 0; feature < names.size(); ++feature) {
        const auto flat = (comparison * round_count + round) * names.size() + feature;
        const auto aggregate = aggregate_effects(effects[flat], derived_seed(seed, std::to_string(flat)));
        const auto pass = round < 128U ? 1U : 2U;
        const auto compression = round < 128U ? round / 64U : 0U;
        const auto local = round % 64U;
        csv_row(contrast_csv, {std::to_string(round), std::to_string(pass), std::to_string(compression),
            std::to_string(local), names[feature], comparison_names[comparison],
            std::to_string(aggregate.prevhash_count), std::to_string(aggregate.bje_count),
            std::to_string(aggregate.mean_rank), std::to_string(aggregate.median_rank),
            std::to_string(aggregate.ci_low), std::to_string(aggregate.ci_high),
            std::to_string(aggregate.mean_ks)});
        if (std::abs(aggregate.mean_rank) > maximum_abs) {
          maximum_abs = std::abs(aggregate.mean_rank);
          maximum_value = aggregate.mean_rank;
          maximum_feature = names[feature];
        }
      }
      const auto pass = round < 128U ? 1U : 2U;
      csv_row(maxima_csv, {std::to_string(round), std::to_string(pass),
          std::to_string(round < 128U ? round / 64U : 0U), std::to_string(round % 64U),
          comparison_names[comparison], maximum_feature, std::to_string(maximum_value),
          "DESCRIPTIVE_MULTIPLE_LOOKS_UNADJUSTED_NOT_EVIDENCE"});
    }
  }
  contrast_csv.close(); maxima_csv.close();
  const auto analysis_seconds = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - analysis_started).count();
  const auto summary = nlohmann::json{{"schema_version", 1},
      {"campaign_id", manifest.at("campaign_id")},
      {"scope", "DISCOVERY_EXPLORATORY_NOT_VALIDATED"}, {"validation_opened", false},
      {"holdout_opened", false}, {"analyzed_bje", analyzed_bje},
      {"selected_bjen", selected_bjen_count}, {"anomalies", anomalies.size()},
      {"analysis_seconds", analysis_seconds},
      {"multiple_testing_warning", "round maxima are descriptive, multiple-looks and unadjusted"},
      {"cryptanalytic_claim", false}};
  checkpoint::StateStore(analysis / "summary.json").save(summary);
  append_report(directory, "\n## Analyse discovery\n\nAnalyse Y-order et trajectoires 192 rounds terminée en " +
      std::to_string(analysis_seconds) + " s. Les résultats sont exploratoires, non validés et ne constituent aucune preuve cryptanalytique.\n");
  return summary;
}

std::filesystem::path export_bje(const std::filesystem::path& directory,
                                 const std::string& block_id) {
  const auto manifest = checkpoint::StateStore(directory / "manifest.json").load_or(nlohmann::json());
  require(manifest.value("experiment", "") == "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY",
          "not a Phase 3 trajectory campaign");
  const auto& block = find_block(manifest, block_id);
  require_discovery(block, "trajectory-export-bje");
  require(capture_is_complete(directory, block), "BJE capture is incomplete or checksum-invalid");
  auto header = block_header(block);
  const auto sorted = reconstruct_and_sort(header,
      read_capture(directory / "captures" / (block_id + ".t20.bin")),
      kProductionThresholdBits, true);
  const auto output_directory = directory / "exports_discovery";
  std::filesystem::create_directories(output_directory);
  const auto output_path = output_directory / (block_id + "_y_sorted.csv");
  if (std::filesystem::exists(output_path)) throw std::runtime_error("immutable BJE export already exists");
  std::ofstream output(output_path, std::ios::binary);
  require(static_cast<bool>(output), "cannot create BJE export");
  csv_row(output, {"rank", "nonce", "nonce_hex", "Y_hex", "leading_zero_bits", "quality_bits"});
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    csv_row(output, {std::to_string(i + 1U), std::to_string(sorted[i].nonce), hex_u32(sorted[i].nonce),
        header_space::pow_value_hex(sorted[i].y),
        std::to_string(header_space::leading_zero_bits(sorted[i].y)),
        std::to_string(quality_bits(sorted[i].y))});
  }
  return output_path;
}

std::filesystem::path trace_bjen(const std::filesystem::path& directory,
                                 const std::string& block_id,
                                 const std::uint32_t nonce) {
  const auto manifest = checkpoint::StateStore(directory / "manifest.json").load_or(nlohmann::json());
  require(manifest.value("experiment", "") == "PHASE_3_POST_SCAN_Y_SORT_TRAJECTORY",
          "not a Phase 3 trajectory campaign");
  const auto& block = find_block(manifest, block_id);
  require_discovery(block, "trajectory-trace");
  auto header = block_header(block);
  bitcoin::set_nonce(header, nonce);
  const auto first = crypto::sha256(header);
  const auto digest = crypto::sha256d(header);
  const auto y = header_space::pow_value(digest);
  const auto stem = "bjen_" + block_id.substr(0U, 16U) + "_nonce_" + hex_u32(nonce);
  const auto output = directory / "traces_discovery" / stem;
  if (std::filesystem::exists(output)) throw std::runtime_error("immutable detailed trace already exists");
  whitebox::SpecimenMetadata metadata{
      "trajectory_" + block_id + "_" + std::to_string(nonce),
      "Phase 3 discovery BJEN exhaustive SHA256d trace", stem,
      crypto::digest_hex(first), crypto::digest_hex(digest), crypto::bitcoin_hash_hex(digest)};
  const auto artifacts = whitebox::build_sha256d_whitebox(header, metadata);
  require(artifacts.trace.at("experiment").at("total_round_count").get<unsigned>() == 192U,
          "white-box output does not contain exactly 192 rounds");
  require(artifacts.trace.at("final").at("bitcoin_display_hash").get<std::string>() ==
              header_space::pow_value_hex(y), "white-box final hash/Y mismatch");
  whitebox::write_sha256d_whitebox(artifacts, metadata, output);
  checkpoint::StateStore(output / "trajectory_request.json").save({
      {"campaign_id", manifest.at("campaign_id")}, {"block_id", block_id},
      {"partition", "discovery"}, {"nonce_uint32", nonce}, {"nonce_hex", hex_u32(nonce)},
      {"y_hex", header_space::pow_value_hex(y)}, {"round_count", 192},
      {"sha_pass_1_compressions", 2}, {"sha_pass_2_compressions", 1}});
  return output;
}

nlohmann::json run_smoke(const context_campaign::ArchivedContext& context,
                         const std::filesystem::path& kernel,
                         const std::string& device,
                         const std::size_t local_size,
                         const std::uint64_t nonce_count,
                         const unsigned threshold_bits) {
  require(nonce_count > 0U && nonce_count <= header_space::kNonceSpaceSize,
          "smoke nonce range is invalid");
  require(threshold_bits != kProductionThresholdBits,
          "smoke must use a non-production threshold so it cannot be mistaken for ground truth");
  const auto extranonce2 = context_campaign::sample_extranonce2(
      0x534d4f4b45ULL, context.work_fingerprint, context.extranonce2_size, 1U).front();
  const auto work = stratum::build_work(context.job, context.extranonce1, extranonce2, 0U);
  const auto cpu = header_space::scan_sparse_hits_cpu_complete(
      work.header, 0U, nonce_count, threshold_bits, 64U);
  const auto cpu_sorted = unique_sorted(cpu.nonces);
  const auto reconstructed = reconstruct_and_sort(work.header, cpu_sorted, threshold_bits, true);
  bool gpu_available = false, exact_match = false;
  std::size_t gpu_hits = 0U, gpu_retries = 0U;
  double gpu_seconds = 0.0;
  if (header_space::opencl_compiled() && !header_space::enumerate_gpu_devices().empty()) {
    gpu_available = true;
    header_space::GpuScanner scanner(device, kernel, local_size);
    const auto gpu = scanner.scan_sparse_hits_complete(
        work.header, 0U, nonce_count, threshold_bits, 64U);
    const auto gpu_sorted = unique_sorted(gpu.nonces);
    exact_match = gpu.total_hit_count == cpu.total_hit_count && gpu_sorted == cpu_sorted && !gpu.overflow;
    require(exact_match, "trajectory smoke CPU/GPU sparse nonce sets differ");
    gpu_hits = gpu_sorted.size();
    gpu_retries = gpu.overflow_retries;
    gpu_seconds = gpu.elapsed_seconds;
  }
  std::size_t replay_rounds = 0U;
  bool y_replayed = false;
  if (!reconstructed.empty()) {
    auto header = work.header;
    bitcoin::set_nonce(header, reconstructed.front().nonce);
    const auto trace = crypto::trace_reduced_sha256d(header, 64U);
    const auto features = extract_trajectory_features(trace);
    replay_rounds = features.size();
    y_replayed = header_space::pow_value(trace.digest) == reconstructed.front().y;
  }
  return {{"command", "trajectory-smoke"}, {"scientific_ground_truth", false},
          {"threshold_bits", threshold_bits}, {"nonce_start", 0}, {"nonce_count", nonce_count},
          {"cpu_hits", cpu_sorted.size()}, {"cpu_overflow_retries", cpu.overflow_retries},
          {"cpu_verification_count", reconstructed.size()}, {"gpu_available", gpu_available},
          {"gpu_hits", gpu_hits}, {"gpu_overflow_retries", gpu_retries},
          {"gpu_seconds", gpu_seconds}, {"cpu_gpu_exact_set_match", exact_match},
          {"replay_rounds", replay_rounds}, {"replay_y_exact", y_replayed},
          {"status", (!gpu_available || exact_match) && (reconstructed.empty() || (replay_rounds == 192U && y_replayed))
              ? "PASS" : "FAIL"}};
}

}  // namespace srm::research::context_trajectory
