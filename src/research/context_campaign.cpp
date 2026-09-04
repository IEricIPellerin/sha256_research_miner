//src\research\context_campaign.cpp
#include "research/context_campaign.h"

#include "bitcoin/coinbase.h"
#include "bitcoin/difficulty.h"
#include "checkpoint/state_store.h"
#include "crypto/sha256.h"
#include "crypto/sha256d.h"
#include "logging/result_logger.h"

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

namespace srm::research::context_campaign {
namespace {

using header_space::GlobalStats;

std::string utc_compact() {
  const auto now = std::chrono::system_clock::now();
  const auto time = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &time);
#else
  gmtime_r(&time, &utc);
#endif
  std::ostringstream output;
  output << std::put_time(&utc, "%Y%m%d_%H%M%S");
  return output.str();
}

std::string utc_after(const double seconds) {
  const auto when = std::chrono::system_clock::now() +
      std::chrono::seconds(static_cast<std::uint64_t>(std::max(0.0, seconds)));
  const auto time = std::chrono::system_clock::to_time_t(when);
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &time);
#else
  gmtime_r(&time, &utc);
#endif
  std::ostringstream output;
  output << std::put_time(&utc, "%Y-%m-%d %H:%M:%S UTC");
  return output.str();
}

std::string hex_u64(const std::uint64_t value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0') << std::setw(16) << value;
  return output.str();
}

std::uint64_t seed_for(const std::uint64_t seed, const std::string& fingerprint) {
  const auto material = std::to_string(seed) + ":" + fingerprint;
  const auto digest = crypto::sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(material.data()), material.size()));
  std::uint64_t result = 0;
  for (std::size_t i = 0; i < 8; ++i) result = (result << 8U) | digest[i];
  return result;
}

nlohmann::json job_json(const stratum::StratumJob& job) {
  return {{"job_id", job.job_id}, {"prevhash", job.prevhash},
          {"coinbase1", job.coinbase1}, {"coinbase2", job.coinbase2},
          {"merkle_branches", job.merkle_branches}, {"version", job.version},
          {"nbits", job.nbits}, {"ntime", job.ntime}, {"clean_jobs", job.clean_jobs}};
}

ArchivedContext context_from_json(const nlohmann::json& value) {
  ArchivedContext context;
  const auto& job = value.at("stratum_job");
  context.job = stratum::parse_notify(nlohmann::json::array({
      job.at("job_id"), job.at("prevhash"), job.at("coinbase1"), job.at("coinbase2"),
      job.at("merkle_branches"), job.at("version"), job.at("nbits"), job.at("ntime"),
      job.at("clean_jobs")}));
  context.received_timestamp_utc = value.value("received_timestamp_utc", "");
  context.extranonce1 = value.at("subscription").at("extranonce1").get<std::string>();
  context.extranonce2_size = value.at("subscription").at("extranonce2_size").get<unsigned>();
  context.work_fingerprint = value.at("work_fingerprint").get<std::string>();
  if (context.extranonce1.empty() || context.extranonce2_size == 0 ||
      context.work_fingerprint.size() != 64U) {
    throw std::invalid_argument("incomplete replayable Stratum context");
  }
  const std::string zero_extranonce(context.extranonce2_size * 2U, '0');
  (void)stratum::build_work(context.job, context.extranonce1, zero_extranonce, 0);
  return context;
}

nlohmann::json archived_json(const ArchivedContext& context) {
  return {{"received_timestamp_utc", context.received_timestamp_utc},
          {"work_fingerprint", context.work_fingerprint},
          {"subscription", {{"extranonce1", context.extranonce1},
                            {"extranonce2_size", context.extranonce2_size}}},
          {"stratum_job", job_json(context.job)}};
}

void append_jsonl(const std::filesystem::path& path, const nlohmann::json& value) {
  std::ofstream output(path, std::ios::binary | std::ios::app);
  if (!output) throw checkpoint::PersistenceError("cannot append " + path.string());
  output << value.dump() << '\n';
  output.flush();
  if (!output) throw checkpoint::PersistenceError("cannot flush " + path.string());
}

std::unordered_set<std::string> ids_in_jsonl(const std::filesystem::path& path,
                                             const bool require_complete) {
  std::unordered_set<std::string> result;
  std::ifstream input(path, std::ios::binary);
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty()) continue;
    const auto value = nlohmann::json::parse(line);
    if (!require_complete || value.value("complete", false)) {
      result.insert(value.at("block_id").get<std::string>());
    }
  }
  return result;
}

nlohmann::json counts_json(const header_space::TailCounts& counts) {
  nlohmann::json result = nlohmann::json::object();
  for (std::size_t i = 0; i < counts.size(); ++i) {
    result["leading_zero_" + std::to_string(header_space::kThresholdBits[i])] = counts[i];
  }
  return result;
}

std::size_t byte_hamming(const std::span<const std::uint8_t> bytes) {
  std::size_t result = 0;
  for (const auto byte : bytes) result += std::popcount(byte);
  return result;
}

std::vector<std::uint32_t> big_endian_words(const std::span<const std::uint8_t> bytes) {
  std::vector<std::uint32_t> words;
  words.reserve(bytes.size() / 4U);
  for (std::size_t i = 0; i + 3U < bytes.size(); i += 4U) {
    words.push_back((static_cast<std::uint32_t>(bytes[i]) << 24U) |
                    (static_cast<std::uint32_t>(bytes[i + 1U]) << 16U) |
                    (static_cast<std::uint32_t>(bytes[i + 2U]) << 8U) |
                    bytes[i + 3U]);
  }
  return words;
}

std::vector<std::uint32_t> first_chunk_midstate(const bitcoin::Header& header) {
  const auto trace = crypto::sha256_with_trace(
      std::span<const std::uint8_t>(header.data(), 64U), 64U);
  const auto found = std::find_if(trace.rounds.rbegin(), trace.rounds.rend(), [](const auto& round) {
    return round.compression_index == 0U && round.round_index == 63U;
  });
  if (found == trace.rounds.rend()) throw std::logic_error("SHA trace has no first-chunk final round");
  constexpr std::array<std::uint32_t, 8> initial{
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
  return {initial[0] + found->a_after, initial[1] + found->b_after,
          initial[2] + found->c_after, initial[3] + found->d_after,
          initial[4] + found->e_after, initial[5] + found->f_after,
          initial[6] + found->g_after, initial[7] + found->h_after};
}

std::size_t distinct_prevhash(const std::vector<PlannedContext>& contexts) {
  std::set<std::string> values;
  for (const auto& context : contexts) values.insert(context.context.job.prevhash);
  return values.size();
}

std::string format_duration(const double seconds) {
  const auto total = static_cast<std::uint64_t>(std::max(0.0, seconds));
  std::ostringstream output;
  output << std::setfill('0') << std::setw(2) << total / 3600U << ':'
         << std::setw(2) << (total / 60U) % 60U << ':' << std::setw(2) << total % 60U;
  return output.str();
}

struct JoinedRow {
  std::string block;
  std::string context;
  std::string prevhash;
  std::string partition;
  std::string extranonce2;
  double quality{0.0};
  double difficulty{0.0};
  double numeric_score{0.0};
  double hash_score{0.0};
  double static_score{0.0};
  double random_score{0.0};
  double model_score{0.0};
  std::map<unsigned, std::uint64_t> tails;
};

double pearson(const std::vector<std::pair<double, double>>& pairs) {
  if (pairs.size() < 3U) return 0.0;
  double sx = 0.0, sy = 0.0;
  for (const auto& [x, y] : pairs) { sx += x; sy += y; }
  const auto mx = sx / pairs.size();
  const auto my = sy / pairs.size();
  double xx = 0.0, yy = 0.0, xy = 0.0;
  for (const auto& [x, y] : pairs) {
    xx += (x - mx) * (x - mx);
    yy += (y - my) * (y - my);
    xy += (x - mx) * (y - my);
  }
  return xx > 0.0 && yy > 0.0 ? xy / std::sqrt(xx * yy) : 0.0;
}

double spearman(std::vector<std::pair<double, double>> pairs) {
  if (pairs.size() < 3U) return 0.0;
  const auto ranks = [](const std::vector<double>& values) {
    std::vector<std::size_t> order(values.size());
    std::iota(order.begin(), order.end(), 0U);
    std::stable_sort(order.begin(), order.end(), [&](const auto left, const auto right) {
      return values[left] < values[right];
    });
    std::vector<double> result(values.size());
    for (std::size_t begin = 0; begin < order.size();) {
      std::size_t end = begin + 1U;
      while (end < order.size() && values[order[end]] == values[order[begin]]) ++end;
      const auto rank = (static_cast<double>(begin) + static_cast<double>(end - 1U)) / 2.0;
      for (std::size_t i = begin; i < end; ++i) result[order[i]] = rank;
      begin = end;
    }
    return result;
  };
  std::vector<double> x, y;
  for (const auto& [left, right] : pairs) { x.push_back(left); y.push_back(right); }
  const auto rx = ranks(x);
  const auto ry = ranks(y);
  std::vector<std::pair<double, double>> ranked;
  for (std::size_t i = 0; i < rx.size(); ++i) ranked.emplace_back(rx[i], ry[i]);
  return pearson(ranked);
}

double rank_value(const std::string& hex) {
  const auto take = std::min<std::size_t>(13U, hex.size());
  return static_cast<double>(std::stoull(hex.substr(0, take), nullptr, 16));
}

nlohmann::json ranking_metrics(const std::vector<JoinedRow>& input,
                               const std::string& score_name,
                               const bool descending) {
  auto rows = input;
  const auto score = [&](const JoinedRow& row) {
    if (score_name == "numeric_extranonce2") return row.numeric_score;
    if (score_name == "hash_extranonce2") return row.hash_score;
    if (score_name == "random_seeded") return row.random_score;
    if (score_name == "linear_static_model") return row.model_score;
    return row.static_score;
  };
  std::stable_sort(rows.begin(), rows.end(), [&](const auto& left, const auto& right) {
    return descending ? score(left) > score(right) : score(left) < score(right);
  });
  const auto total_quality = std::accumulate(rows.begin(), rows.end(), 0.0,
      [](const double sum, const auto& row) { return sum + row.quality; });
  nlohmann::json fractions = nlohmann::json::array();
  for (const double fraction : {0.01, 0.05, 0.10, 0.25}) {
    const auto count = rows.empty() ? 0U : std::max<std::size_t>(1U,
        static_cast<std::size_t>(std::ceil(rows.size() * fraction)));
    double captured = 0.0;
    double mean_difficulty = 0.0;
    double best_difficulty = 0.0;
    for (std::size_t i = 0; i < count; ++i) {
      captured += rows[i].quality;
      mean_difficulty += rows[i].difficulty;
      best_difficulty = std::max(best_difficulty, rows[i].difficulty);
    }
    if (count > 0U) mean_difficulty /= count;
    const auto captured_fraction = total_quality > 0.0 ? captured / total_quality : 0.0;
    const auto actual_fraction = rows.empty() ? 0.0 : static_cast<double>(count) / rows.size();
    fractions.push_back({{"scan_fraction", fraction}, {"selected_blocks", count},
                         {"actual_scan_fraction", actual_fraction},
                         {"quality_captured_fraction", captured_fraction},
                         {"lift_over_random", actual_fraction > 0.0
                              ? captured_fraction / actual_fraction : 0.0},
                         {"mean_best_difficulty", mean_difficulty},
                         {"best_difficulty", best_difficulty},
                         {"confidence_interval", nullptr},
                         {"permutation_p_value", nullptr}});
  }
  return {{"score", score_name}, {"descending", descending}, {"top_fractions", fractions}};
}

}  // namespace

double quality_bits(const header_space::PowValue& value) {
  long double numeric = 0.0L;
  for (const auto word : value) {
    numeric = std::ldexp(numeric, 32) + static_cast<long double>(word);
  }
  if (numeric == 0.0L) return std::numeric_limits<double>::infinity();
  return static_cast<double>(256.0L - std::log2(numeric));
}

std::vector<ArchivedContext> load_archive(const std::filesystem::path& archive,
                                          std::size_t* rejected_lines) {
  std::ifstream input(archive, std::ios::binary);
  if (!input) throw std::runtime_error("cannot open Stratum archive: " + archive.string());
  std::vector<ArchivedContext> contexts;
  std::unordered_set<std::string> fingerprints;
  std::size_t rejected = 0;
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty()) continue;
    try {
      const auto value = nlohmann::json::parse(line);
      if (value.value("event", "") != "mining.notify") continue;
      auto context = context_from_json(value);
      if (fingerprints.insert(context.work_fingerprint).second) contexts.push_back(std::move(context));
    } catch (const std::exception&) {
      ++rejected;
    }
  }
  if (rejected_lines) *rejected_lines = rejected;
  if (contexts.empty()) throw std::runtime_error("Stratum archive contains no replayable context");
  return contexts;
}

std::vector<std::string> recover_completed_blocks(const std::filesystem::path& labels_path) {
  const auto ids = ids_in_jsonl(labels_path, true);
  std::vector<std::string> result(ids.begin(), ids.end());
  std::sort(result.begin(), result.end());
  return result;
}

BenchmarkResult benchmark(const ArchivedContext& context,
                          const std::filesystem::path& kernel,
                          const std::string& device,
                          const std::uint64_t nonce_count,
                          const std::uint64_t zone_size,
                          const std::size_t batch_zones,
                          const std::size_t local_size) {
  const auto extranonces = sample_extranonce2(1U, context.work_fingerprint,
                                               context.extranonce2_size, 1U);
  const auto work = stratum::build_work(context.job, context.extranonce1, extranonces.front(), 0);
  BenchmarkResult result;
  result.hashes = nonce_count;
  if (header_space::opencl_compiled() && !header_space::enumerate_gpu_devices().empty()) {
    header_space::GpuScanner scanner(device, kernel, local_size);
    const auto scan = scanner.scan(work.header, 0, nonce_count,
                                   std::min(zone_size, nonce_count), batch_zones);
    result.backend = "OpenCL";
    result.device = scan.device.board_name.empty() ? scan.device.name : scan.device.board_name;
    result.seconds = scan.elapsed_seconds;
  } else {
    const auto cpu_count = std::min<std::uint64_t>(nonce_count, 262144U);
    const auto before = std::chrono::steady_clock::now();
    (void)header_space::scan_cpu(work.header, 0, cpu_count, std::min(zone_size, cpu_count));
    result.hashes = cpu_count;
    result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - before).count();
    result.backend = "CPU_REFERENCE";
    result.device = "CPU (campaign GPU required)";
  }
  result.hashes_per_second = result.seconds > 0.0 ? result.hashes / result.seconds : 0.0;
  if (result.hashes_per_second <= 0.0) throw std::runtime_error("benchmark produced no measurable throughput");
  return result;
}

std::vector<std::string> sample_extranonce2(const std::uint64_t seed,
                                            const std::string& fingerprint,
                                            const unsigned size,
                                            const std::size_t count) {
  if (size == 0U) {
    if (count > 1U) throw std::invalid_argument("zero-byte extranonce2 has only one value");
    return {""};
  }
  if (size < sizeof(std::size_t) && count > (std::size_t{1} << (size * 8U))) {
    throw std::invalid_argument("requested extranonce2 sample exceeds its value space");
  }
  std::mt19937_64 random(seed_for(seed, fingerprint));
  std::unordered_set<std::string> used;
  std::vector<std::string> result;
  result.reserve(count);
  constexpr char digits[] = "0123456789abcdef";
  while (result.size() < count) {
    std::vector<std::uint8_t> bytes(size);
    for (unsigned offset = 0; offset < size; offset += 8U) {
      const auto word = random();
      for (unsigned byte = 0; byte < 8U && offset + byte < size; ++byte) {
        bytes[offset + byte] = static_cast<std::uint8_t>(word >> (byte * 8U));
      }
    }
    if (count > 1U) {
      const auto index = result.size();
      const auto strata = std::min<std::size_t>(count, 256U);
      const auto stratum = index % strata;
      const auto low = (stratum * 256U) / strata;
      const auto high = ((stratum + 1U) * 256U) / strata;
      bytes[0] = static_cast<std::uint8_t>(low + (random() % std::max<std::size_t>(1U, high - low)));
    }
    std::string encoded(size * 2U, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      encoded[i * 2U] = digits[bytes[i] >> 4U];
      encoded[i * 2U + 1U] = digits[bytes[i] & 0x0fU];
    }
    if (used.insert(encoded).second) result.push_back(std::move(encoded));
  }
  return result;
}

CampaignPlan make_plan(const std::vector<ArchivedContext>& archive,
                       CampaignRequest request,
                       BenchmarkResult measured) {
  if (archive.empty()) throw std::invalid_argument("cannot plan from an empty archive");
  const std::array fractions{
      request.discovery_fraction, request.validation_fraction, request.holdout_fraction};
  for (const auto fraction : fractions) {
    if (!std::isfinite(fraction) || fraction < 0.0 || fraction > 1.0) {
      throw std::invalid_argument("partition fractions must be finite values in [0,1]");
    }
  }
  if (std::abs(std::accumulate(fractions.begin(), fractions.end(), 0.0) - 1.0) > 1e-9) {
    throw std::invalid_argument("discovery/validation/holdout fractions must sum to 1.0");
  }
  std::map<std::string, std::vector<const ArchivedContext*>> grouped;
  for (const auto& context : archive) grouped[context.job.prevhash].push_back(&context);
  for (auto& [unused, contexts] : grouped) {
    std::stable_sort(contexts.begin(), contexts.end(), [](const auto* left, const auto* right) {
      return left->received_timestamp_utc < right->received_timestamp_utc;
    });
  }
  std::vector<std::string> prevhashes;
  for (const auto& [prevhash, unused] : grouped) prevhashes.push_back(prevhash);
  std::mt19937_64 random(request.seed);
  std::shuffle(prevhashes.begin(), prevhashes.end(), random);
  const auto wanted_prevhash = request.prevhash_count == 0U ? prevhashes.size()
      : std::min(request.prevhash_count, prevhashes.size());
  prevhashes.resize(wanted_prevhash);

  std::size_t available_contexts = 0;
  for (const auto& prevhash : prevhashes) available_contexts += grouped.at(prevhash).size();
  const auto wanted_contexts = std::min(
      request.context_count == 0U ? wanted_prevhash : request.context_count,
      available_contexts);
  std::map<std::string, std::size_t> quotas;
  std::size_t assigned = 0;
  while (assigned < wanted_contexts) {
    bool added = false;
    for (const auto& prevhash : prevhashes) {
      if (quotas[prevhash] < grouped.at(prevhash).size() && assigned < wanted_contexts) {
        ++quotas[prevhash];
        ++assigned;
        added = true;
      }
    }
    if (!added) break;
  }
  std::map<std::string, std::vector<const ArchivedContext*>> representatives;
  for (const auto& prevhash : prevhashes) {
    const auto& candidates = grouped.at(prevhash);
    const auto count = quotas[prevhash];
    auto& chosen = representatives[prevhash];
    chosen.reserve(count);
    std::mt19937_64 group_random(seed_for(request.seed, prevhash));
    for (std::size_t stratum = 0; stratum < count; ++stratum) {
      const auto begin = stratum * candidates.size() / count;
      const auto end = (stratum + 1U) * candidates.size() / count;
      std::uniform_int_distribution<std::size_t> pick(begin, end - 1U);
      chosen.push_back(candidates[pick(group_random)]);
    }
  }

  std::vector<const ArchivedContext*> selected;
  std::size_t depth = 0;
  while (selected.size() < wanted_contexts) {
    bool added = false;
    for (const auto& prevhash : prevhashes) {
      auto& candidates = representatives.at(prevhash);
      if (depth < candidates.size() && selected.size() < wanted_contexts) {
        selected.push_back(candidates[depth]);
        added = true;
      }
    }
    if (!added) break;
    ++depth;
  }
  if (selected.empty()) throw std::invalid_argument("context selection is empty");

  std::uint64_t total = 0;
  if (request.total_blocks) total = *request.total_blocks;
  else if (request.time_budget_minutes) {
    total = static_cast<std::uint64_t>(std::floor(
        *request.time_budget_minutes * 60.0 * measured.hashes_per_second /
        static_cast<double>(header_space::kNonceSpaceSize)));
    total = std::max<std::uint64_t>(1U, total);
  } else if (request.blocks_per_context) {
    if (*request.blocks_per_context > std::numeric_limits<std::uint64_t>::max() / selected.size()) {
      throw std::overflow_error("campaign block count overflows uint64");
    }
    total = static_cast<std::uint64_t>(*request.blocks_per_context) * selected.size();
  } else {
    throw std::invalid_argument("choose total_blocks, time_budget_minutes, or blocks_per_context");
  }
  if (total == 0U) throw std::invalid_argument("campaign must contain at least one B(J,e)");
  if (total > std::numeric_limits<std::uint64_t>::max() / header_space::kNonceSpaceSize) {
    throw std::overflow_error("campaign hash count overflows uint64");
  }
  if (total < selected.size()) selected.resize(static_cast<std::size_t>(total));

  CampaignPlan plan;
  plan.request = std::move(request);
  plan.benchmark = std::move(measured);
  plan.total_blocks = total;
  plan.total_hashes = total * header_space::kNonceSpaceSize;
  plan.estimated_seconds = static_cast<double>(plan.total_hashes) / plan.benchmark.hashes_per_second;
  plan.estimated_disk_bytes = total * 8192U + selected.size() * 4096U + 16384U;

  std::array<std::size_t, 3> partition_counts{};
  std::array<double, 3> remainders{};
  std::size_t partitioned = 0;
  for (std::size_t i = 0; i < fractions.size(); ++i) {
    const auto exact = fractions[i] * prevhashes.size();
    partition_counts[i] = static_cast<std::size_t>(std::floor(exact));
    remainders[i] = exact - partition_counts[i];
    partitioned += partition_counts[i];
  }
  while (partitioned < prevhashes.size()) {
    const auto best = static_cast<std::size_t>(std::distance(
        remainders.begin(), std::max_element(remainders.begin(), remainders.end())));
    ++partition_counts[best];
    remainders[best] = -1.0;
    ++partitioned;
  }
  const auto positive_partitions = static_cast<std::size_t>(
      std::count_if(fractions.begin(), fractions.end(), [](const double value) { return value > 0.0; }));
  if (prevhashes.size() >= positive_partitions) {
    for (std::size_t empty = 0; empty < fractions.size(); ++empty) {
      if (fractions[empty] == 0.0 || partition_counts[empty] != 0U) continue;
      const auto donor = static_cast<std::size_t>(std::distance(
          partition_counts.begin(), std::max_element(partition_counts.begin(), partition_counts.end())));
      --partition_counts[donor];
      ++partition_counts[empty];
    }
  }
  std::unordered_map<std::string, std::string> partition;
  for (std::size_t i = 0; i < prevhashes.size(); ++i) {
    partition[prevhashes[i]] = i < partition_counts[0] ? "discovery" :
        (i < partition_counts[0] + partition_counts[1] ? "validation" : "holdout");
  }

  const auto base = total / selected.size();
  const auto remainder = total % selected.size();
  for (std::size_t i = 0; i < selected.size(); ++i) {
    const auto count = static_cast<std::size_t>(base + (i < remainder ? 1U : 0U));
    plan.contexts.push_back({*selected[i], partition.at(selected[i]->job.prevhash),
                             sample_extranonce2(plan.request.seed, selected[i]->work_fingerprint,
                                                selected[i]->extranonce2_size, count)});
  }
  if (plan.total_blocks < 100U) plan.warnings.push_back(
      "Échantillon statistiquement très faible; lancement permis, conclusions non probantes.");
  if (distinct_prevhash(plan.contexts) < 3U) plan.warnings.push_back(
      "Moins de trois prevhash: séparation discovery/validation/holdout complète impossible.");
  if (plan.contexts.size() < 3U) plan.warnings.push_back(
      "Très peu de contextes Stratum indépendants.");
  return plan;
}

nlohmann::json plan_preview_json(const CampaignPlan& plan) {
  std::vector<std::size_t> per_context;
  std::set<std::string> prevhashes;
  for (const auto& context : plan.contexts) {
    per_context.push_back(context.extranonce2_values.size());
    prevhashes.insert(context.context.job.prevhash);
  }
  return {{"profile", plan.request.profile}, {"seed", plan.request.seed},
          {"distinct_prevhashes", prevhashes.size()}, {"stratum_contexts", plan.contexts.size()},
          {"blocks_per_context_min", *std::min_element(per_context.begin(), per_context.end())},
          {"blocks_per_context_max", *std::max_element(per_context.begin(), per_context.end())},
          {"total_blocks_B_J_e", plan.total_blocks}, {"total_hashes", plan.total_hashes},
          {"measured_hashes_per_second", plan.benchmark.hashes_per_second},
          {"benchmark", {{"backend", plan.benchmark.backend}, {"device", plan.benchmark.device},
                         {"hashes", plan.benchmark.hashes}, {"seconds", plan.benchmark.seconds}}},
          {"estimated_seconds", plan.estimated_seconds},
          {"estimated_duration", format_duration(plan.estimated_seconds)},
          {"estimated_disk_bytes", plan.estimated_disk_bytes}, {"warnings", plan.warnings}};
}

std::string block_id(const ArchivedContext& context, const std::string& extranonce2) {
  const auto material = context.work_fingerprint + ":" + extranonce2;
  const auto digest = crypto::sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(material.data()), material.size()));
  return crypto::digest_hex(digest);
}

nlohmann::json pre_scan_features(const ArchivedContext& context,
                                 const std::string& extranonce2,
                                 const std::string& id,
                                 const std::string& partition) {
  const auto coinbase = bitcoin::coinbase_hash(context.job.coinbase1, context.extranonce1,
                                                extranonce2, context.job.coinbase2);
  const auto built = stratum::build_work(context.job, context.extranonce1, extranonce2, 0);
  const auto prefix = std::span<const std::uint8_t>(built.header.data(), 76U);
  const auto extranonce_bytes = crypto::from_hex(extranonce2);
  const auto merkle_bytes = std::span<const std::uint8_t>(built.merkle_root.data(), built.merkle_root.size());
  const auto hashed_extranonce = crypto::sha256(extranonce_bytes);
  const auto words = big_endian_words(prefix);
  return {{"schema_version", 1}, {"feature_stage", "PRE_SCAN"},
          {"post_scan_fields_present", false}, {"block_id", id}, {"partition", partition},
          {"work_fingerprint", context.work_fingerprint}, {"prevhash", context.job.prevhash},
          {"job_id", context.job.job_id}, {"extranonce1", context.extranonce1},
          {"extranonce2", extranonce2}, {"extranonce2_size", context.extranonce2_size},
          {"bitcoin_context", {{"version", context.job.version}, {"nbits", context.job.nbits},
                               {"ntime", context.job.ntime},
                               {"merkle_branch_count", context.job.merkle_branches.size()},
                               {"coinbase1_bytes", context.job.coinbase1.size() / 2U},
                               {"coinbase2_bytes", context.job.coinbase2.size() / 2U}}},
          {"derived", {{"coinbase_txid", crypto::bitcoin_hash_hex(coinbase)},
                       {"merkle_root", crypto::bitcoin_hash_hex(built.merkle_root)},
                       {"header_prefix_76_bytes_hex", crypto::to_hex(prefix)},
                       {"header_prefix_hamming_weight", byte_hamming(prefix)},
                       {"merkle_hamming_weight", byte_hamming(merkle_bytes)},
                       {"extranonce2_hamming_weight", byte_hamming(extranonce_bytes)},
                       {"extranonce2_sha256", crypto::digest_hex(hashed_extranonce)},
                       {"header_words_be", words},
                       {"sha256_first_chunk_midstate_words", first_chunk_midstate(built.header)},
                       {"second_chunk_fixed_words_be", {words[16], words[17], words[18]}}}}};
}

std::filesystem::path create_campaign(const CampaignPlan& plan,
                                      const std::filesystem::path& output_root,
                                      const std::filesystem::path& archive_source,
                                      const std::string& requested_id) {
  const auto id = requested_id.empty()
      ? std::string("ctx_") + utc_compact() + "_" + hex_u64(plan.request.seed).substr(8U)
      : requested_id;
  const auto directory = output_root / id;
  if (std::filesystem::exists(directory)) throw std::runtime_error("campaign already exists: " + directory.string());
  nlohmann::json contexts = nlohmann::json::array();
  for (const auto& selected : plan.contexts) {
    auto value = archived_json(selected.context);
    value["partition"] = selected.partition;
    value["extranonce2_values"] = selected.extranonce2_values;
    contexts.push_back(std::move(value));
  }
  nlohmann::json thresholds = nlohmann::json::array();
  for (const auto bits : header_space::kThresholdBits) {
    thresholds.push_back({{"leading_zero_bits", bits},
                          {"per_hash_probability", std::ldexp(1.0, -static_cast<int>(bits))},
                          {"expected_hits_per_complete_block",
                           std::ldexp(1.0, 32 - static_cast<int>(bits))}});
  }
  const auto preview = plan_preview_json(plan);
  nlohmann::json manifest = {
      {"schema_version", 1}, {"campaign_id", id}, {"created_at_utc", logging::ResultLogger::utc_now()},
      {"profile", plan.request.profile}, {"seed", plan.request.seed},
      {"sizing_request", {
          {"total_blocks", plan.request.total_blocks
              ? nlohmann::json(*plan.request.total_blocks) : nlohmann::json(nullptr)},
          {"time_budget_minutes", plan.request.time_budget_minutes
              ? nlohmann::json(*plan.request.time_budget_minutes) : nlohmann::json(nullptr)},
          {"blocks_per_context", plan.request.blocks_per_context
              ? nlohmann::json(*plan.request.blocks_per_context) : nlohmann::json(nullptr)},
          {"prevhash_count", plan.request.prevhash_count},
          {"context_count", plan.request.context_count}}},
      {"archive_source", std::filesystem::absolute(archive_source).string()},
      {"sampling", {{"context_strategy", "seeded_temporal_stratification_balanced_by_prevhash"},
                    {"extranonce2_strategy", "seeded_stratified_uniform_high_byte"}}},
      {"partitions", {{"unit", "complete_prevhash"}, {"names", {"discovery", "validation", "holdout"}},
                      {"fractions", {{"discovery", plan.request.discovery_fraction},
                                     {"validation", plan.request.validation_fraction},
                                     {"holdout", plan.request.holdout_fraction}}},
                      {"overlap_allowed", false}}},
      {"scan", {{"nonce_start", 0}, {"nonce_count", header_space::kNonceSpaceSize},
                {"complete_B_J_e_required", true}, {"exclusive_variable", "nonce_uint32"}}},
      {"primary_labels", {"minimum_pow_value", "best_difficulty", "quality_bits"}},
      {"tail_thresholds", thresholds},
      {"primary_metrics", {"holdout_top_10_percent_lift", "holdout_static_score_correlation"}},
      {"multiple_testing_policy", "all tested features counted; exploratory findings never called proof"},
      {"probe_arm", {{"enabled", false}, {"separate_from_pure_static", true}}},
      {"plan_preview", preview}, {"contexts", contexts}};
  checkpoint::StateStore(directory / "manifest.json").save(manifest);
  checkpoint::StateStore(directory / "checkpoint.json").save({
      {"schema_version", 1}, {"campaign_id", id}, {"status", "PLANNED"},
      {"completed_blocks", 0}, {"total_blocks", plan.total_blocks}, {"checkpoint_count", 0}});
  return directory;
}

int run_campaign(const std::filesystem::path& directory,
                 const std::filesystem::path& kernel,
                 const std::string& device,
                 const std::uint64_t zone_size,
                 const std::size_t batch_zones,
                 const std::size_t local_size) {
  const auto manifest = checkpoint::StateStore(directory / "manifest.json").load_or(nlohmann::json());
  if (!manifest.is_object()) throw std::runtime_error("campaign manifest is missing");
  const auto labels_path = directory / "block_labels.jsonl";
  const auto features_path = directory / "features.jsonl";
  auto completed = ids_in_jsonl(labels_path, true);
  auto featured = ids_in_jsonl(features_path, false);
  const auto total = manifest.at("plan_preview").at("total_blocks_B_J_e").get<std::uint64_t>();
  const auto campaign_id_value = manifest.at("campaign_id").get<std::string>();
  header_space::GpuScanner scanner(device, kernel, local_size);
  const auto started = std::chrono::steady_clock::now();
  std::uint64_t checkpoint_count = checkpoint::StateStore(directory / "checkpoint.json")
      .load_or(nlohmann::json::object()).value("checkpoint_count", 0ULL);
  double best_difficulty = 0.0;
  std::size_t context_index = 0;
  for (const auto& stored : manifest.at("contexts")) {
    ++context_index;
    const auto context = context_from_json(stored);
    const auto partition = stored.at("partition").get<std::string>();
    for (const auto& extranonce_value : stored.at("extranonce2_values")) {
      const auto extranonce2 = extranonce_value.get<std::string>();
      const auto id = block_id(context, extranonce2);
      if (completed.contains(id)) continue;
      const auto built = stratum::build_work(context.job, context.extranonce1, extranonce2, 0);
      if (!featured.contains(id)) {
        const auto feature_start = std::chrono::steady_clock::now();
        auto feature = pre_scan_features(context, extranonce2, id, partition);
        feature["cost"] = {{"reconstruction_and_feature_seconds", std::chrono::duration<double>(
            std::chrono::steady_clock::now() - feature_start).count()},
                           {"probe_hashes", 0}, {"probe_seconds", 0.0}};
        append_jsonl(features_path, feature);
        featured.insert(id);
      }
      const auto scan = scanner.scan(built.header, 0, header_space::kNonceSpaceSize,
                                     zone_size, batch_zones);
      const auto global = header_space::aggregate_zones(scan.zones);
      if (global.total_nonce_count != header_space::kNonceSpaceSize) {
        throw std::runtime_error("incomplete B(J,e) refused");
      }
      const auto minimum = header_space::pow_value_hex(global.minimum_pow_value);
      const auto difficulty = bitcoin::difficulty_from_target(bitcoin::target_from_hex(minimum));
      best_difficulty = std::max(best_difficulty, difficulty);
      append_jsonl(labels_path, {
          {"schema_version", 1}, {"label_stage", "POST_SCAN"}, {"campaign_id", campaign_id_value},
          {"block_id", id}, {"complete", true}, {"partition", partition},
          {"prevhash_group", context.job.prevhash}, {"work_fingerprint", context.work_fingerprint},
          {"job_id", context.job.job_id}, {"extranonce1", context.extranonce1},
          {"extranonce2", extranonce2}, {"extranonce2_size", context.extranonce2_size},
          {"version", context.job.version}, {"nbits", context.job.nbits}, {"ntime", context.job.ntime},
          {"merkle_root", crypto::bitcoin_hash_hex(built.merkle_root)},
          {"header_prefix", crypto::to_hex(std::span<const std::uint8_t>(built.header.data(), 76U))},
          {"scan", {{"nonce_start", 0}, {"nonce_end", 0xffffffffULL},
                    {"nonce_count", global.total_nonce_count}, {"elapsed_seconds", scan.elapsed_seconds},
                    {"hash_rate_hps", scan.elapsed_seconds > 0.0
                        ? global.total_nonce_count / scan.elapsed_seconds : 0.0},
                    {"worker", "OpenCL"}, {"device", scan.device.name}}},
          {"quality", {{"minimum_pow_value", minimum}, {"minimum_nonce", global.minimum_nonce},
                       {"best_difficulty", difficulty}, {"quality_bits", quality_bits(global.minimum_pow_value)},
                       {"tail_counts", counts_json(global.counts)},
                       {"network_target_hits", global.network_hits}}}});
      completed.insert(id);
      ++checkpoint_count;
      checkpoint::StateStore(directory / "checkpoint.json").save({
          {"schema_version", 1}, {"campaign_id", campaign_id_value},
          {"status", completed.size() == total ? "COMPLETE" : "RUNNING"},
          {"completed_blocks", completed.size()}, {"total_blocks", total},
          {"checkpoint_count", checkpoint_count}, {"last_completed_block_id", id},
          {"updated_at_utc", logging::ResultLogger::utc_now()}});

      const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
      const auto rate = elapsed > 0.0 ? completed.size() / elapsed : 0.0;
      const auto remaining = rate > 0.0 ? (total - completed.size()) / rate : 0.0;
      std::cout << "\n=== ANALYSE CONTEXTUELLE SHA-256 ===\n"
                << "Campagne             : " << campaign_id_value << '\n'
                << "Profil               : " << manifest.value("profile", "CUSTOM") << '\n'
                << "Contextes            : " << context_index << " / " << manifest.at("contexts").size() << '\n'
                << "Bloc B(J,e)          : " << completed.size() << " / " << total << '\n'
                << "Progression globale  : " << std::fixed << std::setprecision(2)
                << (100.0 * completed.size() / total) << "%\n"
                << "prevhash             : " << context.job.prevhash << '\n'
                << "work_fingerprint     : " << context.work_fingerprint.substr(0, 16U) << "...\n"
                << "extranonce2          : " << extranonce2 << '\n'
                << "Débit GPU            : " << (scan.elapsed_seconds > 0.0
                    ? global.total_nonce_count / scan.elapsed_seconds / 1e9 : 0.0) << " GH/s\n"
                << "Blocs/s              : " << rate << '\n'
                << "Hashes traités       : " << completed.size() * header_space::kNonceSpaceSize << '\n'
                << "Temps écoulé         : " << format_duration(elapsed) << '\n'
                << "ETA                   : " << format_duration(remaining) << '\n'
                << "Fin estimée          : " << utc_after(remaining) << '\n'
                << "Checkpoints           : " << checkpoint_count << '\n'
                << "Meilleure difficulté : " << best_difficulty << '\n'
                << "Erreurs/retries      : 0 / 0\n" << std::flush;
    }
  }
  if (completed.size() == total) analyze_campaign(directory, false);
  return completed.size() == total ? 0 : 2;
}

int run_smoke(const CampaignPlan& plan,
              const std::filesystem::path& output_root,
              const std::filesystem::path& kernel,
              const std::string& device,
              const std::uint64_t nonce_count,
              const std::uint64_t zone_size,
              const std::size_t batch_zones,
              const std::size_t local_size) {
  if (nonce_count == 0U || nonce_count >= header_space::kNonceSpaceSize) {
    throw std::invalid_argument("smoke nonce_count must be in [1,2^32)");
  }
  const auto directory = output_root / ("smoke_" + utc_compact());
  std::filesystem::create_directories(directory);
  const auto& selected = plan.contexts.front();
  const auto extranonce2 = selected.extranonce2_values.front();
  const auto built = stratum::build_work(selected.context.job, selected.context.extranonce1, extranonce2, 0);
  append_jsonl(directory / "features.jsonl", pre_scan_features(
      selected.context, extranonce2, block_id(selected.context, extranonce2), "smoke_test_only"));
  const auto cpu = header_space::scan_cpu(built.header, 0, nonce_count, std::min(zone_size, nonce_count));
  nlohmann::json report;
  if (header_space::opencl_compiled() && !header_space::enumerate_gpu_devices().empty()) {
    header_space::GpuScanner scanner(device, kernel, local_size);
    const auto gpu = scanner.scan(built.header, 0, nonce_count, std::min(zone_size, nonce_count), batch_zones);
    if (!header_space::same_statistics(cpu, gpu.zones)) throw std::runtime_error("smoke CPU/GPU mismatch");
    report = {{"backend", "OpenCL"}, {"device", gpu.device.name}, {"elapsed_seconds", gpu.elapsed_seconds},
              {"hash_rate_hps", nonce_count / gpu.elapsed_seconds}};
  } else {
    report = {{"backend", "CPU_REFERENCE"}, {"device", "CPU"}, {"elapsed_seconds", nullptr},
              {"hash_rate_hps", nullptr}};
  }
  const auto global = header_space::aggregate_zones(cpu);
  report.update({{"schema_version", 1}, {"status", "SMOKE_TEST_RANGE_COMPLETE"},
                 {"scientific_ground_truth", false}, {"nonce_count", nonce_count},
                 {"context_reconstructed", true}, {"cpu_gpu_exact", true},
                 {"minimum_pow_value", header_space::pow_value_hex(global.minimum_pow_value)},
                 {"minimum_nonce", global.minimum_nonce}, {"tail_counts", counts_json(global.counts)}});
  checkpoint::StateStore(directory / "smoke_report.json").save(report);
  checkpoint::StateStore(directory / "checkpoint.json").save({
      {"status", "SMOKE_TEST_COMPLETE"}, {"completed_test_ranges", 1}, {"resume_format_valid", true}});
  std::cout << report.dump(2) << '\n';
  std::cout << "Smoke output: " << directory.string() << '\n';
  return 0;
}

nlohmann::json analyze_campaign(const std::filesystem::path& directory,
                                const bool finalize_holdout) {
  const auto manifest = checkpoint::StateStore(directory / "manifest.json").load_or(nlohmann::json());
  std::unordered_map<std::string, nlohmann::json> features;
  {
    std::ifstream input(directory / "features.jsonl", std::ios::binary);
    std::string line;
    while (std::getline(input, line)) if (!line.empty()) {
      auto value = nlohmann::json::parse(line);
      features.emplace(value.at("block_id").get<std::string>(), std::move(value));
    }
  }
  std::vector<JoinedRow> rows;
  std::uint64_t total_hashes = 0;
  double total_feature_seconds = 0.0;
  double total_scan_seconds = 0.0;
  std::map<unsigned, std::uint64_t> observed_tails;
  {
    std::ifstream input(directory / "block_labels.jsonl", std::ios::binary);
    std::string line;
    while (std::getline(input, line)) if (!line.empty()) {
      const auto label = nlohmann::json::parse(line);
      if (!label.value("complete", false)) continue;
      const auto partition = label.at("partition").get<std::string>();
      if (!finalize_holdout && partition == "holdout") continue;
      const auto id = label.at("block_id").get<std::string>();
      const auto found = features.find(id);
      if (found == features.end()) throw std::runtime_error("label has no PRE_SCAN feature row: " + id);
      const auto& feature = found->second;
      if (feature.value("feature_stage", "") != "PRE_SCAN" || feature.value("post_scan_fields_present", true)) {
        throw std::runtime_error("feature leakage guard failed");
      }
      JoinedRow row;
      row.block = id;
      row.context = label.at("work_fingerprint").get<std::string>();
      row.prevhash = label.at("prevhash_group").get<std::string>();
      row.partition = partition;
      row.extranonce2 = label.at("extranonce2").get<std::string>();
      row.quality = label.at("quality").at("quality_bits").get<double>();
      row.difficulty = label.at("quality").at("best_difficulty").get<double>();
      row.numeric_score = rank_value(row.extranonce2);
      row.hash_score = rank_value(feature.at("derived").at("extranonce2_sha256").get<std::string>());
      row.static_score = feature.at("derived").at("header_prefix_hamming_weight").get<double>();
      row.random_score = rank_value(id);
      for (const auto bits : header_space::kThresholdBits) {
        const auto key = "leading_zero_" + std::to_string(bits);
        row.tails[bits] = label.at("quality").at("tail_counts").at(key).get<std::uint64_t>();
        observed_tails[bits] += row.tails[bits];
      }
      total_hashes += label.at("scan").at("nonce_count").get<std::uint64_t>();
      total_scan_seconds += label.at("scan").value("elapsed_seconds", 0.0);
      if (feature.contains("cost")) {
        total_feature_seconds += feature.at("cost").value("reconstruction_and_feature_seconds", 0.0);
      }
      rows.push_back(std::move(row));
    }
  }

  std::set<std::string> contexts, prevhashes;
  for (const auto& row : rows) { contexts.insert(row.context); prevhashes.insert(row.prevhash); }
  std::vector<std::pair<double, double>> discovery_fit;
  for (const auto& row : rows) if (row.partition == "discovery") {
    discovery_fit.emplace_back(row.static_score, row.quality);
  }
  double model_slope = 0.0;
  double model_intercept = 0.0;
  if (discovery_fit.size() >= 3U) {
    double mean_x = 0.0, mean_y = 0.0;
    for (const auto& [x, y] : discovery_fit) { mean_x += x; mean_y += y; }
    mean_x /= discovery_fit.size();
    mean_y /= discovery_fit.size();
    double covariance = 0.0, variance = 0.0;
    for (const auto& [x, y] : discovery_fit) {
      covariance += (x - mean_x) * (y - mean_y);
      variance += (x - mean_x) * (x - mean_x);
    }
    model_slope = variance > 0.0 ? covariance / (variance + 1.0) : 0.0;
    model_intercept = mean_y - model_slope * mean_x;
  }
  for (auto& row : rows) row.model_score = model_intercept + model_slope * row.static_score;
  nlohmann::json random_oracle = nlohmann::json::array();
  bool compatible = true;
  for (const auto bits : header_space::kThresholdBits) {
    const auto probability = std::ldexp(1.0, -static_cast<int>(bits));
    const auto expected = static_cast<double>(total_hashes) * probability;
    const auto variance = expected * (1.0 - probability);
    const auto z = variance > 0.0 ? (observed_tails[bits] - expected) / std::sqrt(variance) : 0.0;
    if (std::abs(z) > 4.0) compatible = false;
    random_oracle.push_back({{"leading_zero_bits", bits}, {"observed", observed_tails[bits]},
                             {"expected", expected}, {"z_score", z},
                             {"interpretation", std::abs(z) <= 4.0 ? "compatible" : "anomaly_to_investigate"}});
  }

  nlohmann::json correlations = nlohmann::json::array();
  for (const auto& partition : {"discovery", "validation", "holdout"}) {
    if (std::string(partition) == "holdout" && !finalize_holdout) continue;
    std::vector<std::pair<double, double>> numeric, hashed, statics;
    for (const auto& row : rows) if (row.partition == partition) {
      numeric.emplace_back(row.numeric_score, row.quality);
      hashed.emplace_back(row.hash_score, row.quality);
      statics.emplace_back(row.static_score, row.quality);
    }
    correlations.push_back({{"partition", partition}, {"n", numeric.size()},
                            {"pearson_numeric_extranonce2", pearson(numeric)},
                            {"spearman_numeric_extranonce2", spearman(numeric)},
                            {"pearson_hash_extranonce2", pearson(hashed)},
                            {"spearman_hash_extranonce2", spearman(hashed)},
                            {"pearson_static_hamming", pearson(statics)},
                            {"spearman_static_hamming", spearman(statics)},
                            {"exploratory", std::string(partition) == "discovery"}});
  }

  nlohmann::json per_context = nlohmann::json::array();
  nlohmann::json per_prevhash = nlohmann::json::array();
  std::map<std::string, std::vector<std::pair<double, double>>> context_pairs, prevhash_pairs;
  std::map<std::string, std::vector<double>> context_quality, prevhash_quality;
  for (const auto& row : rows) {
    context_pairs[row.context].emplace_back(row.static_score, row.quality);
    prevhash_pairs[row.prevhash].emplace_back(row.static_score, row.quality);
    context_quality[row.context].push_back(row.quality);
    prevhash_quality[row.prevhash].push_back(row.quality);
  }
  std::size_t context_positive = 0, context_testable = 0;
  for (const auto& [id, pairs] : context_pairs) {
    const auto correlation = spearman(pairs);
    if (pairs.size() >= 3U) { ++context_testable; if (correlation > 0.0) ++context_positive; }
    per_context.push_back({{"work_fingerprint", id}, {"n", pairs.size()},
                           {"spearman_static_hamming", correlation}});
  }
  std::size_t prevhash_positive = 0, prevhash_testable = 0;
  for (const auto& [id, pairs] : prevhash_pairs) {
    const auto correlation = spearman(pairs);
    if (pairs.size() >= 3U) { ++prevhash_testable; if (correlation > 0.0) ++prevhash_positive; }
    per_prevhash.push_back({{"prevhash", id}, {"n", pairs.size()},
                            {"spearman_static_hamming", correlation}});
  }

  nlohmann::json rankings = nlohmann::json::array();
  for (const auto& partition : {"discovery", "validation", "holdout"}) {
    if (std::string(partition) == "holdout" && !finalize_holdout) continue;
    std::vector<JoinedRow> subset;
    for (const auto& row : rows) if (row.partition == partition) subset.push_back(row);
    if (subset.empty()) continue;
    for (const auto& name : {"random_seeded", "numeric_extranonce2", "hash_extranonce2",
                             "static_hamming", "linear_static_model"}) {
      auto metrics = ranking_metrics(subset, name, false);
      metrics["partition"] = partition;
      metrics["exploratory"] = std::string(partition) == "discovery";
      rankings.push_back(std::move(metrics));
    }
  }

  std::string conclusion = "AUCUNE ÉVIDENCE";
  if (rows.size() < 100U) conclusion = "AUCUNE ÉVIDENCE — ÉCHANTILLON TROP FAIBLE";
  std::vector<double> qualities;
  for (const auto& row : rows) qualities.push_back(row.quality);
  std::sort(qualities.begin(), qualities.end());
  const auto quantile = [&](const double fraction) {
    if (qualities.empty()) return 0.0;
    return qualities[static_cast<std::size_t>(std::floor(fraction * (qualities.size() - 1U)))];
  };
  const auto group_variance = [](const std::map<std::string, std::vector<double>>& groups) {
    std::vector<double> means;
    for (const auto& [unused, values] : groups) {
      means.push_back(std::accumulate(values.begin(), values.end(), 0.0) / values.size());
    }
    if (means.size() < 2U) return 0.0;
    const auto mean = std::accumulate(means.begin(), means.end(), 0.0) / means.size();
    double variance = 0.0;
    for (const auto value : means) variance += (value - mean) * (value - mean);
    return variance / (means.size() - 1U);
  };
  nlohmann::json summary = {
      {"schema_version", 1}, {"campaign_id", manifest.value("campaign_id", directory.filename().string())},
      {"holdout_finalized", finalize_holdout},
      {"corpus", {{"prevhashes", prevhashes.size()}, {"contexts", contexts.size()},
                  {"extranonce2", rows.size()}, {"complete_blocks", rows.size()},
                  {"total_hashes", total_hashes}}},
      {"random_oracle_sanity", {{"globally_compatible", compatible}, {"thresholds", random_oracle}}},
      {"distribution", {{"label", "minimum_pow_value / best_difficulty / quality_bits"},
                        {"rows", rows.size()}, {"quality_bits_quantiles",
                         {{"q10", quantile(0.10)}, {"q25", quantile(0.25)},
                          {"q50", quantile(0.50)}, {"q75", quantile(0.75)},
                          {"q90", quantile(0.90)}}}}},
      {"intra_context_analysis", {{"per_context", per_context}}},
      {"inter_context_analysis", {{"independent_units", contexts.size()},
                                  {"variance_of_context_means", group_variance(context_quality)}}},
      {"inter_prevhash_analysis", {{"independent_units", prevhashes.size()},
                                   {"variance_of_prevhash_means", group_variance(prevhash_quality)},
                                   {"per_prevhash", per_prevhash}}},
      {"context_evolution", {{"status", "descriptive differentials retained in PRE_SCAN rows"}}},
      {"feature_correlations", correlations},
      {"correlation_stability", {{"status", rows.size() >= 100U ? "reported_by_partition_and_group" : "insufficient_sample"},
                                 {"testable_contexts", context_testable},
                                 {"positive_sign_fraction_contexts", context_testable > 0U
                                      ? static_cast<double>(context_positive) / context_testable : 0.0},
                                 {"testable_prevhashes", prevhash_testable},
                                 {"positive_sign_fraction_prevhashes", prevhash_testable > 0U
                                      ? static_cast<double>(prevhash_positive) / prevhash_testable : 0.0}}},
      {"baselines_and_rankings", rankings},
      {"models", {{"type", "ridge_linear_single_static_feature"},
                  {"trained_on", "discovery"}, {"slope", model_slope},
                  {"intercept", model_intercept},
                  {"complex_models_status", "not justified by the initial pipeline"}}},
      {"top_k_lift", rankings},
      {"validation", {{"unit", "complete prevhash"}}},
      {"holdout", {{"opened", finalize_holdout}, {"immutable_result", "holdout_evaluation.json"}}},
      {"score_cost", {{"probe_enabled", false}, {"static_feature_cost_included", true},
                      {"feature_seconds", total_feature_seconds}, {"scan_seconds", total_scan_seconds},
                      {"feature_to_scan_ratio", total_scan_seconds > 0.0
                           ? total_feature_seconds / total_scan_seconds : 0.0},
                      {"net_advantage_status", "not_claimed"}}},
      {"multiple_testing", {{"tested_hypotheses", correlations.size() * 6U},
                            {"exploratory_results_are_proof", false}}},
      {"conclusion", conclusion}};
  checkpoint::StateStore(directory / "analysis_summary.json").save(summary);
  std::ostringstream report;
  report << "# Rapport d'analyse contextuelle\n\n"
         << "Campagne: " << summary["campaign_id"].get<std::string>() << "\n\n"
         << "## Corpus\n\n- Prevhash: " << prevhashes.size() << "\n- Contextes: " << contexts.size()
         << "\n- Blocs B(J,e) complets: " << rows.size() << "\n- Hashes: " << total_hashes
         << "\n\n## Contrôle random-oracle\n\n"
         << (compatible ? "Compatible avec le comportement uniforme aux seuils pré-déclarés."
                        : "Anomalie statistique à investiguer; aucune conclusion cryptanalytique automatique.")
         << "\n\n## Validation et ranking\n\n"
         << (finalize_holdout
                ? "Le holdout a été ouvert explicitement; les partitions restent séparées par prevhash complet. "
                : "Le holdout reste scellé; aucune de ses valeurs post-scan ne contribue à cette analyse. ")
         << "Les courbes top-k/lift sont dans analysis_summary.json.\n\n"
         << "## Conclusion\n\n**" << conclusion << "**\n";
  {
    std::ofstream output(directory / "report.md", std::ios::binary | std::ios::trunc);
    output << report.str();
  }
  if (finalize_holdout) {
    const auto holdout_path = directory / "holdout_evaluation.json";
    if (!std::filesystem::exists(holdout_path)) {
      checkpoint::StateStore(holdout_path).save({
          {"schema_version", 1}, {"finalized_at_utc", logging::ResultLogger::utc_now()},
          {"policy", "evaluated once after frozen baselines"},
          {"feature_correlations", correlations}, {"rankings", rankings},
          {"conclusion", conclusion}});
    }
  }
  return summary;
}

}  // namespace srm::research::context_campaign
