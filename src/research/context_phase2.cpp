#include "research/context_phase2.h"

#include "crypto/sha256.h"
#include "logging/result_logger.h"
#include "research/sha256d_whitebox.h"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace srm::research::context_phase2 {
namespace {

constexpr std::array<const char*, 8> kStateNames{
    "a", "b", "c", "d", "e", "f", "g", "h"};
constexpr std::array<double, 4> kLambdas{0.1, 1.0, 10.0, 100.0};
constexpr std::array<double, 8> kRefinementLambdas{
    0.1, 1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0};
constexpr std::array<double, 4> kTopFractions{0.01, 0.05, 0.10, 0.25};
constexpr std::array<unsigned, 7> kTailBits{26U, 28U, 30U, 32U, 34U, 36U, 38U};

struct FeatureValue {
  double value{};
  std::string category;
  std::string family;
  std::string description;
};

using FeatureMap = std::map<std::string, FeatureValue>;

struct Snapshot {
  std::array<std::uint8_t, 76> header{};
  std::array<std::uint8_t, 32> merkle{};
  whitebox::Sha256State midstate{};
  std::array<whitebox::Sha256State, 3> round_after{};
  std::uint32_t c3{};
  std::uint32_t w16{};
  std::uint32_t w17{};
  CarrySummary c3_carries{};
};

struct Row {
  std::string block_id;
  std::string context;
  std::string prevhash;
  std::string extranonce2;
  std::vector<double> x;
  std::vector<double> context_feature_ranks;
  Snapshot snapshot;
  double quality{};
  double difficulty{};
  double log_difficulty{};
  std::array<double, 7> tails{};
  double rank_quality{};
  double context_quality_score{};
  double rank_t30{};
  double context_t30_score{};
  double cv_prediction{std::numeric_limits<double>::quiet_NaN()};
  double cv_prediction_rank{};
  double rank_cv_prediction{std::numeric_limits<double>::quiet_NaN()};
  double rank_cv_prediction_rank{};
  double t30_cv_prediction{std::numeric_limits<double>::quiet_NaN()};
  double t30_cv_prediction_rank{};
  std::size_t outer_fold{};
};

struct SchemaEntry {
  std::string name;
  std::string category;
  std::string family;
  std::string description;
};

[[noreturn]] void fail(const std::string& message) {
  throw std::runtime_error("Phase 2A discovery guard: " + message);
}

void require(const bool condition, const std::string& message) {
  if (!condition) fail(message);
}

std::uint32_t read_be32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
         (static_cast<std::uint32_t>(bytes[1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2]) << 8U) |
         static_cast<std::uint32_t>(bytes[3]);
}

std::uint64_t read_be64(const std::uint8_t* bytes) {
  std::uint64_t result = 0U;
  for (unsigned i = 0; i < 8U; ++i) result = (result << 8U) | bytes[i];
  return result;
}

std::string hash_text(const std::string& value) {
  const auto* begin = reinterpret_cast<const std::uint8_t*>(value.data());
  return crypto::digest_hex(crypto::sha256(
      std::span<const std::uint8_t>(begin, value.size())));
}

std::string file_sha256(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) fail("cannot hash source file: " + path.string());
  std::vector<std::uint8_t> bytes(
      (std::istreambuf_iterator<char>(input)),
      std::istreambuf_iterator<char>());
  return crypto::digest_hex(crypto::sha256(bytes));
}

nlohmann::json directory_sha256(const std::filesystem::path& directory) {
  require(std::filesystem::is_directory(directory),
          "historical artifact directory is missing: " + directory.string());
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
    if (entry.is_regular_file()) files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  nlohmann::json result = nlohmann::json::object();
  for (const auto& path : files) {
    result[std::filesystem::relative(path, directory).generic_string()] =
        file_sha256(path);
  }
  return result;
}

nlohmann::json read_json(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) fail("cannot open required source file: " + path.string());
  nlohmann::json result;
  input >> result;
  return result;
}

void write_text(const std::filesystem::path& path, const std::string& text) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) fail("cannot create artifact: " + path.string());
  output << text;
  if (!output) fail("cannot finish artifact: " + path.string());
}

void write_json(const std::filesystem::path& path, const nlohmann::json& value) {
  write_text(path, value.dump(2) + "\n");
}

void add_scalar(FeatureMap& output, const std::string& name,
                const double value, const std::string& category,
                const std::string& family, const std::string& description) {
  require(std::isfinite(value), "non-finite feature " + name);
  const auto [unused, inserted] = output.emplace(
      name, FeatureValue{value, category, family, description});
  require(inserted, "duplicate feature name " + name);
}

void add_word(FeatureMap& output, const std::string& prefix,
              const std::uint32_t value, const std::string& category,
              const std::string& family,
              const std::string& = {}) {
  const auto add = [&](const std::string& suffix, const double metric,
                       const std::string& description) {
    add_scalar(output, prefix + "." + suffix, metric, category, family,
               description);
  };
  add("uint32", static_cast<double>(value), "exact unsigned 32-bit value");
  add("normalized", static_cast<double>(value) / 4294967295.0,
      "uint32 divided by 2^32-1");
  add("popcount", static_cast<double>(std::popcount(value)), "Hamming weight");
  add("leading_zeros", static_cast<double>(std::countl_zero(value)),
      "leading zero bits");
  add("trailing_zeros", static_cast<double>(std::countr_zero(value)),
      "trailing zero bits");
  add("leading_ones", static_cast<double>(std::countl_one(value)),
      "leading one bits");
  add("trailing_ones", static_cast<double>(std::countr_one(value)),
      "trailing one bits");
  add("transitions", static_cast<double>(
          std::popcount((value ^ (value >> 1U)) & 0x7fffffffU)),
      "adjacent 0/1 transitions");
  for (unsigned byte = 0; byte < 4U; ++byte) {
    const auto shift = (3U - byte) * 8U;
    add("byte" + std::to_string(byte) + "_popcount",
        static_cast<double>(std::popcount((value >> shift) & 0xffU)),
        "big-endian byte Hamming weight");
  }
  add("half_hi_popcount", static_cast<double>(std::popcount(value >> 16U)),
      "high half-word Hamming weight");
  add("half_lo_popcount", static_cast<double>(std::popcount(value & 0xffffU)),
      "low half-word Hamming weight");
}

void add_carries(FeatureMap& output, const std::string& prefix,
                 const std::vector<std::uint32_t>& operands,
                 const std::string& category, const std::string& family) {
  const auto summary = fixed_addition_carries(operands);
  add_scalar(output, prefix + ".carry_count", summary.carry_count, category,
             family, "bit columns with non-zero carry-out");
  add_scalar(output, prefix + ".maximum_chain", summary.maximum_chain,
             category, family, "longest consecutive carry-out chain");
  add_scalar(output, prefix + ".chain_count", summary.chain_count, category,
             family, "number of carry-out chains");
  add_scalar(output, prefix + ".carry_mask_uint32",
             static_cast<double>(summary.carry_mask), category, family,
             "bit mask of carry-out positions");
  add_scalar(output, prefix + ".maximum_carry_value",
             static_cast<double>(summary.maximum_carry_value), category,
             family, "largest integer carry-out in a bit column");
}

unsigned byte_hamming(const std::span<const std::uint8_t> left,
                      const std::span<const std::uint8_t> right) {
  require(left.size() == right.size(), "Hamming inputs have different sizes");
  unsigned result = 0U;
  for (std::size_t i = 0; i < left.size(); ++i) {
    result += std::popcount(static_cast<unsigned>(left[i] ^ right[i]));
  }
  return result;
}

unsigned state_hamming(const whitebox::Sha256State& left,
                       const whitebox::Sha256State& right) {
  unsigned result = 0U;
  for (std::size_t i = 0; i < left.size(); ++i) {
    result += std::popcount(left[i] ^ right[i]);
  }
  return result;
}

std::uint32_t big_sigma0(const std::uint32_t value) {
  return std::rotr(value, 2) ^ std::rotr(value, 13) ^ std::rotr(value, 22);
}

std::uint32_t big_sigma1(const std::uint32_t value) {
  return std::rotr(value, 6) ^ std::rotr(value, 11) ^ std::rotr(value, 25);
}

std::uint32_t small_sigma0(const std::uint32_t value) {
  return std::rotr(value, 7) ^ std::rotr(value, 18) ^ (value >> 3U);
}

std::uint32_t small_sigma1(const std::uint32_t value) {
  return std::rotr(value, 17) ^ std::rotr(value, 19) ^ (value >> 10U);
}

std::uint32_t choice(const std::uint32_t e, const std::uint32_t f,
                     const std::uint32_t g) {
  return (e & f) ^ (~e & g);
}

std::uint32_t majority(const std::uint32_t a, const std::uint32_t b,
                       const std::uint32_t c) {
  return (a & b) ^ (a & c) ^ (b & c);
}

void reject_post_scan_keys(const nlohmann::json& source) {
  static constexpr std::array<std::string_view, 8> banned{
      "minimum_nonce", "minimum_pow_value", "best_difficulty",
      "quality_bits", "tail_counts", "network_target_hits", "ranking",
      "rank_quality_bits"};
  const auto dumped = source.dump();
  for (const auto key : banned) {
    require(dumped.find(std::string("\"") + std::string(key) + "\"") ==
                std::string::npos,
            "POST_SCAN key found in PRE_SCAN source: " + std::string(key));
  }
}

FeatureMap self_feature_map(const nlohmann::json& source, Snapshot* snapshot) {
  require(source.value("feature_stage", "") == "PRE_SCAN",
          "source feature_stage is not PRE_SCAN");
  require(!source.value("post_scan_fields_present", true),
          "source feature row reports POST_SCAN fields");
  require(source.value("partition", "") == "discovery",
          "attempt to derive a non-discovery feature row");
  reject_post_scan_keys(source);

  const auto& derived = source.at("derived");
  const auto header_bytes = crypto::from_hex(
      derived.at("header_prefix_76_bytes_hex").get<std::string>());
  require(header_bytes.size() == 76U, "header prefix is not 76 bytes");
  const auto prescan = whitebox::build_prescan_compression1(header_bytes);
  const auto& stored_midstate =
      derived.at("sha256_first_chunk_midstate_words");
  require(stored_midstate.size() == 8U, "stored midstate has wrong width");
  for (std::size_t i = 0; i < 8U; ++i) {
    require(stored_midstate.at(i).get<std::uint32_t>() == prescan.midstate[i],
            "stored midstate differs from white-box reconstruction");
  }

  const auto merkle_bytes = crypto::from_hex(
      derived.at("merkle_root").get<std::string>());
  require(merkle_bytes.size() == 32U, "Merkle root is not 32 bytes");
  const auto extranonce_bytes = crypto::from_hex(
      source.at("extranonce2").get<std::string>());
  require(extranonce_bytes.size() == source.at("extranonce2_size").get<unsigned>(),
          "extranonce2 width disagrees with source metadata");

  FeatureMap output;
  std::array<std::uint32_t, 19> header_words{};
  for (std::size_t i = 0; i < header_words.size(); ++i) {
    header_words[i] = read_be32(header_bytes.data() + i * 4U);
    add_word(output, "header.word" + std::to_string(i), header_words[i],
             "SELF_ONLY", "HEADER", "");
  }
  const auto& stored_header_words = derived.at("header_words_be");
  require(stored_header_words.size() == header_words.size(),
          "stored header word count is not 19");
  for (std::size_t i = 0; i < header_words.size(); ++i) {
    require(stored_header_words.at(i).get<std::uint32_t>() == header_words[i],
            "stored header words differ from prefix bytes");
  }

  for (std::size_t i = 0; i < prescan.midstate.size(); ++i) {
    add_word(output, "midstate.h" + std::to_string(i), prescan.midstate[i],
             "SELF_ONLY", "MIDSTATE", "");
  }
  for (std::size_t i = 0; i < 8U; ++i) {
    add_word(output, "merkle.word" + std::to_string(i),
             read_be32(merkle_bytes.data() + i * 4U), "SELF_ONLY",
             "MERKLE", "");
  }
  for (std::size_t offset = 0, word = 0; offset < extranonce_bytes.size();
       offset += 4U, ++word) {
    std::array<std::uint8_t, 4> padded{};
    const auto take = std::min<std::size_t>(4U, extranonce_bytes.size() - offset);
    std::copy_n(extranonce_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                take, padded.begin());
    add_word(output, "extranonce2.word" + std::to_string(word),
             read_be32(padded.data()), "SELF_ONLY", "EXTRANONCE2", "");
  }
  add_word(output, "field.version", header_words[0], "SELF_ONLY", "HEADER_FIELD", "");
  add_word(output, "field.ntime", header_words[17], "SELF_ONLY", "HEADER_FIELD", "");
  add_word(output, "field.nbits", header_words[18], "SELF_ONLY", "HEADER_FIELD", "");

  for (const auto& round : prescan.rounds) {
    const auto prefix = "round" + std::to_string(round.round_index);
    for (std::size_t i = 0; i < 8U; ++i) {
      add_word(output, prefix + ".before." + kStateNames[i], round.before[i],
               "SELF_ONLY", "ROUND_STATE", "");
      add_word(output, prefix + ".after." + kStateNames[i], round.after[i],
               "SELF_ONLY", "ROUND_STATE", "");
    }
    add_word(output, prefix + ".W", round.w, "SELF_ONLY", "ROUND_PRIMITIVE", "");
    add_word(output, prefix + ".K", round.k, "SELF_ONLY", "ROUND_PRIMITIVE", "");
    add_word(output, prefix + ".Sigma0_a", round.sigma0_a, "SELF_ONLY", "SHA_FUNCTION", "");
    add_word(output, prefix + ".Sigma1_e", round.sigma1_e, "SELF_ONLY", "SHA_FUNCTION", "");
    add_word(output, prefix + ".Ch", round.choice, "SELF_ONLY", "SHA_FUNCTION", "");
    add_word(output, prefix + ".Maj", round.majority, "SELF_ONLY", "SHA_FUNCTION", "");
    add_word(output, prefix + ".T1", round.temp1, "SELF_ONLY", "ROUND_RESULT", "");
    add_word(output, prefix + ".T2", round.temp2, "SELF_ONLY", "ROUND_RESULT", "");
    add_carries(output, prefix + ".T1", {round.before[7], round.sigma1_e,
                   round.choice, round.k, round.w}, "SELF_ONLY", "FIXED_CARRY");
    add_carries(output, prefix + ".T2", {round.sigma0_a, round.majority},
                "SELF_ONLY", "FIXED_CARRY");
    add_carries(output, prefix + ".new_a", {round.temp1, round.temp2},
                "SELF_ONLY", "FIXED_CARRY");
    add_carries(output, prefix + ".new_e", {round.before[3], round.temp1},
                "SELF_ONLY", "FIXED_CARRY");
  }

  const auto& r3 = prescan.rounds[2].after;
  const auto r3_sigma0 = big_sigma0(r3[0]);
  const auto r3_sigma1 = big_sigma1(r3[4]);
  const auto r3_choice = choice(r3[4], r3[5], r3[6]);
  const auto r3_majority = majority(r3[0], r3[1], r3[2]);
  add_word(output, "round3.C3", prescan.round3_c3, "SELF_ONLY", "ROUND3_BOUNDARY", "");
  add_word(output, "round3.T2", prescan.round3_t2, "SELF_ONLY", "ROUND3_BOUNDARY", "");
  add_word(output, "round3.Sigma0_a", r3_sigma0, "SELF_ONLY", "SHA_FUNCTION", "");
  add_word(output, "round3.Sigma1_e", r3_sigma1, "SELF_ONLY", "SHA_FUNCTION", "");
  add_word(output, "round3.Ch", r3_choice, "SELF_ONLY", "SHA_FUNCTION", "");
  add_word(output, "round3.Maj", r3_majority, "SELF_ONLY", "SHA_FUNCTION", "");
  add_carries(output, "round3.C3", {r3[7], r3_sigma1, r3_choice, 0xe9b5dba5U},
              "SELF_ONLY", "FIXED_CARRY");
  add_carries(output, "round3.T2", {r3_sigma0, r3_majority},
              "SELF_ONLY", "FIXED_CARRY");
  for (unsigned bit = 1U; bit < 32U; ++bit) {
    const auto denominator = std::ldexp(1.0, static_cast<int>(bit));
    const auto mask = (std::uint32_t{1} << bit) - 1U;
    add_scalar(output, "round3.C3_plus_uniform_nonce.carry_into_bit" +
        std::to_string(bit) + "_probability",
        static_cast<double>(prescan.round3_c3 & mask) / denominator,
        "SELF_ONLY", "ANALYTIC_UNIFORM_CARRY",
        "exact probability over the complete uint32 nonce domain");
  }
  add_scalar(output, "round3.C3_plus_uniform_nonce.expected_carry_count",
             expected_uniform_addend_carries(prescan.round3_c3),
             "SELF_ONLY", "ANALYTIC_UNIFORM_CARRY",
             "sum of exact carry-in probabilities for bits 1..31");

  const auto w1 = prescan.fixed_chunk_words[1];
  const auto w2 = prescan.fixed_chunk_words[2];
  const auto w15 = prescan.fixed_chunk_words[15];
  for (const auto& [name, value] : std::vector<std::pair<std::string, std::uint32_t>>{
           {"W16", prescan.w16}, {"W17", prescan.w17},
           {"W16.sigma0_W1", prescan.w16_sigma0_w1},
           {"W16.rotr7_W1", std::rotr(w1, 7)},
           {"W16.rotr18_W1", std::rotr(w1, 18)},
           {"W16.shr3_W1", w1 >> 3U},
           {"W17.sigma0_W2", prescan.w17_sigma0_w2},
           {"W17.rotr7_W2", std::rotr(w2, 7)},
           {"W17.rotr18_W2", std::rotr(w2, 18)},
           {"W17.shr3_W2", w2 >> 3U},
           {"W17.sigma1_W15", prescan.w17_sigma1_w15},
           {"W17.rotr17_W15", std::rotr(w15, 17)},
           {"W17.rotr19_W15", std::rotr(w15, 19)},
           {"W17.shr10_W15", w15 >> 10U}}) {
    add_word(output, "schedule." + name, value, "SELF_ONLY", "FIXED_SCHEDULE", "");
  }
  add_carries(output, "schedule.W16", {prescan.fixed_chunk_words[0],
                  prescan.w16_sigma0_w1}, "SELF_ONLY", "FIXED_CARRY");
  add_carries(output, "schedule.W17", {w1, prescan.w17_sigma0_w2,
                  prescan.w17_sigma1_w15}, "SELF_ONLY", "FIXED_CARRY");
  add_word(output, "schedule.W17.partial_W1_plus_sigma0_W2",
           w1 + prescan.w17_sigma0_w2, "SELF_ONLY", "FIXED_SCHEDULE", "");
  add_carries(output, "schedule.W17.partial_W1_plus_sigma0_W2",
              {w1, prescan.w17_sigma0_w2}, "SELF_ONLY", "FIXED_CARRY");
  add_scalar(output, "schedule.W16_nonce_independent",
             prescan.w16_nonce_independent ? 1.0 : 0.0, "SELF_ONLY",
             "DEPENDENCY_AUDIT", "exact dependency classification");
  add_scalar(output, "schedule.W17_nonce_independent",
             prescan.w17_nonce_independent ? 1.0 : 0.0, "SELF_ONLY",
             "DEPENDENCY_AUDIT", "exact dependency classification");
  add_scalar(output, "schedule.W18_nonce_dependent",
             prescan.w18_nonce_dependent ? 1.0 : 0.0, "SELF_ONLY",
             "DEPENDENCY_AUDIT", "exact dependency classification");

  std::array<unsigned, 8> state_weights{};
  for (std::size_t i = 0; i < 8U; ++i) state_weights[i] = std::popcount(r3[i]);
  const auto [minimum_weight, maximum_weight] = std::minmax_element(
      state_weights.begin(), state_weights.end());
  const auto mean_weight = std::accumulate(state_weights.begin(), state_weights.end(), 0.0) / 8.0;
  double variance = 0.0;
  for (const auto value : state_weights) variance += (value - mean_weight) * (value - mean_weight);
  add_scalar(output, "composite.r2_state_popcount.mean", mean_weight,
             "SELF_ONLY", "COMPOSITE", "mean state-word Hamming weight");
  add_scalar(output, "composite.r2_state_popcount.variance", variance / 8.0,
             "SELF_ONLY", "COMPOSITE", "population variance of state-word Hamming weights");
  add_scalar(output, "composite.r2_state_popcount.minimum", *minimum_weight,
             "SELF_ONLY", "COMPOSITE", "minimum state-word Hamming weight");
  add_scalar(output, "composite.r2_state_popcount.maximum", *maximum_weight,
             "SELF_ONLY", "COMPOSITE", "maximum state-word Hamming weight");
  for (std::size_t i = 0; i < 8U; ++i) {
    for (std::size_t j = i + 1U; j < 8U; ++j) {
      const auto prefix = std::string("composite.r2_state.") + kStateNames[i] + "_" + kStateNames[j];
      add_scalar(output, prefix + ".hamming_distance",
                 std::popcount(r3[i] ^ r3[j]), "SELF_ONLY", "COMPOSITE",
                 "pairwise state Hamming distance");
      add_scalar(output, prefix + ".xor_normalized",
                 static_cast<double>(r3[i] ^ r3[j]) / 4294967295.0,
                 "SELF_ONLY", "COMPOSITE", "pairwise state XOR");
      add_scalar(output, prefix + ".add_normalized",
                 static_cast<double>(r3[i] + r3[j]) / 4294967295.0,
                 "SELF_ONLY", "COMPOSITE", "pairwise addition modulo 2^32");
      add_scalar(output, prefix + ".difference_normalized",
                 static_cast<double>(r3[i] - r3[j]) / 4294967295.0,
                 "SELF_ONLY", "COMPOSITE", "pairwise difference modulo 2^32");
      add_scalar(output, prefix + ".rotation_xor_normalized",
                 static_cast<double>(r3[i] ^ std::rotr(r3[j], 16)) / 4294967295.0,
                 "SELF_ONLY", "COMPOSITE", "XOR with 16-bit rotated peer");
    }
  }
  for (std::size_t i = 0; i < 4U; ++i) {
    add_scalar(output, std::string("composite.symmetry.") + kStateNames[i] +
                 "_" + kStateNames[7U - i] + "_hamming",
               std::popcount(r3[i] ^ r3[7U - i]), "SELF_ONLY", "COMPOSITE",
               "left/right state symmetry distance");
  }

  add_scalar(output, "baseline.numeric_extranonce2",
             extranonce_bytes.size() >= 8U
                 ? static_cast<double>(read_be64(extranonce_bytes.data())) /
                       static_cast<double>(std::numeric_limits<std::uint64_t>::max())
                 : static_cast<double>(read_be32(
                       std::array<std::uint8_t, 4>{}.data())),
             "SELF_ONLY", "SANITY_BASELINE", "numeric extranonce2 baseline");
  const auto extranonce_hash = crypto::sha256(extranonce_bytes);
  add_scalar(output, "baseline.hash_extranonce2",
             static_cast<double>(read_be64(extranonce_hash.data())) /
                 static_cast<double>(std::numeric_limits<std::uint64_t>::max()),
             "SELF_ONLY", "SANITY_BASELINE", "SHA256(extranonce2) baseline");
  unsigned header_weight = 0U;
  for (const auto byte : header_bytes) header_weight += std::popcount(byte);
  add_scalar(output, "baseline.header_prefix_hamming_weight", header_weight,
             "SELF_ONLY", "SANITY_BASELINE", "header-prefix Hamming-weight baseline");
  const auto id_hash = crypto::sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(source.at("block_id").get_ref<const std::string&>().data()),
      source.at("block_id").get_ref<const std::string&>().size()));
  add_scalar(output, "baseline.random_deterministic",
             static_cast<double>(read_be64(id_hash.data())) /
                 static_cast<double>(std::numeric_limits<std::uint64_t>::max()),
             "SELF_ONLY", "SANITY_BASELINE", "deterministic random-order baseline");

  if (snapshot != nullptr) {
    std::copy(header_bytes.begin(), header_bytes.end(), snapshot->header.begin());
    std::copy(merkle_bytes.begin(), merkle_bytes.end(), snapshot->merkle.begin());
    snapshot->midstate = prescan.midstate;
    for (std::size_t i = 0; i < 3U; ++i) snapshot->round_after[i] = prescan.rounds[i].after;
    snapshot->c3 = prescan.round3_c3;
    snapshot->w16 = prescan.w16;
    snapshot->w17 = prescan.w17;
    snapshot->c3_carries = fixed_addition_carries(
        {r3[7], r3_sigma1, r3_choice, 0xe9b5dba5U});
  }
  return output;
}

nlohmann::json feature_map_json(const FeatureMap& values) {
  nlohmann::json result = nlohmann::json::object();
  for (const auto& [name, item] : values) result[name] = item.value;
  return result;
}

}  // namespace

CarrySummary fixed_addition_carries(
    const std::vector<std::uint32_t>& operands) {
  if (operands.empty()) throw std::invalid_argument("carry analysis needs operands");
  CarrySummary result;
  std::uint64_t carry = 0U;
  unsigned current_chain = 0U;
  bool in_chain = false;
  for (unsigned bit = 0U; bit < 32U; ++bit) {
    std::uint64_t column = carry;
    for (const auto operand : operands) column += (operand >> bit) & 1U;
    carry = column >> 1U;
    result.maximum_carry_value = std::max(result.maximum_carry_value, carry);
    if (carry != 0U) {
      ++result.carry_count;
      ++current_chain;
      result.maximum_chain = std::max(result.maximum_chain, current_chain);
      result.carry_mask |= std::uint32_t{1} << bit;
      if (!in_chain) {
        ++result.chain_count;
        in_chain = true;
      }
    } else {
      current_chain = 0U;
      in_chain = false;
    }
  }
  return result;
}

double expected_uniform_addend_carries(const std::uint32_t fixed) {
  double result = 0.0;
  for (unsigned bit = 1U; bit < 32U; ++bit) {
    const auto mask = (std::uint32_t{1} << bit) - 1U;
    result += static_cast<double>(fixed & mask) /
              std::ldexp(1.0, static_cast<int>(bit));
  }
  return result;
}

nlohmann::json derive_self_features(const nlohmann::json& source_feature) {
  const auto values = self_feature_map(source_feature, nullptr);
  nlohmann::json schema = nlohmann::json::array();
  for (const auto& [name, item] : values) {
    schema.push_back({{"name", name}, {"category", item.category},
                      {"family", item.family},
                      {"description", item.description}});
  }
  return {{"schema_version", kSchemaVersion},
          {"feature_stage", "PRE_SCAN_DERIVED"},
          {"partition", "discovery"},
          {"block_id", source_feature.at("block_id")},
          {"features", feature_map_json(values)},
          {"schema", std::move(schema)}};
}

std::string deterministic_context_reference(
    const std::vector<nlohmann::json>& source_features) {
  if (source_features.empty()) throw std::invalid_argument("empty context");
  std::string selected;
  std::string selected_hash;
  for (const auto& source : source_features) {
    require(source.value("partition", "") == "discovery",
            "context reference received non-discovery row");
    const auto id = source.at("block_id").get<std::string>();
    const auto digest = hash_text(id);
    if (selected.empty() || std::tie(digest, id) < std::tie(selected_hash, selected)) {
      selected = id;
      selected_hash = digest;
    }
  }
  return selected;
}

std::vector<std::size_t> grouped_fold_assignment(
    const std::vector<std::string>& groups, const std::size_t fold_count,
    const std::uint64_t seed) {
  if (fold_count < 2U) throw std::invalid_argument("at least two folds are required");
  std::set<std::string> unique(groups.begin(), groups.end());
  if (unique.size() < fold_count) throw std::invalid_argument("fewer groups than folds");
  std::vector<std::pair<std::string, std::string>> ordered;
  for (const auto& group : unique) {
    ordered.emplace_back(hash_text(std::to_string(seed) + ":" + group), group);
  }
  std::sort(ordered.begin(), ordered.end());
  std::unordered_map<std::string, std::size_t> owner;
  for (std::size_t i = 0; i < ordered.size(); ++i) owner[ordered[i].second] = i % fold_count;
  std::vector<std::size_t> result;
  result.reserve(groups.size());
  for (const auto& group : groups) result.push_back(owner.at(group));
  return result;
}

std::vector<std::size_t> intra_context_topk_selection(
    const std::vector<std::string>& contexts,
    const std::vector<double>& scores,
    const double fraction,
    const bool descending) {
  if (contexts.size() != scores.size()) {
    throw std::invalid_argument("context and score vector lengths differ");
  }
  if (!(fraction > 0.0 && fraction <= 1.0)) {
    throw std::invalid_argument("top-k fraction must be in (0,1]");
  }
  std::map<std::string, std::vector<std::size_t>> grouped;
  for (std::size_t i = 0; i < contexts.size(); ++i) grouped[contexts[i]].push_back(i);
  std::vector<std::size_t> selected;
  for (auto& [unused, indices] : grouped) {
    std::stable_sort(indices.begin(), indices.end(), [&](const auto left, const auto right) {
      if (scores[left] != scores[right]) {
        return descending ? scores[left] > scores[right]
                          : scores[left] < scores[right];
      }
      return left < right;
    });
    const auto count = std::min(indices.size(), std::max<std::size_t>(1U,
        static_cast<std::size_t>(std::ceil(indices.size() * fraction))));
    selected.insert(selected.end(), indices.begin(), indices.begin() +
                    static_cast<std::ptrdiff_t>(count));
  }
  return selected;
}

namespace {

std::vector<double> values_for_schema(const FeatureMap& values,
                                      const std::vector<SchemaEntry>& schema) {
  require(values.size() == schema.size(), "feature schema cardinality changed between rows");
  std::vector<double> result;
  result.reserve(schema.size());
  for (const auto& entry : schema) {
    const auto found = values.find(entry.name);
    require(found != values.end(), "feature missing from row: " + entry.name);
    require(found->second.category == entry.category &&
                found->second.family == entry.family,
            "feature metadata changed between rows: " + entry.name);
    result.push_back(found->second.value);
  }
  return result;
}

void establish_schema(const FeatureMap& values,
                      std::vector<SchemaEntry>& schema) {
  require(schema.empty(), "schema already established");
  for (const auto& [name, item] : values) {
    schema.push_back({name, item.category, item.family, item.description});
  }
}

FeatureMap relative_feature_map(const Row& row, const Row& reference,
                                const std::string& category,
                                const std::string& prefix) {
  FeatureMap output;
  add_scalar(output, prefix + ".header_hamming_distance",
             byte_hamming(row.snapshot.header, reference.snapshot.header),
             category, "RELATIVE_DISTANCE", "76-byte header-prefix Hamming distance");
  add_scalar(output, prefix + ".merkle_hamming_distance",
             byte_hamming(row.snapshot.merkle, reference.snapshot.merkle),
             category, "RELATIVE_DISTANCE", "Merkle-root Hamming distance");
  add_scalar(output, prefix + ".midstate_hamming_distance",
             state_hamming(row.snapshot.midstate, reference.snapshot.midstate),
             category, "RELATIVE_DISTANCE", "eight-word midstate Hamming distance");
  for (std::size_t round = 0; round < 3U; ++round) {
    add_scalar(output, prefix + ".round" + std::to_string(round) +
                   "_state_hamming_distance",
               state_hamming(row.snapshot.round_after[round],
                             reference.snapshot.round_after[round]),
               category, "RELATIVE_DISTANCE",
               "eight-word post-round state Hamming distance");
  }
  add_word(output, prefix + ".C3_xor",
           row.snapshot.c3 ^ reference.snapshot.c3,
           category, "RELATIVE_ROUND3", "");
  add_word(output, prefix + ".C3_modular_difference",
           row.snapshot.c3 - reference.snapshot.c3,
           category, "RELATIVE_ROUND3", "");
  add_word(output, prefix + ".W16_xor",
           row.snapshot.w16 ^ reference.snapshot.w16,
           category, "RELATIVE_SCHEDULE", "");
  add_word(output, prefix + ".W16_modular_difference",
           row.snapshot.w16 - reference.snapshot.w16,
           category, "RELATIVE_SCHEDULE", "");
  add_word(output, prefix + ".W17_xor",
           row.snapshot.w17 ^ reference.snapshot.w17,
           category, "RELATIVE_SCHEDULE", "");
  add_word(output, prefix + ".W17_modular_difference",
           row.snapshot.w17 - reference.snapshot.w17,
           category, "RELATIVE_SCHEDULE", "");
  add_scalar(output, prefix + ".C3_carry_count_difference",
             static_cast<double>(row.snapshot.c3_carries.carry_count) -
                 reference.snapshot.c3_carries.carry_count,
             category, "RELATIVE_CARRY", "difference in fixed C3 carry counts");
  add_scalar(output, prefix + ".C3_carry_chain_difference",
             static_cast<double>(row.snapshot.c3_carries.maximum_chain) -
                 reference.snapshot.c3_carries.maximum_chain,
             category, "RELATIVE_CARRY", "difference in maximum C3 carry chains");
  add_scalar(output, prefix + ".C3_carry_mask_hamming_distance",
             std::popcount(row.snapshot.c3_carries.carry_mask ^
                           reference.snapshot.c3_carries.carry_mask),
             category, "RELATIVE_CARRY", "carry-profile mask Hamming distance");
  return output;
}

std::unordered_map<std::string, std::size_t> reference_rows(
    const std::vector<Row>& rows,
    const std::function<const std::string&(const Row&)>& group) {
  std::unordered_map<std::string, std::size_t> result;
  std::unordered_map<std::string, std::string> hashes;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const auto& key = group(rows[i]);
    const auto digest = hash_text(rows[i].block_id);
    const auto found = result.find(key);
    if (found == result.end() ||
        std::tie(digest, rows[i].block_id) <
            std::tie(hashes.at(key), rows[found->second].block_id)) {
      result[key] = i;
      hashes[key] = digest;
    }
  }
  return result;
}

void append_relative_features(std::vector<Row>& rows,
                              std::vector<SchemaEntry>& schema) {
  const auto context_refs = reference_rows(rows, [](const Row& row) -> const std::string& {
    return row.context;
  });
  const auto prevhash_refs = reference_rows(rows, [](const Row& row) -> const std::string& {
    return row.prevhash;
  });
  std::vector<SchemaEntry> relative_schema;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    auto values = relative_feature_map(
        rows[i], rows[context_refs.at(rows[i].context)], "CONTEXT_RELATIVE",
        "context_relative");
    auto prevhash_values = relative_feature_map(
        rows[i], rows[prevhash_refs.at(rows[i].prevhash)], "PREVHASH_RELATIVE",
        "prevhash_relative");
    values.insert(prevhash_values.begin(), prevhash_values.end());
    if (relative_schema.empty()) establish_schema(values, relative_schema);
    const auto appended = values_for_schema(values, relative_schema);
    rows[i].x.insert(rows[i].x.end(), appended.begin(), appended.end());
  }
  schema.insert(schema.end(), relative_schema.begin(), relative_schema.end());
}

struct LoadedData {
  nlohmann::json manifest;
  nlohmann::json checkpoint;
  std::vector<Row> rows;
  std::vector<SchemaEntry> schema;
  std::size_t source_feature_lines{};
  std::size_t source_label_lines{};
  std::size_t discovery_label_lines{};
  std::size_t validation_labels_used{};
  std::size_t holdout_labels_used{};
};

LoadedData load_discovery(const std::filesystem::path& directory,
                          const bool load_targets) {
  LoadedData data;
  data.manifest = read_json(directory / "manifest.json");
  data.checkpoint = read_json(directory / "checkpoint.json");
  const auto campaign_id = data.manifest.value("campaign_id", "");
  require(!campaign_id.empty(), "manifest has no campaign_id");
  require(data.checkpoint.value("campaign_id", "") == campaign_id,
          "checkpoint campaign_id differs from manifest");
  require(data.checkpoint.value("status", "") == "COMPLETE",
          "source campaign is not COMPLETE");

  const auto features_path = directory / "features.jsonl";
  std::ifstream features(features_path, std::ios::binary);
  if (!features) fail("cannot open features.jsonl");
  std::set<std::string> ids;
  std::string line;
  while (std::getline(features, line)) {
    if (line.empty()) continue;
    ++data.source_feature_lines;
    const auto source = nlohmann::json::parse(line);
    const auto partition = source.value("partition", "");
    require(partition == "discovery" || partition == "validation" ||
                partition == "holdout",
            "unknown feature partition");
    if (partition != "discovery") continue;
    Row row;
    row.block_id = source.at("block_id").get<std::string>();
    row.context = source.at("work_fingerprint").get<std::string>();
    row.prevhash = source.at("prevhash").get<std::string>();
    row.extranonce2 = source.at("extranonce2").get<std::string>();
    require(ids.insert(row.block_id).second, "duplicate discovery feature block_id");
    const auto values = self_feature_map(source, &row.snapshot);
    if (data.schema.empty()) establish_schema(values, data.schema);
    row.x = values_for_schema(values, data.schema);
    data.rows.push_back(std::move(row));
    if (data.rows.size() % 500U == 0U) {
      std::cout << "Phase 2A PRE_SCAN: " << data.rows.size()
                << " discovery rows reconstructed\n";
    }
  }
  require(!data.rows.empty(), "no discovery feature rows found");
  append_relative_features(data.rows, data.schema);

  std::unordered_map<std::string, std::size_t> row_index;
  for (std::size_t i = 0; i < data.rows.size(); ++i) row_index[data.rows[i].block_id] = i;
  std::set<std::string> seen_labels;
  std::ifstream labels(directory / "block_labels.jsonl", std::ios::binary);
  if (!labels) fail("cannot open block_labels.jsonl");
  while (std::getline(labels, line)) {
    if (line.empty()) continue;
    ++data.source_label_lines;
    const auto label = nlohmann::json::parse(line);
    const auto partition = label.value("partition", "");
    require(partition == "discovery" || partition == "validation" ||
                partition == "holdout",
            "unknown label partition");
    // The barrier is deliberately before every access to the quality object.
    if (partition != "discovery") continue;
    ++data.discovery_label_lines;
    require(label.value("label_stage", "POST_SCAN") == "POST_SCAN",
            "discovery label_stage is not POST_SCAN");
    require(label.value("complete", false), "incomplete discovery label row");
    const auto id = label.at("block_id").get<std::string>();
    const auto found = row_index.find(id);
    require(found != row_index.end(), "discovery label has no PRE_SCAN row");
    require(seen_labels.insert(id).second, "duplicate discovery label block_id");
    require(label.at("prevhash_group").get<std::string>() ==
                data.rows[found->second].prevhash,
            "feature/label prevhash mismatch");
    if (!load_targets) continue;
    auto& row = data.rows[found->second];
    const auto& quality = label.at("quality");
    row.quality = quality.at("quality_bits").get<double>();
    row.difficulty = quality.at("best_difficulty").get<double>();
    row.log_difficulty = std::log(std::max(row.difficulty,
                                          std::numeric_limits<double>::min()));
    for (std::size_t i = 0; i < kTailBits.size(); ++i) {
      row.tails[i] = static_cast<double>(quality.at("tail_counts").at(
          "leading_zero_" + std::to_string(kTailBits[i])).get<std::uint64_t>());
    }
  }
  require(seen_labels.size() == data.rows.size(),
          "discovery feature/label cardinality mismatch");
  require(data.source_feature_lines == data.source_label_lines,
          "source feature/label line counts differ");
  require(data.source_label_lines ==
              data.checkpoint.at("completed_blocks").get<std::size_t>(),
          "source line count differs from completed checkpoint");

  if (load_targets) {
    std::map<std::string, std::vector<std::size_t>> contexts;
    for (std::size_t i = 0; i < data.rows.size(); ++i) contexts[data.rows[i].context].push_back(i);
    for (const auto& [unused, indices] : contexts) {
      const auto assign_rank_target = [&](const auto value, const auto set_rank,
                                          const auto set_score) {
        auto ordered = indices;
        std::stable_sort(ordered.begin(), ordered.end(), [&](const auto left,
                                                             const auto right) {
          if (value(data.rows[left]) != value(data.rows[right])) {
            return value(data.rows[left]) > value(data.rows[right]);
          }
          return data.rows[left].block_id < data.rows[right].block_id;
        });
        for (std::size_t begin = 0; begin < ordered.size();) {
          std::size_t end = begin + 1U;
          while (end < ordered.size() &&
                 value(data.rows[ordered[end]]) == value(data.rows[ordered[begin]])) {
            ++end;
          }
          const auto average_rank =
              (static_cast<double>(begin + 1U) + static_cast<double>(end)) / 2.0;
          for (std::size_t i = begin; i < end; ++i) {
            set_rank(data.rows[ordered[i]], average_rank);
            set_score(data.rows[ordered[i]], indices.size() > 1U
                ? (static_cast<double>(indices.size()) - average_rank) /
                      static_cast<double>(indices.size() - 1U)
                : 1.0);
          }
          begin = end;
        }
      };
      assign_rank_target(
          [](const Row& row) { return row.quality; },
          [](Row& row, const double rank) { row.rank_quality = rank; },
          [](Row& row, const double score) { row.context_quality_score = score; });
      assign_rank_target(
          [](const Row& row) { return row.tails[2]; },
          [](Row& row, const double rank) { row.rank_t30 = rank; },
          [](Row& row, const double score) { row.context_t30_score = score; });
    }
  }
  return data;
}

std::vector<double> ranks(const std::vector<double>& values) {
  std::vector<std::size_t> order(values.size());
  std::iota(order.begin(), order.end(), 0U);
  std::stable_sort(order.begin(), order.end(), [&](const auto left, const auto right) {
    return values[left] < values[right];
  });
  std::vector<double> result(values.size());
  for (std::size_t begin = 0; begin < order.size();) {
    std::size_t end = begin + 1U;
    while (end < order.size() && values[order[end]] == values[order[begin]]) ++end;
    const auto rank = (static_cast<double>(begin + 1U) + static_cast<double>(end)) / 2.0;
    for (std::size_t i = begin; i < end; ++i) result[order[i]] = rank;
    begin = end;
  }
  return result;
}

void prepare_context_feature_ranks(std::vector<Row>& rows) {
  std::map<std::string, std::vector<std::size_t>> contexts;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    rows[i].context_feature_ranks.resize(rows[i].x.size());
    contexts[rows[i].context].push_back(i);
  }
  for (const auto& [unused, indices] : contexts) {
    for (std::size_t feature = 0; feature < rows.front().x.size(); ++feature) {
      std::vector<double> values;
      values.reserve(indices.size());
      for (const auto index : indices) values.push_back(rows[index].x[feature]);
      const auto feature_ranks = ranks(values);
      const auto mean = std::accumulate(
          feature_ranks.begin(), feature_ranks.end(), 0.0) / feature_ranks.size();
      double squared = 0.0;
      for (const auto rank : feature_ranks) squared += (rank - mean) * (rank - mean);
      const auto scale = std::sqrt(squared);
      for (std::size_t i = 0; i < indices.size(); ++i) {
        rows[indices[i]].context_feature_ranks[feature] = scale > 0.0
            ? (feature_ranks[i] - mean) / scale : 0.0;
      }
    }
  }
}

double pearson(const std::vector<double>& x, const std::vector<double>& y) {
  require(x.size() == y.size(), "correlation vector length mismatch");
  if (x.size() < 2U) return 0.0;
  const auto mx = std::accumulate(x.begin(), x.end(), 0.0) / x.size();
  const auto my = std::accumulate(y.begin(), y.end(), 0.0) / y.size();
  double xx = 0.0, yy = 0.0, xy = 0.0;
  for (std::size_t i = 0; i < x.size(); ++i) {
    xx += (x[i] - mx) * (x[i] - mx);
    yy += (y[i] - my) * (y[i] - my);
    xy += (x[i] - mx) * (y[i] - my);
  }
  return xx > 0.0 && yy > 0.0 ? xy / std::sqrt(xx * yy) : 0.0;
}

double spearman(const std::vector<double>& x, const std::vector<double>& y) {
  return pearson(ranks(x), ranks(y));
}

double kendall_tau_b(const std::vector<double>& x, const std::vector<double>& y) {
  require(x.size() == y.size(), "Kendall vector length mismatch");
  const auto n = x.size();
  if (n < 2U) return 0.0;
  std::vector<std::pair<double, double>> pairs;
  pairs.reserve(n);
  for (std::size_t i = 0; i < n; ++i) pairs.emplace_back(x[i], y[i]);
  std::sort(pairs.begin(), pairs.end());
  std::vector<double> ys;
  ys.reserve(n);
  for (const auto& pair : pairs) ys.push_back(pair.second);
  std::sort(ys.begin(), ys.end());
  ys.erase(std::unique(ys.begin(), ys.end()), ys.end());
  std::vector<std::uint64_t> fenwick(ys.size() + 1U, 0U);
  const auto add = [&](std::size_t pos) {
    for (++pos; pos < fenwick.size(); pos += pos & (~pos + 1U)) ++fenwick[pos];
  };
  const auto sum = [&](std::size_t pos) {
    std::uint64_t result = 0U;
    for (; pos > 0U; pos -= pos & (~pos + 1U)) result += fenwick[pos];
    return result;
  };
  std::uint64_t concordant = 0U, discordant = 0U, previous = 0U;
  for (std::size_t begin = 0; begin < n;) {
    std::size_t end = begin + 1U;
    while (end < n && pairs[end].first == pairs[begin].first) ++end;
    for (std::size_t i = begin; i < end; ++i) {
      const auto rank = static_cast<std::size_t>(
          std::lower_bound(ys.begin(), ys.end(), pairs[i].second) - ys.begin());
      const auto lower = sum(rank);
      const auto lower_or_equal = sum(rank + 1U);
      concordant += lower;
      discordant += previous - lower_or_equal;
    }
    for (std::size_t i = begin; i < end; ++i) {
      const auto rank = static_cast<std::size_t>(
          std::lower_bound(ys.begin(), ys.end(), pairs[i].second) - ys.begin());
      add(rank);
      ++previous;
    }
    begin = end;
  }
  const auto choose2 = [](const std::uint64_t count) { return count * (count - 1U) / 2U; };
  const auto total = choose2(n);
  std::uint64_t ties_x = 0U, ties_y = 0U;
  for (std::size_t begin = 0; begin < n;) {
    std::size_t end = begin + 1U;
    while (end < n && pairs[end].first == pairs[begin].first) ++end;
    ties_x += choose2(end - begin);
    begin = end;
  }
  std::sort(pairs.begin(), pairs.end(), [](const auto& left, const auto& right) {
    return std::tie(left.second, left.first) < std::tie(right.second, right.first);
  });
  for (std::size_t begin = 0; begin < n;) {
    std::size_t end = begin + 1U;
    while (end < n && pairs[end].second == pairs[begin].second) ++end;
    ties_y += choose2(end - begin);
    begin = end;
  }
  const auto denominator = std::sqrt(
      static_cast<double>(total - ties_x) * static_cast<double>(total - ties_y));
  return denominator > 0.0
      ? (static_cast<double>(concordant) - static_cast<double>(discordant)) / denominator
      : 0.0;
}

std::vector<double> column(const std::vector<Row>& rows,
                           const std::size_t feature,
                           const std::vector<std::size_t>* indices = nullptr) {
  std::vector<double> result;
  if (indices == nullptr) {
    result.reserve(rows.size());
    for (const auto& row : rows) result.push_back(row.x[feature]);
  } else {
    result.reserve(indices->size());
    for (const auto index : *indices) result.push_back(rows[index].x[feature]);
  }
  return result;
}

std::vector<double> target(const std::vector<Row>& rows,
                           const std::size_t target_index,
                           const std::vector<std::size_t>* indices = nullptr) {
  const auto value = [&](const Row& row) {
    if (target_index == 0U) return row.quality;
    if (target_index == 1U) return row.log_difficulty;
    return row.tails[target_index - 2U];
  };
  std::vector<double> result;
  if (indices == nullptr) {
    result.reserve(rows.size());
    for (const auto& row : rows) result.push_back(value(row));
  } else {
    result.reserve(indices->size());
    for (const auto index : *indices) result.push_back(value(rows[index]));
  }
  return result;
}

std::string csv_number(const double value) {
  std::ostringstream output;
  output << std::setprecision(17) << value;
  return output.str();
}

enum class ModelTarget {
  AbsoluteQuality,
  ContextQualityScore,
  ContextT30Score
};

double model_response(const Row& row, const ModelTarget target_kind) {
  if (target_kind == ModelTarget::ContextQualityScore) {
    return row.context_quality_score;
  }
  if (target_kind == ModelTarget::ContextT30Score) {
    return row.context_t30_score;
  }
  return row.quality;
}

double& model_prediction(Row& row, const ModelTarget target_kind) {
  if (target_kind == ModelTarget::ContextQualityScore) {
    return row.rank_cv_prediction;
  }
  if (target_kind == ModelTarget::ContextT30Score) {
    return row.t30_cv_prediction;
  }
  return row.cv_prediction;
}

double model_prediction(const Row& row, const ModelTarget target_kind) {
  if (target_kind == ModelTarget::ContextQualityScore) {
    return row.rank_cv_prediction;
  }
  if (target_kind == ModelTarget::ContextT30Score) {
    return row.t30_cv_prediction;
  }
  return row.cv_prediction;
}

double& model_prediction_rank(Row& row, const ModelTarget target_kind) {
  if (target_kind == ModelTarget::ContextQualityScore) {
    return row.rank_cv_prediction_rank;
  }
  if (target_kind == ModelTarget::ContextT30Score) {
    return row.t30_cv_prediction_rank;
  }
  return row.cv_prediction_rank;
}

double model_prediction_rank(const Row& row, const ModelTarget target_kind) {
  if (target_kind == ModelTarget::ContextQualityScore) {
    return row.rank_cv_prediction_rank;
  }
  if (target_kind == ModelTarget::ContextT30Score) {
    return row.t30_cv_prediction_rank;
  }
  return row.cv_prediction_rank;
}

std::vector<double> model_responses(
    const std::vector<Row>& rows, const ModelTarget target_kind,
    const std::vector<std::size_t>* indices = nullptr) {
  std::vector<double> result;
  if (indices == nullptr) {
    result.reserve(rows.size());
    for (const auto& row : rows) result.push_back(model_response(row, target_kind));
  } else {
    result.reserve(indices->size());
    for (const auto index : *indices) result.push_back(model_response(rows[index], target_kind));
  }
  return result;
}

std::vector<std::size_t> select_features(
    const std::vector<Row>& rows, const std::vector<std::size_t>& train,
    const std::vector<SchemaEntry>& schema, const std::size_t maximum,
    const ModelTarget target_kind, const bool exclude_sanity_baselines) {
  const auto y = model_responses(rows, target_kind, &train);
  struct TrainingContext {
    std::size_t prevhash_index{};
    std::vector<std::size_t> rows;
  };
  std::vector<TrainingContext> training_contexts;
  std::size_t training_prevhash_count = 0U;
  const auto intra_context_target = target_kind != ModelTarget::AbsoluteQuality;
  if (intra_context_target) {
    std::map<std::string, std::vector<std::size_t>> context_rows;
    std::map<std::string, std::size_t> prevhash_indices;
    for (const auto index : train) context_rows[rows[index].context].push_back(index);
    for (const auto& [unused, indices] : context_rows) {
      const auto [position, inserted] = prevhash_indices.emplace(
          rows[indices.front()].prevhash, prevhash_indices.size());
      (void)inserted;
      training_contexts.push_back({position->second, indices});
    }
    training_prevhash_count = prevhash_indices.size();
  }
  std::vector<std::pair<double, std::size_t>> scored;
  for (std::size_t feature = 0; feature < rows.front().x.size(); ++feature) {
    if (exclude_sanity_baselines && schema[feature].family == "SANITY_BASELINE") continue;
    double correlation = 0.0;
    if (intra_context_target) {
      std::vector<double> prevhash_sums(training_prevhash_count, 0.0);
      std::vector<std::size_t> prevhash_context_counts(training_prevhash_count, 0U);
      for (const auto& context : training_contexts) {
        std::vector<double> feature_ranks, response;
        feature_ranks.reserve(context.rows.size());
        response.reserve(context.rows.size());
        for (const auto index : context.rows) {
          require(rows[index].context_feature_ranks.size() == rows[index].x.size(),
                  "PRE_SCAN context feature ranks were not prepared");
          feature_ranks.push_back(rows[index].context_feature_ranks[feature]);
          response.push_back(model_response(rows[index], target_kind));
        }
        prevhash_sums[context.prevhash_index] += pearson(feature_ranks, response);
        ++prevhash_context_counts[context.prevhash_index];
      }
      for (std::size_t prevhash = 0; prevhash < training_prevhash_count; ++prevhash) {
        require(prevhash_context_counts[prevhash] > 0U,
                "empty prevhash in primary feature selection");
        correlation += prevhash_sums[prevhash] / prevhash_context_counts[prevhash];
      }
      correlation /= training_prevhash_count;
    } else {
      correlation = pearson(column(rows, feature, &train), y);
    }
    if (std::isfinite(correlation) && std::abs(correlation) > 0.0) {
      scored.emplace_back(std::abs(correlation), feature);
    }
  }
  std::stable_sort(scored.begin(), scored.end(), [](const auto& left, const auto& right) {
    if (left.first != right.first) return left.first > right.first;
    return left.second < right.second;
  });
  std::vector<std::size_t> result;
  for (std::size_t i = 0; i < std::min(maximum, scored.size()); ++i) {
    result.push_back(scored[i].second);
  }
  require(!result.empty(), "no non-constant train feature available");
  return result;
}

struct RidgeModel {
  std::vector<std::size_t> features;
  std::vector<double> means;
  std::vector<double> scales;
  std::vector<double> beta;
  double y_mean{};
  std::size_t fitted_row_count{};
};

std::vector<double> solve_linear(std::vector<std::vector<double>> matrix,
                                 std::vector<double> right) {
  const auto n = right.size();
  for (std::size_t pivot = 0; pivot < n; ++pivot) {
    auto best = pivot;
    for (std::size_t row = pivot + 1U; row < n; ++row) {
      if (std::abs(matrix[row][pivot]) > std::abs(matrix[best][pivot])) best = row;
    }
    require(std::abs(matrix[best][pivot]) > 1e-14, "singular ridge system");
    std::swap(matrix[pivot], matrix[best]);
    std::swap(right[pivot], right[best]);
    const auto diagonal = matrix[pivot][pivot];
    for (std::size_t column = pivot; column < n; ++column) matrix[pivot][column] /= diagonal;
    right[pivot] /= diagonal;
    for (std::size_t row = 0; row < n; ++row) {
      if (row == pivot) continue;
      const auto factor = matrix[row][pivot];
      if (factor == 0.0) continue;
      for (std::size_t column = pivot; column < n; ++column) {
        matrix[row][column] -= factor * matrix[pivot][column];
      }
      right[row] -= factor * right[pivot];
    }
  }
  return right;
}

RidgeModel fit_ridge(const std::vector<Row>& rows,
                     const std::vector<std::size_t>& train,
                     const std::vector<std::size_t>& features,
                     const double lambda,
                     const ModelTarget target_kind) {
  RidgeModel model;
  model.features = features;
  model.means.resize(features.size());
  model.scales.resize(features.size());
  model.fitted_row_count = train.size();
  for (const auto index : train) model.y_mean += model_response(rows[index], target_kind);
  model.y_mean /= train.size();
  for (std::size_t j = 0; j < features.size(); ++j) {
    for (const auto index : train) model.means[j] += rows[index].x[features[j]];
    model.means[j] /= train.size();
    double variance = 0.0;
    for (const auto index : train) {
      const auto delta = rows[index].x[features[j]] - model.means[j];
      variance += delta * delta;
    }
    model.scales[j] = std::sqrt(variance / train.size());
    if (!(model.scales[j] > 0.0)) model.scales[j] = 1.0;
  }
  std::vector<std::vector<double>> gram(
      features.size(), std::vector<double>(features.size(), 0.0));
  std::vector<double> rhs(features.size(), 0.0);
  std::vector<double> z(features.size());
  for (const auto index : train) {
    for (std::size_t j = 0; j < features.size(); ++j) {
      z[j] = (rows[index].x[features[j]] - model.means[j]) / model.scales[j];
      rhs[j] += z[j] * (model_response(rows[index], target_kind) - model.y_mean);
    }
    for (std::size_t j = 0; j < features.size(); ++j) {
      for (std::size_t k = 0; k < features.size(); ++k) gram[j][k] += z[j] * z[k];
    }
  }
  for (std::size_t j = 0; j < features.size(); ++j) gram[j][j] += lambda;
  model.beta = solve_linear(std::move(gram), std::move(rhs));
  return model;
}

double predict(const RidgeModel& model, const Row& row) {
  auto result = model.y_mean;
  for (std::size_t j = 0; j < model.features.size(); ++j) {
    result += model.beta[j] *
              (row.x[model.features[j]] - model.means[j]) / model.scales[j];
  }
  return result;
}

double rmse(const std::vector<double>& actual, const std::vector<double>& predicted) {
  require(actual.size() == predicted.size(), "RMSE vector length mismatch");
  double squared = 0.0;
  for (std::size_t i = 0; i < actual.size(); ++i) {
    const auto error = actual[i] - predicted[i];
    squared += error * error;
  }
  return actual.empty() ? 0.0 : std::sqrt(squared / actual.size());
}

struct CvArtifacts {
  nlohmann::json summary;
  std::string predictions_csv;
  std::vector<double> predictions;
  std::vector<double> predicted_context_ranks;
};

CvArtifacts grouped_nested_cv(std::vector<Row>& rows,
                              const std::vector<SchemaEntry>& schema,
                              const Options& options,
                              const ModelTarget target_kind,
                              const std::span<const double> lambda_grid,
                              const std::string& phase_name) {
  require(!lambda_grid.empty(), "ridge lambda grid cannot be empty");
  const auto intra_context_target = target_kind != ModelTarget::AbsoluteQuality;
  const auto target_name = target_kind == ModelTarget::ContextQualityScore
      ? "context_quality_score"
      : target_kind == ModelTarget::ContextT30Score
          ? "context_t30_score" : "quality_bits";
  const auto role = target_kind == ModelTarget::ContextT30Score
      ? "EXPLORATORY_DISCOVERY_T30"
      : intra_context_target ? "PRIMARY_OPERATIONAL" : "SECONDARY_DESCRIPTIVE";
  for (auto& row : rows) {
    model_prediction(row, target_kind) = std::numeric_limits<double>::quiet_NaN();
    model_prediction_rank(row, target_kind) = 0.0;
  }
  std::vector<std::string> groups;
  groups.reserve(rows.size());
  for (const auto& row : rows) groups.push_back(row.prevhash);
  std::set<std::string> unique_groups(groups.begin(), groups.end());
  const auto folds = std::min(options.outer_folds, unique_groups.size());
  require(folds >= 2U, "grouped CV needs at least two discovery prevhashes");
  const auto owners = grouped_fold_assignment(groups, folds, options.seed);
  nlohmann::json fold_audits = nlohmann::json::array();

  for (std::size_t fold = 0; fold < folds; ++fold) {
    std::vector<std::size_t> train, test;
    std::set<std::string> train_groups, test_groups;
    for (std::size_t i = 0; i < rows.size(); ++i) {
      if (owners[i] == fold) {
        test.push_back(i);
        test_groups.insert(rows[i].prevhash);
      } else {
        train.push_back(i);
        train_groups.insert(rows[i].prevhash);
      }
    }
    require(!train.empty() && !test.empty(), "empty outer CV split");
    std::vector<std::string> overlap;
    std::set_intersection(train_groups.begin(), train_groups.end(),
                          test_groups.begin(), test_groups.end(),
                          std::back_inserter(overlap));
    require(overlap.empty(), "outer CV split a prevhash");

    double selected_lambda = lambda_grid.front();
    nlohmann::json inner_scores = nlohmann::json::array();
    nlohmann::json inner_fold_audits = nlohmann::json::array();
    if (train_groups.size() >= 3U) {
      const auto inner_fold_count = std::min<std::size_t>(4U, train_groups.size());
      std::vector<std::string> inner_groups;
      inner_groups.reserve(train.size());
      for (const auto index : train) inner_groups.push_back(rows[index].prevhash);
      const auto inner_owner = grouped_fold_assignment(
          inner_groups, inner_fold_count, options.seed + fold + 1U);
      struct InnerSplit {
        std::size_t fold{};
        std::vector<std::size_t> train;
        std::vector<std::size_t> test;
        std::vector<std::size_t> selected;
        std::set<std::string> train_groups;
        std::set<std::string> test_groups;
      };
      std::vector<InnerSplit> inner_splits(inner_fold_count);
      for (std::size_t inner_fold = 0; inner_fold < inner_fold_count; ++inner_fold) {
        auto& split = inner_splits[inner_fold];
        split.fold = inner_fold;
        for (std::size_t pos = 0; pos < train.size(); ++pos) {
          const auto index = train[pos];
          if (inner_owner[pos] == inner_fold) {
            split.test.push_back(index);
            split.test_groups.insert(rows[index].prevhash);
          } else {
            split.train.push_back(index);
            split.train_groups.insert(rows[index].prevhash);
          }
        }
        std::vector<std::string> inner_overlap;
        std::set_intersection(split.train_groups.begin(), split.train_groups.end(),
                              split.test_groups.begin(), split.test_groups.end(),
                              std::back_inserter(inner_overlap));
        require(inner_overlap.empty(), "inner CV split a prevhash");
        split.selected = select_features(
            rows, split.train, schema, options.selected_feature_count,
            target_kind, intra_context_target);
        nlohmann::json selected_names = nlohmann::json::array();
        for (const auto feature : split.selected) {
          selected_names.push_back(schema[feature].name);
        }
        inner_fold_audits.push_back({
            {"inner_fold", inner_fold}, {"train_rows", split.train.size()},
            {"test_rows", split.test.size()},
            {"train_prevhashes", split.train_groups},
            {"test_prevhashes", split.test_groups},
            {"prevhash_overlap", inner_overlap},
            {"selected_features", selected_names},
            {"feature_selection_scope", "inner_train_only"},
            {"normalization_scope", "inner_train_only"},
            {"test_target_rows_used_for_training", 0}});
      }
      auto best_error = std::numeric_limits<double>::infinity();
      for (const auto lambda : lambda_grid) {
        double total_squared = 0.0;
        std::size_t count = 0U;
        for (const auto& split : inner_splits) {
          const auto model = fit_ridge(
              rows, split.train, split.selected, lambda, target_kind);
          for (const auto index : split.test) {
            const auto error = model_response(rows[index], target_kind) -
                               predict(model, rows[index]);
            total_squared += error * error;
            ++count;
          }
        }
        const auto error = std::sqrt(total_squared / count);
        inner_scores.push_back({{"lambda", lambda}, {"grouped_inner_cv_rmse", error}});
        if (error < best_error) {
          best_error = error;
          selected_lambda = lambda;
        }
      }
    }

    const auto selected = select_features(
        rows, train, schema, options.selected_feature_count, target_kind,
        intra_context_target);
    const auto model = fit_ridge(rows, train, selected, selected_lambda, target_kind);
    for (const auto index : test) {
      model_prediction(rows[index], target_kind) = predict(model, rows[index]);
      rows[index].outer_fold = fold;
    }
    nlohmann::json selected_names = nlohmann::json::array();
    for (const auto feature : selected) selected_names.push_back(schema[feature].name);
    fold_audits.push_back({
        {"outer_fold", fold}, {"train_rows", train.size()}, {"test_rows", test.size()},
        {"train_prevhashes", train_groups}, {"test_prevhashes", test_groups},
        {"prevhash_overlap", overlap}, {"selected_lambda", selected_lambda},
        {"selected_lambda_is_grid_boundary",
         selected_lambda == lambda_grid.front() || selected_lambda == lambda_grid.back()},
        {"selected_lambda_is_lower_grid_boundary",
         selected_lambda == lambda_grid.front()},
        {"selected_lambda_is_upper_grid_boundary",
         selected_lambda == lambda_grid.back()},
        {"lambda_selection_source", "grouped_inner_cv_rmse_only"},
        {"outer_test_metrics_used_for_lambda_selection", false},
        {"inner_cv", inner_scores}, {"inner_folds", inner_fold_audits},
        {"selected_features", selected_names},
        {"training_target", target_name},
        {"test_target_rows_used_for_training", 0},
        {"excluded_feature_families",
         intra_context_target ? nlohmann::json::array({"SANITY_BASELINE"})
                              : nlohmann::json::array()},
        {"normalization", {{"scope", "outer_train_only"},
                           {"fitted_row_count", model.fitted_row_count}}},
        {"feature_selection", {{"scope", "outer_train_only"},
                               {"fitted_row_count", train.size()},
                               {"statistic", intra_context_target
                                    ? "absolute mean prevhash of context-level Spearman"
                                    : "absolute pooled Pearson"}}}});
  }
  for (const auto& row : rows) {
    require(std::isfinite(model_prediction(row, target_kind)),
            "missing outer CV prediction");
  }

  std::map<std::string, std::vector<std::size_t>> contexts;
  for (std::size_t i = 0; i < rows.size(); ++i) contexts[rows[i].context].push_back(i);
  for (const auto& [unused, indices] : contexts) {
    auto ordered = indices;
    std::stable_sort(ordered.begin(), ordered.end(), [&](const auto left, const auto right) {
      const auto left_score = model_prediction(rows[left], target_kind);
      const auto right_score = model_prediction(rows[right], target_kind);
      if (left_score != right_score) return left_score > right_score;
      return rows[left].block_id < rows[right].block_id;
    });
    for (std::size_t begin = 0; begin < ordered.size();) {
      std::size_t end = begin + 1U;
      const auto begin_score = model_prediction(rows[ordered[begin]], target_kind);
      while (end < ordered.size()) {
        const auto end_score = model_prediction(rows[ordered[end]], target_kind);
        if (end_score != begin_score) break;
        ++end;
      }
      const auto average_rank =
          (static_cast<double>(begin + 1U) + static_cast<double>(end)) / 2.0;
      for (std::size_t i = begin; i < end; ++i) {
        model_prediction_rank(rows[ordered[i]], target_kind) = average_rank;
      }
      begin = end;
    }
  }
  std::vector<double> actual, predicted, actual_rank, predicted_rank;
  for (const auto& row : rows) {
    actual.push_back(model_response(row, target_kind));
    predicted.push_back(model_prediction(row, target_kind));
    actual_rank.push_back(target_kind == ModelTarget::ContextT30Score
                              ? row.rank_t30 : row.rank_quality);
    predicted_rank.push_back(model_prediction_rank(row, target_kind));
  }

  std::map<std::string, std::vector<double>> correlations_by_prevhash;
  std::vector<double> context_correlations;
  for (const auto& [unused, indices] : contexts) {
    std::vector<double> context_actual, context_predicted;
    for (const auto index : indices) {
      context_actual.push_back(target_kind == ModelTarget::AbsoluteQuality
                                   ? rows[index].context_quality_score
                                   : model_response(rows[index], target_kind));
      context_predicted.push_back(predicted[index]);
    }
    const auto correlation = spearman(context_actual, context_predicted);
    context_correlations.push_back(correlation);
    correlations_by_prevhash[rows[indices.front()].prevhash].push_back(correlation);
  }
  std::vector<double> prevhash_correlations;
  for (const auto& [unused, values] : correlations_by_prevhash) {
    prevhash_correlations.push_back(
        std::accumulate(values.begin(), values.end(), 0.0) / values.size());
  }
  const auto summarize = [](std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const auto mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    const auto median = values.size() % 2U
        ? values[values.size() / 2U]
        : (values[values.size() / 2U - 1U] + values[values.size() / 2U]) / 2.0;
    return nlohmann::json{{"count", values.size()}, {"mean", mean}, {"median", median}};
  };
  nlohmann::json summary = {
      {"schema_version", kSchemaVersion}, {"phase", phase_name},
      {"model", "standardized_ridge"}, {"target", target_name},
      {"role", role},
      {"outer_fold_count", folds}, {"inner_fold_max", 4U},
      {"group_unit", "prevhash"},
      {"lambda_grid", std::vector<double>(lambda_grid.begin(), lambda_grid.end())},
      {"lambda_selection_source", "grouped_inner_cv_rmse_only"},
      {"outer_test_metrics_used_for_lambda_selection", false},
      {"feature_selection_max", options.selected_feature_count},
      {"normalization_scope", "train_only"},
      {"feature_selection_scope", "train_only"},
      {"feature_selection_statistic",
       intra_context_target
           ? "absolute mean prevhash of context-level Spearman, train-only"
           : "absolute pooled Pearson, train-only"},
      {"inner_cv_normalization_scope", "inner_train_only"},
      {"inner_cv_feature_selection_scope", "inner_train_only"},
      {"inner_cv_lambda_selection_scope", "outer_train_only"},
      {"sanity_baseline_admissible", !intra_context_target},
      {"excluded_feature_families",
       intra_context_target ? nlohmann::json::array({"SANITY_BASELINE"})
                            : nlohmann::json::array()},
      {"target_source_stage", "POST_SCAN_Y_ONLY"},
      {"target_in_feature_matrix", false},
      {"folds", fold_audits},
      {"metrics", {{"rmse", rmse(actual, predicted)},
                   {"pearson", pearson(actual, predicted)},
                   {"spearman", spearman(actual, predicted)},
                   {"pooled_rank_spearman_descriptive",
                    spearman(actual_rank, predicted_rank)},
                   {"per_context_spearman", summarize(context_correlations)},
                   {"per_prevhash_context_spearman", summarize(prevhash_correlations)},
                   {"per_prevhash_context_spearman_values", prevhash_correlations}}},
      {"validation_rows_used", 0}, {"holdout_rows_used", 0},
      {"status", "exploratory_cross_validated_on_discovery"}};
  std::ostringstream csv;
  if (target_kind == ModelTarget::ContextQualityScore) {
    csv << "block_id,prevhash,work_fingerprint,outer_fold,actual_context_quality_score,"
           "predicted_context_quality_score,actual_rank_quality_bits,"
           "predicted_rank_quality_bits_within_context\n";
  } else if (target_kind == ModelTarget::ContextT30Score) {
    csv << "block_id,prevhash,work_fingerprint,outer_fold,actual_T30_count,"
           "actual_context_T30_score,predicted_context_T30_score,actual_rank_T30,"
           "predicted_rank_T30_within_context\n";
  } else {
    csv << "block_id,prevhash,work_fingerprint,outer_fold,actual_quality_bits,"
           "predicted_quality_bits,actual_rank_quality_bits,predicted_rank_quality_bits\n";
  }
  for (const auto& row : rows) {
    csv << row.block_id << ',' << row.prevhash << ',' << row.context << ','
        << row.outer_fold << ',';
    if (target_kind == ModelTarget::ContextT30Score) {
      csv << csv_number(row.tails[2]) << ',';
    }
    csv << csv_number(model_response(row, target_kind)) << ','
        << csv_number(model_prediction(row, target_kind)) << ','
        << csv_number(target_kind == ModelTarget::ContextT30Score
                          ? row.rank_t30 : row.rank_quality) << ','
        << csv_number(model_prediction_rank(row, target_kind)) << '\n';
  }
  return {std::move(summary), csv.str(), std::move(predicted),
          std::move(predicted_rank)};
}

struct UnivariateArtifacts {
  std::string csv;
  std::vector<double> quality_spearman;
  std::size_t tested_hypotheses{};
};

UnivariateArtifacts univariate_analysis(const std::vector<Row>& rows,
                                         const std::vector<SchemaEntry>& schema) {
  static constexpr std::array<const char*, 9> target_names{
      "quality_bits", "log_best_difficulty", "tail_count_T26",
      "tail_count_T28", "tail_count_T30", "tail_count_T32",
      "tail_count_T34", "tail_count_T36", "tail_count_T38"};
  std::array<std::vector<double>, 9> targets;
  for (std::size_t i = 0; i < targets.size(); ++i) targets[i] = target(rows, i);
  std::ostringstream csv;
  csv << "feature,category,family,target,n,pearson,spearman,kendall_tau_b,status\n";
  std::vector<double> quality_spearman(schema.size());
  for (std::size_t feature = 0; feature < schema.size(); ++feature) {
    const auto x = column(rows, feature);
    for (std::size_t target_index = 0; target_index < targets.size(); ++target_index) {
      const auto p = pearson(x, targets[target_index]);
      const auto s = spearman(x, targets[target_index]);
      const auto k = kendall_tau_b(x, targets[target_index]);
      if (target_index == 0U) quality_spearman[feature] = s;
      csv << schema[feature].name << ',' << schema[feature].category << ','
          << schema[feature].family << ',' << target_names[target_index] << ','
          << rows.size() << ',' << csv_number(p) << ',' << csv_number(s) << ','
          << csv_number(k) << ','
          << (target_index >= 6U ? "descriptive_rare_tail_discovery_only"
                                 : "exploratory_discovery_only") << '\n';
    }
    if ((feature + 1U) % 100U == 0U) {
      std::cout << "Phase 2A univariate: " << feature + 1U << '/' << schema.size()
                << " features\n";
    }
  }
  return {csv.str(), std::move(quality_spearman), schema.size() * targets.size()};
}

struct GroupArtifacts {
  std::string intra_context_csv;
  std::string per_prevhash_csv;
};

GroupArtifacts group_analysis(const std::vector<Row>& rows,
                              const std::vector<SchemaEntry>& schema) {
  std::map<std::string, std::vector<std::size_t>> contexts, prevhashes;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    contexts[rows[i].context].push_back(i);
    prevhashes[rows[i].prevhash].push_back(i);
  }
  std::ostringstream context_csv, prevhash_csv;
  context_csv << "feature,category,scope,work_fingerprint,prevhash,n,"
                 "spearman_feature_vs_rank_quality_bits,same_sign_as_global,"
                 "context_spearman_mean,context_spearman_median,context_same_sign_fraction\n";
  prevhash_csv << "feature,category,prevhash,n,spearman_feature_vs_quality_bits,"
                  "context_spearman_mean,context_spearman_median,context_same_sign_fraction\n";
  std::vector<double> global_ranks;
  global_ranks.reserve(rows.size());
  for (const auto& row : rows) global_ranks.push_back(row.rank_quality);
  for (std::size_t feature = 0; feature < schema.size(); ++feature) {
    const auto global_rank_correlation =
        spearman(column(rows, feature), global_ranks);
    std::map<std::string, std::vector<double>> correlations_by_prevhash;
    std::vector<double> all_context_correlations;
    std::size_t all_matching = 0U;
    for (const auto& [context, indices] : contexts) {
      std::vector<double> ranks_quality;
      ranks_quality.reserve(indices.size());
      for (const auto index : indices) ranks_quality.push_back(rows[index].rank_quality);
      const auto correlation = spearman(column(rows, feature, &indices), ranks_quality);
      const auto sign_matches = global_rank_correlation == 0.0 || correlation == 0.0 ||
          ((global_rank_correlation > 0.0) == (correlation > 0.0));
      correlations_by_prevhash[rows[indices.front()].prevhash].push_back(correlation);
      all_context_correlations.push_back(correlation);
      if (sign_matches) ++all_matching;
      context_csv << schema[feature].name << ',' << schema[feature].category << ",CONTEXT,"
                  << context << ',' << rows[indices.front()].prevhash << ','
                  << indices.size() << ',' << csv_number(correlation) << ','
                  << (sign_matches ? 1 : 0) << ",,,\n";
    }
    std::sort(all_context_correlations.begin(), all_context_correlations.end());
    const auto all_mean = std::accumulate(all_context_correlations.begin(),
                                          all_context_correlations.end(), 0.0) /
                          all_context_correlations.size();
    const auto all_median = all_context_correlations.size() % 2U
        ? all_context_correlations[all_context_correlations.size() / 2U]
        : (all_context_correlations[all_context_correlations.size() / 2U - 1U] +
           all_context_correlations[all_context_correlations.size() / 2U]) / 2.0;
    context_csv << schema[feature].name << ',' << schema[feature].category
                << ",AGGREGATE,__ALL_CONTEXTS__,__ALL_PREVHASHES__,"
                << all_context_correlations.size() << ",,,"
                << csv_number(all_mean) << ',' << csv_number(all_median) << ','
                << csv_number(static_cast<double>(all_matching) /
                              all_context_correlations.size()) << '\n';
    for (const auto& [prevhash, indices] : prevhashes) {
      auto correlations = correlations_by_prevhash[prevhash];
      std::sort(correlations.begin(), correlations.end());
      const auto mean = std::accumulate(correlations.begin(), correlations.end(), 0.0) /
                        correlations.size();
      const auto median = correlations.size() % 2U
          ? correlations[correlations.size() / 2U]
          : (correlations[correlations.size() / 2U - 1U] +
             correlations[correlations.size() / 2U]) / 2.0;
      std::size_t matching = 0U;
      for (const auto value : correlations) {
        if (global_rank_correlation == 0.0 || value == 0.0 ||
            ((global_rank_correlation > 0.0) == (value > 0.0))) ++matching;
      }
      const auto correlation = spearman(column(rows, feature, &indices),
                                        target(rows, 0U, &indices));
      prevhash_csv << schema[feature].name << ',' << schema[feature].category << ','
                   << prevhash << ',' << indices.size() << ','
                   << csv_number(correlation) << ',' << csv_number(mean) << ','
                   << csv_number(median) << ','
                   << csv_number(static_cast<double>(matching) / correlations.size()) << '\n';
    }
  }
  return {context_csv.str(), prevhash_csv.str()};
}

std::vector<double> primary_prevhash_feature_statistics(
    const std::vector<Row>& rows, const std::size_t feature,
    const ModelTarget target_kind,
    const std::vector<double>* response_override = nullptr,
    std::vector<double>* context_statistics = nullptr) {
  std::map<std::string, std::vector<std::size_t>> contexts;
  for (std::size_t i = 0; i < rows.size(); ++i) contexts[rows[i].context].push_back(i);
  std::map<std::string, std::vector<double>> by_prevhash;
  for (const auto& [unused, indices] : contexts) {
    std::vector<double> x, y;
    x.reserve(indices.size());
    y.reserve(indices.size());
    for (const auto index : indices) {
      x.push_back(rows[index].x[feature]);
      y.push_back(response_override == nullptr
                      ? model_response(rows[index], target_kind)
                      : response_override->at(index));
    }
    const auto correlation = spearman(x, y);
    if (context_statistics != nullptr) context_statistics->push_back(correlation);
    by_prevhash[rows[indices.front()].prevhash].push_back(correlation);
  }
  std::vector<double> result;
  result.reserve(by_prevhash.size());
  for (const auto& [unused, values] : by_prevhash) {
    result.push_back(std::accumulate(values.begin(), values.end(), 0.0) /
                     values.size());
  }
  return result;
}

struct PrimaryFeatureArtifacts {
  std::string csv;
  std::vector<double> mean_prevhash_spearman;
};

double percentile(std::vector<double> values, double fraction);

PrimaryFeatureArtifacts primary_feature_analysis(
    const std::vector<Row>& rows, const std::vector<SchemaEntry>& schema,
    const Options& options, const ModelTarget target_kind,
    const std::string& status) {
  std::ostringstream csv;
  csv << "feature,category,family,target,context_count,prevhash_count,"
         "context_spearman_mean,context_spearman_median,"
         "prevhash_spearman_mean,prevhash_spearman_median,"
         "prevhash_coherent_sign_fraction,prevhash_bootstrap_ci_low,"
         "prevhash_bootstrap_ci_high,status\n";
  std::vector<double> primary_scores(schema.size());
  for (std::size_t feature = 0; feature < schema.size(); ++feature) {
    std::vector<double> context_values;
    auto prevhash_values = primary_prevhash_feature_statistics(
        rows, feature, target_kind, nullptr, &context_values);
    auto sorted_context = context_values;
    auto sorted_prevhash = prevhash_values;
    std::sort(sorted_context.begin(), sorted_context.end());
    std::sort(sorted_prevhash.begin(), sorted_prevhash.end());
    const auto mean_of = [](const std::vector<double>& values) {
      return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    };
    const auto median_of = [](const std::vector<double>& values) {
      return values.size() % 2U
          ? values[values.size() / 2U]
          : (values[values.size() / 2U - 1U] + values[values.size() / 2U]) / 2.0;
    };
    const auto context_mean = mean_of(context_values);
    const auto context_median = median_of(sorted_context);
    const auto prevhash_mean = mean_of(prevhash_values);
    const auto prevhash_median = median_of(sorted_prevhash);
    primary_scores[feature] = prevhash_mean;
    std::size_t coherent = 0U;
    for (const auto value : prevhash_values) {
      if (prevhash_mean == 0.0 || value == 0.0 ||
          ((prevhash_mean > 0.0) == (value > 0.0))) ++coherent;
    }
    std::mt19937_64 rng(options.seed ^
                        (0x94d049bb133111ebULL + feature));
    std::uniform_int_distribution<std::size_t> choose(0U, prevhash_values.size() - 1U);
    std::vector<double> bootstrapped;
    bootstrapped.reserve(options.bootstrap_replicates);
    for (std::size_t replicate = 0; replicate < options.bootstrap_replicates; ++replicate) {
      double mean = 0.0;
      for (std::size_t draw = 0; draw < prevhash_values.size(); ++draw) {
        mean += prevhash_values[choose(rng)];
      }
      bootstrapped.push_back(mean / prevhash_values.size());
    }
    csv << schema[feature].name << ',' << schema[feature].category << ','
        << schema[feature].family << ','
        << (target_kind == ModelTarget::ContextT30Score
                ? "context_t30_score" : "context_quality_score") << ','
        << context_values.size() << ','
        << prevhash_values.size() << ',' << csv_number(context_mean) << ','
        << csv_number(context_median) << ',' << csv_number(prevhash_mean) << ','
        << csv_number(prevhash_median) << ','
        << csv_number(static_cast<double>(coherent) / prevhash_values.size()) << ','
        << csv_number(percentile(bootstrapped, 0.025)) << ','
        << csv_number(percentile(bootstrapped, 0.975))
        << ',' << status << '\n';
  }
  return {csv.str(), std::move(primary_scores)};
}

double percentile(std::vector<double> values, const double fraction) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  const auto position = fraction * static_cast<double>(values.size() - 1U);
  const auto lower = static_cast<std::size_t>(std::floor(position));
  const auto upper = static_cast<std::size_t>(std::ceil(position));
  const auto weight = position - lower;
  return values[lower] * (1.0 - weight) + values[upper] * weight;
}

std::vector<std::size_t> top_candidate_features(
    const std::vector<double>& correlations, const std::size_t maximum) {
  std::vector<std::pair<double, std::size_t>> order;
  for (std::size_t i = 0; i < correlations.size(); ++i) {
    if (std::isfinite(correlations[i]) && std::abs(correlations[i]) > 0.0)
      order.emplace_back(std::abs(correlations[i]), i);
  }
  std::stable_sort(order.begin(), order.end(), [](const auto& left, const auto& right) {
    if (left.first != right.first) return left.first > right.first;
    return left.second < right.second;
  });
  std::vector<std::size_t> result;
  for (std::size_t i = 0; i < std::min(maximum, order.size()); ++i) result.push_back(order[i].second);
  return result;
}

std::vector<std::size_t> top_primary_candidate_features(
    const std::vector<double>& correlations,
    const std::vector<SchemaEntry>& schema,
    const std::size_t maximum) {
  require(correlations.size() == schema.size(),
          "primary candidate scores do not match feature schema");
  std::vector<std::pair<double, std::size_t>> order;
  for (std::size_t i = 0; i < correlations.size(); ++i) {
    if (schema[i].family == "SANITY_BASELINE") continue;
    if (std::isfinite(correlations[i]) && std::abs(correlations[i]) > 0.0) {
      order.emplace_back(std::abs(correlations[i]), i);
    }
  }
  std::stable_sort(order.begin(), order.end(), [](const auto& left, const auto& right) {
    if (left.first != right.first) return left.first > right.first;
    return left.second < right.second;
  });
  std::vector<std::size_t> result;
  for (std::size_t i = 0; i < std::min(maximum, order.size()); ++i) {
    result.push_back(order[i].second);
  }
  return result;
}

nlohmann::json permutation_analysis(
    const std::vector<Row>& rows, const std::vector<SchemaEntry>& schema,
    const std::vector<double>& primary_scores, const Options& options) {
  const auto candidates = top_primary_candidate_features(
      primary_scores, schema, options.selected_feature_count);
  std::map<std::string, std::vector<std::size_t>> contexts;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    contexts[rows[i].context].push_back(i);
  }
  std::vector<double> y;
  y.reserve(rows.size());
  for (const auto& row : rows) y.push_back(row.context_quality_score);
  nlohmann::json results = nlohmann::json::array();
  for (const auto feature : candidates) {
    const auto observed = primary_scores[feature];
    const auto prevhash_statistics =
        primary_prevhash_feature_statistics(
            rows, feature, ModelTarget::ContextQualityScore);
    std::mt19937_64 bootstrap_rng(options.seed ^ (0x9e3779b97f4a7c15ULL + feature));
    std::vector<double> bootstrapped;
    bootstrapped.reserve(options.bootstrap_replicates);
    std::uniform_int_distribution<std::size_t> choose_group(
        0U, prevhash_statistics.size() - 1U);
    for (std::size_t replicate = 0; replicate < options.bootstrap_replicates; ++replicate) {
      double mean = 0.0;
      for (std::size_t draw = 0; draw < prevhash_statistics.size(); ++draw) {
        mean += prevhash_statistics[choose_group(bootstrap_rng)];
      }
      bootstrapped.push_back(mean / prevhash_statistics.size());
    }
    std::mt19937_64 permutation_rng(options.seed ^ (0xd1b54a32d192ed03ULL + feature));
    std::size_t as_or_more_extreme = 0U;
    for (std::size_t replicate = 0; replicate < options.permutation_replicates; ++replicate) {
      auto permuted = y;
      for (const auto& [unused, indices] : contexts) {
        std::vector<double> local;
        local.reserve(indices.size());
        for (const auto index : indices) local.push_back(permuted[index]);
        std::shuffle(local.begin(), local.end(), permutation_rng);
        for (std::size_t i = 0; i < indices.size(); ++i) permuted[indices[i]] = local[i];
      }
      const auto permuted_prevhash = primary_prevhash_feature_statistics(
          rows, feature, ModelTarget::ContextQualityScore, &permuted);
      const auto permuted_statistic = std::accumulate(
          permuted_prevhash.begin(), permuted_prevhash.end(), 0.0) /
          permuted_prevhash.size();
      if (std::abs(permuted_statistic) >= std::abs(observed)) ++as_or_more_extreme;
    }
    results.push_back({
        {"feature", schema[feature].name}, {"category", schema[feature].category},
        {"observed_mean_prevhash_intra_context_spearman", observed},
        {"prevhash_bootstrap_ci95", {percentile(bootstrapped, 0.025),
                                     percentile(bootstrapped, 0.975)}},
        {"post_selection_unadjusted_within_context_permutation_p_value",
         static_cast<double>(as_or_more_extreme + 1U) /
             static_cast<double>(options.permutation_replicates + 1U)},
        {"status", "POST_SELECTION_EXPLORATORY_UNADJUSTED_NOT_EVIDENCE"}});
  }
  return {
      {"schema_version", kSchemaVersion}, {"phase", "2A_DISCOVERY_ONLY"},
      {"seed", options.seed}, {"independent_bootstrap_unit", "prevhash"},
      {"permutation", "context_quality_score labels shuffled within each discovery context"},
      {"bootstrap_replicates", options.bootstrap_replicates},
      {"permutation_replicates", options.permutation_replicates},
      {"candidate_selection", "largest absolute mean prevhash intra-context Spearman; SANITY_BASELINE excluded"},
      {"multiple_selection_adjustment", "none; post-selection values are exploratory and unadjusted"},
      {"tested_candidate_count", candidates.size()}, {"results", std::move(results)},
      {"validation_rows_used", 0}, {"holdout_rows_used", 0}};
}

struct SelectionAwarePermutationArtifacts {
  nlohmann::json summary;
  std::string null_csv;
  std::vector<double> observed_scores;
};

SelectionAwarePermutationArtifacts selection_aware_permutation_analysis(
    const std::vector<Row>& rows, const std::vector<SchemaEntry>& schema,
    const Options& options) {
  struct ContextUnit {
    std::vector<std::size_t> rows;
    double prevhash_weight{};
  };
  std::map<std::string, std::vector<std::size_t>> context_rows;
  std::map<std::string, std::size_t> contexts_per_prevhash;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    context_rows[rows[i].context].push_back(i);
  }
  for (const auto& [unused, indices] : context_rows) {
    ++contexts_per_prevhash[rows[indices.front()].prevhash];
  }
  std::vector<ContextUnit> contexts;
  contexts.reserve(context_rows.size());
  for (const auto& [unused, indices] : context_rows) {
    const auto& prevhash = rows[indices.front()].prevhash;
    contexts.push_back({indices,
        1.0 / (static_cast<double>(contexts_per_prevhash.size()) *
               contexts_per_prevhash.at(prevhash))});
  }

  const auto score_all_features = [&](const std::vector<double>& response) {
    require(response.size() == rows.size(),
            "selection-aware response length mismatch");
    std::vector<double> scores(schema.size(), 0.0);
    for (const auto& context : contexts) {
      double mean = 0.0;
      for (const auto index : context.rows) mean += response[index];
      mean /= context.rows.size();
      double squared = 0.0;
      for (const auto index : context.rows) {
        const auto delta = response[index] - mean;
        squared += delta * delta;
      }
      const auto scale = std::sqrt(squared);
      if (!(scale > 0.0)) continue;
      for (const auto index : context.rows) {
        require(rows[index].context_feature_ranks.size() == schema.size(),
                "PRE_SCAN rank cache unavailable for selection-aware permutation");
        const auto response_z = (response[index] - mean) / scale;
        for (std::size_t feature = 0; feature < schema.size(); ++feature) {
          scores[feature] += context.prevhash_weight *
              rows[index].context_feature_ranks[feature] * response_z;
        }
      }
    }
    return scores;
  };

  struct Maximum {
    std::size_t feature{};
    double score{};
  };
  const auto maximum_for_family = [&](const std::vector<double>& scores,
                                      const bool sanity) {
    Maximum result{};
    bool found = false;
    for (std::size_t feature = 0; feature < schema.size(); ++feature) {
      if ((schema[feature].family == "SANITY_BASELINE") != sanity) continue;
      if (!found || std::abs(scores[feature]) > std::abs(result.score)) {
        result = {feature, scores[feature]};
        found = true;
      }
    }
    require(found, sanity ? "no sanity baseline available"
                          : "no admissible scientific feature available");
    return result;
  };

  std::vector<double> observed_response;
  observed_response.reserve(rows.size());
  for (const auto& row : rows) observed_response.push_back(row.context_quality_score);
  auto observed_scores = score_all_features(observed_response);
  const auto observed_scientific = maximum_for_family(observed_scores, false);
  const auto observed_sanity = maximum_for_family(observed_scores, true);
  const auto admissible_count = static_cast<std::size_t>(std::count_if(
      schema.begin(), schema.end(), [](const auto& feature) {
        return feature.family != "SANITY_BASELINE";
      }));
  const auto sanity_count = schema.size() - admissible_count;

  std::mt19937_64 rng(options.seed ^ 0x6a09e667f3bcc909ULL);
  std::size_t scientific_as_extreme = 0U, sanity_as_extreme = 0U;
  std::vector<double> scientific_null, sanity_null;
  scientific_null.reserve(options.permutation_replicates);
  sanity_null.reserve(options.permutation_replicates);
  std::ostringstream null_csv;
  null_csv << "permutation,selected_scientific_feature,scientific_score,"
              "scientific_max_abs,selected_sanity_feature,sanity_score,sanity_max_abs\n";
  for (std::size_t replicate = 0; replicate < options.permutation_replicates;
       ++replicate) {
    auto permuted = observed_response;
    for (const auto& context : contexts) {
      std::vector<double> local;
      local.reserve(context.rows.size());
      for (const auto index : context.rows) local.push_back(permuted[index]);
      std::shuffle(local.begin(), local.end(), rng);
      for (std::size_t i = 0; i < context.rows.size(); ++i) {
        permuted[context.rows[i]] = local[i];
      }
    }
    const auto scores = score_all_features(permuted);
    const auto scientific = maximum_for_family(scores, false);
    const auto sanity = maximum_for_family(scores, true);
    const auto scientific_max = std::abs(scientific.score);
    const auto sanity_max = std::abs(sanity.score);
    scientific_null.push_back(scientific_max);
    sanity_null.push_back(sanity_max);
    if (scientific_max >= std::abs(observed_scientific.score)) {
      ++scientific_as_extreme;
    }
    if (sanity_max >= std::abs(observed_sanity.score)) ++sanity_as_extreme;
    null_csv << replicate << ',' << schema[scientific.feature].name << ','
             << csv_number(scientific.score) << ',' << csv_number(scientific_max)
             << ',' << schema[sanity.feature].name << ','
             << csv_number(sanity.score) << ',' << csv_number(sanity_max) << '\n';
  }

  const auto null_summary = [](const std::vector<double>& values) {
    const auto mean = values.empty() ? 0.0 :
        std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    return nlohmann::json{{"count", values.size()}, {"mean", mean},
                          {"median", percentile(values, 0.5)},
                          {"q95", percentile(values, 0.95)},
                          {"maximum", values.empty() ? 0.0
                                                     : *std::max_element(values.begin(), values.end())}};
  };
  nlohmann::json summary = {
      {"schema_version", kSchemaVersion},
      {"phase", "2A_REFINEMENT_DISCOVERY_ONLY"},
      {"branch", "SELECTION_AWARE_MAX_STATISTIC"},
      {"target", "context_quality_score"},
      {"target_source_stage", "POST_SCAN_Y_ONLY"},
      {"target_in_feature_matrix", false},
      {"seed", options.seed},
      {"permutation_replicates", options.permutation_replicates},
      {"permutation", "Y shuffled independently within every discovery context"},
      {"statistic", "max abs(mean prevhash intra-context Spearman)"},
      {"selection_refit_inside_each_permutation", true},
      {"feature_scores_recomputed_inside_each_permutation", true},
      {"max_statistic_includes_all_admissible_features", true},
      {"admissible_scientific_feature_count", admissible_count},
      {"features_scored_per_permutation", schema.size()},
      {"sanity_baseline_excluded_from_scientific_candidates", true},
      {"observed_scientific_best", {
          {"feature", schema[observed_scientific.feature].name},
          {"signed_score", observed_scientific.score},
          {"absolute_score", std::abs(observed_scientific.score)}}},
      {"scientific_null_maxima", null_summary(scientific_null)},
      {"selection_aware_max_statistic_p_value",
       static_cast<double>(scientific_as_extreme + 1U) /
           static_cast<double>(options.permutation_replicates + 1U)},
      {"sanity_baseline_control", {
          {"feature_count", sanity_count},
          {"observed_best_feature", schema[observed_sanity.feature].name},
          {"observed_signed_score", observed_sanity.score},
          {"observed_absolute_score", std::abs(observed_sanity.score)},
          {"null_maxima", null_summary(sanity_null)},
          {"max_statistic_p_value",
           static_cast<double>(sanity_as_extreme + 1U) /
               static_cast<double>(options.permutation_replicates + 1U)}}},
      {"validation_rows_used", 0}, {"holdout_rows_used", 0},
      {"status", "DISCOVERY_EXPLORATORY_NOT_VALIDATED"}};
  return {std::move(summary), null_csv.str(), std::move(observed_scores)};
}

struct Score {
  std::string name;
  std::vector<double> values;
  bool descending{};
  std::string status;
};

struct TopkArtifacts {
  std::string csv;
  std::size_t score_count{};
};

TopkArtifacts global_topk_analysis(const std::vector<Row>& rows,
                                   const std::vector<SchemaEntry>& schema,
                                   const std::vector<double>& correlations,
                                   const Options& options) {
  std::vector<Score> scores;
  const auto find_feature = [&](const std::string& name) {
    const auto found = std::find_if(schema.begin(), schema.end(), [&](const auto& entry) {
      return entry.name == name;
    });
    require(found != schema.end(), "missing sanity baseline " + name);
    return static_cast<std::size_t>(found - schema.begin());
  };
  for (const auto& name : {"baseline.random_deterministic", "baseline.numeric_extranonce2",
                           "baseline.hash_extranonce2", "baseline.header_prefix_hamming_weight"}) {
    const auto feature = find_feature(name);
    scores.push_back({name, column(rows, feature), true, "sanity_baseline"});
  }
  const auto candidates = top_candidate_features(
      correlations, std::min<std::size_t>(16U, options.selected_feature_count));
  for (const auto feature : candidates) {
    scores.push_back({schema[feature].name, column(rows, feature),
                      correlations[feature] >= 0.0,
                      "secondary_global_exploratory_candidate"});
  }
  std::vector<double> cv_values;
  for (const auto& row : rows) cv_values.push_back(row.cv_prediction);
  scores.push_back({"grouped_outer_cv_quality_ridge", std::move(cv_values), true,
                    "secondary_global_cross_validated_prediction"});

  std::map<std::string, std::vector<std::size_t>> groups;
  for (std::size_t i = 0; i < rows.size(); ++i) groups[rows[i].prevhash].push_back(i);
  std::vector<std::vector<std::size_t>> group_indices;
  for (const auto& [unused, indices] : groups) group_indices.push_back(indices);
  const auto global_quality = std::accumulate(rows.begin(), rows.end(), 0.0,
      [](const double sum, const Row& row) { return sum + row.quality; }) / rows.size();
  std::array<double, 7> total_tails{};
  for (const auto& row : rows) {
    for (std::size_t tail = 0; tail < total_tails.size(); ++tail) total_tails[tail] += row.tails[tail];
  }

  std::ostringstream csv;
  csv << "score,status,descending,top_fraction,selected_rows,actual_fraction,mean_quality_bits,"
         "quality_mean_lift,quality_lift_bootstrap_ci_low,quality_lift_bootstrap_ci_high,"
         "best_difficulty";
  for (const auto bits : kTailBits) {
    csv << ",T" << bits << "_captured,T" << bits << "_capture_fraction,T" << bits << "_lift";
  }
  csv << '\n';
  for (std::size_t score_index = 0; score_index < scores.size(); ++score_index) {
    const auto& score = scores[score_index];
    for (const auto fraction : kTopFractions) {
      std::vector<std::size_t> order(rows.size());
      std::iota(order.begin(), order.end(), 0U);
      std::stable_sort(order.begin(), order.end(), [&](const auto left, const auto right) {
        if (score.values[left] != score.values[right]) {
          return score.descending ? score.values[left] > score.values[right]
                                  : score.values[left] < score.values[right];
        }
        return rows[left].block_id < rows[right].block_id;
      });
      const auto selected = std::max<std::size_t>(1U,
          static_cast<std::size_t>(std::ceil(rows.size() * fraction)));
      const auto actual_fraction = static_cast<double>(selected) / rows.size();
      double quality_sum = 0.0, best_difficulty = 0.0;
      std::array<double, 7> captured{};
      for (std::size_t i = 0; i < selected; ++i) {
        const auto& row = rows[order[i]];
        quality_sum += row.quality;
        best_difficulty = std::max(best_difficulty, row.difficulty);
        for (std::size_t tail = 0; tail < captured.size(); ++tail) captured[tail] += row.tails[tail];
      }
      const auto mean_quality = quality_sum / selected;
      const auto lift = global_quality != 0.0 ? mean_quality / global_quality : 0.0;

      std::mt19937_64 rng(options.seed ^ (score_index * 0x9e3779b97f4a7c15ULL) ^
                          static_cast<std::uint64_t>(fraction * 10000.0));
      std::uniform_int_distribution<std::size_t> choose_group(0U, group_indices.size() - 1U);
      std::vector<double> bootstrap_lifts;
      for (std::size_t replicate = 0; replicate < options.bootstrap_replicates; ++replicate) {
        std::vector<std::size_t> sampled;
        for (std::size_t draw = 0; draw < group_indices.size(); ++draw) {
          const auto& group = group_indices[choose_group(rng)];
          sampled.insert(sampled.end(), group.begin(), group.end());
        }
        std::stable_sort(sampled.begin(), sampled.end(), [&](const auto left, const auto right) {
          if (score.values[left] != score.values[right]) {
            return score.descending ? score.values[left] > score.values[right]
                                    : score.values[left] < score.values[right];
          }
          return rows[left].block_id < rows[right].block_id;
        });
        const auto take = std::max<std::size_t>(1U,
            static_cast<std::size_t>(std::ceil(sampled.size() * fraction)));
        double all_mean = 0.0, selected_mean = 0.0;
        for (const auto index : sampled) all_mean += rows[index].quality;
        for (std::size_t i = 0; i < take; ++i) selected_mean += rows[sampled[i]].quality;
        all_mean /= sampled.size();
        selected_mean /= take;
        bootstrap_lifts.push_back(all_mean != 0.0 ? selected_mean / all_mean : 0.0);
      }
      csv << score.name << ',' << score.status << ',' << (score.descending ? 1 : 0)
          << ',' << csv_number(fraction) << ',' << selected << ','
          << csv_number(actual_fraction) << ',' << csv_number(mean_quality) << ','
          << csv_number(lift) << ',' << csv_number(percentile(bootstrap_lifts, 0.025))
          << ',' << csv_number(percentile(bootstrap_lifts, 0.975)) << ','
          << csv_number(best_difficulty);
      for (std::size_t tail = 0; tail < captured.size(); ++tail) {
        const auto capture_fraction = total_tails[tail] > 0.0
            ? captured[tail] / total_tails[tail] : 0.0;
        csv << ',' << csv_number(captured[tail]) << ',' << csv_number(capture_fraction)
            << ',' << csv_number(actual_fraction > 0.0
                                      ? capture_fraction / actual_fraction : 0.0);
      }
      csv << '\n';
    }
  }
  return {csv.str(), scores.size()};
}

TopkArtifacts intra_context_topk_analysis(
    const std::vector<Row>& rows, const std::vector<SchemaEntry>& schema,
    const std::vector<double>& primary_scores,
    const CvArtifacts& rank_cv, const Options& options,
    const std::string& candidate_status =
        "primary_intra_context_exploratory_candidate",
    const std::string& model_name = "grouped_outer_cv_rank_ridge",
    const std::string& model_status =
        "primary_intra_context_oof_prediction") {
  std::vector<Score> scores;
  const auto find_feature = [&](const std::string& name) {
    const auto found = std::find_if(schema.begin(), schema.end(), [&](const auto& entry) {
      return entry.name == name;
    });
    require(found != schema.end(), "missing sanity baseline " + name);
    return static_cast<std::size_t>(found - schema.begin());
  };
  for (const auto& name : {"baseline.random_deterministic", "baseline.numeric_extranonce2",
                           "baseline.hash_extranonce2", "baseline.header_prefix_hamming_weight"}) {
    scores.push_back({name, column(rows, find_feature(name)), true, "sanity_baseline"});
  }
  const auto candidates = top_primary_candidate_features(
      primary_scores, schema,
      std::min<std::size_t>(16U, options.selected_feature_count));
  for (const auto feature : candidates) {
    scores.push_back({schema[feature].name, column(rows, feature),
                      primary_scores[feature] >= 0.0,
                      candidate_status});
  }
  scores.push_back({model_name, rank_cv.predictions, true, model_status});

  std::vector<std::string> context_ids;
  context_ids.reserve(rows.size());
  std::map<std::string, std::vector<std::size_t>> prevhash_groups;
  std::set<std::string> distinct_contexts;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    context_ids.push_back(rows[i].context);
    distinct_contexts.insert(rows[i].context);
    prevhash_groups[rows[i].prevhash].push_back(i);
  }
  std::vector<std::vector<std::size_t>> groups;
  for (const auto& [unused, indices] : prevhash_groups) groups.push_back(indices);
  const auto global_quality = std::accumulate(rows.begin(), rows.end(), 0.0,
      [](const double sum, const Row& row) { return sum + row.quality; }) / rows.size();
  std::array<double, 7> total_tails{};
  for (const auto& row : rows) {
    for (std::size_t tail = 0; tail < total_tails.size(); ++tail) total_tails[tail] += row.tails[tail];
  }

  std::ostringstream csv;
  csv << "score,status,descending,top_fraction,context_count,selected_rows,"
         "selected_per_context_min,selected_per_context_max,actual_fraction,"
         "mean_quality_bits,quality_mean_lift,quality_lift_bootstrap_ci_low,"
         "quality_lift_bootstrap_ci_high,best_difficulty_descriptive";
  for (const auto bits : kTailBits) {
    csv << ",T" << bits << "_captured,T" << bits << "_capture_fraction,T"
        << bits << "_lift,T" << bits << "_lift_bootstrap_ci_low,T"
        << bits << "_lift_bootstrap_ci_high";
  }
  csv << '\n';

  for (std::size_t score_index = 0; score_index < scores.size(); ++score_index) {
    const auto& score = scores[score_index];
    for (const auto fraction : kTopFractions) {
      const auto selected = intra_context_topk_selection(
          context_ids, score.values, fraction, score.descending);
      std::map<std::string, std::size_t> selected_counts;
      double quality_sum = 0.0, best_difficulty = 0.0;
      std::array<double, 7> captured{};
      for (const auto index : selected) {
        ++selected_counts[rows[index].context];
        quality_sum += rows[index].quality;
        best_difficulty = std::max(best_difficulty, rows[index].difficulty);
        for (std::size_t tail = 0; tail < captured.size(); ++tail) {
          captured[tail] += rows[index].tails[tail];
        }
      }
      require(selected_counts.size() == distinct_contexts.size(),
              "intra-context top-k omitted a context");
      std::size_t minimum_selected = std::numeric_limits<std::size_t>::max();
      std::size_t maximum_selected = 0U;
      for (const auto& [unused, count] : selected_counts) {
        minimum_selected = std::min(minimum_selected, count);
        maximum_selected = std::max(maximum_selected, count);
      }
      const auto actual_fraction = static_cast<double>(selected.size()) / rows.size();
      const auto mean_quality = quality_sum / selected.size();
      const auto lift = global_quality != 0.0 ? mean_quality / global_quality : 0.0;

      struct GroupMetric {
        double all_quality{};
        std::size_t all_count{};
        double selected_quality{};
        std::size_t selected_count{};
        std::array<double, 7> all_tails{};
        std::array<double, 7> selected_tails{};
      };
      std::vector<GroupMetric> group_metrics;
      for (const auto& group : groups) {
        std::vector<std::string> local_contexts;
        std::vector<double> local_scores;
        GroupMetric metric;
        for (const auto index : group) {
          local_contexts.push_back(rows[index].context);
          local_scores.push_back(score.values[index]);
          metric.all_quality += rows[index].quality;
          ++metric.all_count;
          for (std::size_t tail = 0; tail < metric.all_tails.size(); ++tail) {
            metric.all_tails[tail] += rows[index].tails[tail];
          }
        }
        const auto local_selected = intra_context_topk_selection(
            local_contexts, local_scores, fraction, score.descending);
        for (const auto local_index : local_selected) {
          metric.selected_quality += rows[group[local_index]].quality;
          ++metric.selected_count;
          for (std::size_t tail = 0; tail < metric.selected_tails.size(); ++tail) {
            metric.selected_tails[tail] += rows[group[local_index]].tails[tail];
          }
        }
        group_metrics.push_back(metric);
      }
      std::mt19937_64 rng(options.seed ^
          (score_index * 0x9e3779b97f4a7c15ULL) ^
          static_cast<std::uint64_t>(fraction * 10000.0));
      std::uniform_int_distribution<std::size_t> choose(0U, group_metrics.size() - 1U);
      std::vector<double> bootstrap_lifts;
      std::array<std::vector<double>, 7> bootstrap_tail_lifts;
      for (auto& values : bootstrap_tail_lifts) {
        values.reserve(options.bootstrap_replicates);
      }
      for (std::size_t replicate = 0; replicate < options.bootstrap_replicates; ++replicate) {
        GroupMetric sampled;
        for (std::size_t draw = 0; draw < group_metrics.size(); ++draw) {
          const auto& metric = group_metrics[choose(rng)];
          sampled.all_quality += metric.all_quality;
          sampled.all_count += metric.all_count;
          sampled.selected_quality += metric.selected_quality;
          sampled.selected_count += metric.selected_count;
          for (std::size_t tail = 0; tail < sampled.all_tails.size(); ++tail) {
            sampled.all_tails[tail] += metric.all_tails[tail];
            sampled.selected_tails[tail] += metric.selected_tails[tail];
          }
        }
        const auto all_mean = sampled.all_quality / sampled.all_count;
        const auto selected_mean = sampled.selected_quality / sampled.selected_count;
        bootstrap_lifts.push_back(all_mean != 0.0 ? selected_mean / all_mean : 0.0);
        const auto sampled_fraction =
            static_cast<double>(sampled.selected_count) / sampled.all_count;
        for (std::size_t tail = 0; tail < sampled.all_tails.size(); ++tail) {
          const auto sampled_capture = sampled.all_tails[tail] > 0.0
              ? sampled.selected_tails[tail] / sampled.all_tails[tail] : 0.0;
          bootstrap_tail_lifts[tail].push_back(
              sampled_fraction > 0.0 ? sampled_capture / sampled_fraction : 0.0);
        }
      }

      csv << score.name << ',' << score.status << ',' << (score.descending ? 1 : 0)
          << ',' << csv_number(fraction) << ',' << distinct_contexts.size() << ','
          << selected.size() << ',' << minimum_selected << ',' << maximum_selected
          << ',' << csv_number(actual_fraction) << ',' << csv_number(mean_quality)
          << ',' << csv_number(lift) << ','
          << csv_number(percentile(bootstrap_lifts, 0.025)) << ','
          << csv_number(percentile(bootstrap_lifts, 0.975)) << ','
          << csv_number(best_difficulty);
      for (std::size_t tail = 0; tail < captured.size(); ++tail) {
        const auto capture_fraction = total_tails[tail] > 0.0
            ? captured[tail] / total_tails[tail] : 0.0;
        csv << ',' << csv_number(captured[tail]) << ',' << csv_number(capture_fraction)
            << ',' << csv_number(actual_fraction > 0.0
                                      ? capture_fraction / actual_fraction : 0.0)
            << ',' << csv_number(percentile(bootstrap_tail_lifts[tail], 0.025))
            << ',' << csv_number(percentile(bootstrap_tail_lifts[tail], 0.975));
      }
      csv << '\n';
    }
  }
  return {csv.str(), scores.size()};
}

nlohmann::json schema_json(const std::vector<SchemaEntry>& schema) {
  nlohmann::json entries = nlohmann::json::array();
  std::map<std::string, std::size_t> categories, families;
  for (const auto& entry : schema) {
    entries.push_back({{"name", entry.name}, {"type", "number"},
                       {"category", entry.category}, {"family", entry.family},
                       {"description", entry.description},
                       {"feature_stage", "PRE_SCAN"}});
    ++categories[entry.category];
    ++families[entry.family];
  }
  return {{"schema_version", kSchemaVersion},
          {"phase", "2A_DISCOVERY_ONLY"},
          {"representation", "dense deterministic numeric vector; entries define index order"},
          {"reference_rule", "minimum (SHA256(ASCII block_id), block_id) within the PRE_SCAN group"},
          {"feature_count", schema.size()}, {"category_counts", categories},
          {"family_counts", families}, {"features", std::move(entries)},
          {"post_scan_fields_allowed", false}};
}

void write_derived_jsonl(const std::filesystem::path& path,
                         const std::vector<Row>& rows) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) fail("cannot create artifact: " + path.string());
  for (const auto& row : rows) {
    output << nlohmann::json({
        {"schema_version", kSchemaVersion}, {"phase", "2A_DISCOVERY_ONLY"},
        {"feature_stage", "PRE_SCAN_DERIVED"}, {"partition", "discovery"},
        {"block_id", row.block_id}, {"work_fingerprint", row.context},
        {"prevhash", row.prevhash}, {"extranonce2", row.extranonce2},
        {"feature_values", row.x},
        {"feature_layout", "feature_schema.json order"}}).dump() << '\n';
  }
  if (!output) fail("cannot finish artifact: " + path.string());
}

std::string report_markdown(const LoadedData& data,
                            const UnivariateArtifacts& univariate,
                            const CvArtifacts& quality_cv,
                            const CvArtifacts& rank_cv,
                            const nlohmann::json& permutation,
                            const TopkArtifacts& intra_topk,
                            const TopkArtifacts& global_topk,
                            const Options& options) {
  std::set<std::string> contexts, prevhashes;
  for (const auto& row : data.rows) {
    contexts.insert(row.context);
    prevhashes.insert(row.prevhash);
  }
  std::ostringstream report;
  report << "# Phase 2A — white-box PRE_SCAN enrichment\n\n"
         << "Campaign: `" << data.manifest.at("campaign_id").get<std::string>() << "`\n\n"
         << "## Scientific boundary\n\n"
         << "This run is **discovery only**. Validation and holdout labels were skipped by the loader "
            "before any quality field was accessed. No nonce space was scanned and no GPU scanner was called. "
            "The source campaign files are read-only inputs.\n\n"
         << "- Discovery rows: " << data.rows.size() << "\n"
         << "- Discovery prevhash groups: " << prevhashes.size() << "\n"
         << "- Discovery contexts: " << contexts.size() << "\n"
         << "- Validation rows used: 0\n"
         << "- Holdout rows used: 0\n"
         << "- Derived PRE_SCAN features: " << data.schema.size() << "\n"
         << "- Univariate hypotheses counted: " << univariate.tested_hypotheses << "\n\n"
         << "## Primary operational objective\n\n"
         << "The primary question is whether PRE_SCAN features can rank extranonce2 candidates **within each "
            "Stratum context J** so that the best B(J,e) spaces can be scanned first. The normalized training "
            "target is `(n_context - mean_rank_quality_bits) / (n_context - 1)`, with 1.0 best and 0.0 worst. "
            "It is POST_SCAN and is used only as Y. Feature summaries first compute a Spearman statistic in each "
            "context, average the two context statistics within each prevhash, and treat the "
         << prevhashes.size() << " prevhashes as the strong units for summaries and bootstrap intervals.\n\n"
         << "Operational top-k selection is performed independently inside every context before selections are "
            "combined. The primary ridge model is trained on `context_quality_score`; `SANITY_BASELINE` features "
            "are categorically ineligible for its feature selection. Its OOF predictions are ranked within each "
            "test context.\n\n"
         << "## Methods\n\n"
         << "Rounds 0–2 of SHA-256 compression 1, the round-3 fixed boundary, W16/W17, fixed carries, "
            "and exact uniform-nonce carry expectations were reconstructed through the repository's existing "
            "white-box SHA engine. W18 is recorded only as nonce-dependent. Context and prevhash references are "
            "chosen by the minimum `(SHA256(ASCII block_id), block_id)` and never by a label.\n\n"
         << "Pearson, Spearman, and Kendall tau-b are reported separately for each declared target. "
            "Candidate intervals bootstrap whole prevhash groups. Permutations shuffle labels within contexts. "
            "Both ridge models use " << rank_cv.summary.at("outer_fold_count")
         << " outer grouped folds; scaling, feature selection, and lambda choice are fit only inside training data. "
            "Seed: `" << options.seed << "`.\n\n"
         << "Primary intra-context top-k compares " << intra_topk.score_count
         << " scores. The global quality model and global top-k comparison ("
         << global_topk.score_count << " scores) are retained only as **SECONDARY / DESCRIPTIVE** analyses. "
            "Their pooled ranking is not the operational test.\n\n"
         << "## Interpretation\n\n"
         << "Every result in this directory is exploratory or discovery-cross-validated. **Nothing in Phase 2A "
            "is validated**, and these artifacts do not establish a SHA weakness or a proven mining advantage. "
            "A recipe must be frozen before a later Phase 2B validation analysis.\n\n"
         << "Permutation candidates tested: " << permutation.at("tested_candidate_count") << ".\n";
  (void)quality_cv;
  return report.str();
}

std::string refinement_report_markdown(
    const LoadedData& data, const CvArtifacts& refined_rank_cv,
    const CvArtifacts& t30_cv,
    const SelectionAwarePermutationArtifacts& selection_aware,
    const TopkArtifacts& refined_rank_topk,
    const TopkArtifacts& t30_topk, const Options& options) {
  std::set<std::string> contexts, prevhashes;
  for (const auto& row : data.rows) {
    contexts.insert(row.context);
    prevhashes.insert(row.prevhash);
  }
  std::ostringstream report;
  report << "# Phase 2A refinement — discovery only\n\n"
         << "Campaign: `" << data.manifest.at("campaign_id").get<std::string>()
         << "`\n\n"
         << "This is a separate immutable refinement of `phase2_discovery_v1`. "
            "It uses discovery labels only. Validation and holdout labels were skipped before "
            "quality access; no GPU, nonce scan, new Stratum job, or holdout finalization was used.\n\n"
         << "- Discovery rows: " << data.rows.size() << "\n"
         << "- Contexts: " << contexts.size() << "\n"
         << "- Prevhash groups: " << prevhashes.size() << "\n"
         << "- PRE_SCAN features: " << data.schema.size() << "\n"
         << "- Validation rows used: 0\n"
         << "- Holdout rows used: 0\n\n"
         << "## Ridge lambda refinement\n\n"
         << "The primary `context_quality_score` ridge model keeps the same deterministic "
            "prevhash-grouped nested CV and seed, but evaluates lambdas through 1,000,000. "
            "Every fold records all inner-CV RMSE values, the selected lambda, and whether it "
            "remains a grid boundary. Outer-test performance never selects lambda. The associated "
            "intra-context top-k table compares " << refined_rank_topk.score_count
         << " scores.\n\n"
         << "## EXPLORATORY_DISCOVERY_T30\n\n"
         << "`quality.tail_counts.leading_zero_30` is POST_SCAN and is used only to build the "
            "within-context mean-rank target `context_t30_score`. It never enters X. The T30 ridge "
            "uses the same nested prevhash-grouped discipline and produces distinct OOF predictions. "
            "Its top-k table compares " << t30_topk.score_count
         << " scores and reports quality plus T26–T38 capture metrics with prevhash bootstrap intervals.\n\n"
         << "## Selection-aware permutation\n\n"
         << "Each of " << options.permutation_replicates
         << " permutations shuffles Y within contexts, recomputes all "
         << selection_aware.summary.at("admissible_scientific_feature_count")
         << " admissible scientific feature scores, reselects the maximum absolute mean-prevhash "
            "intra-context Spearman statistic, and compares the observed winner with that null of maxima. "
            "SANITY_BASELINE controls are evaluated separately.\n\n"
         << "## Interpretation\n\n"
         << "All outputs are **DISCOVERY / EXPLORATORY / NOT VALIDATED**. They are not evidence of "
            "a cryptanalytic weakness or mining advantage. No validation recipe is frozen or chosen "
            "automatically by this refinement.\n\n"
         << "Refined quality-rank OOF mean per-prevhash Spearman: `"
         << refined_rank_cv.summary.at("metrics").at("per_prevhash_context_spearman").at("mean")
         << "`. T30 OOF mean per-prevhash Spearman: `"
         << t30_cv.summary.at("metrics").at("per_prevhash_context_spearman").at("mean")
         << "`.\n";
  return report.str();
}

}  // namespace

nlohmann::json run(const std::filesystem::path& campaign_directory,
                   const Options& options) {
  const auto started = std::chrono::steady_clock::now();
  require(std::filesystem::is_directory(campaign_directory),
          "campaign directory does not exist");
  require(options.outer_folds >= 2U, "outer fold count must be at least two");
  require(options.selected_feature_count > 0U,
          "selected feature count must be positive");
  require(!options.expected_campaign_id.empty(), "expected campaign_id must be explicit");
  const auto output_directory = campaign_directory / "phase2_discovery_v1";
  if (!options.check_only) {
    require(!std::filesystem::exists(output_directory),
            "phase2_discovery_v1 already exists; immutable analysis artifacts are not overwritten");
  }

  const std::array<std::filesystem::path, 5> source_paths{
      campaign_directory / "manifest.json",
      campaign_directory / "features.jsonl",
      campaign_directory / "block_labels.jsonl",
      campaign_directory / "analysis_summary.json",
      campaign_directory / "report.md"};
  nlohmann::json digests_before = nlohmann::json::object();
  for (const auto& path : source_paths) {
    require(std::filesystem::is_regular_file(path),
            "required source artifact is missing: " + path.filename().string());
    digests_before[path.filename().string()] = file_sha256(path);
  }
  const auto sealed_summary = read_json(campaign_directory / "analysis_summary.json");
  require(!sealed_summary.value("holdout_finalized", false),
          "source analysis says holdout_finalized=true");
  require(!sealed_summary.value("holdout", nlohmann::json::object())
               .value("opened", false),
          "source analysis says holdout.opened=true");

  auto data = load_discovery(campaign_directory, !options.check_only);
  require(data.manifest.at("campaign_id").get<std::string>() ==
              options.expected_campaign_id,
          "campaign_id is not the frozen Phase 2A campaign " +
              options.expected_campaign_id);
  std::set<std::string> contexts, prevhashes;
  for (const auto& row : data.rows) {
    contexts.insert(row.context);
    prevhashes.insert(row.prevhash);
  }
  nlohmann::json audit = {
      {"schema_version", kSchemaVersion},
      {"phase", "2A_DISCOVERY_ONLY"},
      {"campaign_id", data.manifest.at("campaign_id")},
      {"expected_campaign_id", options.expected_campaign_id},
      {"timestamp_utc", data.manifest.value("created_at_utc", "unknown")},
      {"timestamp_policy", "source campaign timestamp retained for byte-reproducibility"},
#ifdef SRM_CODE_VERSION
      {"code_version", SRM_CODE_VERSION},
#else
      {"code_version", "repository worktree build; commit not embedded"},
#endif
      {"source_feature_lines", data.source_feature_lines},
      {"source_label_lines", data.source_label_lines},
      {"discovery_rows_used", data.rows.size()},
      {"validation_rows_used", 0},
      {"holdout_rows_used", 0},
      {"discovery_prevhashes", prevhashes.size()},
      {"discovery_contexts", contexts.size()},
      {"derived_feature_count", data.schema.size()},
      {"statistical_seed", options.seed},
      {"source_sha256_before", digests_before},
      {"partition_guards", {
          {"accepted_partition", "discovery"},
          {"label_quality_access_after_partition_guard", true},
          {"validation_quality_accessed", false},
          {"holdout_quality_accessed", false},
          {"source_holdout_sealed", true},
          {"finalize_holdout_supported", false},
          {"gpu_scanner_called", false},
          {"nonce_scan_called", false},
          {"source_open_mode", "read_only"}}},
      {"context_reference_rule",
       "minimum (SHA256(ASCII block_id), block_id) within each discovery PRE_SCAN context"},
      {"status", options.check_only ? "DRY_RUN_CHECK_PASSED" : "ANALYSIS_COMPLETE"}};

  if (options.check_only) {
    nlohmann::json after = nlohmann::json::object();
    for (const auto& path : source_paths) after[path.filename().string()] = file_sha256(path);
    require(after == digests_before, "source file changed during dry-run");
    audit["source_sha256_after"] = std::move(after);
    audit["source_files_unchanged"] = true;
    audit["artifacts_written"] = 0;
    std::cout << "Phase 2A dry-run total: " << std::fixed << std::setprecision(3)
              << std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - started).count()
              << " seconds\n";
    return audit;
  }

  std::cout << "Phase 2A statistics: univariate analysis\n";
  const auto univariate = univariate_analysis(data.rows, data.schema);
  std::cout << "Phase 2A statistics: intra-context and prevhash summaries\n";
  const auto grouped = group_analysis(data.rows, data.schema);
  const auto primary_features = primary_feature_analysis(
      data.rows, data.schema, options, ModelTarget::ContextQualityScore,
      "exploratory_primary_discovery_only");
  prepare_context_feature_ranks(data.rows);
  std::cout << "Phase 2A statistics: primary rank and secondary quality grouped CV\n";
  const auto rank_cv = grouped_nested_cv(
      data.rows, data.schema, options, ModelTarget::ContextQualityScore,
      kLambdas, "2A_DISCOVERY_ONLY");
  const auto quality_cv = grouped_nested_cv(
      data.rows, data.schema, options, ModelTarget::AbsoluteQuality,
      kLambdas, "2A_DISCOVERY_ONLY");
  std::cout << "Phase 2A statistics: grouped bootstrap and permutations\n";
  const auto permutation = permutation_analysis(
      data.rows, data.schema, primary_features.mean_prevhash_spearman, options);
  std::cout << "Phase 2A statistics: primary intra-context and secondary global top-k\n";
  const auto intra_topk = intra_context_topk_analysis(
      data.rows, data.schema, primary_features.mean_prevhash_spearman,
      rank_cv, options);
  const auto global_topk = global_topk_analysis(
      data.rows, data.schema, univariate.quality_spearman, options);

  nlohmann::json digests_after = nlohmann::json::object();
  for (const auto& path : source_paths) digests_after[path.filename().string()] = file_sha256(path);
  require(digests_after == digests_before, "source campaign changed during Phase 2A");
  audit["source_sha256_after"] = digests_after;
  audit["source_files_unchanged"] = true;
  audit["multiple_testing"] = {
      {"all_univariate_hypotheses_counted", univariate.tested_hypotheses},
      {"permutation_candidate_tests", permutation.at("tested_candidate_count")},
      {"phase2a_validated_results", 0},
      {"post_selection_p_values_adjusted", false},
      {"interpretation", "POST_SELECTION / EXPLORATORY / UNADJUSTED; not evidence"}};
  audit["statistical_configuration"] = {
      {"outer_folds", options.outer_folds},
      {"bootstrap_replicates", options.bootstrap_replicates},
      {"permutation_replicates", options.permutation_replicates},
      {"ridge_lambda_grid", kLambdas},
      {"selected_feature_count", options.selected_feature_count}};
  audit["analysis_roles"] = {
      {"primary_operational", {
          "intra_context_feature_summary.csv", "topk_lift_intra_context.csv",
          "grouped_cv_rank_summary.json", "grouped_cv_rank_predictions.csv"}},
      {"secondary_descriptive", {
          "univariate_features.csv", "intra_context_rank.csv",
          "per_prevhash_summary.csv", "grouped_cv_summary.json",
          "grouped_cv_predictions.csv", "topk_lift_global_descriptive.csv"}},
      {"primary_ridge_excluded_feature_families", {"SANITY_BASELINE"}}};
  audit["artifacts"] = {
      "audit.json", "feature_schema.json", "derived_features_discovery.jsonl",
      "univariate_features.csv", "intra_context_rank.csv",
      "per_prevhash_summary.csv", "intra_context_feature_summary.csv",
      "grouped_cv_rank_predictions.csv", "grouped_cv_rank_summary.json",
      "topk_lift_intra_context.csv", "grouped_cv_predictions.csv",
      "grouped_cv_summary.json", "topk_lift_global_descriptive.csv",
      "permutation_summary.json",
      "report.md"};

  std::filesystem::create_directory(output_directory);
  write_json(output_directory / "feature_schema.json", schema_json(data.schema));
  write_derived_jsonl(output_directory / "derived_features_discovery.jsonl",
                      data.rows);
  write_text(output_directory / "univariate_features.csv", univariate.csv);
  write_text(output_directory / "intra_context_rank.csv", grouped.intra_context_csv);
  write_text(output_directory / "per_prevhash_summary.csv", grouped.per_prevhash_csv);
  write_text(output_directory / "intra_context_feature_summary.csv",
             primary_features.csv);
  write_text(output_directory / "grouped_cv_rank_predictions.csv",
             rank_cv.predictions_csv);
  write_json(output_directory / "grouped_cv_rank_summary.json", rank_cv.summary);
  write_text(output_directory / "topk_lift_intra_context.csv", intra_topk.csv);
  write_text(output_directory / "grouped_cv_predictions.csv",
             quality_cv.predictions_csv);
  write_json(output_directory / "grouped_cv_summary.json", quality_cv.summary);
  write_text(output_directory / "topk_lift_global_descriptive.csv", global_topk.csv);
  write_json(output_directory / "permutation_summary.json", permutation);
  write_text(output_directory / "report.md",
             report_markdown(data, univariate, quality_cv, rank_cv,
                             permutation, intra_topk, global_topk, options));
  write_json(output_directory / "audit.json", audit);
  std::cout << "Phase 2A total: " << std::fixed << std::setprecision(3)
            << std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - started).count()
            << " seconds\n";
  return audit;
}

nlohmann::json run_refinement(const std::filesystem::path& campaign_directory,
                              const Options& options) {
  const auto started = std::chrono::steady_clock::now();
  require(std::filesystem::is_directory(campaign_directory),
          "campaign directory does not exist");
  require(options.outer_folds >= 2U, "outer fold count must be at least two");
  require(options.selected_feature_count > 0U,
          "selected feature count must be positive");
  require(options.permutation_replicates > 0U,
          "selection-aware permutation count must be positive");
  require(options.bootstrap_replicates > 0U,
          "prevhash bootstrap count must be positive");
  require(!options.expected_campaign_id.empty(),
          "expected campaign_id must be explicit");

  const auto historical_directory = campaign_directory / "phase2_discovery_v1";
  const auto output_directory =
      campaign_directory / "phase2_discovery_v1_refinement";
  require(std::filesystem::is_directory(historical_directory),
          "immutable phase2_discovery_v1 is required before refinement");
  if (!options.check_only) {
    require(!std::filesystem::exists(output_directory),
            "phase2_discovery_v1_refinement already exists; immutable refinement artifacts are not overwritten");
  }

  const std::array<std::filesystem::path, 6> source_paths{
      campaign_directory / "manifest.json",
      campaign_directory / "checkpoint.json",
      campaign_directory / "features.jsonl",
      campaign_directory / "block_labels.jsonl",
      campaign_directory / "analysis_summary.json",
      campaign_directory / "report.md"};
  nlohmann::json source_before = nlohmann::json::object();
  for (const auto& path : source_paths) {
    require(std::filesystem::is_regular_file(path),
            "required source artifact is missing: " + path.filename().string());
    source_before[path.filename().string()] = file_sha256(path);
  }
  const auto historical_before = directory_sha256(historical_directory);
  const auto historical_audit = read_json(historical_directory / "audit.json");
  require(historical_audit.value("campaign_id", "") == options.expected_campaign_id,
          "historical Phase 2A campaign_id does not match frozen campaign");
  require(historical_audit.value("validation_rows_used", 1U) == 0U,
          "historical Phase 2A used validation rows");
  require(historical_audit.value("holdout_rows_used", 1U) == 0U,
          "historical Phase 2A used holdout rows");
  require(historical_audit.at("statistical_seed").get<std::uint64_t>() ==
              options.seed,
          "refinement seed must exactly match immutable Phase 2A seed");
  const auto& historical_configuration =
      historical_audit.at("statistical_configuration");
  require(historical_configuration.at("outer_folds").get<std::size_t>() ==
              options.outer_folds,
          "refinement outer fold count must exactly match immutable Phase 2A");
  require(historical_configuration.at("selected_feature_count").get<std::size_t>() ==
              options.selected_feature_count,
          "refinement selected feature count must exactly match immutable Phase 2A");
  const auto sealed_summary = read_json(campaign_directory / "analysis_summary.json");
  require(!sealed_summary.value("holdout_finalized", false),
          "source analysis says holdout_finalized=true");
  require(!sealed_summary.value("holdout", nlohmann::json::object())
               .value("opened", false),
          "source analysis says holdout.opened=true");

  auto data = load_discovery(campaign_directory, !options.check_only);
  require(data.manifest.at("campaign_id").get<std::string>() ==
              options.expected_campaign_id,
          "campaign_id is not the frozen Phase 2A campaign " +
              options.expected_campaign_id);
  std::set<std::string> contexts, prevhashes;
  for (const auto& row : data.rows) {
    contexts.insert(row.context);
    prevhashes.insert(row.prevhash);
  }
  nlohmann::json audit = {
      {"schema_version", kSchemaVersion},
      {"phase", "2A_REFINEMENT_DISCOVERY_ONLY"},
      {"campaign_id", data.manifest.at("campaign_id")},
      {"expected_campaign_id", options.expected_campaign_id},
#ifdef SRM_CODE_VERSION
      {"code_version", SRM_CODE_VERSION},
#else
      {"code_version", "repository worktree build; commit not embedded"},
#endif
      {"source_feature_lines", data.source_feature_lines},
      {"source_label_lines", data.source_label_lines},
      {"discovery_rows_used", data.rows.size()},
      {"discovery_contexts", contexts.size()},
      {"discovery_prevhashes", prevhashes.size()},
      {"derived_feature_count", data.schema.size()},
      {"validation_rows_used", 0}, {"holdout_rows_used", 0},
      {"statistical_seed", options.seed},
      {"source_sha256_before", source_before},
      {"historical_phase2_sha256_before", historical_before},
      {"historical_phase2_directory", historical_directory.filename().string()},
      {"refinement_output_directory", output_directory.filename().string()},
      {"refinement_output_non_overwrite", true},
      {"historical_fold_recipe_identity_enforced", true},
      {"partition_guards", {
          {"accepted_partition", "discovery"},
          {"label_quality_access_after_partition_guard", true},
          {"validation_quality_accessed", false},
          {"holdout_quality_accessed", false},
          {"source_holdout_sealed", true},
          {"finalize_holdout_supported", false},
          {"gpu_scanner_called", false},
          {"nonce_scan_called", false},
          {"new_stratum_contexts_requested", false},
          {"source_open_mode", "read_only"}}},
      {"t30_boundary", {
          {"source", "quality.tail_counts.leading_zero_30"},
          {"source_stage", "POST_SCAN"},
          {"usage", "Y_ONLY"},
          {"present_in_X", false},
          {"indirect_feature_derivation", false}}},
      {"status", options.check_only ? "DRY_RUN_CHECK_PASSED"
                                    : "ANALYSIS_COMPLETE_DISCOVERY_NOT_VALIDATED"}};

  if (options.check_only) {
    nlohmann::json source_after = nlohmann::json::object();
    for (const auto& path : source_paths) {
      source_after[path.filename().string()] = file_sha256(path);
    }
    const auto historical_after = directory_sha256(historical_directory);
    require(source_after == source_before,
            "source campaign changed during refinement dry-run");
    require(historical_after == historical_before,
            "historical phase2_discovery_v1 changed during refinement dry-run");
    audit["source_sha256_after"] = std::move(source_after);
    audit["historical_phase2_sha256_after"] = historical_after;
    audit["source_files_unchanged"] = true;
    audit["historical_phase2_files_unchanged"] = true;
    audit["refinement_output_exists"] = std::filesystem::exists(output_directory);
    audit["artifacts_written"] = 0;
    std::cout << "Phase 2A refinement dry-run total: " << std::fixed
              << std::setprecision(3)
              << std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - started).count()
              << " seconds\n";
    return audit;
  }

  prepare_context_feature_ranks(data.rows);
  std::cout << "Phase 2A refinement: selection-aware max-statistic permutation\n";
  const auto selection_aware = selection_aware_permutation_analysis(
      data.rows, data.schema, options);
  std::cout << "Phase 2A refinement: expanded-lambda quality-rank grouped CV\n";
  const auto refined_rank_cv = grouped_nested_cv(
      data.rows, data.schema, options, ModelTarget::ContextQualityScore,
      kRefinementLambdas, "2A_REFINEMENT_DISCOVERY_ONLY");
  const auto refined_rank_topk = intra_context_topk_analysis(
      data.rows, data.schema, selection_aware.observed_scores, refined_rank_cv,
      options, "refinement_quality_rank_candidate",
      "grouped_outer_cv_rank_ridge_expanded_lambda",
      "refinement_quality_rank_oof_prediction");

  std::cout << "Phase 2A refinement: EXPLORATORY_DISCOVERY_T30 feature summary\n";
  const auto t30_features = primary_feature_analysis(
      data.rows, data.schema, options, ModelTarget::ContextT30Score,
      "EXPLORATORY_DISCOVERY_T30_NOT_VALIDATED");
  std::cout << "Phase 2A refinement: EXPLORATORY_DISCOVERY_T30 grouped CV\n";
  const auto t30_cv = grouped_nested_cv(
      data.rows, data.schema, options, ModelTarget::ContextT30Score,
      kRefinementLambdas, "2A_REFINEMENT_DISCOVERY_ONLY");
  const auto t30_topk = intra_context_topk_analysis(
      data.rows, data.schema, t30_features.mean_prevhash_spearman, t30_cv,
      options, "EXPLORATORY_DISCOVERY_T30_candidate",
      "grouped_outer_cv_T30_rank_ridge",
      "EXPLORATORY_DISCOVERY_T30_oof_prediction");

  nlohmann::json source_after = nlohmann::json::object();
  for (const auto& path : source_paths) {
    source_after[path.filename().string()] = file_sha256(path);
  }
  const auto historical_after = directory_sha256(historical_directory);
  require(source_after == source_before,
          "source campaign changed during Phase 2A refinement");
  require(historical_after == historical_before,
          "historical phase2_discovery_v1 changed during refinement");
  audit["source_sha256_after"] = source_after;
  audit["historical_phase2_sha256_after"] = historical_after;
  audit["source_files_unchanged"] = true;
  audit["historical_phase2_files_unchanged"] = true;
  audit["statistical_configuration"] = {
      {"outer_folds", options.outer_folds},
      {"inner_fold_max", 4U},
      {"bootstrap_replicates", options.bootstrap_replicates},
      {"selection_aware_permutation_replicates",
       options.permutation_replicates},
      {"selected_feature_count", options.selected_feature_count},
      {"ridge_lambda_grid", kRefinementLambdas},
      {"fold_group_unit", "prevhash"},
      {"feature_selection_scope", "train_only"},
      {"normalization_scope", "train_only"},
      {"lambda_selection_scope", "inner_grouped_cv_train_only"},
      {"sanity_baseline_admissible_to_scientific_model", false}};
  audit["analysis_branches"] = {
      {"ridge_lambda_refinement", {
          {"target", "context_quality_score"},
          {"status", "DISCOVERY_EXPLORATORY_NOT_VALIDATED"}}},
      {"EXPLORATORY_DISCOVERY_T30", {
          {"target", "context_t30_score"},
          {"raw_target", "quality.tail_counts.leading_zero_30"},
          {"status", "DISCOVERY_EXPLORATORY_NOT_VALIDATED"}}},
      {"selection_aware_permutation", {
          {"target", "context_quality_score"},
          {"selection_refit_inside_each_permutation", true},
          {"status", "DISCOVERY_EXPLORATORY_NOT_VALIDATED"}}}};
  audit["artifacts"] = {
      "audit.json", "feature_schema.json",
      "ridge_lambda_refinement_summary.json",
      "ridge_lambda_refinement_predictions.csv",
      "ridge_lambda_refinement_topk_intra_context.csv",
      "t30_intra_context_feature_summary.csv",
      "t30_grouped_cv_summary.json", "t30_grouped_cv_predictions.csv",
      "t30_topk_lift_intra_context.csv",
      "selection_aware_permutation_summary.json",
      "selection_aware_permutation_null.csv", "report.md"};
  audit["artifacts_written"] = audit.at("artifacts").size();

  require(std::filesystem::create_directory(output_directory),
          "could not create immutable refinement output directory");
  write_json(output_directory / "feature_schema.json", schema_json(data.schema));
  write_json(output_directory / "ridge_lambda_refinement_summary.json",
             refined_rank_cv.summary);
  write_text(output_directory / "ridge_lambda_refinement_predictions.csv",
             refined_rank_cv.predictions_csv);
  write_text(output_directory / "ridge_lambda_refinement_topk_intra_context.csv",
             refined_rank_topk.csv);
  write_text(output_directory / "t30_intra_context_feature_summary.csv",
             t30_features.csv);
  write_json(output_directory / "t30_grouped_cv_summary.json", t30_cv.summary);
  write_text(output_directory / "t30_grouped_cv_predictions.csv",
             t30_cv.predictions_csv);
  write_text(output_directory / "t30_topk_lift_intra_context.csv", t30_topk.csv);
  write_json(output_directory / "selection_aware_permutation_summary.json",
             selection_aware.summary);
  write_text(output_directory / "selection_aware_permutation_null.csv",
             selection_aware.null_csv);
  write_text(output_directory / "report.md",
             refinement_report_markdown(data, refined_rank_cv, t30_cv,
                                        selection_aware, refined_rank_topk,
                                        t30_topk, options));
  write_json(output_directory / "audit.json", audit);
  std::cout << "Phase 2A refinement total: " << std::fixed
            << std::setprecision(3)
            << std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - started).count()
            << " seconds\n";
  return audit;
}

}  // namespace srm::research::context_phase2
