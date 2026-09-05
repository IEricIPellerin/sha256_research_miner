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
  Snapshot snapshot;
  double quality{};
  double difficulty{};
  double log_difficulty{};
  std::array<double, 7> tails{};
  double rank_quality{};
  double cv_prediction{std::numeric_limits<double>::quiet_NaN()};
  double cv_prediction_rank{};
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
      auto ordered = indices;
      std::stable_sort(ordered.begin(), ordered.end(), [&](const auto left, const auto right) {
        if (data.rows[left].quality != data.rows[right].quality)
          return data.rows[left].quality > data.rows[right].quality;
        return data.rows[left].block_id < data.rows[right].block_id;
      });
      for (std::size_t begin = 0; begin < ordered.size();) {
        std::size_t end = begin + 1U;
        while (end < ordered.size() &&
               data.rows[ordered[end]].quality == data.rows[ordered[begin]].quality) ++end;
        const auto average_rank =
            (static_cast<double>(begin + 1U) + static_cast<double>(end)) / 2.0;
        for (std::size_t i = begin; i < end; ++i) {
          data.rows[ordered[i]].rank_quality = average_rank;
        }
        begin = end;
      }
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

double pearson(const std::vector<double>& x, const std::vector<double>& y) {
  require(x.size() == y.size(), "correlation vector length mismatch");
  if (x.size() < 3U) return 0.0;
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

std::vector<std::size_t> select_features(
    const std::vector<Row>& rows, const std::vector<std::size_t>& train,
    const std::size_t maximum) {
  const auto y = target(rows, 0U, &train);
  std::vector<std::pair<double, std::size_t>> scored;
  for (std::size_t feature = 0; feature < rows.front().x.size(); ++feature) {
    const auto correlation = pearson(column(rows, feature, &train), y);
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
                     const double lambda) {
  RidgeModel model;
  model.features = features;
  model.means.resize(features.size());
  model.scales.resize(features.size());
  model.fitted_row_count = train.size();
  for (const auto index : train) model.y_mean += rows[index].quality;
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
      rhs[j] += z[j] * (rows[index].quality - model.y_mean);
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
};

CvArtifacts grouped_nested_cv(std::vector<Row>& rows,
                              const std::vector<SchemaEntry>& schema,
                              const Options& options) {
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

    double selected_lambda = kLambdas.front();
    nlohmann::json inner_scores = nlohmann::json::array();
    if (train_groups.size() >= 3U) {
      const auto inner_fold_count = std::min<std::size_t>(4U, train_groups.size());
      std::vector<std::string> inner_groups;
      inner_groups.reserve(train.size());
      for (const auto index : train) inner_groups.push_back(rows[index].prevhash);
      const auto inner_owner = grouped_fold_assignment(
          inner_groups, inner_fold_count, options.seed + fold + 1U);
      struct InnerSplit {
        std::vector<std::size_t> train;
        std::vector<std::size_t> test;
        std::vector<std::size_t> selected;
      };
      std::vector<InnerSplit> inner_splits(inner_fold_count);
      for (std::size_t inner_fold = 0; inner_fold < inner_fold_count; ++inner_fold) {
        auto& split = inner_splits[inner_fold];
        for (std::size_t pos = 0; pos < train.size(); ++pos) {
          (inner_owner[pos] == inner_fold ? split.test : split.train).push_back(train[pos]);
        }
        split.selected = select_features(rows, split.train,
                                         options.selected_feature_count);
      }
      auto best_error = std::numeric_limits<double>::infinity();
      for (const auto lambda : kLambdas) {
        double total_squared = 0.0;
        std::size_t count = 0U;
        for (const auto& split : inner_splits) {
          const auto model = fit_ridge(rows, split.train, split.selected, lambda);
          for (const auto index : split.test) {
            const auto error = rows[index].quality - predict(model, rows[index]);
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

    const auto selected = select_features(rows, train, options.selected_feature_count);
    const auto model = fit_ridge(rows, train, selected, selected_lambda);
    for (const auto index : test) {
      rows[index].cv_prediction = predict(model, rows[index]);
      rows[index].outer_fold = fold;
    }
    nlohmann::json selected_names = nlohmann::json::array();
    for (const auto feature : selected) selected_names.push_back(schema[feature].name);
    fold_audits.push_back({
        {"outer_fold", fold}, {"train_rows", train.size()}, {"test_rows", test.size()},
        {"train_prevhashes", train_groups}, {"test_prevhashes", test_groups},
        {"prevhash_overlap", overlap}, {"selected_lambda", selected_lambda},
        {"inner_cv", inner_scores}, {"selected_features", selected_names},
        {"normalization", {{"scope", "outer_train_only"},
                           {"fitted_row_count", model.fitted_row_count}}},
        {"feature_selection", {{"scope", "outer_train_only"},
                               {"fitted_row_count", train.size()}}}});
  }
  for (const auto& row : rows) require(std::isfinite(row.cv_prediction), "missing outer CV prediction");

  std::map<std::string, std::vector<std::size_t>> contexts;
  for (std::size_t i = 0; i < rows.size(); ++i) contexts[rows[i].context].push_back(i);
  for (const auto& [unused, indices] : contexts) {
    auto ordered = indices;
    std::stable_sort(ordered.begin(), ordered.end(), [&](const auto left, const auto right) {
      if (rows[left].cv_prediction != rows[right].cv_prediction)
        return rows[left].cv_prediction > rows[right].cv_prediction;
      return rows[left].block_id < rows[right].block_id;
    });
    for (std::size_t begin = 0; begin < ordered.size();) {
      std::size_t end = begin + 1U;
      while (end < ordered.size() &&
             rows[ordered[end]].cv_prediction == rows[ordered[begin]].cv_prediction) ++end;
      const auto average_rank =
          (static_cast<double>(begin + 1U) + static_cast<double>(end)) / 2.0;
      for (std::size_t i = begin; i < end; ++i) {
        rows[ordered[i]].cv_prediction_rank = average_rank;
      }
      begin = end;
    }
  }
  std::vector<double> actual, predicted, actual_rank, predicted_rank;
  for (const auto& row : rows) {
    actual.push_back(row.quality);
    predicted.push_back(row.cv_prediction);
    actual_rank.push_back(row.rank_quality);
    predicted_rank.push_back(row.cv_prediction_rank);
  }
  nlohmann::json summary = {
      {"schema_version", kSchemaVersion}, {"phase", "2A_DISCOVERY_ONLY"},
      {"model", "standardized_ridge"}, {"target", "quality_bits"},
      {"outer_fold_count", folds}, {"inner_fold_max", 4U},
      {"group_unit", "prevhash"}, {"lambda_grid", kLambdas},
      {"feature_selection_max", options.selected_feature_count},
      {"normalization_scope", "train_only"},
      {"feature_selection_scope", "train_only"},
      {"inner_cv_normalization_scope", "inner_train_only"},
      {"inner_cv_feature_selection_scope", "inner_train_only"},
      {"inner_cv_lambda_selection_scope", "outer_train_only"},
      {"folds", fold_audits},
      {"metrics", {{"rmse", rmse(actual, predicted)},
                   {"pearson", pearson(actual, predicted)},
                   {"spearman", spearman(actual, predicted)},
                   {"intra_context_rank_spearman",
                    spearman(actual_rank, predicted_rank)}}},
      {"validation_rows_used", 0}, {"holdout_rows_used", 0},
      {"status", "exploratory_cross_validated_on_discovery"}};
  std::ostringstream csv;
  csv << "block_id,prevhash,work_fingerprint,outer_fold,actual_quality_bits,"
         "predicted_quality_bits,actual_rank_quality_bits,predicted_rank_quality_bits\n";
  for (const auto& row : rows) {
    csv << row.block_id << ',' << row.prevhash << ',' << row.context << ','
        << row.outer_fold << ',' << csv_number(row.quality) << ','
        << csv_number(row.cv_prediction) << ',' << csv_number(row.rank_quality)
        << ',' << csv_number(row.cv_prediction_rank) << '\n';
  }
  return {std::move(summary), csv.str()};
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

nlohmann::json permutation_analysis(
    const std::vector<Row>& rows, const std::vector<SchemaEntry>& schema,
    const std::vector<double>& correlations, const Options& options) {
  const auto candidates = top_candidate_features(
      correlations, options.selected_feature_count);
  std::map<std::string, std::vector<std::size_t>> prevhashes, contexts;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    prevhashes[rows[i].prevhash].push_back(i);
    contexts[rows[i].context].push_back(i);
  }
  std::vector<std::vector<std::size_t>> group_indices;
  for (const auto& [unused, indices] : prevhashes) group_indices.push_back(indices);
  const auto y = target(rows, 0U);
  nlohmann::json results = nlohmann::json::array();
  for (const auto feature : candidates) {
    const auto x = column(rows, feature);
    const auto observed = spearman(x, y);
    std::mt19937_64 bootstrap_rng(options.seed ^ (0x9e3779b97f4a7c15ULL + feature));
    std::vector<double> bootstrapped;
    bootstrapped.reserve(options.bootstrap_replicates);
    std::uniform_int_distribution<std::size_t> choose_group(0U, group_indices.size() - 1U);
    for (std::size_t replicate = 0; replicate < options.bootstrap_replicates; ++replicate) {
      std::vector<double> bx, by;
      for (std::size_t draw = 0; draw < group_indices.size(); ++draw) {
        for (const auto index : group_indices[choose_group(bootstrap_rng)]) {
          bx.push_back(x[index]);
          by.push_back(y[index]);
        }
      }
      bootstrapped.push_back(spearman(bx, by));
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
      if (std::abs(spearman(x, permuted)) >= std::abs(observed)) ++as_or_more_extreme;
    }
    results.push_back({
        {"feature", schema[feature].name}, {"category", schema[feature].category},
        {"observed_spearman_quality_bits", observed},
        {"prevhash_bootstrap_ci95", {percentile(bootstrapped, 0.025),
                                     percentile(bootstrapped, 0.975)}},
        {"within_context_permutation_p_value",
         static_cast<double>(as_or_more_extreme + 1U) /
             static_cast<double>(options.permutation_replicates + 1U)},
        {"status", "exploratory_candidate_selected_on_discovery"}});
  }
  return {
      {"schema_version", kSchemaVersion}, {"phase", "2A_DISCOVERY_ONLY"},
      {"seed", options.seed}, {"independent_bootstrap_unit", "prevhash"},
      {"permutation", "quality labels shuffled within each discovery context"},
      {"bootstrap_replicates", options.bootstrap_replicates},
      {"permutation_replicates", options.permutation_replicates},
      {"candidate_selection", "largest absolute discovery Spearman; exploratory and not validated"},
      {"tested_candidate_count", candidates.size()}, {"results", std::move(results)},
      {"validation_rows_used", 0}, {"holdout_rows_used", 0}};
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

TopkArtifacts topk_analysis(const std::vector<Row>& rows,
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
                      "exploratory_candidate_selected_on_discovery"});
  }
  std::vector<double> cv_values;
  for (const auto& row : rows) cv_values.push_back(row.cv_prediction);
  scores.push_back({"grouped_outer_cv_ridge", std::move(cv_values), true,
                    "cross_validated_discovery_prediction"});

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
                            const CvArtifacts& cv,
                            const nlohmann::json& permutation,
                            const TopkArtifacts& topk,
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
         << "## Methods\n\n"
         << "Rounds 0–2 of SHA-256 compression 1, the round-3 fixed boundary, W16/W17, fixed carries, "
            "and exact uniform-nonce carry expectations were reconstructed through the repository's existing "
            "white-box SHA engine. W18 is recorded only as nonce-dependent. Context and prevhash references are "
            "chosen by the minimum `(SHA256(ASCII block_id), block_id)` and never by a label.\n\n"
         << "Pearson, Spearman, and Kendall tau-b are reported separately for each declared target. "
            "Candidate intervals bootstrap whole prevhash groups. Permutations shuffle labels within contexts. "
            "The ridge model uses " << cv.summary.at("outer_fold_count")
         << " outer grouped folds; scaling, feature selection, and lambda choice are fit only inside training data. "
            "Seed: `" << options.seed << "`.\n\n"
         << "Top-k output compares " << topk.score_count
         << " scores, including all four sanity baselines and grouped outer-CV predictions.\n\n"
         << "## Interpretation\n\n"
         << "Every result in this directory is exploratory or discovery-cross-validated. **Nothing in Phase 2A "
            "is validated**, and these artifacts do not establish a SHA weakness or a proven mining advantage. "
            "A recipe must be frozen before a later Phase 2B validation analysis.\n\n"
         << "Permutation candidates tested: " << permutation.at("tested_candidate_count") << ".\n";
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
  std::set<std::string> contexts, prevhashes;
  for (const auto& row : data.rows) {
    contexts.insert(row.context);
    prevhashes.insert(row.prevhash);
  }
  nlohmann::json audit = {
      {"schema_version", kSchemaVersion},
      {"phase", "2A_DISCOVERY_ONLY"},
      {"campaign_id", data.manifest.at("campaign_id")},
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
  std::cout << "Phase 2A statistics: nested grouped cross-validation\n";
  const auto cv = grouped_nested_cv(data.rows, data.schema, options);
  std::cout << "Phase 2A statistics: grouped bootstrap and permutations\n";
  const auto permutation = permutation_analysis(
      data.rows, data.schema, univariate.quality_spearman, options);
  std::cout << "Phase 2A statistics: top-k lift\n";
  const auto topk = topk_analysis(data.rows, data.schema,
                                  univariate.quality_spearman, options);

  nlohmann::json digests_after = nlohmann::json::object();
  for (const auto& path : source_paths) digests_after[path.filename().string()] = file_sha256(path);
  require(digests_after == digests_before, "source campaign changed during Phase 2A");
  audit["source_sha256_after"] = digests_after;
  audit["source_files_unchanged"] = true;
  audit["multiple_testing"] = {
      {"all_univariate_hypotheses_counted", univariate.tested_hypotheses},
      {"permutation_candidate_tests", permutation.at("tested_candidate_count")},
      {"phase2a_validated_results", 0},
      {"interpretation", "exploratory discovery-only"}};
  audit["statistical_configuration"] = {
      {"outer_folds", options.outer_folds},
      {"bootstrap_replicates", options.bootstrap_replicates},
      {"permutation_replicates", options.permutation_replicates},
      {"ridge_lambda_grid", kLambdas},
      {"selected_feature_count", options.selected_feature_count}};
  audit["artifacts"] = {
      "audit.json", "feature_schema.json", "derived_features_discovery.jsonl",
      "univariate_features.csv", "intra_context_rank.csv",
      "per_prevhash_summary.csv", "grouped_cv_predictions.csv",
      "grouped_cv_summary.json", "topk_lift.csv", "permutation_summary.json",
      "report.md"};

  std::filesystem::create_directory(output_directory);
  write_json(output_directory / "feature_schema.json", schema_json(data.schema));
  write_derived_jsonl(output_directory / "derived_features_discovery.jsonl",
                      data.rows);
  write_text(output_directory / "univariate_features.csv", univariate.csv);
  write_text(output_directory / "intra_context_rank.csv", grouped.intra_context_csv);
  write_text(output_directory / "per_prevhash_summary.csv", grouped.per_prevhash_csv);
  write_text(output_directory / "grouped_cv_predictions.csv", cv.predictions_csv);
  write_json(output_directory / "grouped_cv_summary.json", cv.summary);
  write_text(output_directory / "topk_lift.csv", topk.csv);
  write_json(output_directory / "permutation_summary.json", permutation);
  write_text(output_directory / "report.md",
             report_markdown(data, univariate, cv, permutation, topk, options));
  write_json(output_directory / "audit.json", audit);
  std::cout << "Phase 2A total: " << std::fixed << std::setprecision(3)
            << std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - started).count()
            << " seconds\n";
  return audit;
}

}  // namespace srm::research::context_phase2
