//src\mining\mining_controller.cpp
#include "mining/mining_controller.h"

#include "bitcoin/block_header.h"
#include "bitcoin/difficulty.h"
#include "checkpoint/state_store.h"
#include "crypto/reduced_sha256.h"
#include "crypto/sha256d.h"
#include "logging/result_logger.h"
#include "logging/best_pow_tracker.h"
#include "mining/benchmark.h"
#include "mining/cpu_miner.h"
#include "mining/gpu_miner.h"
#include "mining/work_allocator.h"
#include "stratum/stratum_client.h"
#include "telemetry/telemetry.h"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace srm::mining {
namespace {

std::string reverse_hex(std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> reversed(bytes.rbegin(), bytes.rend());
  return crypto::to_hex(reversed);
}

std::string sha256_word_hex(const std::uint32_t value) {
  std::ostringstream output;
  output << std::hex << std::nouppercase << std::setfill('0') << std::setw(8) << value;
  return output.str();
}

nlohmann::json sha256_rounds_json(const std::vector<crypto::Sha256RoundTrace>& rounds) {
  auto result = nlohmann::json::array();
  for (const auto& trace : rounds) {
    result.push_back({
        {"compression", trace.compression_index},
        {"round", trace.round_index + 1U},
        {"w", sha256_word_hex(trace.w)},
        {"sum0", sha256_word_hex(trace.sum0)},
        {"sum1", sha256_word_hex(trace.sum1)},
        {"choice", sha256_word_hex(trace.choice)},
        {"majority", sha256_word_hex(trace.majority)},
        {"temp1", sha256_word_hex(trace.temp1)},
        {"temp2", sha256_word_hex(trace.temp2)},
        {"before", {
            {"a", sha256_word_hex(trace.a_before)}, {"b", sha256_word_hex(trace.b_before)},
            {"c", sha256_word_hex(trace.c_before)}, {"d", sha256_word_hex(trace.d_before)},
            {"e", sha256_word_hex(trace.e_before)}, {"f", sha256_word_hex(trace.f_before)},
            {"g", sha256_word_hex(trace.g_before)}, {"h", sha256_word_hex(trace.h_before)}}},
        {"after", {
            {"a", sha256_word_hex(trace.a_after)}, {"b", sha256_word_hex(trace.b_after)},
            {"c", sha256_word_hex(trace.c_after)}, {"d", sha256_word_hex(trace.d_after)},
            {"e", sha256_word_hex(trace.e_after)}, {"f", sha256_word_hex(trace.f_after)},
            {"g", sha256_word_hex(trace.g_after)}, {"h", sha256_word_hex(trace.h_after)}}},
    });
  }
  return result;
}

using ResearchState = std::array<std::uint32_t, 8>;
using ResearchBlock = std::array<std::uint8_t, 64>;

constexpr std::array<const char*, 8> kResearchRegisters{
    "a", "b", "c", "d", "e", "f", "g", "h"};

struct ResearchNonceSelection {
  std::uint32_t nonce;
  nlohmann::json labels;
};

struct ResearchTraceRecord {
  std::uint32_t nonce;
  nlohmann::json labels;
  bitcoin::Header header;
  crypto::ReducedSha256dTrace trace;
  nlohmann::json trajectory;
};

void require_research(const bool condition, const std::string& detail) {
  if (!condition) throw std::runtime_error("research trace analysis failed: " + detail);
}

std::uint32_t read_research_be32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
         (static_cast<std::uint32_t>(bytes[1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2]) << 8U) |
         static_cast<std::uint32_t>(bytes[3]);
}

ResearchState research_before_state(const crypto::Sha256RoundTrace& trace) {
  return {trace.a_before, trace.b_before, trace.c_before, trace.d_before,
          trace.e_before, trace.f_before, trace.g_before, trace.h_before};
}

ResearchState research_after_state(const crypto::Sha256RoundTrace& trace) {
  return {trace.a_after, trace.b_after, trace.c_after, trace.d_after,
          trace.e_after, trace.f_after, trace.g_after, trace.h_after};
}

nlohmann::json research_state_json(const ResearchState& state) {
  auto value = nlohmann::json::object();
  for (std::size_t i = 0; i < state.size(); ++i) {
    value[kResearchRegisters[i]] = sha256_word_hex(state[i]);
  }
  return value;
}

ResearchState research_digest_words(const crypto::Digest& digest) {
  ResearchState words{};
  for (std::size_t i = 0; i < words.size(); ++i) {
    words[i] = read_research_be32(digest.data() + i * 4U);
  }
  return words;
}

unsigned research_word_hamming(const std::uint32_t left, const std::uint32_t right) {
  return std::popcount(left ^ right);
}

unsigned research_state_hamming(const ResearchState& left, const ResearchState& right) {
  unsigned total = 0;
  for (std::size_t i = 0; i < left.size(); ++i) total += research_word_hamming(left[i], right[i]);
  return total;
}

bool research_round_equal(const crypto::Sha256RoundTrace& left,
                          const crypto::Sha256RoundTrace& right) {
  return left.compression_index == right.compression_index && left.round_index == right.round_index &&
         left.w == right.w && left.sum0 == right.sum0 && left.sum1 == right.sum1 &&
         left.choice == right.choice && left.majority == right.majority &&
         left.temp1 == right.temp1 && left.temp2 == right.temp2 &&
         research_before_state(left) == research_before_state(right) &&
         research_after_state(left) == research_after_state(right);
}

ResearchBlock research_final_block(const std::span<const std::uint8_t> message,
                                   const std::size_t offset) {
  require_research(offset <= message.size(), "invalid SHA-256 padding offset");
  const auto remainder = message.size() - offset;
  require_research(remainder < 56U, "analysis expects a single final SHA-256 padding block");
  ResearchBlock block{};
  std::copy(message.begin() + static_cast<std::ptrdiff_t>(offset), message.end(), block.begin());
  block[remainder] = 0x80U;
  const auto bit_length = static_cast<std::uint64_t>(message.size()) * 8U;
  for (unsigned i = 0; i < 8; ++i) {
    block[block.size() - 1U - i] = static_cast<std::uint8_t>(bit_length >> (i * 8U));
  }
  return block;
}

nlohmann::json research_addition_json(
    const std::vector<std::pair<std::string, std::uint32_t>>& operands,
    const std::uint32_t expected,
    const std::string& context) {
  require_research(!operands.empty(), context + ": addition has no operands");
  std::uint64_t carry = 0;
  std::uint32_t reconstructed = 0;
  std::uint32_t nonzero_mask = 0;
  unsigned nonzero_count = 0;
  unsigned longest_run = 0;
  unsigned current_run = 0;
  std::uint64_t max_carry = 0;
  for (unsigned bit = 0; bit < 32; ++bit) {
    std::uint64_t column_total = carry;
    for (const auto& operand : operands) column_total += (operand.second >> bit) & 1U;
    if ((column_total & 1U) != 0) reconstructed |= std::uint32_t{1} << bit;
    carry = column_total >> 1U;
    max_carry = std::max(max_carry, carry);
    if (carry != 0) {
      nonzero_mask |= std::uint32_t{1} << bit;
      ++nonzero_count;
      longest_run = std::max(longest_run, ++current_run);
    } else {
      current_run = 0;
    }
  }
  require_research(reconstructed == expected,
                   context + ": reconstructed modular sum differs from expected result");

  auto operand_json = nlohmann::json::array();
  for (const auto& operand : operands) {
    operand_json.push_back({{"name", operand.first}, {"value", sha256_word_hex(operand.second)}});
  }
  return {
      {"operands", std::move(operand_json)},
      {"carry_summary", {
          {"model", "order_independent_bit_column_sum"},
          {"nonzero_carry_mask_hex", sha256_word_hex(nonzero_mask)},
          {"nonzero_carry_count", nonzero_count},
          {"longest_nonzero_carry_run", longest_run},
          {"max_carry_value", max_carry},
          {"final_carry_value", carry}}},
      {"result", sha256_word_hex(expected)}};
}

nlohmann::json research_schedule_json(
    const ResearchBlock& block,
    const std::span<const crypto::Sha256RoundTrace> rounds,
    const std::string& context) {
  require_research(rounds.size() == 64U, context + ": message schedule requires exactly 64 traced rounds");
  std::array<std::uint32_t, 64> schedule{};
  auto entries = nlohmann::json::array();
  for (std::size_t t = 0; t < 16; ++t) {
    schedule[t] = read_research_be32(block.data() + t * 4U);
    require_research(schedule[t] == rounds[t].w,
                     context + ": direct message word W" + std::to_string(t) + " differs from trace.w");
    entries.push_back({
        {"t", t}, {"round", t + 1U}, {"source", "message_block"},
        {"w", sha256_word_hex(schedule[t])}});
  }
  for (std::size_t t = 16; t < schedule.size(); ++t) {
    const auto w_t_minus_2 = schedule[t - 2U];
    const auto w_t_minus_7 = schedule[t - 7U];
    const auto w_t_minus_15 = schedule[t - 15U];
    const auto w_t_minus_16 = schedule[t - 16U];
    const auto rotr17 = std::rotr(w_t_minus_2, 17);
    const auto rotr19 = std::rotr(w_t_minus_2, 19);
    const auto shr10 = w_t_minus_2 >> 10U;
    const auto small_sigma1 = rotr17 ^ rotr19 ^ shr10;
    const auto rotr7 = std::rotr(w_t_minus_15, 7);
    const auto rotr18 = std::rotr(w_t_minus_15, 18);
    const auto shr3 = w_t_minus_15 >> 3U;
    const auto small_sigma0 = rotr7 ^ rotr18 ^ shr3;
    schedule[t] = small_sigma1 + w_t_minus_7 + small_sigma0 + w_t_minus_16;
    require_research(schedule[t] == rounds[t].w,
                     context + ": reconstructed extended word W" + std::to_string(t) + " differs from trace.w");
    entries.push_back({
        {"t", t}, {"round", t + 1U}, {"source", "extended_schedule"},
        {"w_t_minus_2", sha256_word_hex(w_t_minus_2)},
        {"w_t_minus_7", sha256_word_hex(w_t_minus_7)},
        {"w_t_minus_15", sha256_word_hex(w_t_minus_15)},
        {"w_t_minus_16", sha256_word_hex(w_t_minus_16)},
        {"rotr17_w_t_minus_2", sha256_word_hex(rotr17)},
        {"rotr19_w_t_minus_2", sha256_word_hex(rotr19)},
        {"shr10_w_t_minus_2", sha256_word_hex(shr10)},
        {"small_sigma1", sha256_word_hex(small_sigma1)},
        {"rotr7_w_t_minus_15", sha256_word_hex(rotr7)},
        {"rotr18_w_t_minus_15", sha256_word_hex(rotr18)},
        {"shr3_w_t_minus_15", sha256_word_hex(shr3)},
        {"small_sigma0", sha256_word_hex(small_sigma0)},
        {"result_w", sha256_word_hex(schedule[t])}});
  }
  return {
      {"block_hex", crypto::to_hex(block)},
      {"word_count", entries.size()},
      {"extended_schedule_validated", true},
      {"words", std::move(entries)}};
}

nlohmann::json research_round_json(
    const crypto::Sha256RoundTrace& trace,
    const unsigned sha,
    std::array<std::uint32_t, 64>& derived_constants,
    const bool establish_constants,
    const std::string& context) {
  const auto rotr2_a = std::rotr(trace.a_before, 2);
  const auto rotr13_a = std::rotr(trace.a_before, 13);
  const auto rotr22_a = std::rotr(trace.a_before, 22);
  const auto reconstructed_sum0 = rotr2_a ^ rotr13_a ^ rotr22_a;
  const auto rotr6_e = std::rotr(trace.e_before, 6);
  const auto rotr11_e = std::rotr(trace.e_before, 11);
  const auto rotr25_e = std::rotr(trace.e_before, 25);
  const auto reconstructed_sum1 = rotr6_e ^ rotr11_e ^ rotr25_e;
  const auto reconstructed_choice =
      (trace.e_before & trace.f_before) ^ (~trace.e_before & trace.g_before);
  const auto reconstructed_majority =
      (trace.a_before & trace.b_before) ^ (trace.a_before & trace.c_before) ^
      (trace.b_before & trace.c_before);
  require_research(reconstructed_sum0 == trace.sum0, context + ": Sigma0 mismatch");
  require_research(reconstructed_sum1 == trace.sum1, context + ": Sigma1 mismatch");
  require_research(reconstructed_choice == trace.choice, context + ": choice mismatch");
  require_research(reconstructed_majority == trace.majority, context + ": majority mismatch");

  const auto derived_k = trace.temp1 - trace.h_before - trace.sum1 - trace.choice - trace.w;
  if (establish_constants) {
    derived_constants[trace.round_index] = derived_k;
  } else {
    require_research(derived_constants[trace.round_index] == derived_k,
                     context + ": derived K differs from the value established by the first compression");
  }

  const auto temp1 = research_addition_json(
      {{"h", trace.h_before}, {"sum1", trace.sum1}, {"choice", trace.choice},
       {"derived_k", derived_k}, {"w", trace.w}},
      trace.temp1, context + ": T1");
  const auto temp2 = research_addition_json(
      {{"sum0", trace.sum0}, {"majority", trace.majority}},
      trace.temp2, context + ": T2");
  const auto new_a = research_addition_json(
      {{"temp1", trace.temp1}, {"temp2", trace.temp2}},
      trace.a_after, context + ": new_a");
  const auto new_e = research_addition_json(
      {{"d", trace.d_before}, {"temp1", trace.temp1}},
      trace.e_after, context + ": new_e");

  require_research(trace.b_after == trace.a_before, context + ": new_b transfer mismatch");
  require_research(trace.c_after == trace.b_before, context + ": new_c transfer mismatch");
  require_research(trace.d_after == trace.c_before, context + ": new_d transfer mismatch");
  require_research(trace.f_after == trace.e_before, context + ": new_f transfer mismatch");
  require_research(trace.g_after == trace.f_before, context + ": new_g transfer mismatch");
  require_research(trace.h_after == trace.g_before, context + ": new_h transfer mismatch");

  const auto before = research_before_state(trace);
  const auto after = research_after_state(trace);
  auto register_hamming = nlohmann::json::object();
  unsigned total_hamming = 0;
  for (std::size_t i = 0; i < before.size(); ++i) {
    const auto distance = research_word_hamming(before[i], after[i]);
    register_hamming[kResearchRegisters[i]] = distance;
    total_hamming += distance;
  }

  return {
      {"identity", {
          {"sha", sha}, {"compression", trace.compression_index},
          {"round", trace.round_index + 1U}}},
      {"message", {{"w", sha256_word_hex(trace.w)}}},
      {"before", research_state_json(before)},
      {"large_sigma0", {
          {"rotr2_a", sha256_word_hex(rotr2_a)},
          {"rotr13_a", sha256_word_hex(rotr13_a)},
          {"rotr22_a", sha256_word_hex(rotr22_a)},
          {"sum0", sha256_word_hex(trace.sum0)}}},
      {"large_sigma1", {
          {"rotr6_e", sha256_word_hex(rotr6_e)},
          {"rotr11_e", sha256_word_hex(rotr11_e)},
          {"rotr25_e", sha256_word_hex(rotr25_e)},
          {"sum1", sha256_word_hex(trace.sum1)}}},
      {"functions", {
          {"choice", sha256_word_hex(trace.choice)},
          {"majority", sha256_word_hex(trace.majority)}}},
      {"derived_k", sha256_word_hex(derived_k)},
      {"temp1", temp1},
      {"temp2", temp2},
      {"state_construction", {
          {"new_a", new_a},
          {"new_e", new_e},
          {"transfers", {
              {"new_b_from_old_a", sha256_word_hex(trace.b_after)},
              {"new_c_from_old_b", sha256_word_hex(trace.c_after)},
              {"new_d_from_old_c", sha256_word_hex(trace.d_after)},
              {"new_f_from_old_e", sha256_word_hex(trace.f_after)},
              {"new_g_from_old_f", sha256_word_hex(trace.g_after)},
              {"new_h_from_old_g", sha256_word_hex(trace.h_after)}}}}},
      {"after", research_state_json(after)},
      {"before_to_after_hamming", {
          {"description", "descriptive BEFORE-to-AFTER register distance; six registers are algorithmic transfers"},
          {"registers", std::move(register_hamming)},
          {"total", total_hamming}}},
      {"validation", {
          {"primitives", true}, {"temp1", true}, {"temp2", true},
          {"new_a", true}, {"new_e", true}, {"register_transfers", true}}}};
}

nlohmann::json research_compression_json(
    const unsigned sha,
    const unsigned compression,
    const ResearchBlock& block,
    const std::span<const crypto::Sha256RoundTrace> rounds,
    const ResearchState& expected_output,
    std::array<std::uint32_t, 64>& derived_constants,
    const bool establish_constants) {
  const auto context = "SHA" + std::to_string(sha) + "/compression" + std::to_string(compression);
  require_research(rounds.size() == 64U, context + ": expected exactly 64 rounds");
  for (std::size_t i = 0; i < rounds.size(); ++i) {
    require_research(rounds[i].compression_index == compression,
                     context + ": trace compression index mismatch at round " + std::to_string(i + 1U));
    require_research(rounds[i].round_index == i,
                     context + ": trace round index mismatch at round " + std::to_string(i + 1U));
  }
  for (std::size_t i = 0; i + 1U < rounds.size(); ++i) {
    require_research(research_after_state(rounds[i]) == research_before_state(rounds[i + 1U]),
                     context + ": AFTER(round " + std::to_string(i + 1U) +
                         ") differs from BEFORE(round " + std::to_string(i + 2U) + ")");
  }

  const auto input_state = research_before_state(rounds.front());
  const auto final_working_state = research_after_state(rounds.back());
  auto round_json = nlohmann::json::array();
  for (std::size_t i = 0; i < rounds.size(); ++i) {
    round_json.push_back(research_round_json(
        rounds[i], sha, derived_constants, establish_constants,
        context + "/round" + std::to_string(i + 1U)));
  }

  auto feed_forward = nlohmann::json::array();
  for (std::size_t i = 0; i < input_state.size(); ++i) {
    const auto word_context = context + "/feed_forward/word" + std::to_string(i);
    auto addition = research_addition_json(
        {{"input_chaining_word", input_state[i]},
         {"final_working_word", final_working_state[i]}},
        expected_output[i], word_context);
    addition["word_index"] = i;
    addition["register"] = kResearchRegisters[i];
    addition["input_chaining_word"] = sha256_word_hex(input_state[i]);
    addition["final_working_word"] = sha256_word_hex(final_working_state[i]);
    addition["output_chaining_word"] = sha256_word_hex(expected_output[i]);
    feed_forward.push_back(std::move(addition));
  }

  return {
      {"sha", sha},
      {"compression", compression},
      {"input_state", research_state_json(input_state)},
      {"message_schedule", research_schedule_json(block, rounds, context)},
      {"rounds", std::move(round_json)},
      {"final_working_state", research_state_json(final_working_state)},
      {"feed_forward", std::move(feed_forward)},
      {"output_state", research_state_json(expected_output)},
      {"validation", {
          {"round_count", 64}, {"message_schedule", true},
          {"intra_compression_transitions", true}, {"feed_forward", true}}}};
}

std::vector<ResearchNonceSelection> research_nonce_selections(
    const std::uint32_t reference_nonce,
    const config::ResearchTraceAnalysisConfig& analysis) {
  std::map<std::uint32_t, nlohmann::json> selected;
  const auto add = [&](const std::uint32_t nonce, nlohmann::json label) {
    if (nonce == reference_nonce) return;
    auto [item, inserted] = selected.try_emplace(nonce, nlohmann::json::array());
    (void)inserted;
    item->second.push_back(std::move(label));
  };

  if (analysis.single_bit_flips) {
    for (unsigned bit = 0; bit < 32; ++bit) {
      add(reference_nonce ^ (std::uint32_t{1} << bit),
          {{"kind", "single_bit_flip"}, {"bit", bit}});
    }
  }
  for (std::uint64_t delta = 1; delta <= analysis.neighbor_radius; ++delta) {
    const auto reference_wide = static_cast<std::uint64_t>(reference_nonce);
    if (delta <= reference_wide) {
      add(static_cast<std::uint32_t>(reference_wide - delta),
          {{"kind", "neighbor"}, {"delta", -static_cast<std::int64_t>(delta)}});
    }
    if (reference_wide + delta <= std::numeric_limits<std::uint32_t>::max()) {
      add(static_cast<std::uint32_t>(reference_wide + delta),
          {{"kind", "neighbor"}, {"delta", static_cast<std::int64_t>(delta)}});
    }
  }
  for (const auto nonce : analysis.control_nonces) add(nonce, {{"kind", "control"}});

  std::vector<ResearchNonceSelection> result;
  result.reserve(selected.size());
  for (auto& [nonce, labels] : selected) {
    result.push_back({nonce, std::move(labels)});
  }
  return result;
}

ResearchTraceRecord research_trace_record(
    const bitcoin::Header& base_header,
    const std::uint32_t nonce,
    nlohmann::json labels) {
  auto header = base_header;
  bitcoin::set_nonce(header, nonce);
  auto trace = crypto::trace_reduced_sha256d(header, 64);
  require_research(trace.first_sha.rounds.size() == 128U,
                   "nonce " + std::to_string(nonce) + ": first SHA must contain 128 rounds");
  require_research(trace.second_sha.rounds.size() == 64U,
                   "nonce " + std::to_string(nonce) + ": second SHA must contain 64 rounds");
  return {nonce, std::move(labels), header, std::move(trace), nlohmann::json()};
}

void research_annotate_w3_labels(ResearchTraceRecord& record, const std::uint32_t reference_w3) {
  const auto w3 = record.trace.first_sha.rounds.at(64U + 3U).w;
  const auto difference = reference_w3 ^ w3;
  for (auto& label : record.labels) {
    if (label.value("kind", "") != "single_bit_flip") continue;
    const auto distance = research_word_hamming(reference_w3, w3);
    require_research(distance == 1U,
                     "nonce " + std::to_string(record.nonce) +
                         ": single-bit nonce flip did not produce exactly one changed bit in W3");
    label["w3_changed_bit"] = std::countr_zero(difference);
    label["w3_hamming"] = distance;
  }
}

nlohmann::json research_trajectory_json(
    const ResearchTraceRecord& record,
    const std::uint32_t reference_w3) {
  const auto& first_rounds = record.trace.first_sha.rounds;
  const auto& second_rounds = record.trace.second_sha.rounds;
  const std::span<const crypto::Sha256RoundTrace> first_compression(
      first_rounds.data(), 64U);
  const std::span<const crypto::Sha256RoundTrace> first_final_compression(
      first_rounds.data() + 64U, 64U);
  const std::span<const crypto::Sha256RoundTrace> second_compression(
      second_rounds.data(), 64U);

  ResearchBlock first_block{};
  std::copy_n(record.header.begin(), first_block.size(), first_block.begin());
  const auto first_tail = research_final_block(record.header, 64U);
  const auto second_block = research_final_block(record.trace.first_sha.digest, 0U);
  const auto first_compression_output = research_before_state(first_rounds.at(64U));
  const auto first_digest_words = research_digest_words(record.trace.first_sha.digest);
  const auto second_digest_words = research_digest_words(record.trace.second_sha.digest);

  std::array<std::uint32_t, 64> derived_constants{};
  auto first_compressions = nlohmann::json::array();
  first_compressions.push_back(research_compression_json(
      1U, 0U, first_block, first_compression, first_compression_output,
      derived_constants, true));
  first_compressions.push_back(research_compression_json(
      1U, 1U, first_tail, first_final_compression, first_digest_words,
      derived_constants, false));
  auto second_compressions = nlohmann::json::array();
  second_compressions.push_back(research_compression_json(
      2U, 0U, second_block, second_compression, second_digest_words,
      derived_constants, false));

  auto linked_words = nlohmann::json::array();
  for (std::size_t i = 0; i < first_digest_words.size(); ++i) {
    require_research(second_rounds[i].w == first_digest_words[i],
                     "nonce " + std::to_string(record.nonce) +
                         ": first SHA digest does not match second SHA message word W" + std::to_string(i));
    linked_words.push_back({
        {"t", i},
        {"first_sha_digest_word", sha256_word_hex(first_digest_words[i])},
        {"second_sha_message_word", sha256_word_hex(second_rounds[i].w)},
        {"match", true}});
  }

  auto header_bytes = nlohmann::json::array();
  for (std::size_t i = 76; i < 80; ++i) header_bytes.push_back(record.header[i]);
  const auto w3 = first_rounds.at(64U + 3U).w;
  auto w3_changes = nlohmann::json::array();
  for (const auto& label : record.labels) {
    if (label.value("kind", "") == "single_bit_flip") {
      w3_changes.push_back({
          {"nonce_bit", label.at("bit")},
          {"w3_changed_bit", label.at("w3_changed_bit")},
          {"w3_hamming", label.at("w3_hamming")}});
    }
  }
  const auto final_hash = crypto::bitcoin_hash_hex(record.trace.digest);

  return {
      {"nonce", record.nonce},
      {"labels", record.labels},
      {"header_hex", bitcoin::header_hex(record.header)},
      {"nonce_hex", sha256_word_hex(record.nonce)},
      {"nonce_header_bytes", std::move(header_bytes)},
      {"nonce_header_bytes_hex", bitcoin::nonce_header_le_hex(record.header)},
      {"sha1_compression1_w3", sha256_word_hex(w3)},
      {"sha1_compression1_w3_reference", sha256_word_hex(reference_w3)},
      {"single_bit_w3_changes", std::move(w3_changes)},
      {"final_hash", final_hash},
      {"first_sha", {
          {"digest", crypto::digest_hex(record.trace.first_sha.digest)},
          {"digest_format", "sha256_digest_hex"},
          {"compressions", std::move(first_compressions)}}},
      {"first_sha_to_second_sha", {
          {"first_sha_digest", crypto::digest_hex(record.trace.first_sha.digest)},
          {"second_sha_message_prefix_bytes", crypto::to_hex(record.trace.first_sha.digest)},
          {"second_sha_message_block_hex", crypto::to_hex(second_block)},
          {"word_links", std::move(linked_words)},
          {"exact_match", true}}},
      {"second_sha", {
          {"digest", crypto::digest_hex(record.trace.second_sha.digest)},
          {"digest_format", "sha256_digest_hex"},
          {"compressions", std::move(second_compressions)}}},
      {"final", {
          {"first_sha_digest_raw", crypto::digest_hex(record.trace.first_sha.digest)},
          {"second_sha_digest_raw", crypto::digest_hex(record.trace.second_sha.digest)},
          {"bitcoin_display_hash", final_hash}}},
      {"validation", {
          {"total_rounds", 192}, {"compression_count", 3},
          {"message_schedules", true}, {"round_arithmetic", true},
          {"register_transfers", true}, {"intra_compression_transitions", true},
          {"feed_forward", true}, {"first_sha_to_second_sha", true}}}};
}

nlohmann::json research_state_diff_json(
    const ResearchState& reference,
    const ResearchState& candidate,
    const bool include_ratio) {
  auto result = nlohmann::json::object();
  unsigned total = 0;
  for (std::size_t i = 0; i < reference.size(); ++i) {
    const auto distance = research_word_hamming(reference[i], candidate[i]);
    result[kResearchRegisters[i]] = distance;
    total += distance;
  }
  result["total_hamming"] = total;
  if (include_ratio) result["diffusion_ratio"] = static_cast<double>(total) / 256.0;
  return result;
}

nlohmann::json research_round_position(const unsigned sha,
                                       const unsigned compression,
                                       const unsigned round) {
  return {{"sha", sha}, {"compression", compression}, {"round", round}};
}

nlohmann::json research_diffusion_json(
    const ResearchTraceRecord& reference,
    const ResearchTraceRecord& candidate) {
  require_research(candidate.trace.first_sha.rounds.size() == reference.trace.first_sha.rounds.size() &&
                       candidate.trace.second_sha.rounds.size() == reference.trace.second_sha.rounds.size(),
                   "nonce " + std::to_string(candidate.nonce) + ": candidate/reference trace sizes differ");
  for (std::size_t i = 0; i < 64U; ++i) {
    require_research(research_round_equal(reference.trace.first_sha.rounds[i],
                                          candidate.trace.first_sha.rounds[i]),
                     "nonce " + std::to_string(candidate.nonce) +
                         ": SHA1/compression0 differs at round " + std::to_string(i + 1U));
  }
  for (std::size_t i = 64U; i < 67U; ++i) {
    require_research(research_round_equal(reference.trace.first_sha.rounds[i],
                                          candidate.trace.first_sha.rounds[i]),
                     "nonce " + std::to_string(candidate.nonce) +
                         ": SHA1/compression1 round " + std::to_string(i - 63U) + " must be identical");
  }

  auto first_w_difference = nlohmann::json(nullptr);
  auto first_temp1_difference = nlohmann::json(nullptr);
  auto first_after_state_difference = nlohmann::json(nullptr);
  auto first_before_state_difference = nlohmann::json(nullptr);
  auto first_non_w_primitive_difference = nlohmann::json(nullptr);
  auto round_differences = nlohmann::json::array();

  const auto compare_round = [&](const crypto::Sha256RoundTrace& reference_round,
                                 const crypto::Sha256RoundTrace& candidate_round,
                                 const unsigned sha) {
    const auto compression = reference_round.compression_index;
    const auto human_round = reference_round.round_index + 1U;
    const auto position = research_round_position(sha, compression, human_round);
    const auto reference_before = research_before_state(reference_round);
    const auto candidate_before = research_before_state(candidate_round);
    const auto reference_after = research_after_state(reference_round);
    const auto candidate_after = research_after_state(candidate_round);
    const auto before_total = research_state_hamming(reference_before, candidate_before);
    const auto after_total = research_state_hamming(reference_after, candidate_after);
    if (first_w_difference.is_null() && reference_round.w != candidate_round.w) first_w_difference = position;
    if (first_temp1_difference.is_null() && reference_round.temp1 != candidate_round.temp1) {
      first_temp1_difference = position;
    }
    if (first_after_state_difference.is_null() && after_total != 0U) first_after_state_difference = position;
    if (first_before_state_difference.is_null() && before_total != 0U) first_before_state_difference = position;
    if (first_non_w_primitive_difference.is_null() &&
        (reference_round.sum0 != candidate_round.sum0 || reference_round.sum1 != candidate_round.sum1 ||
         reference_round.choice != candidate_round.choice ||
         reference_round.majority != candidate_round.majority ||
         reference_round.temp2 != candidate_round.temp2)) {
      first_non_w_primitive_difference = position;
    }

    round_differences.push_back({
        {"sha", sha}, {"compression", compression}, {"round", human_round},
        {"w_hamming", research_word_hamming(reference_round.w, candidate_round.w)},
        {"rotr2_a_hamming", research_word_hamming(
            std::rotr(reference_round.a_before, 2), std::rotr(candidate_round.a_before, 2))},
        {"rotr13_a_hamming", research_word_hamming(
            std::rotr(reference_round.a_before, 13), std::rotr(candidate_round.a_before, 13))},
        {"rotr22_a_hamming", research_word_hamming(
            std::rotr(reference_round.a_before, 22), std::rotr(candidate_round.a_before, 22))},
        {"sum0_hamming", research_word_hamming(reference_round.sum0, candidate_round.sum0)},
        {"rotr6_e_hamming", research_word_hamming(
            std::rotr(reference_round.e_before, 6), std::rotr(candidate_round.e_before, 6))},
        {"rotr11_e_hamming", research_word_hamming(
            std::rotr(reference_round.e_before, 11), std::rotr(candidate_round.e_before, 11))},
        {"rotr25_e_hamming", research_word_hamming(
            std::rotr(reference_round.e_before, 25), std::rotr(candidate_round.e_before, 25))},
        {"sum1_hamming", research_word_hamming(reference_round.sum1, candidate_round.sum1)},
        {"choice_hamming", research_word_hamming(reference_round.choice, candidate_round.choice)},
        {"majority_hamming", research_word_hamming(reference_round.majority, candidate_round.majority)},
        {"temp1_hamming", research_word_hamming(reference_round.temp1, candidate_round.temp1)},
        {"temp2_hamming", research_word_hamming(reference_round.temp2, candidate_round.temp2)},
        {"before", research_state_diff_json(reference_before, candidate_before, false)},
        {"after", research_state_diff_json(reference_after, candidate_after, true)}});
  };

  for (std::size_t i = 0; i < reference.trace.first_sha.rounds.size(); ++i) {
    compare_round(reference.trace.first_sha.rounds[i], candidate.trace.first_sha.rounds[i], 1U);
  }
  for (std::size_t i = 0; i < reference.trace.second_sha.rounds.size(); ++i) {
    compare_round(reference.trace.second_sha.rounds[i], candidate.trace.second_sha.rounds[i], 2U);
  }

  const auto expected_first_w = research_round_position(1U, 1U, 4U);
  require_research(first_w_difference == expected_first_w,
                   "nonce " + std::to_string(candidate.nonce) +
                       ": first W difference must be SHA1/compression1/round4");
  return {
      {"nonce", candidate.nonce},
      {"labels", candidate.labels},
      {"final_hash", crypto::bitcoin_hash_hex(candidate.trace.digest)},
      {"final_digest_hamming", crypto::hamming_distance(reference.trace.digest, candidate.trace.digest)},
      {"first_w_difference", std::move(first_w_difference)},
      {"first_temp1_difference", std::move(first_temp1_difference)},
      {"first_after_state_difference", std::move(first_after_state_difference)},
      {"first_before_state_difference", std::move(first_before_state_difference)},
      {"first_non_w_primitive_difference", std::move(first_non_w_primitive_difference)},
      {"rounds", std::move(round_differences)},
      {"validation", {
          {"round_count", 192}, {"sha1_compression0_identical", true},
          {"sha1_compression1_rounds_1_to_3_identical", true},
          {"first_w_difference_is_round_4", true}}}};
}

struct ResearchAnalysisReports {
  nlohmann::json trajectories;
  nlohmann::json diffusion;
  std::size_t candidate_count;
  std::size_t trajectory_count;
};

ResearchAnalysisReports research_analysis_reports(
    const bitcoin::Header& reference_header,
    const crypto::ReducedSha256dTrace& reference_trace,
    const std::string& header_id,
    const std::uint32_t reference_nonce,
    const config::ResearchTraceAnalysisConfig& analysis) {
  constexpr auto genesis_hash =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
  require_research(crypto::bitcoin_hash_hex(reference_trace.digest) == genesis_hash,
                   "reference nonce does not produce the exact Bitcoin Genesis hash");
  require_research(reference_trace.first_sha.rounds.size() == 128U &&
                       reference_trace.second_sha.rounds.size() == 64U,
                   "reference trace must contain exactly 192 rounds in three compressions");

  ResearchTraceRecord reference{
      reference_nonce,
      nlohmann::json::array({{{"kind", "reference"}}}),
      reference_header,
      reference_trace,
      nlohmann::json()};
  const auto reference_w3 = reference.trace.first_sha.rounds.at(64U + 3U).w;
  reference.trajectory = research_trajectory_json(reference, reference_w3);

  const auto selections = research_nonce_selections(reference_nonce, analysis);
  std::vector<ResearchTraceRecord> candidates;
  candidates.reserve(selections.size());
  std::optional<std::uint32_t> previous_nonce;
  bool multiple_labels_preserved = false;
  for (const auto& selection : selections) {
    require_research(selection.nonce != reference_nonce,
                     "reference nonce was incorrectly retained as a candidate");
    if (previous_nonce) {
      require_research(*previous_nonce < selection.nonce,
                       "candidate nonce set is not strictly unique");
    }
    previous_nonce = selection.nonce;
    multiple_labels_preserved = multiple_labels_preserved || selection.labels.size() > 1U;
    auto record = research_trace_record(reference_header, selection.nonce, selection.labels);
    research_annotate_w3_labels(record, reference_w3);
    record.trajectory = research_trajectory_json(record, reference_w3);
    candidates.push_back(std::move(record));
  }

  auto comparisons = nlohmann::json::array();
  for (const auto& candidate : candidates) {
    comparisons.push_back(research_diffusion_json(reference, candidate));
  }

  const auto metadata = nlohmann::json{
      {"carry_model", "order_independent_bit_column_sum"},
      {"word_value_format", "lowercase_8_digit_hex_without_prefix"},
      {"round_numbering", "human_1_to_64"},
      {"rounds_per_compression", 64},
      {"compressions_per_sha", {{"first_sha", 2}, {"second_sha", 1}}},
      {"full_trajectories_saved", analysis.save_full_trajectories},
      {"single_bit_flips", analysis.single_bit_flips},
      {"neighbor_radius", analysis.neighbor_radius},
      {"control_nonce_count", analysis.control_nonces.size()}};
  const auto validation = nlohmann::json{
      {"candidate_nonces_unique", true},
      {"reference_excluded_from_candidates", true},
      {"multiple_labels_preserved", multiple_labels_preserved},
      {"rounds_per_trajectory", 192},
      {"compressions_per_trajectory", 3},
      {"message_schedule_words_per_compression", 64},
      {"extended_schedules", true},
      {"round_arithmetic", true},
      {"register_transfers", true},
      {"intra_compression_transitions", true},
      {"feed_forward", true},
      {"first_sha_to_second_sha", true},
      {"sha1_compression0_identical", true},
      {"sha1_compression1_rounds_1_to_3_identical", true},
      {"first_w_difference_is_sha1_compression1_round4", true},
      {"single_bit_flip_w3_hamming_is_one", true},
      {"reference_genesis_hash", true}};

  nlohmann::json trajectories_report = nullptr;
  if (analysis.save_full_trajectories) {
    auto trajectories = nlohmann::json::array();
    trajectories.push_back(std::move(reference.trajectory));
    for (auto& candidate : candidates) trajectories.push_back(std::move(candidate.trajectory));
    trajectories_report = {
        {"schema_version", 1},
        {"mode", "research_trace_analysis"},
        {"axis", "intrinsic_causal_trajectory"},
        {"header_id", header_id},
        {"reference_nonce", reference_nonce},
        {"candidate_count", candidates.size()},
        {"trajectory_count", trajectories.size()},
        {"carry_model", "order_independent_bit_column_sum"},
        {"metadata", metadata},
        {"validation", validation},
        {"trajectories", std::move(trajectories)}};
  }

  nlohmann::json diffusion_report = {
      {"schema_version", 1},
      {"mode", "research_trace_analysis"},
      {"axis", "nonce_diffusion_against_reference"},
      {"header_id", header_id},
      {"reference_nonce", reference_nonce},
      {"reference_hash", crypto::bitcoin_hash_hex(reference.trace.digest)},
      {"candidate_count", candidates.size()},
      {"metadata", metadata},
      {"validation", validation},
      {"comparisons", std::move(comparisons)}};
  return {std::move(trajectories_report), std::move(diffusion_report),
          candidates.size(), candidates.size() + 1U};
}

std::string live_work_fingerprint(
    const stratum::StratumJob& job,
    const std::string& extranonce1,
    const unsigned extranonce2_size) {
  nlohmann::json value = {
      {"job_id", job.job_id},
      {"prevhash", job.prevhash},
      {"coinbase1", job.coinbase1},
      {"coinbase2", job.coinbase2},
      {"merkle_branches", job.merkle_branches},
      {"version", job.version},
      {"nbits", job.nbits},
      {"ntime", job.ntime},
      {"extranonce1", extranonce1},
      {"extranonce2_size", extranonce2_size},
  };

  const auto serialized = value.dump();

  return crypto::digest_hex(
      crypto::sha256(
          std::span<const std::uint8_t>(
              reinterpret_cast<const std::uint8_t*>(serialized.data()),
              serialized.size())));
}

std::string allocator_state_name(const config::Mode mode) {
  if (mode == config::Mode::Live) return "live_state.json";
  if (mode == config::Mode::HistoricalTest) return "historical_state.json";
  if (mode == config::Mode::MockStratum) return "mock_state.json";
  if (mode == config::Mode::Benchmark) return "benchmark_state.json";
  return "research_state.json";
}

}  // namespace

struct MiningController::Impl {
  config::AppConfig config;
  telemetry::Telemetry telemetry;
  logging::ResultLogger logger;
  logging::BestPowTracker best_pow;
  WorkAllocator allocator;
  std::atomic<std::uint64_t> active_generation{0};
  std::unique_ptr<CpuMiner> cpu;
  std::unique_ptr<GpuMiner> gpu;
  std::unique_ptr<stratum::StratumClient> client;
  std::mutex control_mutex;
  std::mutex submissions_mutex;
  std::map<std::int64_t, Solution> pending_submissions;
  std::string extranonce1;
  unsigned extranonce2_size{0};
  bool subscribed{false};
  bool authorized{false};
  double share_difficulty{1.0};
  std::optional<stratum::StratumJob> pending_job;
  std::string previous_prevhash;
  std::chrono::steady_clock::time_point started{std::chrono::steady_clock::now()};
  std::uint64_t prior_uptime_ms{0};

  explicit Impl(config::AppConfig value)
      : config(std::move(value)), telemetry(config.console.refresh_ms),
        logger(config.logging.directory, config.logging.save_session_log,
               config.logging.save_block_candidates, config.logging.save_share_audits,
               config.logging.share_audit_retention_hours,
               config.logging.permanent_high_difficulty_threshold),
        best_pow(config.logging.directory),
        allocator(checkpoint::StateStore(config.project_root / "state" / allocator_state_name(config.mode)),
                  config::mode_name(config.mode)) {
    const auto saved = allocator.snapshot();
    prior_uptime_ms = saved.value("uptime_ms", 0ULL);
    const auto counters = saved.value("counters", nlohmann::json::object());
    telemetry.cpu_hashes.store(counters.value("cpu_hashes", 0ULL));
    telemetry.gpu_hashes.store(counters.value("gpu_hashes", 0ULL));
    telemetry.shares.store(counters.value("shares", 0ULL));
    telemetry.accepted.store(counters.value("accepted", 0ULL));
    telemetry.rejected.store(counters.value("rejected", 0ULL));
    telemetry.stale_jobs.store(counters.value("stale_jobs", 0ULL));
    telemetry.headers_complete.store(counters.value("headers_complete", 0ULL));
    const auto best = saved.value("best_hash", "");
    if (!best.empty()) telemetry.observe_best(best);
  }

  void event(const std::string& text) {
    telemetry.event(text);
    logger.event(text);
  }

  nlohmann::json counters_json() const {
    return {
        {"counters", {
            {"hashes", telemetry.cpu_hashes.load() + telemetry.gpu_hashes.load()},
            {"cpu_hashes", telemetry.cpu_hashes.load()}, {"gpu_hashes", telemetry.gpu_hashes.load()},
            {"shares", telemetry.shares.load()}, {"accepted", telemetry.accepted.load()},
            {"rejected", telemetry.rejected.load()}, {"stale_jobs", telemetry.stale_jobs.load()},
            {"headers_complete", telemetry.headers_complete.load()}}},
        {"uptime_ms", prior_uptime_ms + static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count())}};
  }

  void safe_checkpoint(const std::string& context) {
    try {
      allocator.checkpoint(counters_json());
    } catch (const checkpoint::PersistenceError& error) {
      event("[CHECKPOINT] " + context + ": " + error.what());
    }
  }

  Solution make_solution(const Candidate& candidate) {
    if (bitcoin::get_nonce(candidate.header) != candidate.nonce) {
      throw std::logic_error("candidate nonce differs from serialized header nonce");
    }
    Solution solution;
    solution.job_id = candidate.context.job.job_id;
    solution.username = config.ckpool.username;
    solution.extranonce1 = candidate.context.extranonce1;
    solution.extranonce2 = candidate.extranonce2;
    solution.extranonce2_size = candidate.context.extranonce2_size;
    solution.clean_jobs = candidate.context.job.clean_jobs;
    solution.coinbase1 = candidate.context.job.coinbase1;
    solution.coinbase2 = candidate.context.job.coinbase2;
    solution.merkle_branches = candidate.context.job.merkle_branches;
    solution.work_fingerprint = candidate.context.work_fingerprint;
    solution.version = candidate.context.job.version;
    solution.prevhash = candidate.context.job.prevhash;
    solution.merkle_root = crypto::bitcoin_hash_hex(candidate.merkle_root);
    solution.ntime = candidate.context.job.ntime;
    solution.nbits = candidate.context.job.nbits;
    solution.nonce_value = candidate.nonce;
    solution.nonce = bitcoin::stratum_nonce_hex(candidate.nonce);
    solution.nonce_header_le = bitcoin::nonce_header_le_hex(candidate.header);
    solution.header_hex = bitcoin::header_hex(candidate.header);
    solution.hash = crypto::bitcoin_hash_hex(candidate.digest);
    solution.network_target = bitcoin::target_hex(candidate.context.network_target);
    solution.share_target = bitcoin::target_hex(candidate.context.share_target);
    solution.share_difficulty = candidate.context.share_difficulty;
    solution.hash_difficulty = bitcoin::difficulty_from_hash(candidate.digest);
    solution.network_difficulty = bitcoin::difficulty_from_target(candidate.context.network_target);
    solution.network_difficulty_ratio = solution.network_difficulty > 0.0
        ? solution.hash_difficulty / solution.network_difficulty : 0.0;
    solution.worker = candidate.worker;
    solution.detected_timestamp_utc = logging::ResultLogger::utc_now();
    solution.network_candidate = candidate.network_candidate;
    solution.share_candidate = candidate.share_candidate;
    return solution;
  }

  void on_candidate(Candidate candidate) {
    const bool active = candidate.context.generation ==
        active_generation.load(std::memory_order_acquire);
    auto solution = make_solution(candidate);
    telemetry.observe_best(solution.hash);
    const auto total_hashes = telemetry.cpu_hashes.load(std::memory_order_relaxed) +
                              telemetry.gpu_hashes.load(std::memory_order_relaxed) + 1U;
    const auto uptime_ms = prior_uptime_ms + static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
    logging::BestPowUpdate record;
    try {
      record = best_pow.observe(solution, total_hashes, uptime_ms);
    } catch (const std::exception& error) {
      event("[RECORD POW] persistance impossible: " + std::string(error.what()));
    }
    if (record.is_record) {
      event("[RECORD POW] nouveau record hash=" + solution.hash +
            " difficulté=" + std::to_string(solution.hash_difficulty) +
            " worker=" + solution.worker);
      try { logger.save_permanent_event(solution, "personal_record"); }
      catch (const checkpoint::PersistenceError& error) {
        event("[RECORD POW] historique permanent non sauvegardé: " + std::string(error.what()));
      }
    }
    if (!active) return;  // local PoW remains recorded; stale Stratum work is never submitted
    if (!solution.share_candidate && !solution.network_candidate) return;

    telemetry.shares.fetch_add(1, std::memory_order_relaxed);
    if (solution.network_candidate || record.is_record ||
        solution.hash_difficulty >= config.console.high_difficulty_threshold) {
      event("[SHARE] trouvée hash=" + solution.hash +
            " difficulté=" + std::to_string(solution.hash_difficulty) +
            " nonce_stratum=" + solution.nonce +
            " nonce_header_le=" + solution.nonce_header_le);
    }
    if (solution.network_candidate) {
      event("[BLOCK] candidat réseau détecté");
    }
    if (!record.is_record && (solution.network_candidate ||
        solution.hash_difficulty >= config.logging.permanent_high_difficulty_threshold)) {
      try {
        logger.save_permanent_event(
            solution, solution.network_candidate ? "network_candidate" : "high_difficulty_share");
      } catch (const checkpoint::PersistenceError& error) {
        event("[SHARE] historique permanent non sauvegardé: " + std::string(error.what()));
      }
    }

    const bool can_submit = client && client->connected() && client->authorized();
    if (can_submit) {
      solution.submitted_timestamp_utc = logging::ResultLogger::utc_now();
      solution.submission_status = "pending";
    } else {
      solution.submission_status = "not_submitted";
      solution.local_submission_error = "CKPool connection inactive";
    }

    if (solution.network_candidate) {
      try {
        logger.save_candidate(solution);  // critical artifact, durable before the secondary audit
      } catch (const checkpoint::PersistenceError& error) {
        solution.submission_status = "local_error";
        solution.local_submission_error =
            std::string("durable block_candidate pre-submit save failed: ") + error.what();
        event("[BLOCK] soumission annulée: sauvegarde durable du block_candidate impossible: " +
              std::string(error.what()));
        try { logger.update_candidate(solution); }
        catch (const checkpoint::PersistenceError&) { solution.result_file.clear(); }
        try { logger.save_share_audit(solution); }
        catch (const checkpoint::PersistenceError& audit_error) {
          solution.share_audit_file.clear();
          event("[SHARE] audit d'erreur non sauvegardé après échec du block_candidate: " +
                std::string(audit_error.what()));
        }
        return;
      }
      try {
        logger.save_share_audit(solution);
      } catch (const checkpoint::PersistenceError& error) {
        solution.share_audit_file.clear();
        event("[BLOCK] avertissement: share_audit non sauvegardé; block_candidate durable conservé: " +
              std::string(error.what()));
      }
    } else {
      try {
        logger.save_share_audit(solution);  // ordinary share remains durable before submission
      } catch (const checkpoint::PersistenceError& error) {
        solution.submission_status = "local_error";
        solution.local_submission_error =
            std::string("durable share_audit pre-submit save failed: ") + error.what();
        try { logger.update_share_audit(solution); }
        catch (const checkpoint::PersistenceError&) { solution.share_audit_file.clear(); }
        event("[SHARE] soumission annulée: sauvegarde durable du share_audit impossible: " +
              std::string(error.what()));
        return;
      }
    }

    if (!can_submit) {
      event("[SHARE] non soumise: connexion CKPool inactive");
      return;
    }
    if (solution.network_candidate) event("[BLOCK] soumission immédiate");

    try {
      std::scoped_lock lock(submissions_mutex);
      const auto id = client->submit(solution.username, solution.job_id, solution.extranonce2, solution.ntime, solution.nonce);
      solution.submission_id = id;
      const auto [item, inserted] = pending_submissions.emplace(id, std::move(solution));
      if (!inserted) throw std::logic_error("duplicate Stratum submission id");
      if (item->second.network_candidate) {
        try { logger.update_candidate(item->second); }
        catch (const checkpoint::PersistenceError& error) {
          event("[BLOCK] candidat non mis à jour après envoi: " + std::string(error.what()));
        }
      }
      if (!item->second.share_audit_file.empty()) {
        try { logger.update_share_audit(item->second); }
        catch (const checkpoint::PersistenceError& error) {
          event("[SHARE] audit non mis à jour après envoi: " + std::string(error.what()));
        }
      }
    } catch (const std::exception& error) {
      solution.submission_status = "local_error";
      solution.local_submission_error = std::string("local submission error: ") + error.what();
      if (solution.network_candidate) {
        try { logger.update_candidate(solution); }
        catch (const checkpoint::PersistenceError& persistence_error) {
          event("[BLOCK] erreur locale non sauvegardée: " + std::string(persistence_error.what()));
        }
      }
      if (!solution.share_audit_file.empty()) {
        try { logger.update_share_audit(solution); }
        catch (const checkpoint::PersistenceError& persistence_error) {
          event("[SHARE] audit d'erreur non sauvegardé: " + std::string(persistence_error.what()));
        }
      }
      event("[SHARE] erreur de soumission: " + std::string(error.what()));
    }
  }

  void stop_workers() {
    if (cpu) cpu->stop();
    if (gpu) gpu->stop();
  }

  void launch_job(const stratum::StratumJob& job) {
    if (!subscribed || !authorized) { pending_job = job; return; }
    active_generation.fetch_add(1, std::memory_order_acq_rel);
    stop_workers();
    if (job.clean_jobs) {
      allocator.mark_all_stale();
      event("[JOB] clean_jobs=true -> ancien travail interrompu");
    }

    if (previous_prevhash.empty() || previous_prevhash != job.prevhash) event("[JOB] NOUVEAU BLOC / NOUVEAU PREVHASH");
    else event("[JOB] MISE À JOUR DU JOB");
    previous_prevhash = job.prevhash;
    const auto generation =
        active_generation.load(std::memory_order_acquire);

    const auto work_fingerprint =
        live_work_fingerprint(
            job,
            extranonce1,
            extranonce2_size);

    const auto resumed =
        allocator.prepare_live_job(
            job.job_id,
            job.prevhash,
            extranonce1,
            extranonce2_size,
            work_fingerprint,
            config.cpu.enabled ? config.cpu.threads : 1U,
            config.gpu.enabled,
            generation);
    event(resumed ? "[CHECKPOINT] travail CKPool compatible repris" : "[CHECKPOINT] nouveau travail; ancien état live incompatible compacté");
    const LiveMiningJob mining_job{job, extranonce1, bitcoin::share_target_from_difficulty(share_difficulty),
                                   bitcoin::target_from_nbits(job.nbits), share_difficulty,
                                   extranonce2_size, work_fingerprint, generation};
    telemetry.set_job(job.job_id, job.prevhash, job.clean_jobs, share_difficulty, bitcoin::target_hex(mining_job.network_target));

    std::string cpu_ex2;
    std::string gpu_ex2;
    for (const auto& unit : allocator.units()) {
      if (unit.generation != generation || unit.status == WorkStatus::Stale) continue;
      if (unit.worker == WorkerKind::Cpu && cpu_ex2.empty()) cpu_ex2 = unit.extranonce2;
      if (unit.worker == WorkerKind::Gpu && gpu_ex2.empty()) gpu_ex2 = unit.extranonce2;
    }
    auto gpu_name = std::string("désactivé");
    if (config.gpu.enabled) {
      const auto info = gpu->detect(config.gpu.platform, config.gpu.device);
      gpu_name = info.available ? info.name : "OpenCL absent";
    }
    telemetry.set_worker_state(config.cpu.enabled ? config.cpu.threads : 0, cpu_ex2, gpu_name, gpu_ex2);
    if (config.cpu.enabled) cpu->start(mining_job, config.cpu.threads);
    if (config.gpu.enabled) gpu->start(mining_job, config.gpu.auto_tune);
    safe_checkpoint("sauvegarde au lancement du job impossible");
  }

  void append_stratum_archive(nlohmann::json record) {
    try {
      logger.append_jsonl(
          "stratum_jobs.jsonl",
          std::move(record));
    } catch (const std::exception& error) {
      event(
          "[STRATUM ARCHIVE] sauvegarde impossible: " +
          std::string(error.what()));
    }
  }

  void archive_stratum_subscription(
      const std::string& value,
      const unsigned size) {
    append_stratum_archive({
        {"schema_version", 1},
        {"event", "mining.subscribe"},
        {"received_timestamp_utc",
         logging::ResultLogger::utc_now()},
        {"source", {
            {"mode", config::mode_name(config.mode)},
            {"host", config.ckpool.host},
            {"port", config.ckpool.port}}},
        {"subscription", {
            {"extranonce1", value},
            {"extranonce2_size", size}}}
    });
  }

  void archive_stratum_notify(
      const stratum::StratumJob& job) {
    nlohmann::json subscription = {
        {"available", subscribed},
        {"extranonce1", nullptr},
        {"extranonce2_size", nullptr}
    };

    nlohmann::json work_fingerprint = nullptr;

    if (subscribed) {
      subscription["extranonce1"] = extranonce1;
      subscription["extranonce2_size"] =
          extranonce2_size;

      work_fingerprint =
          live_work_fingerprint(
              job,
              extranonce1,
              extranonce2_size);
    }

    append_stratum_archive({
        {"schema_version", 1},
        {"event", "mining.notify"},
        {"received_timestamp_utc",
         logging::ResultLogger::utc_now()},
        {"source", {
            {"mode", config::mode_name(config.mode)},
            {"host", config.ckpool.host},
            {"port", config.ckpool.port}}},
        {"connection_state", {
            {"subscribed", subscribed},
            {"authorized", authorized},
            {"share_difficulty", share_difficulty}}},
        {"subscription", std::move(subscription)},
        {"stratum_job", {
            {"job_id", job.job_id},
            {"clean_jobs", job.clean_jobs},
            {"prevhash", job.prevhash},
            {"coinbase1", job.coinbase1},
            {"coinbase2", job.coinbase2},
            {"merkle_branches",
             job.merkle_branches},
            {"version", job.version},
            {"nbits", job.nbits},
            {"ntime", job.ntime}}},
        {"work_fingerprint",
         std::move(work_fingerprint)}
    });
  }

  void on_job(const stratum::StratumJob& job) {
    std::scoped_lock lock(control_mutex);

    archive_stratum_notify(job);
    launch_job(job);
  }

  int run_live(std::atomic_bool& stop_requested) {
    cpu = std::make_unique<CpuMiner>(allocator, telemetry, active_generation, [this](Candidate candidate) { on_candidate(std::move(candidate)); });
    gpu = std::make_unique<GpuMiner>(allocator, telemetry, active_generation,
                                    [this](Candidate candidate) { on_candidate(std::move(candidate)); },
                                    config.project_root / "kernels" / "sha256d.cl",
                                    config.gpu.profile);
    stratum::StratumClient::Callbacks callbacks;
    callbacks.event = [this](const std::string& text) { event(text); };
    callbacks.subscribed = [this](
        const std::string& value,
        const unsigned size) {
      std::scoped_lock lock(control_mutex);

      extranonce1 = value;
      extranonce2_size = size;
      subscribed = true;

      archive_stratum_subscription(
          extranonce1,
          extranonce2_size);

      if (pending_job && authorized) {
        auto job = *pending_job;
        pending_job.reset();
        launch_job(job);
      }
    };
    callbacks.authorized = [this](const bool accepted) {
      std::scoped_lock lock(control_mutex);
      authorized = accepted;
      telemetry.set_connection(client && client->connected(), accepted, config.ckpool.host + ":" + std::to_string(config.ckpool.port));
      if (accepted && pending_job && subscribed) { auto job = *pending_job; pending_job.reset(); launch_job(job); }
    };
    callbacks.difficulty = [this](const double value) { std::scoped_lock lock(control_mutex); share_difficulty = value; };
    callbacks.job = [this](const stratum::StratumJob& job) { on_job(job); };
    callbacks.submission = [this](const std::int64_t id, const bool accepted, const nlohmann::json& response, const std::uint64_t latency) {
      Solution solution;
      bool found = false;
      {
        std::scoped_lock lock(submissions_mutex);
        const auto item = pending_submissions.find(id);
        if (item != pending_submissions.end()) { solution = std::move(item->second); pending_submissions.erase(item); found = true; }
      }
      if (accepted) telemetry.accepted.fetch_add(1);
      else telemetry.rejected.fetch_add(1);
      if (found) {
        solution.response_timestamp_utc = logging::ResultLogger::utc_now();
        solution.submission_status = accepted ? "accepted" : "rejected";
        solution.accepted = accepted;
        solution.submission_latency_us = latency;
        solution.server_response = response;
        if (!accepted) {
          event("[SHARE] rejetée id=" + std::to_string(id) + " réponse=" + response.dump());
        } else if (solution.network_candidate || solution.personal_record ||
                   solution.hash_difficulty >= config.console.high_difficulty_threshold) {
          event("[SHARE] acceptée id=" + std::to_string(id) +
                " difficulté=" + std::to_string(solution.hash_difficulty));
        }
        if (solution.network_candidate) {
          try { logger.update_candidate(solution); }
          catch (const checkpoint::PersistenceError& error) {
            event("[BLOCK] réponse non sauvegardée: " + std::string(error.what()));
          }
        }
        if (!solution.share_audit_file.empty()) {
          try { logger.update_share_audit(solution); }
          catch (const checkpoint::PersistenceError& error) {
            event("[SHARE] réponse non sauvegardée dans l'audit: " + std::string(error.what()));
          }
        }
      }
      else if (!accepted) {
        event("[SHARE] rejetée id inconnu=" + std::to_string(id) + " réponse=" + response.dump());
      }
    };
    callbacks.disconnected = [this]() {
      std::scoped_lock lock(control_mutex);
      active_generation.fetch_add(1, std::memory_order_acq_rel);
      stop_workers();
      authorized = false; subscribed = false;
      telemetry.set_connection(false, false, config.ckpool.host + ":" + std::to_string(config.ckpool.port));
      safe_checkpoint("sauvegarde à la déconnexion impossible");
    };

    client = std::make_unique<stratum::StratumClient>(config.ckpool, std::move(callbacks));
    telemetry.start();
    telemetry.set_connection(false, false, config.ckpool.host + ":" + std::to_string(config.ckpool.port));
    client->start();
    auto next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
    auto next_retention_purge = std::chrono::steady_clock::now() + std::chrono::hours(1);
    while (!stop_requested.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (std::chrono::steady_clock::now() >= next_checkpoint) {
        safe_checkpoint("sauvegarde périodique impossible");
        next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
      }
      if (std::chrono::steady_clock::now() >= next_retention_purge) {
        try {
          const auto removed = logger.purge_expired_share_audits();
          if (removed > 0U) event("[RÉTENTION] audits de petites shares expirés supprimés=" + std::to_string(removed));
        } catch (const std::exception& error) {
          event("[RÉTENTION] purge impossible: " + std::string(error.what()));
        }
        next_retention_purge = std::chrono::steady_clock::now() + std::chrono::hours(1);
      }
    }
    active_generation.fetch_add(1);
    stop_workers();
    client->stop();
    safe_checkpoint("sauvegarde finale impossible");
    telemetry.stop();
    return 0;
  }

  Solution offline_solution(const bitcoin::Header& header, const crypto::Digest& digest,
                            const bitcoin::Target256& target, const std::string& header_id) {
    Solution value;
    value.job_id = header_id;
    value.username = "OFFLINE";
    value.version = reverse_hex(std::span<const std::uint8_t>(header.data(), 4));
    value.prevhash = reverse_hex(std::span<const std::uint8_t>(header.data() + 4, 32));
    value.merkle_root = reverse_hex(std::span<const std::uint8_t>(header.data() + 36, 32));
    value.ntime = reverse_hex(std::span<const std::uint8_t>(header.data() + 68, 4));
    value.nbits = reverse_hex(std::span<const std::uint8_t>(header.data() + 72, 4));
    value.nonce_value = bitcoin::get_nonce(header);
    value.nonce = bitcoin::stratum_nonce_hex(value.nonce_value);
    value.nonce_header_le = bitcoin::nonce_header_le_hex(header);
    value.header_hex = bitcoin::header_hex(header);
    value.hash = crypto::bitcoin_hash_hex(digest);
    value.network_target = bitcoin::target_hex(target);
    value.share_target = value.network_target;
    value.detected_timestamp_utc = logging::ResultLogger::utc_now();
    value.network_candidate = true;
    value.offline = true;
    value.submission_status = "offline";
    return value;
  }

  int run_historical(std::atomic_bool& stop_requested) {
    auto bytes = crypto::from_hex(config.historical.header_hex);
    bitcoin::Header base{};
    std::copy(bytes.begin(), bytes.end(), base.begin());
    const auto target = bitcoin::target_from_hex(config.historical.target_hex);
    const auto original_nonce = bitcoin::get_nonce(base);
    bitcoin::set_nonce(base, 0);
    const auto header_id = crypto::digest_hex(crypto::sha256(std::span<const std::uint8_t>(base.data(), 76)));

    if (config.historical.known_nonce) {
      auto validation = base;
      bitcoin::set_nonce(validation, *config.historical.known_nonce);
      const auto actual = crypto::bitcoin_hash_hex(crypto::sha256d(validation));
      if (!config.historical.expected_hash.empty() && actual != config.historical.expected_hash) {
        throw std::runtime_error("historical expected_hash mismatch: computed " + actual);
      }
      event("[HISTORICAL] vecteur connu validé: " + actual);
    }
    const auto start_nonce = config.historical.scan_full_nonce_space ? 0ULL : config.historical.nonce_start;
    const auto end_nonce = config.historical.scan_full_nonce_space ? 0x100000000ULL : config.historical.nonce_end;
    allocator.prepare_historical(header_id, start_nonce, end_nonce, config.cpu.threads, 64);
    telemetry.start();
    std::atomic_bool found{false};
    std::mutex save_mutex;
    std::vector<std::jthread> threads;
    for (unsigned index = 0; index < config.cpu.threads; ++index) {
      threads.emplace_back([&, index](const std::stop_token token) {
        (void)index;
        while (!token.stop_requested() && !stop_requested.load() && !found.load()) {
          auto unit = allocator.acquire(WorkerKind::Cpu);
          if (!unit) return;
          auto header = base;
          std::uint64_t pending = 0;
          auto nonce = unit->nonce_next;
          for (; nonce < unit->nonce_end && !found.load() && !stop_requested.load(); ++nonce) {
            bitcoin::set_nonce(header, static_cast<std::uint32_t>(nonce));
            const auto digest = crypto::sha256d(header);
            ++pending;
            if (bitcoin::hash_meets_target(digest, target)) {
              bool expected = false;
              if (found.compare_exchange_strong(expected, true)) {
                std::scoped_lock lock(save_mutex);
                auto solution = offline_solution(header, digest, target, header_id);
                logger.save_candidate(solution);
                event("[BLOCK] BLOCK_FOUND hors ligne hash=" + solution.hash + " nonce=" + std::to_string(nonce));
              }
            }
            if (pending >= 65536) {
              allocator.update_progress(unit->id, nonce + 1, pending);
              telemetry.cpu_hashes.fetch_add(pending);
              pending = 0;
            }
          }
          if (pending) { allocator.update_progress(unit->id, nonce, pending); telemetry.cpu_hashes.fetch_add(pending); }
          if (nonce >= unit->nonce_end) allocator.complete(unit->id); else allocator.release(unit->id);
        }
      });
    }
    auto next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
    while (!found.load() && !stop_requested.load()) {
      const auto work_snapshot = allocator.units();
      const bool any_work = std::any_of(work_snapshot.begin(), work_snapshot.end(), [](const WorkUnit& unit) {
        return unit.status == WorkStatus::Pending || unit.status == WorkStatus::InProgress;
      });
      if (!any_work) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (std::chrono::steady_clock::now() >= next_checkpoint) {
        allocator.checkpoint(counters_json());
        next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
      }
    }
    for (auto& thread : threads) thread.request_stop();
    threads.clear();
    allocator.checkpoint(counters_json());
    telemetry.stop();
    bitcoin::set_nonce(base, original_nonce);
    if (!found.load() && !stop_requested.load()) event("[HISTORICAL] plage terminée sans candidat");
    return found.load() ? 0 : 2;
  }

  int run_research(std::atomic_bool& stop_requested) {
    if (config.research.trace_analysis.enabled && !config.historical.known_nonce) {
      throw std::runtime_error(
          "research trace analysis requires historical.known_nonce as the reference nonce");
    }
    const auto bytes = crypto::from_hex(config.historical.header_hex);
    bitcoin::Header header{};
    std::copy(bytes.begin(), bytes.end(), header.begin());
    bitcoin::set_nonce(header, 0);
    const auto header_id = crypto::digest_hex(crypto::sha256(std::span<const std::uint8_t>(header.data(), 76)));

    if (config.historical.known_nonce) {
        auto validation = header;
        bitcoin::set_nonce(validation, *config.historical.known_nonce);

        const auto standard = crypto::sha256d(validation);
        const auto reduced_64 = crypto::reduced_sha256d(validation, 64);
        const auto trace = crypto::trace_reduced_sha256d(validation, 64);

        if (standard != reduced_64 || standard != trace.digest) {
            throw std::runtime_error(
                "research validation failed: reduced or traced SHA256d round 64 differs from standard SHA256d");
        }

        const auto actual = crypto::bitcoin_hash_hex(standard);

        if (!config.historical.expected_hash.empty() &&
            actual != config.historical.expected_hash) {
            throw std::runtime_error(
                "research validation failed: expected_hash mismatch: computed " + actual);
        }

        constexpr std::size_t first_sha_rounds = 128;
        constexpr std::size_t second_sha_rounds = 64;
        constexpr std::size_t total_traced_rounds = first_sha_rounds + second_sha_rounds;
        if (trace.first_sha.rounds.size() != first_sha_rounds ||
            trace.second_sha.rounds.size() != second_sha_rounds) {
            throw std::runtime_error("research validation failed: Genesis SHA256d trace must contain 128 + 64 rounds");
        }
        if (trace.second_sha.rounds.front().compression_index != 0) {
            throw std::runtime_error("research validation failed: second SHA compression index must restart at zero");
        }

        nlohmann::json detailed_trace = {
            {"header_id", header_id},
            {"nonce", *config.historical.known_nonce},
            {"rounds_per_compression", 64},
            {"total_traced_rounds", total_traced_rounds},
            {"hash", actual},
            {"first_sha", {
                {"digest", crypto::digest_hex(trace.first_sha.digest)},
                {"digest_format", "sha256_digest_hex"},
                {"compressions", 2},
                {"round_trace", sha256_rounds_json(trace.first_sha.rounds)}}},
            {"second_sha", {
                {"digest", crypto::digest_hex(trace.second_sha.digest)},
                {"digest_format", "sha256_digest_hex"},
                {"compressions", 1},
                {"round_trace", sha256_rounds_json(trace.second_sha.rounds)}}},
        };
        logger.save_json_atomic(config.logging.directory / "research_trace_known_nonce.json", detailed_trace);

        event("[RESEARCH] validation SHA256d round=64 OK: " + actual);
        event("[RESEARCH] trace détaillée nonce connu sauvegardée: 192 rounds");

        if (config.research.trace_analysis.enabled) {
          auto reports = research_analysis_reports(
              validation, trace, header_id, *config.historical.known_nonce,
              config.research.trace_analysis);
          if (config.research.trace_analysis.save_full_trajectories) {
            logger.save_json_atomic(
                config.logging.directory / "research_nonce_trajectories.json",
                reports.trajectories);
            event("[RESEARCH] trajectoires causales sauvegardées: " +
                  std::to_string(reports.trajectory_count) + " nonces");
          }
          logger.save_json_atomic(
              config.logging.directory / "research_nonce_diffusion.json",
              reports.diffusion);
          event("[RESEARCH] diffusion nonce sauvegardée: " +
                std::to_string(reports.candidate_count) + " candidats comparés à " +
                std::to_string(*config.historical.known_nonce));
        }
    }

    checkpoint::StateStore state_store(config.project_root / "state" / allocator_state_name(config.mode));
    auto state = state_store.load_or(nlohmann::json::object());
    if (state.value("header_id", "") != header_id) state = nlohmann::json::object();
    std::vector<unsigned> completed = state.value("completed_rounds", std::vector<unsigned>{});

    for (unsigned round = config.research.round_start; round <= config.research.round_end && !stop_requested.load(); ++round) {
      if (std::find(completed.begin(), completed.end(), round) != completed.end()) continue;
      std::array<std::uint64_t, 256> bit_counts{};
      std::uint64_t hamming_total = 0;
      std::uint64_t tested = 0;
      std::uint64_t nonce_next = 0;
      crypto::Digest previous{};
      bool has_previous = false;
      std::string best_hash;
      std::uint32_t best_nonce = 0;
      if (state.value("header_id", "") == header_id && state.value("current_round", 0U) == round &&
          state.value("nonce_next", 0ULL) > 0) {
        nonce_next = state.value("nonce_next", 0ULL);
        tested = state.value("hashes_tested", 0ULL);
        hamming_total = state.value("hamming_total", 0ULL);
        best_hash = state.value("best_hash", "");
        best_nonce = state.value("best_nonce", 0U);
        const auto saved_counts = state.value("bit_counts", std::vector<std::uint64_t>{});
        if (saved_counts.size() == bit_counts.size()) std::copy(saved_counts.begin(), saved_counts.end(), bit_counts.begin());
        const auto previous_hex = state.value("previous_digest", "");
        if (previous_hex.size() == 64) { const auto value = crypto::from_hex(previous_hex); std::copy(value.begin(), value.end(), previous.begin()); has_previous = true; }
      }
      event("[RESEARCH] round=" + std::to_string(round) + " reprise nonce=" + std::to_string(nonce_next));
      for (std::uint64_t nonce = nonce_next; nonce < config.research.sample_count && !stop_requested.load(); ++nonce) {
        bitcoin::set_nonce(header, static_cast<std::uint32_t>(nonce));
        const auto digest = crypto::reduced_sha256d(header, round);
        for (std::size_t byte = 0; byte < digest.size(); ++byte) {
          for (unsigned bit = 0; bit < 8; ++bit) bit_counts[byte * 8 + bit] += (digest[byte] >> bit) & 1U;
        }
        if (has_previous) hamming_total += crypto::hamming_distance(previous, digest);
        previous = digest; has_previous = true; ++tested;
        const auto text = crypto::bitcoin_hash_hex(digest);
        if (best_hash.empty() || text < best_hash) { best_hash = text; best_nonce = static_cast<std::uint32_t>(nonce); }
        if ((nonce + 1) % 65536 == 0) {
          state = {{"schema_version", 1}, {"mode", "research"}, {"header_id", header_id}, {"current_round", round},
                   {"nonce_next", nonce + 1}, {"nonce_end", config.research.sample_count}, {"hashes_tested", tested},
                   {"best_hash", best_hash}, {"best_nonce", best_nonce}, {"hamming_total", hamming_total},
                   {"previous_digest", crypto::digest_hex(previous)}, {"bit_counts", bit_counts}, {"completed_rounds", completed}};
          state_store.save(state);
        }
      }
      if (stop_requested.load()) break;
      nlohmann::json statistics = {
          {"header_id", header_id}, {"round", round}, {"samples", tested}, {"bit_counts", bit_counts},
          {"mean_hamming_distance", tested > 1 ? static_cast<double>(hamming_total) / static_cast<double>(tested - 1) : 0.0},
          {"best_hash", best_hash}, {"best_nonce", best_nonce}};
      logger.save_json_atomic(config.logging.directory / ("research_round_" + std::to_string(round) + ".json"), statistics);
      completed.push_back(round);
      state = {{"schema_version", 1}, {"mode", "research"}, {"header_id", header_id}, {"current_round", round + 1},
               {"nonce_next", 0}, {"nonce_end", config.research.sample_count}, {"hashes_tested", 0},
               {"best_hash", ""}, {"best_nonce", nullptr}, {"statistics", statistics}, {"completed_rounds", completed}};
      state_store.save(state);
    }
    return stop_requested.load() ? 130 : 0;
  }

  int run_benchmark(std::atomic_bool& stop_requested) {
    const auto bytes = crypto::from_hex(config.benchmark.header_hex);
    bitcoin::Header header{};
    std::copy(bytes.begin(), bytes.end(), header.begin());

    gpu = std::make_unique<GpuMiner>(allocator, telemetry, active_generation,
                                    [](Candidate) {}, config.project_root / "kernels" / "sha256d.cl",
                                    config.gpu.profile);
    const auto devices = gpu->enumerate();
    std::cout << "[BENCHMARK] Périphériques OpenCL détectés: " << devices.size() << '\n';
    for (const auto& device : devices) {
      std::cout << "[GPU " << device.index << "] platform_index=" << device.platform_index
                << " device_index=" << device.device_index << " plateforme=\"" << device.platform
                << "\" nom_opencl=\"" << device.name << "\" nom_carte=\"" << device.board_name
                << "\" vendor=\"" << device.vendor
                << "\" driver=\"" << device.driver << "\" compute_units=" << device.compute_units
                << " mémoire=" << device.global_memory << " octets max_work_group="
                << device.max_workgroup_size << '\n';
    }
    std::cout << "[BENCHMARK] warm-up=" << config.benchmark.warmup_ms
              << " ms mesure=" << config.benchmark.measurement_ms << " ms par configuration\n";

    CpuBenchmarkResult cpu_result;
    if (config.cpu.enabled) {
      std::cout << "\n[BENCHMARK CPU]\n";
      cpu_result = benchmark_cpu_sha256d(header, config.benchmark.cpu_threads,
                                         config.benchmark.warmup_ms, config.benchmark.measurement_ms,
                                         stop_requested);
      for (const auto& sample : cpu_result.samples) {
        std::cout << "threads=" << sample.threads << " hashes=" << sample.hashes
                  << " durée=" << std::fixed << std::setprecision(6) << sample.seconds
                  << " s H/s=" << std::setprecision(2) << sample.hash_rate
                  << " (" << format_hash_rate(sample.hash_rate) << ")\n";
      }
      if (!cpu_result.samples.empty()) {
        std::cout << "meilleur=" << cpu_result.best.threads << " threads, "
                  << format_hash_rate(cpu_result.best.hash_rate) << '\n';
      }
    }
    if (stop_requested.load(std::memory_order_acquire)) return 130;

    GpuBenchmarkResult gpu_result;
    if (config.gpu.enabled) {
      if (devices.empty()) throw std::runtime_error("benchmark GPU requested but no OpenCL GPU was detected");
      std::cout << "\n[BENCHMARK GPU]\n";
      gpu_result = gpu->benchmark(header, config.gpu.platform, config.gpu.device, config.gpu.auto_tune,
                                  config.benchmark.warmup_ms, config.benchmark.measurement_ms);
      const auto display_name = gpu_result.device.board_name.empty() ? gpu_result.device.name : gpu_result.device.board_name;
      std::cout << "GPU sélectionné: [GPU " << gpu_result.device.index << "] " << display_name
                << " | nom OpenCL=" << gpu_result.device.name << " | plateforme=" << gpu_result.device.platform
                << " | platform_index=" << gpu_result.device.platform_index
                << " | device_index=" << gpu_result.device.device_index
                << " | driver=" << gpu_result.device.driver << '\n';
      std::cout << "validation CPU/GPU 4096 vecteurs: " << (gpu_result.validated ? "OK" : "ÉCHEC") << '\n';
      for (const auto& sample : gpu_result.samples) {
        std::cout << "local=" << sample.local_work_size << " global=" << sample.global_work_size
                  << " batch=" << sample.batch_size << " hashes=" << sample.hashes
                  << " durée=" << std::fixed << std::setprecision(6) << sample.seconds
                  << " s H/s=" << std::setprecision(2) << sample.hash_rate
                  << " (" << format_hash_rate(sample.hash_rate) << ")\n";
      }
      std::cout << "meilleur=local=" << gpu_result.best.local_work_size
                << " global=" << gpu_result.best.global_work_size
                << " batch=" << gpu_result.best.batch_size << " "
                << format_hash_rate(gpu_result.best.hash_rate) << '\n';
    }

    nlohmann::json profile = {
        {"schema_version", 1},
        {"timestamp_utc", logging::ResultLogger::utc_now()},
        {"mode", "benchmark"},
        {"warmup_ms", config.benchmark.warmup_ms},
        {"measurement_ms", config.benchmark.measurement_ms},
        {"combined_hash_rate_hps", nullptr}};
    profile["cpu"] = {
        {"enabled", config.cpu.enabled},
        {"best_threads", cpu_result.best.threads},
        {"hash_rate_hps", cpu_result.best.hash_rate}};
    profile["gpu"] = {
        {"enabled", config.gpu.enabled},
        {"tuned", gpu_result.validated},
        {"index", gpu_result.device.index},
        {"platform", gpu_result.device.platform},
        {"device_name", gpu_result.device.name},
        {"board_name", gpu_result.device.board_name},
        {"vendor", gpu_result.device.vendor},
        {"driver", gpu_result.device.driver},
        {"compute_units", gpu_result.device.compute_units},
        {"global_memory_bytes", gpu_result.device.global_memory},
        {"max_work_group_size", gpu_result.device.max_workgroup_size},
        {"local_work_size", gpu_result.best.local_work_size},
        {"global_work_size", gpu_result.best.global_work_size},
        {"batch_size", gpu_result.best.batch_size},
        {"hash_rate_hps", gpu_result.best.hash_rate}};
    checkpoint::StateStore(config.benchmark.performance_profile).save(profile);

    std::cout << "\n[BENCHMARK FINAL]\n";
    std::cout << "CPU " << (config.cpu.enabled ? format_hash_rate(cpu_result.best.hash_rate) : "désactivé") << '\n';
    std::cout << "GPU " << (config.gpu.enabled ? format_hash_rate(gpu_result.best.hash_rate) : "désactivé") << '\n';
    std::cout << "TOTAL non mesuré: le test combiné est volontairement séparé de cette première version fiable\n";
    std::cout << "Profil atomique: " << config.benchmark.performance_profile << '\n';
    return 0;
  }

  int run(std::atomic_bool& stop_requested) {
    if (config.mode == config::Mode::Benchmark) return run_benchmark(stop_requested);
    if (config.mode == config::Mode::Live || config.mode == config::Mode::MockStratum) return run_live(stop_requested);
    if (config.mode == config::Mode::HistoricalTest) return run_historical(stop_requested);
    return run_research(stop_requested);
  }
};

MiningController::MiningController(config::AppConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}
MiningController::~MiningController() = default;
int MiningController::run(std::atomic_bool& stop_requested) { return impl_->run(stop_requested); }

}  // namespace srm::mining
