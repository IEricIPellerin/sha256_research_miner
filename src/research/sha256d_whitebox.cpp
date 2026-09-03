//src\research\sha256d_whitebox.cpp
#include "research/sha256d_whitebox.h"

#include "crypto/reduced_sha256.h"
#include "crypto/sha256d.h"
#include "research/header_space.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <map>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace srm::research::whitebox {
namespace {

using Block = std::array<std::uint8_t, 64>;
using State = std::array<std::uint32_t, 8>;

constexpr std::string_view kExpectedHeaderHex =
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c";
constexpr std::string_view kExpectedFirstSha256 =
    "af42031e805ff493a07341e2f74ff58149d22ab9ba19f61343e2c86c71c5d66d";
constexpr std::string_view kExpectedRawSha256d =
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
constexpr std::string_view kExpectedBitcoinHash =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
constexpr std::string_view kNoncePlusOneHeaderHex =
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1eac2b7c";
constexpr std::string_view kNoncePlusOneFirstSha256 =
    "3f20e97bd2b9a79c76c6d8ec16883a3071fc8cf072ecf49ea9c66b7a510d4674";
constexpr std::string_view kNoncePlusOneRawSha256d =
    "1c1ba4714930063bebadce0a323e51d097775dbc444187e6ba0caa5d4a7a229b";
constexpr std::string_view kNoncePlusOneBitcoinHash =
    "9b227a4a5daa0cbae6874144bc5d7797d0513e320aceadeb3b06304971a41b1c";
constexpr std::string_view kNonceBit0FlipHeaderHex =
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1cac2b7c";
constexpr std::string_view kNonceBit0FlipFirstSha256 =
    "b0bded2df03b40f384c981e5b750ad0ccf562554b23c0187bb162ba093bc3dfc";
constexpr std::string_view kNonceBit0FlipRawSha256d =
    "d9665d1c88b5bf70b741453c4a78c9fe36a537659ad0e7fab087cac13d34dc8c";
constexpr std::string_view kNonceBit0FlipBitcoinHash =
    "8cdc343dc1ca87b0fae7d09a6537a536fec9784a3c4541b770bfb5881c5d66d9";
constexpr std::array<unsigned, 10> kModulusBits{1, 2, 4, 8, 12, 16, 20, 24, 28, 32};
constexpr std::array<const char*, 8> kStateNames{"a", "b", "c", "d", "e", "f", "g", "h"};
constexpr std::array<const char*, 8> kChainingNames{"H0", "H1", "H2", "H3", "H4", "H5", "H6", "H7"};
constexpr State kInitialState{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
constexpr std::array<std::uint32_t, 64> kRoundConstants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

struct CompressionStats {
  unsigned sha_pass{};
  unsigned compression_index{};
  std::size_t addition_count{};
  std::map<unsigned, std::size_t> carry_count_distribution;
  std::uint64_t maximum_carry{};
  std::vector<std::string> additions_without_carry;
  std::vector<unsigned> rounds_without_carry;
  unsigned maximum_round_carry_columns{};
  std::vector<unsigned> rounds_with_most_carry_columns;
};

[[noreturn]] void fail(const std::string& message) {
  throw std::runtime_error("SHA256d white-box validation failed: " + message);
}

void require(const bool condition, const std::string& message) {
  if (!condition) fail(message);
}

std::string hex_byte(const std::uint8_t value) {
  std::ostringstream output;
  output << std::hex << std::nouppercase << std::setfill('0') << std::setw(2)
         << static_cast<unsigned>(value);
  return output.str();
}

std::string hex_word(const std::uint32_t value) {
  std::ostringstream output;
  output << std::hex << std::nouppercase << std::setfill('0') << std::setw(8) << value;
  return output.str();
}

std::string reversed_hex(const std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> reversed(bytes.rbegin(), bytes.rend());
  return crypto::to_hex(reversed);
}

std::string binary_value(const std::uint64_t value, const unsigned width) {
  std::string result(width, '0');
  for (unsigned bit = 0; bit < width; ++bit) {
    if (((value >> bit) & 1U) != 0) result[width - 1U - bit] = '1';
  }
  return result;
}

std::uint32_t low_bits(const std::uint32_t value, const unsigned bits) {
  return bits == 32U ? value : value & ((std::uint32_t{1} << bits) - 1U);
}

nlohmann::json modulo_json(const std::uint32_t value) {
  auto result = nlohmann::json::object();
  for (const auto bits : kModulusBits) {
    result["mod_2^" + std::to_string(bits)] = low_bits(value, bits);
  }
  return result;
}

nlohmann::json word_json(const std::uint32_t value) {
  return {
      {"uint32", value},
      {"hex", hex_word(value)},
      {"binary", binary_value(value, 32)},
      {"mod_2k", modulo_json(value)}};
}

nlohmann::json byte_json(const std::uint8_t value) {
  return {{"uint8", value}, {"hex", hex_byte(value)}, {"binary", binary_value(value, 8)}};
}

nlohmann::json bytes_json(const std::span<const std::uint8_t> bytes,
                          const std::size_t absolute_offset = 0) {
  auto result = nlohmann::json::array();
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    auto item = byte_json(bytes[i]);
    item["index"] = i;
    item["absolute_index"] = absolute_offset + i;
    result.push_back(std::move(item));
  }
  return result;
}

void validate_bytes_json(const nlohmann::json& recorded,
                         const std::span<const std::uint8_t> expected,
                         const std::size_t absolute_offset,
                         const std::string& context) {
  require(recorded.is_array() && recorded.size() == expected.size(),
          context + " byte array length mismatch");
  for (std::size_t i = 0; i < expected.size(); ++i) {
    const auto& item = recorded[i];
    require(item.at("index").get<std::size_t>() == i, context + " byte index mismatch");
    require(item.at("absolute_index").get<std::size_t>() == absolute_offset + i,
            context + " absolute byte index mismatch");
    require(item.at("uint8").get<unsigned>() == expected[i], context + " byte value mismatch");
    require(item.at("hex").get<std::string>() == hex_byte(expected[i]), context + " byte hex mismatch");
    require(item.at("binary").get<std::string>() == binary_value(expected[i], 8),
            context + " byte binary mismatch");
  }
}

std::uint32_t read_be32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
         (static_cast<std::uint32_t>(bytes[1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2]) << 8U) |
         static_cast<std::uint32_t>(bytes[3]);
}

std::uint32_t read_le32(const std::uint8_t* bytes) {
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

State digest_words(const crypto::Digest& digest) {
  State result{};
  for (std::size_t i = 0; i < result.size(); ++i) {
    result[i] = read_be32(digest.data() + i * 4U);
  }
  return result;
}

State before_state(const crypto::Sha256RoundTrace& trace) {
  return {trace.a_before, trace.b_before, trace.c_before, trace.d_before,
          trace.e_before, trace.f_before, trace.g_before, trace.h_before};
}

State after_state(const crypto::Sha256RoundTrace& trace) {
  return {trace.a_after, trace.b_after, trace.c_after, trace.d_after,
          trace.e_after, trace.f_after, trace.g_after, trace.h_after};
}

nlohmann::json named_state_json(const State& state,
                                const std::array<const char*, 8>& names) {
  auto result = nlohmann::json::object();
  for (std::size_t i = 0; i < state.size(); ++i) result[names[i]] = word_json(state[i]);
  return result;
}

nlohmann::json addition_json(
    const std::vector<std::pair<std::string, std::uint32_t>>& operands,
    const std::uint32_t expected,
    const std::string& identity) {
  require(!operands.empty(), identity + " has no operands");
  auto operand_values = nlohmann::json::array();
  for (const auto& [name, value] : operands) {
    operand_values.push_back({{"name", name}, {"value", word_json(value)}});
  }

  auto columns = nlohmann::json::array();
  auto nonzero_columns = nlohmann::json::array();
  auto carry_profile = nlohmann::json::array();
  std::uint64_t carry = 0;
  std::uint32_t reconstructed = 0;
  unsigned longest_run = 0;
  unsigned current_run = 0;
  std::uint64_t max_carry = 0;
  for (unsigned bit = 0; bit < 32; ++bit) {
    const auto carry_in = carry;
    auto operand_bits = nlohmann::json::array();
    std::uint64_t column_sum = carry_in;
    for (const auto& [name, value] : operands) {
      const auto operand_bit = static_cast<unsigned>((value >> bit) & 1U);
      operand_bits.push_back({{"name", name}, {"bit", operand_bit}});
      column_sum += operand_bit;
    }
    const auto result_bit = static_cast<unsigned>(column_sum & 1U);
    carry = column_sum >> 1U;
    if (result_bit != 0) reconstructed |= std::uint32_t{1} << bit;
    if (carry != 0) {
      nonzero_columns.push_back(bit);
      longest_run = std::max(longest_run, ++current_run);
    } else {
      current_run = 0;
    }
    max_carry = std::max(max_carry, carry);
    carry_profile.push_back(carry);
    columns.push_back({
        {"bit_index", bit},
        {"operand_bits", std::move(operand_bits)},
        {"carry_in", carry_in},
        {"column_sum_integer", column_sum},
        {"result_bit", result_bit},
        {"carry_out", carry}});
  }
  require(reconstructed == expected, identity + " result differs from bit-column reconstruction");
  return {
      {"identity", identity},
      {"arithmetic", "unsigned integer addition modulo 2^32"},
      {"operands", std::move(operand_values)},
      {"bit_columns_lsb_to_msb", std::move(columns)},
      {"result", word_json(expected)},
      {"carry_summary", {
          {"nonzero_carry_columns", std::move(nonzero_columns)},
          {"nonzero_carry_count", std::count_if(carry_profile.begin(), carry_profile.end(),
                                                 [](const nlohmann::json& value) { return value.get<std::uint64_t>() != 0; })},
          {"max_carry_value", max_carry},
          {"longest_nonzero_carry_run", longest_run},
          {"final_carry_out", carry},
          {"carry_profile", std::move(carry_profile)}}}};
}

Block padded_final_block(const std::span<const std::uint8_t> message,
                         const std::size_t offset) {
  require(offset <= message.size(), "invalid padding offset");
  const auto remainder = message.size() - offset;
  require(remainder < 56U, "white-box experiment expects one final padding block");
  Block result{};
  std::copy(message.begin() + static_cast<std::ptrdiff_t>(offset), message.end(), result.begin());
  result[remainder] = 0x80U;
  const auto bit_length = static_cast<std::uint64_t>(message.size()) * 8U;
  for (unsigned i = 0; i < 8; ++i) {
    result[result.size() - 1U - i] = static_cast<std::uint8_t>(bit_length >> (i * 8U));
  }
  return result;
}

nlohmann::json chunk_json(const Block& block,
                          const unsigned sha_pass,
                          const unsigned compression_index,
                          const unsigned chunk_index,
                          nlohmann::json source_segments) {
  return {
      {"sha_pass", sha_pass},
      {"compression_index", compression_index},
      {"chunk_index", chunk_index},
      {"byte_length", block.size()},
      {"hex", crypto::to_hex(block)},
      {"bytes", bytes_json(block)},
      {"source_segments", std::move(source_segments)}};
}

nlohmann::json padding_json(const std::span<const std::uint8_t> message,
                            const std::vector<Block>& blocks,
                            const unsigned sha_pass) {
  const auto total_size = blocks.size() * Block{}.size();
  const auto zero_padding_bytes = total_size - message.size() - 1U - 8U;
  const auto bit_length = static_cast<std::uint64_t>(message.size()) * 8U;
  std::array<std::uint8_t, 8> length_bytes{};
  for (unsigned i = 0; i < 8; ++i) {
    length_bytes[7U - i] = static_cast<std::uint8_t>(bit_length >> (i * 8U));
  }
  std::vector<std::uint8_t> padded_message;
  padded_message.reserve(total_size);
  auto chunk_list = nlohmann::json::array();
  for (std::size_t i = 0; i < blocks.size(); ++i) {
    padded_message.insert(padded_message.end(), blocks[i].begin(), blocks[i].end());
    chunk_list.push_back({{"chunk_index", i}, {"byte_length", 64}, {"hex", crypto::to_hex(blocks[i])}});
  }
  return {
      {"sha_pass", sha_pass},
      {"input_byte_length", message.size()},
      {"input_bit_length", bit_length},
      {"rule", "message || 0x80 || zero bytes || uint64_be(original_bit_length)"},
      {"one_bit_marker_byte", byte_json(0x80U)},
      {"zero_padding_byte_count", zero_padding_bytes},
      {"encoded_length", {
          {"bit_length_uint64", bit_length},
          {"endianness", "big-endian"},
          {"hex", crypto::to_hex(length_bytes)},
          {"bytes", bytes_json(length_bytes)}}},
      {"padded_byte_length", total_size},
      {"padded_message_hex", crypto::to_hex(padded_message)},
      {"chunk_count", blocks.size()},
      {"chunks", std::move(chunk_list)}};
}

nlohmann::json schedule_json(const Block& block,
                             const std::span<const crypto::Sha256RoundTrace> rounds,
                             const std::string& context) {
  require(rounds.size() == 64U, context + " must contain 64 rounds");
  std::array<std::uint32_t, 64> schedule{};
  auto words = nlohmann::json::array();
  for (std::size_t t = 0; t < 16; ++t) {
    const auto offset = t * 4U;
    schedule[t] = read_be32(block.data() + offset);
    require(schedule[t] == rounds[t].w, context + " W[" + std::to_string(t) + "] disagrees with observed trace");
    words.push_back({
        {"t", t},
        {"source", "chunk_bytes_big_endian"},
        {"source_byte_offsets", {offset, offset + 1U, offset + 2U, offset + 3U}},
        {"source_bytes", bytes_json(std::span<const std::uint8_t>(block.data() + offset, 4), offset)},
        {"result", word_json(schedule[t])}});
  }
  for (std::size_t t = 16; t < schedule.size(); ++t) {
    const auto w16 = schedule[t - 16U];
    const auto w15 = schedule[t - 15U];
    const auto w7 = schedule[t - 7U];
    const auto w2 = schedule[t - 2U];
    const auto rotr7 = std::rotr(w15, 7);
    const auto rotr18 = std::rotr(w15, 18);
    const auto shr3 = w15 >> 3U;
    const auto sigma0 = rotr7 ^ rotr18 ^ shr3;
    const auto rotr17 = std::rotr(w2, 17);
    const auto rotr19 = std::rotr(w2, 19);
    const auto shr10 = w2 >> 10U;
    const auto sigma1 = rotr17 ^ rotr19 ^ shr10;
    schedule[t] = w16 + sigma0 + w7 + sigma1;
    require(schedule[t] == rounds[t].w, context + " extended W[" + std::to_string(t) + "] mismatch");
    words.push_back({
        {"t", t},
        {"source", "extended_schedule"},
        {"inputs", {
            {"w_t_minus_16", word_json(w16)},
            {"w_t_minus_15", word_json(w15)},
            {"w_t_minus_7", word_json(w7)},
            {"w_t_minus_2", word_json(w2)}}},
        {"small_sigma0", {
            {"formula", "ROTR7(x) XOR ROTR18(x) XOR SHR3(x)"},
            {"input", word_json(w15)}, {"rotr7", word_json(rotr7)},
            {"rotr18", word_json(rotr18)}, {"shr3", word_json(shr3)},
            {"result", word_json(sigma0)}, {"carry_behavior", "none_bitwise"}}},
        {"small_sigma1", {
            {"formula", "ROTR17(x) XOR ROTR19(x) XOR SHR10(x)"},
            {"input", word_json(w2)}, {"rotr17", word_json(rotr17)},
            {"rotr19", word_json(rotr19)}, {"shr10", word_json(shr10)},
            {"result", word_json(sigma1)}, {"carry_behavior", "none_bitwise"}}},
        {"addition", addition_json(
            {{"W[t-16]", w16}, {"sigma0(W[t-15])", sigma0},
             {"W[t-7]", w7}, {"sigma1(W[t-2])", sigma1}},
            schedule[t], context + "/schedule/W[" + std::to_string(t) + "]")},
        {"result", word_json(schedule[t])}});
  }
  return {{"word_count", words.size()}, {"words", std::move(words)}};
}

nlohmann::json round_json(const crypto::Sha256RoundTrace& trace,
                          const unsigned sha_pass,
                          const unsigned compression_index,
                          const unsigned chunk_index,
                          const std::string& context) {
  const auto rotr2 = std::rotr(trace.a_before, 2);
  const auto rotr13 = std::rotr(trace.a_before, 13);
  const auto rotr22 = std::rotr(trace.a_before, 22);
  const auto sigma0 = rotr2 ^ rotr13 ^ rotr22;
  const auto rotr6 = std::rotr(trace.e_before, 6);
  const auto rotr11 = std::rotr(trace.e_before, 11);
  const auto rotr25 = std::rotr(trace.e_before, 25);
  const auto sigma1 = rotr6 ^ rotr11 ^ rotr25;
  const auto e_and_f = trace.e_before & trace.f_before;
  const auto not_e = ~trace.e_before;
  const auto not_e_and_g = not_e & trace.g_before;
  const auto choice = e_and_f ^ not_e_and_g;
  const auto a_and_b = trace.a_before & trace.b_before;
  const auto a_and_c = trace.a_before & trace.c_before;
  const auto b_and_c = trace.b_before & trace.c_before;
  const auto majority = a_and_b ^ a_and_c ^ b_and_c;
  const auto round = trace.round_index;

  require(trace.sum0 == sigma0, context + " Sigma0 mismatch");
  require(trace.sum1 == sigma1, context + " Sigma1 mismatch");
  require(trace.choice == choice, context + " Ch mismatch");
  require(trace.majority == majority, context + " Maj mismatch");
  require(trace.temp1 == trace.h_before + sigma1 + choice + kRoundConstants[round] + trace.w,
          context + " T1 mismatch");
  require(trace.temp2 == sigma0 + majority, context + " T2 mismatch");
  require(trace.e_after == trace.d_before + trace.temp1, context + " new_e mismatch");
  require(trace.a_after == trace.temp1 + trace.temp2, context + " new_a mismatch");
  require(trace.b_after == trace.a_before && trace.c_after == trace.b_before &&
              trace.d_after == trace.c_before && trace.f_after == trace.e_before &&
              trace.g_after == trace.f_before && trace.h_after == trace.g_before,
          context + " state transfer mismatch");

  return {
      {"sha_pass", sha_pass},
      {"compression_index", compression_index},
      {"chunk_index", chunk_index},
      {"round_index", round},
      {"round_number", round + 1U},
      {"K", word_json(kRoundConstants[round])},
      {"W", word_json(trace.w)},
      {"state_before", named_state_json(before_state(trace), kStateNames)},
      {"Sigma0", {
          {"formula", "ROTR2(a) XOR ROTR13(a) XOR ROTR22(a)"},
          {"rotr2_a", word_json(rotr2)}, {"rotr13_a", word_json(rotr13)},
          {"rotr22_a", word_json(rotr22)}, {"result", word_json(sigma0)},
          {"carry_behavior", "none_bitwise"}}},
      {"Sigma1", {
          {"formula", "ROTR6(e) XOR ROTR11(e) XOR ROTR25(e)"},
          {"rotr6_e", word_json(rotr6)}, {"rotr11_e", word_json(rotr11)},
          {"rotr25_e", word_json(rotr25)}, {"result", word_json(sigma1)},
          {"carry_behavior", "none_bitwise"}}},
      {"Ch", {
          {"formula", "(e AND f) XOR ((NOT e) AND g)"},
          {"e_and_f", word_json(e_and_f)}, {"not_e", word_json(not_e)},
          {"not_e_and_g", word_json(not_e_and_g)}, {"result", word_json(choice)},
          {"carry_behavior", "none_bitwise"}}},
      {"Maj", {
          {"formula", "(a AND b) XOR (a AND c) XOR (b AND c)"},
          {"a_and_b", word_json(a_and_b)}, {"a_and_c", word_json(a_and_c)},
          {"b_and_c", word_json(b_and_c)}, {"result", word_json(majority)},
          {"carry_behavior", "none_bitwise"}}},
      {"additions", {
          {"T1", addition_json(
              {{"h", trace.h_before}, {"Sigma1(e)", sigma1}, {"Ch(e,f,g)", choice},
               {"K[t]", kRoundConstants[round]}, {"W[t]", trace.w}},
              trace.temp1, context + "/T1")},
          {"T2", addition_json(
              {{"Sigma0(a)", sigma0}, {"Maj(a,b,c)", majority}},
              trace.temp2, context + "/T2")},
          {"new_e", addition_json(
              {{"d", trace.d_before}, {"T1", trace.temp1}},
              trace.e_after, context + "/new_e")},
          {"new_a", addition_json(
              {{"T1", trace.temp1}, {"T2", trace.temp2}},
              trace.a_after, context + "/new_a")}}},
      {"state_after", named_state_json(after_state(trace), kStateNames)},
      {"transfers", {
          {"b_after_from_a_before", word_json(trace.b_after)},
          {"c_after_from_b_before", word_json(trace.c_after)},
          {"d_after_from_c_before", word_json(trace.d_after)},
          {"f_after_from_e_before", word_json(trace.f_after)},
          {"g_after_from_f_before", word_json(trace.g_after)},
          {"h_after_from_g_before", word_json(trace.h_after)}}}};
}

nlohmann::json compression_json(
    const unsigned sha_pass,
    const unsigned compression_index,
    const unsigned chunk_index,
    const Block& block,
    const std::span<const crypto::Sha256RoundTrace> rounds,
    const State& output_state,
    nlohmann::json source_segments) {
  const auto context = "sha" + std::to_string(sha_pass) + "/compression" +
                       std::to_string(compression_index);
  require(rounds.size() == 64U, context + " round count is not 64");
  const auto observed_compression_index = sha_pass == 1U ? chunk_index : 0U;
  for (std::size_t i = 0; i < rounds.size(); ++i) {
    require(rounds[i].round_index == i, context + " round index mismatch");
    require(rounds[i].compression_index == observed_compression_index,
            context + " observed compression index mismatch");
  }
  const auto input_state = before_state(rounds.front());
  const auto working_state = after_state(rounds.back());
  auto rounds_json = nlohmann::json::array();
  for (std::size_t i = 0; i < rounds.size(); ++i) {
    rounds_json.push_back(round_json(
        rounds[i], sha_pass, compression_index, chunk_index,
        context + "/round" + std::to_string(i)));
  }
  auto feed_forward = nlohmann::json::array();
  for (std::size_t i = 0; i < input_state.size(); ++i) {
    feed_forward.push_back({
        {"word_index", i},
        {"chaining_word", kChainingNames[i]},
        {"working_register", kStateNames[i]},
        {"addition", addition_json(
            {{std::string(kChainingNames[i]) + "_old", input_state[i]},
             {std::string(kStateNames[i]) + "_round63", working_state[i]}},
            output_state[i], context + "/feed_forward/" + kChainingNames[i])},
        {"result", word_json(output_state[i])}});
  }
  return {
      {"sha_pass", sha_pass},
      {"compression_index", compression_index},
      {"chunk_index", chunk_index},
      {"input_chaining_state", named_state_json(input_state, kChainingNames)},
      {"chunk", chunk_json(block, sha_pass, compression_index, chunk_index,
                           std::move(source_segments))},
      {"initial_words", [&] {
         auto result = nlohmann::json::array();
         for (std::size_t i = 0; i < 16; ++i) {
           result.push_back({{"t", i}, {"value", word_json(read_be32(block.data() + i * 4U))}});
         }
         return result;
       }()},
      {"message_schedule", schedule_json(block, rounds, context)},
      {"rounds", std::move(rounds_json)},
      {"final_working_state", named_state_json(working_state, kStateNames)},
      {"feed_forward", std::move(feed_forward)},
      {"output_chaining_state", named_state_json(output_state, kChainingNames)}};
}

std::uint32_t json_word(const nlohmann::json& value, const std::string& context) {
  require(value.is_object() && value.contains("uint32"), context + " is not a word object");
  const auto word = value.at("uint32").get<std::uint32_t>();
  require(value.at("hex").get<std::string>() == hex_word(word), context + " hexadecimal representation mismatch");
  require(value.at("binary").get<std::string>() == binary_value(word, 32), context + " binary representation mismatch");
  const auto& moduli = value.at("mod_2k");
  for (const auto bits : kModulusBits) {
    require(moduli.at("mod_2^" + std::to_string(bits)).get<std::uint32_t>() == low_bits(word, bits),
            context + " modulo 2^" + std::to_string(bits) + " mismatch");
  }
  return word;
}

std::uint32_t validate_addition(const nlohmann::json& addition,
                                const std::string& context) {
  const auto& operands = addition.at("operands");
  require(operands.is_array() && !operands.empty(), context + " operands missing");
  std::vector<std::pair<std::string, std::uint32_t>> values;
  std::uint64_t wide_sum = 0;
  for (std::size_t i = 0; i < operands.size(); ++i) {
    const auto name = operands[i].at("name").get<std::string>();
    const auto value = json_word(operands[i].at("value"), context + "/operand" + std::to_string(i));
    values.emplace_back(name, value);
    wide_sum += value;
  }
  const auto expected = static_cast<std::uint32_t>(wide_sum);
  require(json_word(addition.at("result"), context + "/result") == expected,
          context + " modular result mismatch");

  const auto& columns = addition.at("bit_columns_lsb_to_msb");
  require(columns.size() == 32U, context + " must contain 32 bit columns");
  std::uint64_t carry = 0;
  std::uint32_t reconstructed = 0;
  std::vector<unsigned> nonzero;
  std::vector<std::uint64_t> profile;
  unsigned longest = 0;
  unsigned current = 0;
  std::uint64_t maximum = 0;
  for (unsigned bit = 0; bit < 32; ++bit) {
    const auto& column = columns[bit];
    require(column.at("bit_index").get<unsigned>() == bit, context + " bit index mismatch");
    require(column.at("carry_in").get<std::uint64_t>() == carry, context + " carry_in mismatch");
    const auto& bits = column.at("operand_bits");
    require(bits.size() == values.size(), context + " operand bit count mismatch");
    std::uint64_t column_sum = carry;
    for (std::size_t i = 0; i < values.size(); ++i) {
      const auto expected_bit = static_cast<unsigned>((values[i].second >> bit) & 1U);
      require(bits[i].at("name").get<std::string>() == values[i].first,
              context + " operand bit name mismatch");
      require(bits[i].at("bit").get<unsigned>() == expected_bit,
              context + " operand bit value mismatch");
      column_sum += expected_bit;
    }
    require(column.at("column_sum_integer").get<std::uint64_t>() == column_sum,
            context + " column integer sum mismatch");
    const auto result_bit = static_cast<unsigned>(column_sum & 1U);
    require(column.at("result_bit").get<unsigned>() == result_bit,
            context + " result bit mismatch");
    if (result_bit != 0) reconstructed |= std::uint32_t{1} << bit;
    carry = column_sum >> 1U;
    require(column.at("carry_out").get<std::uint64_t>() == carry,
            context + " carry_out mismatch");
    profile.push_back(carry);
    maximum = std::max(maximum, carry);
    if (carry != 0) {
      nonzero.push_back(bit);
      longest = std::max(longest, ++current);
    } else {
      current = 0;
    }
  }
  require(reconstructed == expected, context + " bit columns do not reconstruct result");
  const auto& summary = addition.at("carry_summary");
  require(summary.at("nonzero_carry_columns").get<std::vector<unsigned>>() == nonzero,
          context + " nonzero carry columns mismatch");
  require(summary.at("nonzero_carry_count").get<std::size_t>() == nonzero.size(),
          context + " nonzero carry count mismatch");
  require(summary.at("max_carry_value").get<std::uint64_t>() == maximum,
          context + " maximum carry mismatch");
  require(summary.at("longest_nonzero_carry_run").get<unsigned>() == longest,
          context + " longest carry run mismatch");
  require(summary.at("final_carry_out").get<std::uint64_t>() == carry,
          context + " final carry mismatch");
  require(summary.at("carry_profile").get<std::vector<std::uint64_t>>() == profile,
          context + " carry profile mismatch");
  return expected;
}

std::vector<const nlohmann::json*> compressions(const nlohmann::json& trace) {
  std::vector<const nlohmann::json*> result;
  for (const auto& compression : trace.at("sha256_first").at("compressions")) result.push_back(&compression);
  for (const auto& compression : trace.at("sha256_second").at("compressions")) result.push_back(&compression);
  return result;
}

State json_state(const nlohmann::json& state,
                 const std::array<const char*, 8>& names,
                 const std::string& context) {
  State result{};
  for (std::size_t i = 0; i < result.size(); ++i) {
    result[i] = json_word(state.at(names[i]), context + "/" + names[i]);
  }
  return result;
}

void observe_addition_stats(const nlohmann::json& addition,
                            const std::string& identity,
                            CompressionStats& stats) {
  ++stats.addition_count;
  const auto& carry = addition.at("carry_summary");
  const auto count = carry.at("nonzero_carry_count").get<unsigned>();
  ++stats.carry_count_distribution[count];
  stats.maximum_carry = std::max(stats.maximum_carry,
                                 carry.at("max_carry_value").get<std::uint64_t>());
  if (count == 0U) stats.additions_without_carry.push_back(identity);
}

std::vector<CompressionStats> collect_stats(const nlohmann::json& trace) {
  std::vector<CompressionStats> result;
  for (const auto* compression : compressions(trace)) {
    CompressionStats stats;
    stats.sha_pass = compression->at("sha_pass").get<unsigned>();
    stats.compression_index = compression->at("compression_index").get<unsigned>();
    const auto& schedule = compression->at("message_schedule").at("words");
    for (std::size_t t = 16; t < schedule.size(); ++t) {
      observe_addition_stats(schedule[t].at("addition"), "W[" + std::to_string(t) + "]", stats);
    }
    for (const auto& round : compression->at("rounds")) {
      unsigned round_total = 0;
      for (const auto* name : {"T1", "T2", "new_a", "new_e"}) {
        const auto& addition = round.at("additions").at(name);
        observe_addition_stats(addition,
                               "round " + std::to_string(round.at("round_index").get<unsigned>()) + "/" + name,
                               stats);
        round_total += addition.at("carry_summary").at("nonzero_carry_count").get<unsigned>();
      }
      const auto round_index = round.at("round_index").get<unsigned>();
      if (round_total == 0U) stats.rounds_without_carry.push_back(round_index);
      if (round_total > stats.maximum_round_carry_columns) {
        stats.maximum_round_carry_columns = round_total;
        stats.rounds_with_most_carry_columns = {round_index};
      } else if (round_total == stats.maximum_round_carry_columns) {
        stats.rounds_with_most_carry_columns.push_back(round_index);
      }
    }
    for (const auto& item : compression->at("feed_forward")) {
      observe_addition_stats(item.at("addition"),
                             "feed_forward/" + item.at("chaining_word").get<std::string>(), stats);
    }
    result.push_back(std::move(stats));
  }
  return result;
}

nlohmann::json stats_json(const std::vector<CompressionStats>& stats,
                          const nlohmann::json& trace) {
  auto result = nlohmann::json::array();
  const auto all_compressions = compressions(trace);
  for (std::size_t i = 0; i < stats.size(); ++i) {
    auto distribution = nlohmann::json::object();
    for (const auto& [carry_count, frequency] : stats[i].carry_count_distribution) {
      distribution[std::to_string(carry_count)] = frequency;
    }
    const auto& compression = *all_compressions[i];
    const auto& schedule = compression.at("message_schedule").at("words");
    result.push_back({
        {"sha_pass", stats[i].sha_pass},
        {"compression_index", stats[i].compression_index},
        {"total_additions", stats[i].addition_count},
        {"nonzero_carry_count_distribution", std::move(distribution)},
        {"maximum_carry_value", stats[i].maximum_carry},
        {"additions_without_carry", stats[i].additions_without_carry},
        {"rounds_without_carry", stats[i].rounds_without_carry},
        {"maximum_total_round_carry_columns", stats[i].maximum_round_carry_columns},
        {"rounds_with_most_carry_columns", stats[i].rounds_with_most_carry_columns},
        {"message_schedule_summary", {
            {"word_count", schedule.size()},
            {"direct_word_count", 16},
            {"extended_word_count", 48},
            {"W0", schedule[0].at("result")},
            {"W15", schedule[15].at("result")},
            {"W16", schedule[16].at("result")},
            {"W63", schedule[63].at("result")}}},
        {"input_chaining_state", compression.at("input_chaining_state")},
        {"output_chaining_state", compression.at("output_chaining_state")}});
  }
  return result;
}

std::string markdown_summary(const nlohmann::json& trace,
                             const std::string_view title) {
  std::ostringstream out;
  out << "# " << title << "\n\n"
      << "Forward-only deterministic trace. This is one specimen, not a cryptanalytic conclusion.\n\n"
      << "- Header bytes: 80\n"
      << "- Compressions: 3\n"
      << "- Rounds: 192\n"
      << "- Schedule words: 3 x 64\n"
      << "- Raw SHA256d: `" << trace.at("final").at("raw_sha256d").get<std::string>() << "`\n"
      << "- Bitcoin display hash: `" << trace.at("final").at("bitcoin_display_hash").get<std::string>() << "`\n\n"
      << "## Compression summaries\n\n"
      << "| SHA | Compression | Additions | Max carry | Carry-count distribution | Carry-free additions | Max round carry columns | Rounds at maximum |\n"
      << "|---:|---:|---:|---:|---|---:|---:|---|\n";
  for (const auto& item : trace.at("compression_summaries")) {
    std::ostringstream distribution;
    bool first = true;
    for (const auto& [count, frequency] : item.at("nonzero_carry_count_distribution").items()) {
      if (!first) distribution << ", ";
      first = false;
      distribution << count << ":" << frequency.get<std::size_t>();
    }
    std::ostringstream rounds;
    first = true;
    for (const auto& round : item.at("rounds_with_most_carry_columns")) {
      if (!first) rounds << ",";
      first = false;
      rounds << round.get<unsigned>();
    }
    out << "| " << item.at("sha_pass").get<unsigned>()
        << " | " << item.at("compression_index").get<unsigned>()
        << " | " << item.at("total_additions").get<std::size_t>()
        << " | " << item.at("maximum_carry_value").get<std::uint64_t>()
        << " | " << distribution.str()
        << " | " << item.at("additions_without_carry").size()
        << " | " << item.at("maximum_total_round_carry_columns").get<unsigned>()
        << " | " << rounds.str() << " |\n";
  }

  const auto compact_state = [](const nlohmann::json& state) {
    std::ostringstream value;
    bool first = true;
    for (const auto* name : kChainingNames) {
      if (!first) value << ' ';
      first = false;
      value << name << '=' << state.at(name).at("hex").get<std::string>();
    }
    return value.str();
  };
  out << "\n### Per-compression states and schedules\n";
  for (const auto& item : trace.at("compression_summaries")) {
    const auto& schedule = item.at("message_schedule_summary");
    out << "\n- SHA " << item.at("sha_pass").get<unsigned>()
        << ", compression " << item.at("compression_index").get<unsigned>()
        << ": W0=`" << schedule.at("W0").at("hex").get<std::string>()
        << "`, W15=`" << schedule.at("W15").at("hex").get<std::string>()
        << "`, W16=`" << schedule.at("W16").at("hex").get<std::string>()
        << "`, W63=`" << schedule.at("W63").at("hex").get<std::string>()
        << "`; carry-free additions=" << item.at("additions_without_carry").size()
        << "; rounds without carry=" << item.at("rounds_without_carry").size() << ".\n"
        << "  - Input: `" << compact_state(item.at("input_chaining_state")) << "`\n"
        << "  - Output: `" << compact_state(item.at("output_chaining_state")) << "`\n";
  }

  out << "\n## All 192 rounds\n\n"
      << "All words are lowercase eight-digit hexadecimal. Carry counts mean columns whose `carry_out` is nonzero.\n\n"
      << "| SHA | Compression | Round | W | a before | e before | Sigma0 | Sigma1 | Ch | Maj | T1 | T2 | a after | e after | T1 carries | T1 max | T2 carries | new_a carries | new_e carries |\n"
      << "|---:|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|---:|\n";
  for (const auto* compression : compressions(trace)) {
    for (const auto& round : compression->at("rounds")) {
      const auto& additions = round.at("additions");
      const auto carry_count = [&](const char* name) {
        return additions.at(name).at("carry_summary").at("nonzero_carry_count").get<unsigned>();
      };
      const auto word_hex = [](const nlohmann::json& word) {
        return word.at("hex").get<std::string>();
      };
      out << "| " << round.at("sha_pass").get<unsigned>()
          << " | " << round.at("compression_index").get<unsigned>()
          << " | " << round.at("round_index").get<unsigned>()
          << " | " << word_hex(round.at("W"))
          << " | " << word_hex(round.at("state_before").at("a"))
          << " | " << word_hex(round.at("state_before").at("e"))
          << " | " << word_hex(round.at("Sigma0").at("result"))
          << " | " << word_hex(round.at("Sigma1").at("result"))
          << " | " << word_hex(round.at("Ch").at("result"))
          << " | " << word_hex(round.at("Maj").at("result"))
          << " | " << word_hex(additions.at("T1").at("result"))
          << " | " << word_hex(additions.at("T2").at("result"))
          << " | " << word_hex(round.at("state_after").at("a"))
          << " | " << word_hex(round.at("state_after").at("e"))
          << " | " << carry_count("T1")
          << " | " << additions.at("T1").at("carry_summary").at("max_carry_value").get<std::uint64_t>()
          << " | " << carry_count("T2")
          << " | " << carry_count("new_a")
          << " | " << carry_count("new_e") << " |\n";
    }
  }
  return out.str();
}

}  // namespace

const SpecimenMetadata& genesis_specimen_metadata() {
  static const SpecimenMetadata metadata{
      "bitcoin_genesis_sha256d_whitebox_reference",
      "Bitcoin Genesis SHA256d white-box summary",
      "genesis_sha256d",
      std::string(kExpectedFirstSha256),
      std::string(kExpectedRawSha256d),
      std::string(kExpectedBitcoinHash)};
  return metadata;
}

const SpecimenMetadata& genesis_nonce_plus_one_specimen_metadata() {
  static const SpecimenMetadata metadata{
      "bitcoin_genesis_nonce_plus_1_sha256d_whitebox_reference",
      "Bitcoin Genesis nonce +1 SHA256d white-box summary",
      "genesis_nonce_plus_1_sha256d",
      std::string(kNoncePlusOneFirstSha256),
      std::string(kNoncePlusOneRawSha256d),
      std::string(kNoncePlusOneBitcoinHash)};
  return metadata;
}

const SpecimenMetadata& genesis_nonce_bit0_flip_specimen_metadata() {
  static const SpecimenMetadata metadata{
      "bitcoin_genesis_nonce_bit0_flip_sha256d_whitebox_reference",
      "Bitcoin Genesis nonce bit 0 flip SHA256d white-box summary",
      "genesis_nonce_bit0_flip_sha256d",
      std::string(kNonceBit0FlipFirstSha256),
      std::string(kNonceBit0FlipRawSha256d),
      std::string(kNonceBit0FlipBitcoinHash)};
  return metadata;
}

Artifacts build_sha256d_whitebox(const std::span<const std::uint8_t> header,
                                 const SpecimenMetadata& metadata) {
  require(header.size() == 80U, "Bitcoin header is not 80 bytes");
  const auto reference_digest = crypto::sha256d(header);
  const auto reference_first_digest = crypto::sha256(header);
  const auto reference_first_hex = crypto::digest_hex(reference_first_digest);
  const auto reference_raw_hex = crypto::digest_hex(reference_digest);
  const auto reference_display_hex = crypto::bitcoin_hash_hex(reference_digest);
  if (!metadata.expected_first_sha256.empty()) {
    require(reference_first_hex == metadata.expected_first_sha256,
            "production SHA-256 does not match the specimen's first-digest vector");
  }
  if (!metadata.expected_raw_sha256d.empty()) {
    require(reference_raw_hex == metadata.expected_raw_sha256d,
            "production SHA256d does not match the specimen's raw-digest vector");
  }
  if (!metadata.expected_bitcoin_display_hash.empty()) {
    require(reference_display_hex == metadata.expected_bitcoin_display_hash,
            "production SHA256d does not match the specimen's display-hash vector");
  }
  const auto expected_display_hash = metadata.expected_bitcoin_display_hash.empty()
      ? reference_display_hex
      : metadata.expected_bitcoin_display_hash;

  const auto observed = crypto::trace_reduced_sha256d(header, 64);
  require(observed.digest == reference_digest, "observed 64-round trace differs from production SHA256d");
  require(observed.first_sha.rounds.size() == 128U, "first SHA trace does not contain 128 rounds");
  require(observed.second_sha.rounds.size() == 64U, "second SHA trace does not contain 64 rounds");

  Block first_chunk{};
  std::copy_n(header.begin(), first_chunk.size(), first_chunk.begin());
  const auto first_tail = padded_final_block(header, 64U);
  const auto second_chunk = padded_final_block(observed.first_sha.digest, 0U);
  const std::vector<Block> first_blocks{first_chunk, first_tail};
  const std::vector<Block> second_blocks{second_chunk};

  const std::span<const crypto::Sha256RoundTrace> c0(observed.first_sha.rounds.data(), 64U);
  const std::span<const crypto::Sha256RoundTrace> c1(observed.first_sha.rounds.data() + 64U, 64U);
  const std::span<const crypto::Sha256RoundTrace> c2(observed.second_sha.rounds.data(), 64U);
  const auto first_midstate = before_state(observed.first_sha.rounds[64]);
  const auto first_digest_words = digest_words(observed.first_sha.digest);
  const auto second_digest_words = digest_words(observed.second_sha.digest);

  auto first_compressions = nlohmann::json::array();
  first_compressions.push_back(compression_json(
      1U, 0U, 0U, first_chunk, c0, first_midstate,
      nlohmann::json::array({{{"kind", "header_bytes"}, {"header_byte_start", 0}, {"header_byte_end", 63}}})));
  first_compressions.push_back(compression_json(
      1U, 1U, 1U, first_tail, c1, first_digest_words,
      nlohmann::json::array({
          {{"kind", "header_bytes"}, {"header_byte_start", 64}, {"header_byte_end", 79}},
          {{"kind", "one_bit_marker"}, {"chunk_byte_start", 16}, {"chunk_byte_end", 16}, {"hex", "80"}},
          {{"kind", "zero_padding"}, {"chunk_byte_start", 17}, {"chunk_byte_end", 55}, {"byte_count", 39}},
          {{"kind", "encoded_message_bit_length"}, {"chunk_byte_start", 56}, {"chunk_byte_end", 63}, {"uint64", 640}, {"hex", "0000000000000280"}}})));
  auto second_compressions = nlohmann::json::array();
  second_compressions.push_back(compression_json(
      2U, 2U, 0U, second_chunk, c2, second_digest_words,
      nlohmann::json::array({
          {{"kind", "first_sha_digest_bytes"}, {"digest_byte_start", 0}, {"digest_byte_end", 31}},
          {{"kind", "one_bit_marker"}, {"chunk_byte_start", 32}, {"chunk_byte_end", 32}, {"hex", "80"}},
          {{"kind", "zero_padding"}, {"chunk_byte_start", 33}, {"chunk_byte_end", 55}, {"byte_count", 23}},
          {{"kind", "encoded_message_bit_length"}, {"chunk_byte_start", 56}, {"chunk_byte_end", 63}, {"uint64", 256}, {"hex", "0000000000000100"}}})));

  nlohmann::json trace = nlohmann::json::object();
  trace["schema_version"] = 1;
  trace["experiment"] = {
      {"id", metadata.experiment_id},
      {"scope", "one known 80-byte Bitcoin header"},
      {"direction", "forward_only_header_to_first_sha256_to_second_sha256_to_final_hash"},
      {"interpretation", "descriptive specimen only; no cryptanalytic or predictive claim"},
      {"rounds_per_compression", 64},
      {"compression_count", 3},
      {"total_round_count", 192},
      {"modulo_projection_bits", kModulusBits}};
  trace["operation_semantics"] = {
      {"bit_indexing", "bit 0 is the least-significant bit; addition columns are stored from bit 0 through bit 31"},
      {"word_serialization", "SHA-256 message words are uint32 decoded big-endian from each four-byte chunk group"},
      {"rotations", {
          {"ROTR_n_output_bit_i_source", "input bit ((i+n) mod 32)"},
          {"SHR_n_output_bit_i_source", "input bit (i+n) when i+n<32, otherwise constant zero"}}},
      {"carry_free_operations", {"ROTR", "SHR", "XOR", "AND", "NOT", "Ch", "Maj"}},
      {"addition_model", "exact integer-valued carry per binary column; multi-operand carry is not boolean"}};
  trace["input"] = {
      {"header_hex", crypto::to_hex(header)},
      {"header_byte_length", header.size()},
      {"header_bytes", bytes_json(header)},
      {"fields", {
          {"version", {{"uint32", read_le32(header.data())}, {"serialized_little_endian_hex", crypto::to_hex(std::span<const std::uint8_t>(header.data(), 4))}}},
          {"previous_block_hash", {{"display_hex", reversed_hex(std::span<const std::uint8_t>(header.data() + 4, 32))}, {"serialized_hex", crypto::to_hex(std::span<const std::uint8_t>(header.data() + 4, 32))}}},
          {"merkle_root", {{"display_hex", reversed_hex(std::span<const std::uint8_t>(header.data() + 36, 32))}, {"serialized_hex", crypto::to_hex(std::span<const std::uint8_t>(header.data() + 36, 32))}}},
          {"nTime", {{"uint32", read_le32(header.data() + 68)}, {"serialized_little_endian_hex", crypto::to_hex(std::span<const std::uint8_t>(header.data() + 68, 4))}}},
          {"nBits", {{"uint32", read_le32(header.data() + 72)}, {"hex", hex_word(read_le32(header.data() + 72))}, {"serialized_little_endian_hex", crypto::to_hex(std::span<const std::uint8_t>(header.data() + 72, 4))}}},
          {"nonce", {{"uint32", read_le32(header.data() + 76)}, {"hex", hex_word(read_le32(header.data() + 76))}, {"serialized_little_endian_hex", crypto::to_hex(std::span<const std::uint8_t>(header.data() + 76, 4))}}}}}};
  trace["sha256_first"] = {
      {"input", {{"byte_length", header.size()}, {"hex", crypto::to_hex(header)}}},
      {"padding", padding_json(header, first_blocks, 1U)},
      {"compressions", std::move(first_compressions)},
      {"output", {
          {"chaining_words", named_state_json(first_digest_words, kChainingNames)},
          {"digest_hex", crypto::digest_hex(observed.first_sha.digest)},
          {"digest_byte_length", observed.first_sha.digest.size()},
          {"digest_bytes", bytes_json(observed.first_sha.digest)}}}};
  trace["sha256_bridge"] = {
      {"rule", "the exact 32 raw digest bytes of the first SHA-256 are the complete input message of the second SHA-256"},
      {"first_sha_digest_hex", crypto::digest_hex(observed.first_sha.digest)},
      {"second_sha_input_hex", crypto::digest_hex(observed.first_sha.digest)},
      {"exact_byte_match", true}};
  trace["sha256_second"] = {
      {"input_digest", {
          {"byte_length", observed.first_sha.digest.size()},
          {"hex", crypto::digest_hex(observed.first_sha.digest)},
          {"bytes", bytes_json(observed.first_sha.digest)}}},
      {"padding", padding_json(observed.first_sha.digest, second_blocks, 2U)},
      {"compressions", std::move(second_compressions)},
      {"output", {
          {"chaining_words", named_state_json(second_digest_words, kChainingNames)},
          {"digest_hex", crypto::digest_hex(observed.second_sha.digest)},
          {"digest_byte_length", observed.second_sha.digest.size()},
          {"digest_bytes", bytes_json(observed.second_sha.digest)}}}};
  trace["final"] = {
      {"raw_sha256d", crypto::digest_hex(observed.digest)},
      {"raw_digest_byte_order", "SHA-256 digest byte order"},
      {"bitcoin_display_hash", crypto::bitcoin_hash_hex(observed.digest)},
      {"bitcoin_display_rule", "reverse the 32 raw SHA256d digest bytes"},
      {"expected_bitcoin_display_hash", expected_display_hash}};

  trace["compression_summaries"] = stats_json(collect_stats(trace), trace);
  trace["validation"] = validate_sha256d_whitebox(trace);
  require(trace.at("final").at("bitcoin_display_hash").get<std::string>() == expected_display_hash,
          "final guard rejected specimen display hash");
  return {trace, markdown_summary(trace, metadata.summary_title)};
}

Artifacts build_genesis_sha256d_whitebox() {
  const auto header = header_space::genesis_header();
  require(crypto::to_hex(header) == kExpectedHeaderHex,
          "Genesis header serialization mismatch before tracing");
  auto artifacts = build_sha256d_whitebox(header, genesis_specimen_metadata());
  artifacts.trace["validation"] = validate_genesis_sha256d_whitebox(artifacts.trace);
  return artifacts;
}

Artifacts build_genesis_nonce_plus_one_sha256d_whitebox() {
  const auto header = crypto::from_hex(kNoncePlusOneHeaderHex);
  auto artifacts = build_sha256d_whitebox(
      header, genesis_nonce_plus_one_specimen_metadata());
  artifacts.trace["validation"] =
      validate_genesis_nonce_plus_one_sha256d_whitebox(artifacts.trace);
  return artifacts;
}

Artifacts build_genesis_nonce_bit0_flip_sha256d_whitebox() {
  const auto header = crypto::from_hex(kNonceBit0FlipHeaderHex);
  auto artifacts = build_sha256d_whitebox(
      header, genesis_nonce_bit0_flip_specimen_metadata());
  artifacts.trace["validation"] =
      validate_genesis_nonce_bit0_flip_sha256d_whitebox(artifacts.trace);
  return artifacts;
}

nlohmann::json validate_sha256d_whitebox(const nlohmann::json& trace) {
  const auto header = crypto::from_hex(trace.at("input").at("header_hex").get<std::string>());
  require(header.size() == 80U, "header length is not 80 bytes");
  require(trace.at("input").at("header_byte_length").get<std::size_t>() == 80U,
          "recorded header byte length mismatch");
  validate_bytes_json(trace.at("input").at("header_bytes"), header, 0U, "input/header_bytes");
  require(trace.at("sha256_first").at("padding").at("input_bit_length").get<std::uint64_t>() == 640U,
          "first SHA encoded length is not 640 bits");
  require(trace.at("sha256_second").at("padding").at("input_bit_length").get<std::uint64_t>() == 256U,
          "second SHA encoded length is not 256 bits");

  Block expected_first_chunk{};
  std::copy_n(header.begin(), expected_first_chunk.size(), expected_first_chunk.begin());
  const auto expected_first_tail = padded_final_block(header, 64U);
  const auto reference_first_digest = crypto::sha256(header);
  const auto expected_second_chunk = padded_final_block(reference_first_digest, 0U);
  const std::array<Block, 3> expected_blocks{
      expected_first_chunk, expected_first_tail, expected_second_chunk};
  const auto expected_first_padded = crypto::to_hex(expected_first_chunk) + crypto::to_hex(expected_first_tail);
  require(trace.at("sha256_first").at("padding").at("padded_message_hex").get<std::string>() == expected_first_padded,
          "first SHA padded message mismatch");
  require(trace.at("sha256_second").at("padding").at("padded_message_hex").get<std::string>() == crypto::to_hex(expected_second_chunk),
          "second SHA padded message mismatch");
  require(trace.at("sha256_first").at("padding").at("encoded_length").at("hex").get<std::string>() == "0000000000000280",
          "first SHA encoded length bytes mismatch");
  require(trace.at("sha256_second").at("padding").at("encoded_length").at("hex").get<std::string>() == "0000000000000100",
          "second SHA encoded length bytes mismatch");

  const auto all = compressions(trace);
  require(all.size() == kCompressionCount, "compression count is not 3");
  State expected_input = kInitialState;
  std::size_t total_rounds = 0;
  std::size_t total_schedule_words = 0;
  bool multi_operand_carry_above_one = false;
  State first_digest_state{};
  State final_digest_state{};

  for (std::size_t compression_position = 0; compression_position < all.size(); ++compression_position) {
    const auto& compression = *all[compression_position];
    const auto global_index = compression.at("compression_index").get<unsigned>();
    require(global_index == compression_position, "global compression index mismatch");
    if (compression_position == 2U) expected_input = kInitialState;
    const auto input_state = json_state(compression.at("input_chaining_state"), kChainingNames,
                                        "compression/input_state");
    require(input_state == expected_input, "compression input chaining state mismatch");

    const auto block_bytes = crypto::from_hex(compression.at("chunk").at("hex").get<std::string>());
    require(block_bytes.size() == 64U, "compression chunk is not 64 bytes");
    require(block_bytes == std::vector<std::uint8_t>(expected_blocks[compression_position].begin(),
                                                     expected_blocks[compression_position].end()),
            "compression chunk differs from independently padded input");
    validate_bytes_json(compression.at("chunk").at("bytes"), block_bytes, 0U,
                        "compression/chunk/bytes");
    const auto& schedule = compression.at("message_schedule").at("words");
    require(schedule.size() == 64U, "message schedule does not contain 64 words");
    total_schedule_words += schedule.size();
    std::array<std::uint32_t, 64> w{};
    for (std::size_t t = 0; t < 16; ++t) {
      w[t] = read_be32(block_bytes.data() + t * 4U);
      validate_bytes_json(schedule[t].at("source_bytes"),
                          std::span<const std::uint8_t>(block_bytes.data() + t * 4U, 4U),
                          t * 4U, "schedule/source_bytes");
      require(json_word(schedule[t].at("result"), "schedule direct word") == w[t],
              "direct schedule word mismatch");
      require(json_word(compression.at("initial_words").at(t).at("value"), "initial word") == w[t],
              "initial word list mismatch");
    }
    for (std::size_t t = 16; t < w.size(); ++t) {
      const auto sigma0 = std::rotr(w[t - 15U], 7) ^ std::rotr(w[t - 15U], 18) ^ (w[t - 15U] >> 3U);
      const auto sigma1 = std::rotr(w[t - 2U], 17) ^ std::rotr(w[t - 2U], 19) ^ (w[t - 2U] >> 10U);
      const auto& schedule_inputs = schedule[t].at("inputs");
      require(json_word(schedule_inputs.at("w_t_minus_16"), "schedule W[t-16]") == w[t - 16U],
              "recorded W[t-16] mismatch");
      require(json_word(schedule_inputs.at("w_t_minus_15"), "schedule W[t-15]") == w[t - 15U],
              "recorded W[t-15] mismatch");
      require(json_word(schedule_inputs.at("w_t_minus_7"), "schedule W[t-7]") == w[t - 7U],
              "recorded W[t-7] mismatch");
      require(json_word(schedule_inputs.at("w_t_minus_2"), "schedule W[t-2]") == w[t - 2U],
              "recorded W[t-2] mismatch");
      require(json_word(schedule[t].at("small_sigma0").at("rotr7"), "schedule ROTR7") == std::rotr(w[t - 15U], 7),
              "schedule ROTR7 mismatch");
      require(json_word(schedule[t].at("small_sigma0").at("rotr18"), "schedule ROTR18") == std::rotr(w[t - 15U], 18),
              "schedule ROTR18 mismatch");
      require(json_word(schedule[t].at("small_sigma0").at("shr3"), "schedule SHR3") == (w[t - 15U] >> 3U),
              "schedule SHR3 mismatch");
      require(json_word(schedule[t].at("small_sigma1").at("rotr17"), "schedule ROTR17") == std::rotr(w[t - 2U], 17),
              "schedule ROTR17 mismatch");
      require(json_word(schedule[t].at("small_sigma1").at("rotr19"), "schedule ROTR19") == std::rotr(w[t - 2U], 19),
              "schedule ROTR19 mismatch");
      require(json_word(schedule[t].at("small_sigma1").at("shr10"), "schedule SHR10") == (w[t - 2U] >> 10U),
              "schedule SHR10 mismatch");
      w[t] = w[t - 16U] + sigma0 + w[t - 7U] + sigma1;
      require(validate_addition(schedule[t].at("addition"), "schedule addition") == w[t],
              "extended schedule addition mismatch");
      require(json_word(schedule[t].at("small_sigma0").at("result"), "small sigma0") == sigma0,
              "small sigma0 mismatch");
      require(json_word(schedule[t].at("small_sigma1").at("result"), "small sigma1") == sigma1,
              "small sigma1 mismatch");
      require(json_word(schedule[t].at("result"), "extended schedule word") == w[t],
              "extended schedule result mismatch");
    }

    const auto& rounds = compression.at("rounds");
    require(rounds.size() == 64U, "compression does not contain 64 rounds");
    total_rounds += rounds.size();
    auto state = input_state;
    for (std::size_t t = 0; t < rounds.size(); ++t) {
      const auto& round = rounds[t];
      require(round.at("round_index").get<unsigned>() == t, "round index mismatch");
      require(json_state(round.at("state_before"), kStateNames, "round/state_before") == state,
              "round state_before mismatch");
      require(json_word(round.at("K"), "round K") == kRoundConstants[t], "round constant mismatch");
      require(json_word(round.at("W"), "round W") == w[t], "round message word mismatch");
      const auto sigma0 = std::rotr(state[0], 2) ^ std::rotr(state[0], 13) ^ std::rotr(state[0], 22);
      const auto sigma1 = std::rotr(state[4], 6) ^ std::rotr(state[4], 11) ^ std::rotr(state[4], 25);
      const auto e_and_f = state[4] & state[5];
      const auto not_e = ~state[4];
      const auto not_e_and_g = not_e & state[6];
      const auto choice = e_and_f ^ not_e_and_g;
      const auto a_and_b = state[0] & state[1];
      const auto a_and_c = state[0] & state[2];
      const auto b_and_c = state[1] & state[2];
      const auto majority = a_and_b ^ a_and_c ^ b_and_c;
      require(json_word(round.at("Sigma0").at("rotr2_a"), "round ROTR2(a)") == std::rotr(state[0], 2),
              "ROTR2(a) mismatch");
      require(json_word(round.at("Sigma0").at("rotr13_a"), "round ROTR13(a)") == std::rotr(state[0], 13),
              "ROTR13(a) mismatch");
      require(json_word(round.at("Sigma0").at("rotr22_a"), "round ROTR22(a)") == std::rotr(state[0], 22),
              "ROTR22(a) mismatch");
      require(json_word(round.at("Sigma1").at("rotr6_e"), "round ROTR6(e)") == std::rotr(state[4], 6),
              "ROTR6(e) mismatch");
      require(json_word(round.at("Sigma1").at("rotr11_e"), "round ROTR11(e)") == std::rotr(state[4], 11),
              "ROTR11(e) mismatch");
      require(json_word(round.at("Sigma1").at("rotr25_e"), "round ROTR25(e)") == std::rotr(state[4], 25),
              "ROTR25(e) mismatch");
      require(json_word(round.at("Sigma0").at("result"), "round Sigma0") == sigma0, "Sigma0 mismatch");
      require(json_word(round.at("Sigma1").at("result"), "round Sigma1") == sigma1, "Sigma1 mismatch");
      require(json_word(round.at("Ch").at("e_and_f"), "round e AND f") == e_and_f, "e AND f mismatch");
      require(json_word(round.at("Ch").at("not_e"), "round NOT e") == not_e, "NOT e mismatch");
      require(json_word(round.at("Ch").at("not_e_and_g"), "round (NOT e) AND g") == not_e_and_g,
              "(NOT e) AND g mismatch");
      require(json_word(round.at("Ch").at("result"), "round Ch") == choice, "Ch mismatch");
      require(json_word(round.at("Maj").at("a_and_b"), "round a AND b") == a_and_b, "a AND b mismatch");
      require(json_word(round.at("Maj").at("a_and_c"), "round a AND c") == a_and_c, "a AND c mismatch");
      require(json_word(round.at("Maj").at("b_and_c"), "round b AND c") == b_and_c, "b AND c mismatch");
      require(json_word(round.at("Maj").at("result"), "round Maj") == majority, "Maj mismatch");
      const auto t1 = state[7] + sigma1 + choice + kRoundConstants[t] + w[t];
      const auto t2 = sigma0 + majority;
      const auto new_e = state[3] + t1;
      const auto new_a = t1 + t2;
      const auto& additions = round.at("additions");
      require(validate_addition(additions.at("T1"), "round T1") == t1, "T1 mismatch");
      require(validate_addition(additions.at("T2"), "round T2") == t2, "T2 mismatch");
      require(validate_addition(additions.at("new_e"), "round new_e") == new_e, "new_e mismatch");
      require(validate_addition(additions.at("new_a"), "round new_a") == new_a, "new_a mismatch");
      multi_operand_carry_above_one = multi_operand_carry_above_one ||
          additions.at("T1").at("carry_summary").at("max_carry_value").get<std::uint64_t>() > 1U;
      state = {new_a, state[0], state[1], state[2], new_e, state[4], state[5], state[6]};
      require(json_state(round.at("state_after"), kStateNames, "round/state_after") == state,
              "round state_after mismatch");
    }

    const auto& feed_forward = compression.at("feed_forward");
    require(feed_forward.size() == 8U, "feed-forward does not contain eight additions");
    State output{};
    for (std::size_t i = 0; i < output.size(); ++i) {
      output[i] = expected_input[i] + state[i];
      require(validate_addition(feed_forward[i].at("addition"), "feed-forward addition") == output[i],
              "feed-forward addition mismatch");
      require(json_word(feed_forward[i].at("result"), "feed-forward result") == output[i],
              "feed-forward result mismatch");
    }
    require(json_state(compression.at("output_chaining_state"), kChainingNames,
                       "compression/output_state") == output,
            "compression output chaining state mismatch");
    expected_input = output;
    if (compression_position == 1U) first_digest_state = output;
    if (compression_position == 2U) final_digest_state = output;
  }

  require(total_rounds == kTotalRoundCount, "total round count is not 192");
  require(total_schedule_words == kCompressionCount * kRoundsPerCompression,
          "total schedule word count is not 192");
  require(multi_operand_carry_above_one, "no five-operand addition preserved a carry_out greater than one");

  crypto::Digest first_digest{};
  crypto::Digest final_digest{};
  for (std::size_t i = 0; i < 8; ++i) {
    for (unsigned byte = 0; byte < 4; ++byte) {
      first_digest[i * 4U + byte] = static_cast<std::uint8_t>(first_digest_state[i] >> (24U - byte * 8U));
      final_digest[i * 4U + byte] = static_cast<std::uint8_t>(final_digest_state[i] >> (24U - byte * 8U));
    }
  }
  require(crypto::digest_hex(first_digest) == trace.at("sha256_first").at("output").at("digest_hex").get<std::string>(),
          "first SHA digest mismatch");
  require(first_digest == reference_first_digest, "reconstructed first SHA digest differs from production SHA-256");
  validate_bytes_json(trace.at("sha256_first").at("output").at("digest_bytes"), first_digest, 0U,
                      "first_sha/output/digest_bytes");
  require(crypto::digest_hex(first_digest) == trace.at("sha256_bridge").at("second_sha_input_hex").get<std::string>(),
          "first-to-second SHA byte bridge mismatch");
  validate_bytes_json(trace.at("sha256_second").at("input_digest").at("bytes"), first_digest, 0U,
                      "second_sha/input_digest/bytes");
  require(crypto::digest_hex(final_digest) == trace.at("sha256_second").at("output").at("digest_hex").get<std::string>(),
          "second SHA digest mismatch");
  validate_bytes_json(trace.at("sha256_second").at("output").at("digest_bytes"), final_digest, 0U,
                      "second_sha/output/digest_bytes");
  require(crypto::digest_hex(final_digest) == trace.at("final").at("raw_sha256d").get<std::string>(),
          "raw SHA256d mismatch");
  const auto expected_display_hash =
      trace.at("final").at("expected_bitcoin_display_hash").get<std::string>();
  require(crypto::bitcoin_hash_hex(final_digest) == expected_display_hash,
          "final Bitcoin display hash differs from recorded specimen vector");
  require(crypto::sha256d(header) == final_digest,
          "independent production SHA256d audit differs from reconstructed trace");

  return {
      {"status", "passed"},
      {"header_exact_80_bytes", true},
      {"first_sha_compression_count", 2},
      {"second_sha_compression_count", 1},
      {"compression_count", all.size()},
      {"rounds_per_compression", 64},
      {"total_round_count", total_rounds},
      {"schedule_words_per_compression", 64},
      {"total_schedule_word_count", total_schedule_words},
      {"extended_schedules_reconstructed", true},
      {"round_primitives_recomputed", true},
      {"round_additions_recomputed", true},
      {"round_transfers_recomputed", true},
      {"feed_forwards_recomputed", true},
      {"all_carry_columns_reconstructed", true},
      {"all_modulo_projections_recomputed", true},
      {"multi_operand_carry_above_one_observed", true},
      {"first_sha_digest_exact", true},
      {"second_sha_digest_exact", true},
      {"production_sha256d_cross_check", true},
      {"bitcoin_display_hash", expected_display_hash}};
}

nlohmann::json validate_genesis_sha256d_whitebox(const nlohmann::json& trace) {
  const auto header_hex = trace.at("input").at("header_hex").get<std::string>();
  require(header_hex == kExpectedHeaderHex,
          "header is not the canonical Genesis serialization");
  require(trace.at("sha256_first").at("output").at("digest_hex").get<std::string>() ==
              kExpectedFirstSha256,
          "Genesis first SHA-256 vector mismatch");
  require(trace.at("final").at("raw_sha256d").get<std::string>() == kExpectedRawSha256d,
          "Genesis raw SHA256d vector mismatch");
  require(trace.at("final").at("bitcoin_display_hash").get<std::string>() ==
              kExpectedBitcoinHash,
          "Genesis display hash vector mismatch");
  return validate_sha256d_whitebox(trace);
}

nlohmann::json validate_genesis_nonce_plus_one_sha256d_whitebox(
    const nlohmann::json& trace) {
  const auto header_hex = trace.at("input").at("header_hex").get<std::string>();
  require(header_hex == kNoncePlusOneHeaderHex,
          "header is not the canonical Genesis nonce +1 serialization");
  require(trace.at("sha256_first").at("output").at("digest_hex").get<std::string>() ==
              kNoncePlusOneFirstSha256,
          "Genesis nonce +1 first SHA-256 vector mismatch");
  require(trace.at("final").at("raw_sha256d").get<std::string>() ==
              kNoncePlusOneRawSha256d,
          "Genesis nonce +1 raw SHA256d vector mismatch");
  require(trace.at("final").at("bitcoin_display_hash").get<std::string>() ==
              kNoncePlusOneBitcoinHash,
          "Genesis nonce +1 display hash vector mismatch");
  return validate_sha256d_whitebox(trace);
}

nlohmann::json validate_genesis_nonce_bit0_flip_sha256d_whitebox(
    const nlohmann::json& trace) {
  const auto header_hex = trace.at("input").at("header_hex").get<std::string>();
  require(header_hex == kNonceBit0FlipHeaderHex,
          "header is not the canonical Genesis nonce bit 0 flip serialization");
  require(trace.at("sha256_first").at("output").at("digest_hex").get<std::string>() ==
              kNonceBit0FlipFirstSha256,
          "Genesis nonce bit 0 flip first SHA-256 vector mismatch");
  require(trace.at("final").at("raw_sha256d").get<std::string>() ==
              kNonceBit0FlipRawSha256d,
          "Genesis nonce bit 0 flip raw SHA256d vector mismatch");
  require(trace.at("final").at("bitcoin_display_hash").get<std::string>() ==
              kNonceBit0FlipBitcoinHash,
          "Genesis nonce bit 0 flip display hash vector mismatch");
  return validate_sha256d_whitebox(trace);
}

nlohmann::json validate_genesis_nonce_plus_one_invariants(
    const nlohmann::json& genesis_trace,
    const nlohmann::json& nonce_plus_one_trace) {
  (void)validate_genesis_sha256d_whitebox(genesis_trace);
  (void)validate_genesis_nonce_plus_one_sha256d_whitebox(nonce_plus_one_trace);

  const auto header_a = crypto::from_hex(
      genesis_trace.at("input").at("header_hex").get<std::string>());
  const auto header_b = crypto::from_hex(
      nonce_plus_one_trace.at("input").at("header_hex").get<std::string>());
  require(header_a.size() == 80U && header_b.size() == 80U,
          "A/B headers are not both 80 bytes");
  require(std::equal(header_a.begin(), header_a.begin() + 76, header_b.begin()),
          "A/B first 76 header bytes differ");
  const auto nonce_a = read_le32(header_a.data() + 76);
  const auto nonce_b = read_le32(header_b.data() + 76);
  require(nonce_a == 2083236893U && nonce_b == 2083236894U && nonce_b == nonce_a + 1U,
          "A/B numeric nonce relationship is not exactly +1");
  std::vector<std::size_t> differing_bytes;
  unsigned header_hamming_distance = 0;
  for (std::size_t i = 0; i < header_a.size(); ++i) {
    if (header_a[i] != header_b[i]) differing_bytes.push_back(i);
    header_hamming_distance += std::popcount(
        static_cast<unsigned>(header_a[i] ^ header_b[i]));
  }
  require(differing_bytes == std::vector<std::size_t>{76U},
          "serialized headers do not differ only at byte 76");
  require(header_hamming_distance == 2U, "A/B header Hamming distance is not two bits");

  const auto& a_compressions = genesis_trace.at("sha256_first").at("compressions");
  const auto& b_compressions = nonce_plus_one_trace.at("sha256_first").at("compressions");
  require(a_compressions.at(0) == b_compressions.at(0),
          "SHA1/compression0 is not bit-for-bit identical");
  const auto& a_rounds = a_compressions.at(1).at("rounds");
  const auto& b_rounds = b_compressions.at(1).at("rounds");
  for (std::size_t round = 0; round < 3; ++round) {
    require(a_rounds.at(round) == b_rounds.at(round),
            "a pre-divergence round differs at index " + std::to_string(round));
  }
  require(a_rounds.at(3) != b_rounds.at(3),
          "round 3 unexpectedly remains identical");

  const auto& round_a = a_rounds.at(3);
  const auto& round_b = b_rounds.at(3);
  require(round_a.at("state_before") == round_b.at("state_before"),
          "round 3 state_before differs");
  const State expected_state{
      0xde845910U, 0x1f8aee5cU, 0xb7f888dfU, 0xbc909a33U,
      0x238956e3U, 0xaf5e1cbaU, 0xa8a8881cU, 0xc3c8d8e9U};
  require(json_state(round_a.at("state_before"), kStateNames, "A/round3/state") ==
              expected_state,
          "round 3 state_before is not the expected shared state");
  for (const auto* operation : {"Sigma0", "Sigma1", "Ch", "Maj"}) {
    require(round_a.at(operation) == round_b.at(operation),
            std::string("round 3 ") + operation + " differs");
  }
  require(round_a.at("K") == round_b.at("K"), "round 3 K differs");

  const auto w_a = json_word(round_a.at("W"), "A/round3/W");
  const auto w_b = json_word(round_b.at("W"), "B/round3/W");
  const auto& additions_a = round_a.at("additions");
  const auto& additions_b = round_b.at("additions");
  const auto& t1_operands_a = additions_a.at("T1").at("operands");
  const auto& t1_operands_b = additions_b.at("T1").at("operands");
  require(t1_operands_a.size() == 5U && t1_operands_b.size() == 5U,
          "round 3 T1 does not expose exactly five operands");
  for (std::size_t operand = 0; operand < 4U; ++operand) {
    require(t1_operands_a.at(operand) == t1_operands_b.at(operand),
            "a non-W round 3 T1 operand differs");
  }
  const auto t1_a = json_word(additions_a.at("T1").at("result"), "A/round3/T1");
  const auto t1_b = json_word(additions_b.at("T1").at("result"), "B/round3/T1");
  const auto t2_a = json_word(additions_a.at("T2").at("result"), "A/round3/T2");
  const auto t2_b = json_word(additions_b.at("T2").at("result"), "B/round3/T2");
  const auto new_a_a = json_word(additions_a.at("new_a").at("result"), "A/round3/new_a");
  const auto new_a_b = json_word(additions_b.at("new_a").at("result"), "B/round3/new_a");
  const auto new_e_a = json_word(additions_a.at("new_e").at("result"), "A/round3/new_e");
  const auto new_e_b = json_word(additions_b.at("new_e").at("result"), "B/round3/new_e");
  require(w_a == 0x1dac2b7cU && w_b == 0x1eac2b7cU, "round 3 W values mismatch");
  require(json_word(t1_operands_a.at(4).at("value"), "A/round3/T1/W") == w_a &&
              json_word(t1_operands_b.at(4).at("value"), "B/round3/T1/W") == w_b,
          "round 3 W is not the sole differing direct T1 operand");
  require(t2_a == 0x8dcc6978U && t2_b == t2_a, "round 3 T2 mismatch");
  require(t1_a == 0x0a94a2a8U && t1_b == 0x0b94a2a8U,
          "round 3 T1 values mismatch");
  require(new_a_a == 0x98610c20U && new_a_b == 0x99610c20U,
          "round 3 new_a values mismatch");
  require(new_e_a == 0xc7253cdbU && new_e_b == 0xc8253cdbU,
          "round 3 new_e values mismatch");
  require(w_b - w_a == 0x01000000U && t1_b - t1_a == 0x01000000U &&
              new_a_b - new_a_a == 0x01000000U &&
              new_e_b - new_e_a == 0x01000000U,
          "round 3 modular deltas mismatch");
  require((w_a ^ w_b) == 0x03000000U && std::popcount(w_a ^ w_b) == 2,
          "round 3 W XOR delta mismatch");
  require((t1_a ^ t1_b) == 0x01000000U && std::popcount(t1_a ^ t1_b) == 1,
          "round 3 T1 XOR delta mismatch");
  require((new_a_a ^ new_a_b) == 0x01000000U &&
              std::popcount(new_a_a ^ new_a_b) == 1,
          "round 3 new_a XOR delta mismatch");
  require((new_e_a ^ new_e_b) == 0x0f000000U &&
              std::popcount(new_e_a ^ new_e_b) == 4,
          "round 3 new_e XOR delta mismatch");

  const auto carry_a = additions_a.at("T1").at("carry_summary").at("carry_profile")
                           .get<std::vector<std::uint64_t>>();
  const auto carry_b = additions_b.at("T1").at("carry_summary").at("carry_profile")
                           .get<std::vector<std::uint64_t>>();
  require(carry_a.size() == 32U && carry_b.size() == 32U,
          "round 3 T1 carry profiles are not 32 columns");
  std::vector<unsigned> differing_carry_columns;
  for (unsigned bit = 0; bit < 32; ++bit) {
    if (carry_a[bit] != carry_b[bit]) differing_carry_columns.push_back(bit);
  }
  require(differing_carry_columns == std::vector<unsigned>{24U} &&
              carry_a[24] == 3U && carry_b[24] == 2U,
          "round 3 T1 carry profile does not differ only at bit 24 (3 -> 2)");

  return {
      {"status", "passed"},
      {"headers_80_bytes", true},
      {"first_76_bytes_identical", true},
      {"nonce_a_uint32", nonce_a},
      {"nonce_b_uint32", nonce_b},
      {"nonce_numeric_delta", 1},
      {"differing_header_byte_indices", differing_bytes},
      {"header_hamming_distance_bits", header_hamming_distance},
      {"sha1_compression0_bit_exact", true},
      {"sha1_compression1_rounds_0_to_2_bit_exact", true},
      {"first_divergence", "SHA1/compression1/round3"},
      {"round3_state_before_identical", true},
      {"round3_state_only_primitives_identical", true},
      {"round3_W_a", hex_word(w_a)},
      {"round3_W_b", hex_word(w_b)},
      {"round3_T1_a", hex_word(t1_a)},
      {"round3_T1_b", hex_word(t1_b)},
      {"round3_T2", hex_word(t2_a)},
      {"round3_new_a_a", hex_word(new_a_a)},
      {"round3_new_a_b", hex_word(new_a_b)},
      {"round3_new_e_a", hex_word(new_e_a)},
      {"round3_new_e_b", hex_word(new_e_b)},
      {"modular_deltas_all_01000000", true},
      {"xor_deltas", {{"W", "03000000"}, {"T1", "01000000"},
                       {"new_a", "01000000"}, {"new_e", "0f000000"}}},
      {"xor_hamming_distances", {{"W", 2}, {"T1", 1},
                                  {"new_a", 1}, {"new_e", 4}}},
      {"T1_differing_carry_columns", differing_carry_columns},
      {"T1_carry_bit24_a", carry_a[24]},
      {"T1_carry_bit24_b", carry_b[24]}};
}

nlohmann::json validate_genesis_nonce_bit0_flip_invariants(
    const nlohmann::json& genesis_trace,
    const nlohmann::json& nonce_bit0_flip_trace) {
  (void)validate_genesis_sha256d_whitebox(genesis_trace);
  (void)validate_genesis_nonce_bit0_flip_sha256d_whitebox(nonce_bit0_flip_trace);

  const auto header_a = crypto::from_hex(
      genesis_trace.at("input").at("header_hex").get<std::string>());
  const auto header_c = crypto::from_hex(
      nonce_bit0_flip_trace.at("input").at("header_hex").get<std::string>());
  require(header_a.size() == 80U && header_c.size() == 80U,
          "A/C headers are not both 80 bytes");
  require(std::equal(header_a.begin(), header_a.begin() + 76, header_c.begin()),
          "A/C first 76 header bytes differ");
  const auto nonce_a = read_le32(header_a.data() + 76);
  const auto nonce_c = read_le32(header_c.data() + 76);
  require(nonce_a == 2083236893U && nonce_c == 2083236892U &&
              nonce_c == (nonce_a ^ 0x00000001U),
          "A/C numeric nonce relationship is not exactly bit 0 flipped");
  std::vector<std::size_t> differing_bytes;
  unsigned header_hamming_distance = 0;
  for (std::size_t i = 0; i < header_a.size(); ++i) {
    if (header_a[i] != header_c[i]) differing_bytes.push_back(i);
    header_hamming_distance += std::popcount(
        static_cast<unsigned>(header_a[i] ^ header_c[i]));
  }
  require(differing_bytes == std::vector<std::size_t>{76U},
          "serialized A/C headers do not differ only at byte 76");
  require(header_hamming_distance == 1U,
          "A/C header Hamming distance is not exactly one bit");

  const auto& a_compressions = genesis_trace.at("sha256_first").at("compressions");
  const auto& c_compressions =
      nonce_bit0_flip_trace.at("sha256_first").at("compressions");
  require(a_compressions.at(0) == c_compressions.at(0),
          "A/C SHA1/compression0 is not bit-for-bit identical");
  const auto& a_rounds = a_compressions.at(1).at("rounds");
  const auto& c_rounds = c_compressions.at(1).at("rounds");
  for (std::size_t round = 0; round < 3; ++round) {
    require(a_rounds.at(round) == c_rounds.at(round),
            "an A/C pre-divergence round differs at index " +
                std::to_string(round));
  }
  require(a_rounds.at(3) != c_rounds.at(3),
          "A/C round 3 unexpectedly remains identical");

  const auto& round_a = a_rounds.at(3);
  const auto& round_c = c_rounds.at(3);
  require(round_a.at("state_before") == round_c.at("state_before"),
          "A/C round 3 state_before differs");
  const State expected_state{
      0xde845910U, 0x1f8aee5cU, 0xb7f888dfU, 0xbc909a33U,
      0x238956e3U, 0xaf5e1cbaU, 0xa8a8881cU, 0xc3c8d8e9U};
  require(json_state(round_a.at("state_before"), kStateNames, "A/round3/state") ==
              expected_state,
          "A/C round 3 state_before is not the expected shared state");
  for (const auto* operation : {"Sigma0", "Sigma1", "Ch", "Maj"}) {
    require(round_a.at(operation) == round_c.at(operation),
            std::string("A/C round 3 ") + operation + " differs");
  }
  require(round_a.at("K") == round_c.at("K"), "A/C round 3 K differs");

  const auto w_a = json_word(round_a.at("W"), "A/round3/W");
  const auto w_c = json_word(round_c.at("W"), "C/round3/W");
  const auto& additions_a = round_a.at("additions");
  const auto& additions_c = round_c.at("additions");
  const auto& t1_operands_a = additions_a.at("T1").at("operands");
  const auto& t1_operands_c = additions_c.at("T1").at("operands");
  require(t1_operands_a.size() == 5U && t1_operands_c.size() == 5U,
          "A/C round 3 T1 does not expose exactly five operands");
  for (std::size_t operand = 0; operand < 4U; ++operand) {
    require(t1_operands_a.at(operand) == t1_operands_c.at(operand),
            "an A/C non-W round 3 T1 operand differs");
  }
  const auto t1_a = json_word(additions_a.at("T1").at("result"), "A/round3/T1");
  const auto t1_c = json_word(additions_c.at("T1").at("result"), "C/round3/T1");
  const auto t2_a = json_word(additions_a.at("T2").at("result"), "A/round3/T2");
  const auto t2_c = json_word(additions_c.at("T2").at("result"), "C/round3/T2");
  const auto new_a_a =
      json_word(additions_a.at("new_a").at("result"), "A/round3/new_a");
  const auto new_a_c =
      json_word(additions_c.at("new_a").at("result"), "C/round3/new_a");
  const auto new_e_a =
      json_word(additions_a.at("new_e").at("result"), "A/round3/new_e");
  const auto new_e_c =
      json_word(additions_c.at("new_e").at("result"), "C/round3/new_e");
  require(w_a == 0x1dac2b7cU && w_c == 0x1cac2b7cU,
          "A/C round 3 W values mismatch");
  require(json_word(t1_operands_a.at(4).at("value"), "A/round3/T1/W") == w_a &&
              json_word(t1_operands_c.at(4).at("value"), "C/round3/T1/W") == w_c,
          "A/C round 3 W is not the sole differing direct T1 operand");
  require(additions_a.at("T2") == additions_c.at("T2") &&
              t2_a == 0x8dcc6978U && t2_c == t2_a,
          "A/C round 3 T2 differs");
  require(t1_a == 0x0a94a2a8U && t1_c == 0x0994a2a8U,
          "A/C round 3 T1 values mismatch");
  require(new_a_a == 0x98610c20U && new_a_c == 0x97610c20U,
          "A/C round 3 new_a values mismatch");
  require(new_e_a == 0xc7253cdbU && new_e_c == 0xc6253cdbU,
          "A/C round 3 new_e values mismatch");
  require(w_c - w_a == 0xff000000U && t1_c - t1_a == 0xff000000U &&
              new_a_c - new_a_a == 0xff000000U &&
              new_e_c - new_e_a == 0xff000000U,
          "A/C round 3 modular deltas mismatch");
  require((w_a ^ w_c) == 0x01000000U && std::popcount(w_a ^ w_c) == 1,
          "A/C round 3 W XOR delta mismatch");
  require((t1_a ^ t1_c) == 0x03000000U && std::popcount(t1_a ^ t1_c) == 2,
          "A/C round 3 T1 XOR delta mismatch");
  require((new_a_a ^ new_a_c) == 0x0f000000U &&
              std::popcount(new_a_a ^ new_a_c) == 4,
          "A/C round 3 new_a XOR delta mismatch");
  require((new_e_a ^ new_e_c) == 0x01000000U &&
              std::popcount(new_e_a ^ new_e_c) == 1,
          "A/C round 3 new_e XOR delta mismatch");

  const auto carry_a = additions_a.at("T1").at("carry_summary").at("carry_profile")
                           .get<std::vector<std::uint64_t>>();
  const auto carry_c = additions_c.at("T1").at("carry_summary").at("carry_profile")
                           .get<std::vector<std::uint64_t>>();
  require(carry_a.size() == 32U && carry_c.size() == 32U,
          "A/C round 3 T1 carry profiles are not 32 columns");
  std::vector<unsigned> differing_carry_columns;
  for (unsigned bit = 0; bit < 32; ++bit) {
    if (carry_a[bit] != carry_c[bit]) differing_carry_columns.push_back(bit);
  }
  require(differing_carry_columns == std::vector<unsigned>{24U} &&
              carry_a[24] == 3U && carry_c[24] == 2U && carry_a[25] == carry_c[25],
          "A/C round 3 T1 carry profile does not differ only at bit 24 (3 -> 2)");

  return {
      {"status", "passed"},
      {"headers_80_bytes", true},
      {"first_76_bytes_identical", true},
      {"nonce_a_uint32", nonce_a},
      {"nonce_c_uint32", nonce_c},
      {"nonce_relationship", "nonce_c = nonce_a XOR 0x00000001"},
      {"differing_header_byte_indices", differing_bytes},
      {"header_hamming_distance_bits", header_hamming_distance},
      {"sha1_compression0_bit_exact", true},
      {"sha1_compression1_rounds_0_to_2_bit_exact", true},
      {"first_divergence", "SHA1/compression1/round3"},
      {"round3_state_before_identical", true},
      {"round3_state_only_primitives_identical", true},
      {"round3_W_a", hex_word(w_a)},
      {"round3_W_c", hex_word(w_c)},
      {"round3_T1_a", hex_word(t1_a)},
      {"round3_T1_c", hex_word(t1_c)},
      {"round3_T2", hex_word(t2_a)},
      {"round3_new_a_a", hex_word(new_a_a)},
      {"round3_new_a_c", hex_word(new_a_c)},
      {"round3_new_e_a", hex_word(new_e_a)},
      {"round3_new_e_c", hex_word(new_e_c)},
      {"modular_deltas", {{"W", "ff000000"}, {"T1", "ff000000"},
                            {"new_a", "ff000000"}, {"new_e", "ff000000"}}},
      {"xor_deltas", {{"W", "01000000"}, {"T1", "03000000"},
                        {"new_a", "0f000000"}, {"new_e", "01000000"}}},
      {"xor_hamming_distances", {{"W", 1}, {"T1", 2},
                                  {"new_a", 4}, {"new_e", 1}}},
      {"T1_differing_carry_columns", differing_carry_columns},
      {"T1_carry_bit24_a", carry_a[24]},
      {"T1_carry_bit24_c", carry_c[24]},
      {"T1_carry_bit25_equal", true}};
}

namespace {

std::string csv_escape(const std::string& value) {
  std::string result = "\"";
  for (const auto character : value) {
    if (character == '"') result += '"';
    result += character;
  }
  result += '"';
  return result;
}

void csv_row(std::ostringstream& output,
             const std::vector<std::string>& fields) {
  for (std::size_t i = 0; i < fields.size(); ++i) {
    if (i != 0U) output << ',';
    output << csv_escape(fields[i]);
  }
  output << '\n';
}

std::string word_hex_json(const nlohmann::json& word) {
  return word.at("hex").get<std::string>();
}

std::string byte_array_hex_json(const nlohmann::json& bytes) {
  std::string result;
  for (const auto& byte : bytes) result += byte.at("hex").get<std::string>();
  return result;
}

std::string named_word_inputs(const nlohmann::json& operands) {
  std::ostringstream result;
  for (std::size_t i = 0; i < operands.size(); ++i) {
    if (i != 0U) result << ';';
    result << operands[i].at("name").get<std::string>() << '='
           << word_hex_json(operands[i].at("value"));
  }
  return result.str();
}

std::string compact_named_state(const nlohmann::json& state,
                                const std::array<const char*, 8>& names) {
  std::ostringstream result;
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (i != 0U) result << ';';
    result << names[i] << '=' << word_hex_json(state.at(names[i]));
  }
  return result.str();
}

std::string trajectory_csv(const nlohmann::json& trace) {
  std::ostringstream output;
  csv_row(output, {"step", "stage", "sha_pass", "compression_index", "round_index",
                   "header_hex", "W", "a_before", "b_before", "c_before", "d_before",
                   "e_before", "f_before", "g_before", "h_before", "Sigma0", "Sigma1",
                   "Ch", "Maj", "T1", "T2", "a_after", "b_after", "c_after", "d_after",
                   "e_after", "f_after", "g_after", "h_after", "T1_nonzero_carry_count",
                   "T1_max_carry", "T2_nonzero_carry_count", "new_a_nonzero_carry_count",
                   "new_e_nonzero_carry_count"});
  std::vector<std::string> header_row(34);
  header_row[0] = "0";
  header_row[1] = "header";
  header_row[5] = trace.at("input").at("header_hex").get<std::string>();
  csv_row(output, header_row);
  std::size_t step = 1;
  for (const auto* compression : compressions(trace)) {
    for (const auto& round : compression->at("rounds")) {
      const auto& before = round.at("state_before");
      const auto& after = round.at("state_after");
      const auto& additions = round.at("additions");
      const auto carry_count = [&](const char* name) {
        return std::to_string(additions.at(name).at("carry_summary")
                                  .at("nonzero_carry_count").get<unsigned>());
      };
      csv_row(output, {
          std::to_string(step++), "round",
          std::to_string(round.at("sha_pass").get<unsigned>()),
          std::to_string(round.at("compression_index").get<unsigned>()),
          std::to_string(round.at("round_index").get<unsigned>()), "",
          word_hex_json(round.at("W")), word_hex_json(before.at("a")),
          word_hex_json(before.at("b")), word_hex_json(before.at("c")),
          word_hex_json(before.at("d")), word_hex_json(before.at("e")),
          word_hex_json(before.at("f")), word_hex_json(before.at("g")),
          word_hex_json(before.at("h")), word_hex_json(round.at("Sigma0").at("result")),
          word_hex_json(round.at("Sigma1").at("result")),
          word_hex_json(round.at("Ch").at("result")),
          word_hex_json(round.at("Maj").at("result")),
          word_hex_json(additions.at("T1").at("result")),
          word_hex_json(additions.at("T2").at("result")),
          word_hex_json(after.at("a")), word_hex_json(after.at("b")),
          word_hex_json(after.at("c")), word_hex_json(after.at("d")),
          word_hex_json(after.at("e")), word_hex_json(after.at("f")),
          word_hex_json(after.at("g")), word_hex_json(after.at("h")),
          carry_count("T1"),
          std::to_string(additions.at("T1").at("carry_summary")
                             .at("max_carry_value").get<std::uint64_t>()),
          carry_count("T2"), carry_count("new_a"), carry_count("new_e")});
    }
  }
  require(step == 193U, "trajectory CSV does not contain header plus 192 rounds");
  return output.str();
}

std::string operations_csv(const nlohmann::json& trace) {
  std::ostringstream output;
  csv_row(output, {"sequence", "sha_pass", "compression_index", "phase", "position",
                   "identity", "inputs", "operation", "output", "operation_type",
                   "carry_applicable"});
  std::size_t sequence = 0;
  const auto append = [&](const unsigned sha_pass, const unsigned compression_index,
                          const std::string& phase, const std::string& position,
                          const std::string& identity, const std::string& inputs,
                          const std::string& operation, const std::string& result,
                          const std::string& type, const bool carry) {
    csv_row(output, {std::to_string(sequence++), std::to_string(sha_pass),
                     std::to_string(compression_index), phase, position, identity,
                     inputs, operation, result, type, carry ? "yes" : "no"});
  };

  for (const auto* compression : compressions(trace)) {
    const auto sha_pass = compression->at("sha_pass").get<unsigned>();
    const auto compression_index = compression->at("compression_index").get<unsigned>();
    const auto& schedule = compression->at("message_schedule").at("words");
    for (std::size_t t = 0; t < schedule.size(); ++t) {
      const auto position = "W[" + std::to_string(t) + "]";
      if (t < 16U) {
        append(sha_pass, compression_index, "schedule", position, position,
               byte_array_hex_json(schedule[t].at("source_bytes")),
               "DECODE_BE32", word_hex_json(schedule[t].at("result")), "bitwise", false);
        continue;
      }
      const auto& word = schedule[t];
      const auto& s0 = word.at("small_sigma0");
      const auto& s1 = word.at("small_sigma1");
      const auto input0 = word_hex_json(s0.at("input"));
      const auto input1 = word_hex_json(s1.at("input"));
      append(sha_pass, compression_index, "schedule", position, position + "/sigma0/ROTR7",
             "x=" + input0, "ROTR7", word_hex_json(s0.at("rotr7")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/sigma0/ROTR18",
             "x=" + input0, "ROTR18", word_hex_json(s0.at("rotr18")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/sigma0/SHR3",
             "x=" + input0, "SHR3", word_hex_json(s0.at("shr3")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/sigma0/XOR",
             "ROTR7=" + word_hex_json(s0.at("rotr7")) + ";ROTR18=" +
                 word_hex_json(s0.at("rotr18")) + ";SHR3=" + word_hex_json(s0.at("shr3")),
             "XOR", word_hex_json(s0.at("result")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/sigma1/ROTR17",
             "x=" + input1, "ROTR17", word_hex_json(s1.at("rotr17")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/sigma1/ROTR19",
             "x=" + input1, "ROTR19", word_hex_json(s1.at("rotr19")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/sigma1/SHR10",
             "x=" + input1, "SHR10", word_hex_json(s1.at("shr10")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/sigma1/XOR",
             "ROTR17=" + word_hex_json(s1.at("rotr17")) + ";ROTR19=" +
                 word_hex_json(s1.at("rotr19")) + ";SHR10=" + word_hex_json(s1.at("shr10")),
             "XOR", word_hex_json(s1.at("result")), "bitwise", false);
      append(sha_pass, compression_index, "schedule", position, position + "/addition",
             named_word_inputs(word.at("addition").at("operands")), "ADD_MOD_2^32",
             word_hex_json(word.at("addition").at("result")), "modular", true);
    }

    for (const auto& round : compression->at("rounds")) {
      const auto round_index = round.at("round_index").get<unsigned>();
      const auto position = "round[" + std::to_string(round_index) + "]";
      const auto& before = round.at("state_before");
      const auto& after = round.at("state_after");
      const auto& s0 = round.at("Sigma0");
      const auto& s1 = round.at("Sigma1");
      const auto& ch = round.at("Ch");
      const auto& maj = round.at("Maj");
      const auto append_bitwise = [&](const std::string& identity,
                                      const std::string& inputs,
                                      const std::string& operation,
                                      const nlohmann::json& result) {
        append(sha_pass, compression_index, "round", position, position + "/" + identity,
               inputs, operation, word_hex_json(result), "bitwise", false);
      };
      append_bitwise("Sigma0/ROTR2", "a=" + word_hex_json(before.at("a")), "ROTR2", s0.at("rotr2_a"));
      append_bitwise("Sigma0/ROTR13", "a=" + word_hex_json(before.at("a")), "ROTR13", s0.at("rotr13_a"));
      append_bitwise("Sigma0/ROTR22", "a=" + word_hex_json(before.at("a")), "ROTR22", s0.at("rotr22_a"));
      append_bitwise("Sigma0/XOR", "ROTR2=" + word_hex_json(s0.at("rotr2_a")) + ";ROTR13=" + word_hex_json(s0.at("rotr13_a")) + ";ROTR22=" + word_hex_json(s0.at("rotr22_a")), "XOR", s0.at("result"));
      append_bitwise("Sigma1/ROTR6", "e=" + word_hex_json(before.at("e")), "ROTR6", s1.at("rotr6_e"));
      append_bitwise("Sigma1/ROTR11", "e=" + word_hex_json(before.at("e")), "ROTR11", s1.at("rotr11_e"));
      append_bitwise("Sigma1/ROTR25", "e=" + word_hex_json(before.at("e")), "ROTR25", s1.at("rotr25_e"));
      append_bitwise("Sigma1/XOR", "ROTR6=" + word_hex_json(s1.at("rotr6_e")) + ";ROTR11=" + word_hex_json(s1.at("rotr11_e")) + ";ROTR25=" + word_hex_json(s1.at("rotr25_e")), "XOR", s1.at("result"));
      append_bitwise("Ch/e_AND_f", "e=" + word_hex_json(before.at("e")) + ";f=" + word_hex_json(before.at("f")), "AND", ch.at("e_and_f"));
      append_bitwise("Ch/NOT_e", "e=" + word_hex_json(before.at("e")), "NOT", ch.at("not_e"));
      append_bitwise("Ch/not_e_AND_g", "NOT_e=" + word_hex_json(ch.at("not_e")) + ";g=" + word_hex_json(before.at("g")), "AND", ch.at("not_e_and_g"));
      append_bitwise("Ch/XOR", "e_AND_f=" + word_hex_json(ch.at("e_and_f")) + ";not_e_AND_g=" + word_hex_json(ch.at("not_e_and_g")), "XOR", ch.at("result"));
      append_bitwise("Maj/a_AND_b", "a=" + word_hex_json(before.at("a")) + ";b=" + word_hex_json(before.at("b")), "AND", maj.at("a_and_b"));
      append_bitwise("Maj/a_AND_c", "a=" + word_hex_json(before.at("a")) + ";c=" + word_hex_json(before.at("c")), "AND", maj.at("a_and_c"));
      append_bitwise("Maj/b_AND_c", "b=" + word_hex_json(before.at("b")) + ";c=" + word_hex_json(before.at("c")), "AND", maj.at("b_and_c"));
      append_bitwise("Maj/XOR", "a_AND_b=" + word_hex_json(maj.at("a_and_b")) + ";a_AND_c=" + word_hex_json(maj.at("a_and_c")) + ";b_AND_c=" + word_hex_json(maj.at("b_and_c")), "XOR", maj.at("result"));
      for (const auto* name : {"T1", "T2", "new_a", "new_e"}) {
        const auto& addition = round.at("additions").at(name);
        append(sha_pass, compression_index, "round", position, position + "/" + name,
               named_word_inputs(addition.at("operands")), "ADD_MOD_2^32",
               word_hex_json(addition.at("result")), "modular", true);
      }
      const std::array<std::pair<const char*, const char*>, 6> transfers{{
          {"b", "a"}, {"c", "b"}, {"d", "c"},
          {"f", "e"}, {"g", "f"}, {"h", "g"}}};
      for (const auto& [destination, source] : transfers) {
        append(sha_pass, compression_index, "round", position,
               position + "/transfer_" + destination,
               std::string(source) + "_before=" + word_hex_json(before.at(source)),
               "TRANSFER", word_hex_json(after.at(destination)), "bitwise", false);
      }
    }
    for (const auto& feed_forward : compression->at("feed_forward")) {
      const auto& addition = feed_forward.at("addition");
      append(sha_pass, compression_index, "feed_forward",
             "word[" + std::to_string(feed_forward.at("word_index").get<unsigned>()) + "]",
             addition.at("identity").get<std::string>(),
             named_word_inputs(addition.at("operands")), "ADD_MOD_2^32",
             word_hex_json(addition.at("result")), "modular", true);
    }
  }
  return output.str();
}

std::string carries_csv(const nlohmann::json& trace) {
  std::ostringstream output;
  csv_row(output, {"sha_pass", "compression_index", "phase", "round_or_word_index",
                   "addition_identity", "bit_index", "operand_bits", "carry_in",
                   "column_sum_integer", "result_bit", "carry_out"});
  const auto append_addition = [&](const unsigned sha_pass,
                                   const unsigned compression_index,
                                   const std::string& phase,
                                   const std::string& position,
                                   const nlohmann::json& addition) {
    for (const auto& column : addition.at("bit_columns_lsb_to_msb")) {
      std::ostringstream operand_bits;
      for (std::size_t i = 0; i < column.at("operand_bits").size(); ++i) {
        if (i != 0U) operand_bits << ';';
        operand_bits << column.at("operand_bits").at(i).at("name").get<std::string>()
                     << '=' << column.at("operand_bits").at(i).at("bit").get<unsigned>();
      }
      csv_row(output, {std::to_string(sha_pass), std::to_string(compression_index),
                       phase, position, addition.at("identity").get<std::string>(),
                       std::to_string(column.at("bit_index").get<unsigned>()),
                       operand_bits.str(),
                       std::to_string(column.at("carry_in").get<std::uint64_t>()),
                       std::to_string(column.at("column_sum_integer").get<std::uint64_t>()),
                       std::to_string(column.at("result_bit").get<unsigned>()),
                       std::to_string(column.at("carry_out").get<std::uint64_t>())});
    }
  };
  for (const auto* compression : compressions(trace)) {
    const auto sha_pass = compression->at("sha_pass").get<unsigned>();
    const auto compression_index = compression->at("compression_index").get<unsigned>();
    const auto& schedule = compression->at("message_schedule").at("words");
    for (std::size_t t = 16; t < schedule.size(); ++t) {
      append_addition(sha_pass, compression_index, "schedule", "W[" + std::to_string(t) + "]",
                      schedule[t].at("addition"));
    }
    for (const auto& round : compression->at("rounds")) {
      const auto position = "round[" + std::to_string(round.at("round_index").get<unsigned>()) + "]";
      for (const auto* name : {"T1", "T2", "new_a", "new_e"}) {
        append_addition(sha_pass, compression_index, "round", position,
                        round.at("additions").at(name));
      }
    }
    for (const auto& feed_forward : compression->at("feed_forward")) {
      append_addition(sha_pass, compression_index, "feed_forward",
                      "word[" + std::to_string(feed_forward.at("word_index").get<unsigned>()) + "]",
                      feed_forward.at("addition"));
    }
  }
  return output.str();
}

std::string transitions_csv(const nlohmann::json& trace) {
  std::ostringstream output;
  csv_row(output, {"sequence", "transition", "sha_pass", "compression_index",
                   "input", "output", "rule"});
  const auto& first_compressions = trace.at("sha256_first").at("compressions");
  const auto& second_compression = trace.at("sha256_second").at("compressions").at(0);
  csv_row(output, {"0", "header_to_chunks", "1", "",
                   trace.at("input").at("header_hex").get<std::string>(),
                   first_compressions.at(0).at("chunk").at("hex").get<std::string>() + ";" +
                       first_compressions.at(1).at("chunk").at("hex").get<std::string>(),
                   "split the 80-byte header and append SHA-256 padding"});
  csv_row(output, {"1", "padding_SHA1", "1", "",
                   trace.at("sha256_first").at("input").at("hex").get<std::string>(),
                   trace.at("sha256_first").at("padding").at("padded_message_hex").get<std::string>(),
                   trace.at("sha256_first").at("padding").at("rule").get<std::string>()});
  csv_row(output, {"2", "feed_forward_compression0", "1", "0",
                   compact_named_state(first_compressions.at(0).at("final_working_state"), kStateNames),
                   compact_named_state(first_compressions.at(0).at("output_chaining_state"), kChainingNames),
                   "H[i] = H_old[i] + working_register[i] mod 2^32"});
  csv_row(output, {"3", "compression0_to_compression1", "1", "0->1",
                   compact_named_state(first_compressions.at(0).at("output_chaining_state"), kChainingNames),
                   compact_named_state(first_compressions.at(1).at("input_chaining_state"), kChainingNames),
                   "output chaining state becomes the next compression input state"});
  csv_row(output, {"4", "feed_forward_compression1", "1", "1",
                   compact_named_state(first_compressions.at(1).at("final_working_state"), kStateNames),
                   compact_named_state(first_compressions.at(1).at("output_chaining_state"), kChainingNames),
                   "H[i] = H_old[i] + working_register[i] mod 2^32"});
  csv_row(output, {"5", "digest_SHA1", "1", "1",
                   compact_named_state(first_compressions.at(1).at("output_chaining_state"), kChainingNames),
                   trace.at("sha256_first").at("output").at("digest_hex").get<std::string>(),
                   "serialize H0..H7 big-endian"});
  csv_row(output, {"6", "digest_SHA1_to_message_SHA2", "1->2", "",
                   trace.at("sha256_bridge").at("first_sha_digest_hex").get<std::string>(),
                   trace.at("sha256_bridge").at("second_sha_input_hex").get<std::string>(),
                   trace.at("sha256_bridge").at("rule").get<std::string>()});
  csv_row(output, {"7", "padding_SHA2", "2", "2",
                   trace.at("sha256_second").at("input_digest").at("hex").get<std::string>(),
                   trace.at("sha256_second").at("padding").at("padded_message_hex").get<std::string>(),
                   trace.at("sha256_second").at("padding").at("rule").get<std::string>()});
  csv_row(output, {"8", "feed_forward_final", "2", "2",
                   compact_named_state(second_compression.at("final_working_state"), kStateNames),
                   compact_named_state(second_compression.at("output_chaining_state"), kChainingNames),
                   "H[i] = H_old[i] + working_register[i] mod 2^32"});
  csv_row(output, {"9", "raw_digest_to_Bitcoin_display_hash", "2", "2",
                   trace.at("final").at("raw_sha256d").get<std::string>(),
                   trace.at("final").at("bitcoin_display_hash").get<std::string>(),
                   trace.at("final").at("bitcoin_display_rule").get<std::string>()});
  return output.str();
}

void write_text_file(const std::filesystem::path& path,
                     const std::string& contents) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("cannot create " + path.string());
  output << contents;
  if (!output) throw std::runtime_error("cannot finish writing " + path.string());
}

}  // namespace

void write_sha256d_whitebox(const Artifacts& artifacts,
                            const SpecimenMetadata& metadata,
                            const std::filesystem::path& output_directory) {
  std::filesystem::create_directories(output_directory);
  require(!metadata.artifact_stem.empty(), "artifact stem is empty");
  write_text_file(output_directory / (metadata.artifact_stem + "_whitebox.json"),
                  artifacts.trace.dump(2) + '\n');
  write_text_file(output_directory / (metadata.artifact_stem + "_whitebox_summary.md"),
                  artifacts.summary_markdown);
  write_text_file(output_directory / (metadata.artifact_stem + "_trajectoire_193_avec_header.csv"),
                  trajectory_csv(artifacts.trace));
  write_text_file(output_directory / (metadata.artifact_stem + "_operations_unitaires.csv"),
                  operations_csv(artifacts.trace));
  write_text_file(output_directory / (metadata.artifact_stem + "_carries_bit_a_bit.csv"),
                  carries_csv(artifacts.trace));
  write_text_file(output_directory / (metadata.artifact_stem + "_transitions_hors_rounds.csv"),
                  transitions_csv(artifacts.trace));
}

void write_genesis_sha256d_whitebox(const Artifacts& artifacts,
                                    const std::filesystem::path& output_directory) {
  write_sha256d_whitebox(artifacts, genesis_specimen_metadata(), output_directory);
}

void write_genesis_nonce_plus_one_sha256d_whitebox(
    const Artifacts& artifacts,
    const std::filesystem::path& output_directory) {
  write_sha256d_whitebox(artifacts, genesis_nonce_plus_one_specimen_metadata(),
                         output_directory);
}

void write_genesis_nonce_bit0_flip_sha256d_whitebox(
    const Artifacts& artifacts,
    const std::filesystem::path& output_directory) {
  write_sha256d_whitebox(artifacts, genesis_nonce_bit0_flip_specimen_metadata(),
                         output_directory);
}

}  // namespace srm::research::whitebox
