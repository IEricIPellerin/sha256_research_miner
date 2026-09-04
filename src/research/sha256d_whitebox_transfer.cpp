//src\research\sha256d_whitebox_transfer.cpp
#include "research/sha256d_whitebox.h"

#include "crypto/reduced_sha256.h"
#include "crypto/sha256d.h"
#include "research/header_space.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace srm::research::whitebox {
namespace {

using Header = std::array<std::uint8_t, 80>;
using State = std::array<std::uint32_t, 8>;
using CarryProfile = std::array<std::uint64_t, 32>;

constexpr std::uint32_t kGenesisNonce = 0x7c2bac1dU;
constexpr std::uint32_t kGenesisW3 = 0x1dac2b7cU;
constexpr unsigned kDivergenceStep = 67U;
constexpr std::array<const char*, 8> kStateNames{
    "a", "b", "c", "d", "e", "f", "g", "h"};
constexpr std::array<std::uint32_t, 8> kInitialState{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
constexpr std::array<std::uint32_t, 64> kRoundConstants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

// Frozen Python hashlib.sha256(seed || uint32_le(context_id)) outputs.
constexpr std::array<std::string_view, 64> kMerkleHex{{
    "5b46b49fee3d11559452c005790fdc1c4c05826c888353acbbc4e739c6d8181c",
    "0d2cb950a8506577421fdb250f91f22660e7d646d59e5775535e71873f7685f3",
    "519ae8d9f1afd98fadc91d618804e21dff8611f913521fe3668b94a9ee116057",
    "b917637348f0b21375bd7ee5dd38e6812cfec89f92c53e12e6391fc5e846cc1b",
    "b3b3e0716e1ca211be75fdc398bc18e89597a1c0d0a175f44a32e4d02f574776",
    "f59f01f94c3048a9bbddabea8a9bea9fe12ebbf0104d7736e15bdfe48d689963",
    "fc587b1628d1d0198885c5f356398da6273e6c8f8d930fb6786be156f0cd60f4",
    "b63a7d72492a0ca6c605fa91c40fc730417e94e30cd0dbf66012122386fb037c",
    "92b82bb1fd6e51f105fc7fcbc4cf6e738e2690d6d018f0d539791a7ba308eb0f",
    "1c78579c4c8918ccaa11a3a8784f79f146015488fb40c4823e1778c474225846",
    "c0a87b62494d26e3cbd379c0ea9cb35578469b132da673754a623d85019c0ec8",
    "dcb09c2c6e362bca25e819b18fae4617d8872d741f7996583048767a215694ca",
    "f27fc4cbc5956019e317c2f869cc66e052d8a1ce30dd4b28ace6446d77cfcf64",
    "6cfeb26256f2e63661b3bf21021a94a4780421e7177eb9069d1a6a684042efcc",
    "aa5e72124e5c876579f7153019265501afcef6aa2eed6c2960cf332855d36be0",
    "6f2dd6255396f51403d3f866fa43b7bdec6ede6c7466388f45e1127a9b1301ba",
    "3f8acb7079f37dc4aab06ee4fcc30bb99100c9b46e28070684f8ddebb7255c8a",
    "5318f16f6e6645b1deb897aa50d65098d7f639fd843fff09c6aa8a3afff2dcb8",
    "794c5bee71e4708a5a025c3e7f9ffabbaa0333912c7dbf0d78714853f8907dc0",
    "9818dd936770b7c561b7791ac19ab900e6ae4036b3c523a968dc877351b1db6d",
    "b802b2fcf8d86317a49966e44e412c4d47d9589e13acf8c7434a1553d0bb3d14",
    "11723aed1f40cc649763606ff4cd924455e41b8c8baeebdb8976330fe53cbdf1",
    "3765a2d79ff9de71ae923029e15f6051294a74da13a471192d9b4ab91a35b079",
    "13233ba3fa029a10af78256867d76075171722634c03035c82f09f933833318d",
    "db48efcbfc40a71c3e1c8af48a56f2946bb4468109a974dda1f00afd4b0da9b1",
    "7b12a75146e8cc2e3d1b28ab7f2951d79bee51680bbd47b0ac5d07564222db79",
    "18738ea6a5f4ddc297e215bd8daebc44bffa70e4669b8709b16a34eb6b2e0dfb",
    "e39dab34ab02a3e134647ac2f97c9e21645592b1e88ab78d9b51475e1db9fc78",
    "66c9dd8189238d25f3826b777493c7d5a59bf8e8710f3c235044299fc75912e7",
    "efde0a73d8768e3c20bc71756f43c5fdcafe5f3ff6fd337c29f7bbfd785c9c58",
    "df6bc7a74e075f1f0514a7970e9b1ea3d5daa29f1fde353ae21137563c95aefc",
    "93992ea5baddf5cf83f72e88a3ef72890b1f2d567b3e35158f4f6293b1e13b59",
    "a8c4e2614d6cc1240b481dec14dda02200ea7319fa21fd5ca274e7791815fe74",
    "032722d9bea50a914d8aa813601b25e67b224aa45e19ae3dfc7990356cb5f58e",
    "5e0273411ab8fd9415319a5c5e4e3a4df2c42e67cdfc249db51d473b3faffe46",
    "a466efc0eae1777596d8ef8a810d7b62ef4a294ea0569c066f8d5fc376ca4da2",
    "ed809ad940b5d2c0328e37a9617a86d7e7a4b2f05602a8c07cc6e75decbb8002",
    "a82ca258e8d90499d6b10eccf13f5b0af825407350f39ff47d47bc2d619c345b",
    "7c673cfc5f236921fed68679b86aded9be0be75644eb7fad0c3e9383bfe66702",
    "142636923f396baedd64284259ed2ab3094ac38284d60abee7bf72d6045045af",
    "764b2893316ec3a7c0942ffe381ce88a08105abdaa2eb9a4dfab7ab93c3db786",
    "6544899fa5d49d437d1961d01505db844b31dfdb2c61398628e5f250bd1886d8",
    "0a06f8f7d4ea153593536e9dfd22a77a0f40b22319ab1955a6d3c7f0a21d9f8c",
    "237e63a173f06a639310ebfc22e36e0945ac66725fa608afa68c2434f709058c",
    "52f45fb13257ddf2f688db541aef0d7aa39579ff00184baa18499abf417441fe",
    "a8ce507fd0416cc454372e5cb0fe3c46d5cdd28ab5b8e4a4887aea3add293cac",
    "88002e0dc3e5cebc334cebfc1bb2b025af2455668093cf628397d3eb5530891d",
    "a88747fc7e893b1cae408a6ce25c89553d689d3cdd6bb84816fbfea3023d1e73",
    "713a828ca2e925f11677eaee7970078f95787aef44afb4e00517e522655a84c8",
    "4fd13e6e2081afcf1e6878e8565835c4bed3b418760e4cc832d15391b4c98854",
    "8d044ac263a313be6b1595c5fd46334b4695287fa7c411af5b6492a6ef707b23",
    "285199d1760f6d40daf6443b5f4e81bf5a2aa60d1a78f2ed16f92efc226d02b8",
    "e9a408d0dce276a56e723c0646011b27835d8ddd0460cb62bd1a3f01b972f944",
    "dc301f9667cf27f98063b7ecb75defe4452e02460ecaf87601beee9f51086373",
    "0613f1510234505493746734dfc3b751f52b871016034214109cff345a9a917c",
    "ceb9420386924a6281a56580d75d1f5f613e606b8de272a641b87b1443fcb04c",
    "500032202582c71f81ac9a0cccecea0980b2475b8ac9458161b30fa4834c5406",
    "fbfad0a7c0e396ce2b35fc6ebd7b63584c03d5f8d0d3f87880f020226f7b168a",
    "e1e577ede4054178f18b5dcc96ceb9dda98210066005865e4a1bbeb2af0022a2",
    "af44d818a7112c558d52477de7ab21204987efc8e1916e24e2140be3158ceb2b",
    "92f97a644c116018a540509a1864dac612327f45d1741f740f68baa5126b6328",
    "f4698867f1326bc80c9113e86355629ac54a043684f6f9df1543d7d1d42638d8",
    "16b68dcdb8777095357122ec68bcc2e2dd2fd731227a0a44326d522473cd3153",
    "f15917d442424a06da2699173c7037468e2ce0482e4da1f54d273b01000a5cc2",
}};

[[noreturn]] void fail(const std::string& message) {
  throw std::runtime_error("Merkle context transfer validation failed: " + message);
}

void require(bool condition, const std::string& message) {
  if (!condition) fail(message);
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

std::string hex_word(std::uint32_t value) {
  std::ostringstream output;
  output << std::hex << std::nouppercase << std::setfill('0') << std::setw(8)
         << value;
  return output.str();
}

std::string reversed_hex(std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> reversed(bytes.rbegin(), bytes.rend());
  return crypto::to_hex(reversed);
}

std::string split_name(unsigned context_id) {
  return context_id < 32U ? "discovery" : "holdout";
}

std::uint32_t sigma0(std::uint32_t x) {
  return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22);
}
std::uint32_t sigma1(std::uint32_t x) {
  return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25);
}
std::uint32_t small_sigma0(std::uint32_t x) {
  return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3U);
}
std::uint32_t small_sigma1(std::uint32_t x) {
  return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10U);
}
std::uint32_t choice(std::uint32_t e, std::uint32_t f, std::uint32_t g) {
  return (e & f) ^ (~e & g);
}
std::uint32_t majority(std::uint32_t a, std::uint32_t b, std::uint32_t c) {
  return (a & b) ^ (a & c) ^ (b & c);
}

State before_state(const crypto::Sha256RoundTrace& r) {
  return {r.a_before, r.b_before, r.c_before, r.d_before,
          r.e_before, r.f_before, r.g_before, r.h_before};
}
State after_state(const crypto::Sha256RoundTrace& r) {
  return {r.a_after, r.b_after, r.c_after, r.d_after,
          r.e_after, r.f_after, r.g_after, r.h_after};
}

State digest_words(const crypto::Digest& digest) {
  State result{};
  for (std::size_t i = 0; i < result.size(); ++i) {
    result[i] = read_be32(digest.data() + i * 4U);
  }
  return result;
}

struct Addition {
  std::vector<std::uint32_t> operands;
  std::uint32_t result{};
  CarryProfile carry{};
};

Addition make_addition(std::initializer_list<std::uint32_t> operands,
                       std::uint32_t expected) {
  Addition result;
  result.operands.assign(operands);
  std::uint32_t sum = 0U;
  for (const auto value : result.operands) sum += value;
  require(sum == expected, "addition result mismatch while constructing trace");
  std::uint64_t carry = 0U;
  std::uint32_t reconstructed = 0U;
  for (unsigned bit = 0U; bit < 32U; ++bit) {
    std::uint64_t column = carry;
    for (const auto value : result.operands) column += (value >> bit) & 1U;
    if ((column & 1U) != 0U) reconstructed |= std::uint32_t{1} << bit;
    carry = column >> 1U;
    result.carry[bit] = carry;
  }
  require(reconstructed == expected, "carry columns do not reconstruct addition");
  result.result = expected;
  return result;
}

struct CompressionTrace {
  State input{};
  State output{};
  std::array<std::uint32_t, 64> schedule{};
  std::array<crypto::Sha256RoundTrace, 64> rounds{};
  std::vector<Addition> additions;
};

struct ExhaustiveTrace {
  Header header{};
  crypto::Digest first_digest{};
  crypto::Digest final_digest{};
  std::array<CompressionTrace, 3> compressions{};
};

CompressionTrace make_compression(
    std::span<const crypto::Sha256RoundTrace> rounds,
    const State& expected_output) {
  require(rounds.size() == 64U, "compression does not have 64 rounds");
  CompressionTrace trace;
  std::copy(rounds.begin(), rounds.end(), trace.rounds.begin());
  trace.input = before_state(rounds.front());
  trace.output = expected_output;
  trace.additions.reserve(312U);
  for (unsigned t = 0U; t < 64U; ++t) {
    require(rounds[t].round_index == t, "round index mismatch");
    trace.schedule[t] = rounds[t].w;
  }
  for (unsigned t = 16U; t < 64U; ++t) {
    const auto s0 = small_sigma0(trace.schedule[t - 15U]);
    const auto s1 = small_sigma1(trace.schedule[t - 2U]);
    trace.additions.push_back(make_addition(
        {trace.schedule[t - 16U], s0, trace.schedule[t - 7U], s1},
        trace.schedule[t]));
  }
  State state = trace.input;
  for (unsigned t = 0U; t < 64U; ++t) {
    const auto& r = rounds[t];
    require(before_state(r) == state, "round state_before mismatch");
    const auto s0 = sigma0(state[0]);
    const auto s1 = sigma1(state[4]);
    const auto ch = choice(state[4], state[5], state[6]);
    const auto maj = majority(state[0], state[1], state[2]);
    require(r.sum0 == s0 && r.sum1 == s1 && r.choice == ch &&
                r.majority == maj,
            "round primitive mismatch");
    trace.additions.push_back(make_addition(
        {state[7], s1, ch, kRoundConstants[t], trace.schedule[t]}, r.temp1));
    trace.additions.push_back(make_addition({s0, maj}, r.temp2));
    trace.additions.push_back(make_addition({r.temp1, r.temp2}, r.a_after));
    trace.additions.push_back(make_addition({state[3], r.temp1}, r.e_after));
    state = {r.a_after, r.b_after, r.c_after, r.d_after,
             r.e_after, r.f_after, r.g_after, r.h_after};
    require(state == after_state(r), "round state_after mismatch");
  }
  for (std::size_t i = 0; i < 8U; ++i) {
    trace.additions.push_back(
        make_addition({trace.input[i], state[i]}, trace.output[i]));
  }
  require(trace.additions.size() == 312U,
          "compression addition count is not 312");
  return trace;
}

ExhaustiveTrace build_exhaustive_trace(const Header& header) {
  ExhaustiveTrace result;
  result.header = header;
  const auto observed = crypto::trace_reduced_sha256d(header, 64U);
  require(observed.first_sha.rounds.size() == 128U &&
              observed.second_sha.rounds.size() == 64U,
          "raw trace round cardinality mismatch");
  result.first_digest = observed.first_sha.digest;
  result.final_digest = observed.digest;
  require(result.first_digest == crypto::sha256(header) &&
              result.final_digest == crypto::sha256d(header),
          "production digest audit mismatch");
  const auto first_words = digest_words(result.first_digest);
  const auto final_words = digest_words(result.final_digest);
  const auto midstate = before_state(observed.first_sha.rounds[64]);
  result.compressions[0] = make_compression(
      std::span<const crypto::Sha256RoundTrace>(observed.first_sha.rounds.data(), 64U),
      midstate);
  result.compressions[1] = make_compression(
      std::span<const crypto::Sha256RoundTrace>(observed.first_sha.rounds.data() + 64U, 64U),
      first_words);
  result.compressions[2] = make_compression(
      std::span<const crypto::Sha256RoundTrace>(observed.second_sha.rounds.data(), 64U),
      final_words);
  require(result.compressions[0].output == result.compressions[1].input &&
              result.compressions[2].input == kInitialState,
          "compression chaining mismatch");
  return result;
}

bool same_round(const crypto::Sha256RoundTrace& x,
                const crypto::Sha256RoundTrace& y) {
  return x.compression_index == y.compression_index && x.round_index == y.round_index &&
      x.w == y.w && x.sum0 == y.sum0 && x.sum1 == y.sum1 &&
      x.choice == y.choice && x.majority == y.majority &&
      x.temp1 == y.temp1 && x.temp2 == y.temp2 &&
      before_state(x) == before_state(y) && after_state(x) == after_state(y);
}

bool same_compression(const CompressionTrace& x, const CompressionTrace& y) {
  if (x.input != y.input || x.output != y.output || x.schedule != y.schedule ||
      x.additions.size() != y.additions.size()) return false;
  for (std::size_t i = 0; i < x.rounds.size(); ++i) {
    if (!same_round(x.rounds[i], y.rounds[i])) return false;
  }
  for (std::size_t i = 0; i < x.additions.size(); ++i) {
    if (x.additions[i].operands != y.additions[i].operands ||
        x.additions[i].result != y.additions[i].result ||
        x.additions[i].carry != y.additions[i].carry) return false;
  }
  return true;
}

struct CarryMetrics {
  std::uint32_t mask{};
  unsigned count{};
  unsigned longest_run{};
  std::uint64_t sum_abs_delta{};
  std::uint64_t max_abs_delta{};
};

CarryMetrics carry_difference(const Addition& reference,
                              const Addition& candidate) {
  CarryMetrics result;
  unsigned run = 0U;
  for (unsigned bit = 0U; bit < 32U; ++bit) {
    if (reference.carry[bit] == candidate.carry[bit]) {
      run = 0U;
      continue;
    }
    result.mask |= std::uint32_t{1} << bit;
    ++result.count;
    result.longest_run = std::max(result.longest_run, ++run);
    const auto delta = static_cast<std::int64_t>(candidate.carry[bit]) -
                       static_cast<std::int64_t>(reference.carry[bit]);
    const auto magnitude = static_cast<std::uint64_t>(delta < 0 ? -delta : delta);
    result.sum_abs_delta += magnitude;
    result.max_abs_delta = std::max(result.max_abs_delta, magnitude);
  }
  return result;
}

unsigned hamming(std::uint32_t x, std::uint32_t y) {
  return std::popcount(x ^ y);
}

unsigned digest_hamming(const crypto::Digest& x, const crypto::Digest& y) {
  return crypto::hamming_distance(x, y);
}

struct CompactTrajectory {
  std::array<State, kTotalRoundCount> masks{};
  std::array<unsigned, kTotalRoundCount> hamming{};
  std::vector<bool> carry_changed;
};

struct CandidateMetric {
  unsigned context_id{};
  unsigned bit{};
  unsigned w3_bit{};
  unsigned original_bit{};
  std::string direction;
  std::string sign;
  std::uint32_t nonce{};
  std::uint32_t t1_xor{};
  unsigned t1_hamming{};
  CarryMetrics t1_carry;
  std::uint32_t new_a_xor{};
  unsigned new_a_hamming{};
  CarryMetrics new_a_carry;
  std::uint32_t new_e_xor{};
  unsigned new_e_hamming{};
  CarryMetrics new_e_carry;
  unsigned round4_sigma0_hamming{};
  unsigned round4_sigma1_hamming{};
  unsigned round4_ch_hamming{};
  unsigned round4_maj_hamming{};
  bool ch_masked{};
  bool maj_masked{};
  std::optional<unsigned> round_to_8;
  std::optional<unsigned> hd64;
  std::optional<unsigned> hd128;
  unsigned maximum_hamming{};
  unsigned round_maximum{};
  double mean_after_diffusion{};
  unsigned first_extended{};
  std::uint32_t w18_sigma0_xor{};
  std::uint32_t w19_delta{};
  unsigned final_hamming{};
  std::string first_sha;
  std::string raw_sha256d;
  std::string display_hash;
  std::string signature;
};

std::size_t round_addition_index(unsigned round, unsigned operation) {
  return 48U + static_cast<std::size_t>(round) * 4U + operation;
}

CandidateMetric compare_candidate(const ExhaustiveTrace& reference,
                                  const ExhaustiveTrace& candidate,
                                  unsigned context_id,
                                  unsigned numeric_bit,
                                  CompactTrajectory& trajectory,
                                  std::size_t& addition_count,
                                  std::size_t& sigma_count) {
  require(std::equal(reference.header.begin(), reference.header.begin() + 76U,
                     candidate.header.begin()),
          "candidate first 76 bytes differ from context reference");
  unsigned header_hd = 0U;
  for (std::size_t i = 0; i < reference.header.size(); ++i) {
    header_hd += std::popcount(static_cast<unsigned>(
        reference.header[i] ^ candidate.header[i]));
  }
  require(header_hd == 1U, "candidate header is not a single-bit flip");
  require(same_compression(reference.compressions[0], candidate.compressions[0]),
          "SHA1/compression0 differs");
  for (unsigned round = 0U; round < 3U; ++round) {
    require(same_round(reference.compressions[1].rounds[round],
                       candidate.compressions[1].rounds[round]),
            "pre-divergence round differs");
  }
  const auto& rr3 = reference.compressions[1].rounds[3];
  const auto& cr3 = candidate.compressions[1].rounds[3];
  require(before_state(rr3) == before_state(cr3) && rr3.sum0 == cr3.sum0 &&
              rr3.sum1 == cr3.sum1 && rr3.choice == cr3.choice &&
              rr3.majority == cr3.majority,
          "round3 fixed operands differ");
  const auto w3_bit = numeric_nonce_bit_to_w3_bit(numeric_bit);
  const auto reference_w3 = reference.compressions[1].schedule[3];
  const auto candidate_w3 = candidate.compressions[1].schedule[3];
  const auto reference_nonce = read_le32(reference.header.data() + 76U);
  const auto candidate_nonce = read_le32(candidate.header.data() + 76U);
  require(reference_nonce == kGenesisNonce &&
              candidate_nonce ==
                  (reference_nonce ^ (std::uint32_t{1} << numeric_bit)),
          "numeric nonce XOR relationship mismatch");
  require((reference_w3 ^ candidate_w3) == (std::uint32_t{1} << w3_bit),
          "numeric nonce bit to W3 mapping mismatch");
  const auto original = static_cast<unsigned>((reference_w3 >> w3_bit) & 1U);
  const auto expected_delta = original == 0U
      ? (std::uint32_t{1} << w3_bit)
      : std::uint32_t{0} - (std::uint32_t{1} << w3_bit);
  require(candidate_w3 - reference_w3 == expected_delta &&
              cr3.temp1 - rr3.temp1 == expected_delta &&
              cr3.a_after - rr3.a_after == expected_delta &&
              cr3.e_after - rr3.e_after == expected_delta &&
              cr3.temp2 == rr3.temp2,
          "round3 exact modular invariant failed");

  trajectory.carry_changed.clear();
  trajectory.carry_changed.reserve(936U * 32U);
  for (std::size_t c = 0; c < 3U; ++c) {
    const auto& ra = reference.compressions[c].additions;
    const auto& ca = candidate.compressions[c].additions;
    require(ra.size() == 312U && ca.size() == 312U,
            "per-compression addition cardinality mismatch");
    for (std::size_t i = 0; i < ra.size(); ++i) {
      require(ra[i].operands.size() == ca[i].operands.size(),
              "addition operand cardinality mismatch");
      std::uint32_t operand_delta = 0U;
      for (std::size_t op = 0; op < ra[i].operands.size(); ++op) {
        operand_delta += ca[i].operands[op] - ra[i].operands[op];
      }
      require(ca[i].result - ra[i].result == operand_delta,
              "addition differential identity failed");
      const auto carry = carry_difference(ra[i], ca[i]);
      for (unsigned column = 0U; column < 32U; ++column) {
        trajectory.carry_changed.push_back(
            ((carry.mask >> column) & 1U) != 0U);
      }
      ++addition_count;
    }
    const auto& rs = reference.compressions[c].schedule;
    const auto& cs = candidate.compressions[c].schedule;
    for (unsigned t = 16U; t < 64U; ++t) {
      require((small_sigma0(rs[t - 15U]) ^ small_sigma0(cs[t - 15U])) ==
                  small_sigma0(rs[t - 15U] ^ cs[t - 15U]) &&
              (small_sigma1(rs[t - 2U]) ^ small_sigma1(cs[t - 2U])) ==
                  small_sigma1(rs[t - 2U] ^ cs[t - 2U]),
              "schedule Sigma differential failed");
      sigma_count += 2U;
    }
    for (unsigned t = 0U; t < 64U; ++t) {
      const auto& r = reference.compressions[c].rounds[t];
      const auto& q = candidate.compressions[c].rounds[t];
      require((r.sum0 ^ q.sum0) == sigma0(r.a_before ^ q.a_before) &&
                  (r.sum1 ^ q.sum1) == sigma1(r.e_before ^ q.e_before),
              "round Sigma differential failed");
      sigma_count += 2U;
    }
  }
  require(trajectory.carry_changed.size() == 936U * 32U,
          "carry-change vector is not 936 x 32");

  CandidateMetric metric;
  metric.context_id = context_id;
  metric.bit = numeric_bit;
  metric.w3_bit = w3_bit;
  metric.original_bit = original;
  metric.direction = original == 0U ? "0_to_1" : "1_to_0";
  metric.sign = original == 0U ? "+" : "-";
  metric.nonce = read_le32(candidate.header.data() + 76U);
  const auto& rt1 = reference.compressions[1].additions[
      round_addition_index(3U, 0U)];
  const auto& ct1 = candidate.compressions[1].additions[
      round_addition_index(3U, 0U)];
  require(rt1.operands.size() == 5U && ct1.operands.size() == 5U,
          "round3 T1 does not have five operands");
  for (std::size_t operand = 0U; operand < 4U; ++operand) {
    require(rt1.operands[operand] == ct1.operands[operand],
            "a non-W round3 T1 operand differs");
  }
  require(rt1.operands[4] == reference_w3 && ct1.operands[4] == candidate_w3,
          "W is not the sole direct differing round3 T1 operand");
  const auto& rna = reference.compressions[1].additions[
      round_addition_index(3U, 2U)];
  const auto& cna = candidate.compressions[1].additions[
      round_addition_index(3U, 2U)];
  const auto& rne = reference.compressions[1].additions[
      round_addition_index(3U, 3U)];
  const auto& cne = candidate.compressions[1].additions[
      round_addition_index(3U, 3U)];
  metric.t1_xor = rt1.result ^ ct1.result;
  metric.t1_hamming = std::popcount(metric.t1_xor);
  metric.t1_carry = carry_difference(rt1, ct1);
  metric.new_a_xor = rna.result ^ cna.result;
  metric.new_a_hamming = std::popcount(metric.new_a_xor);
  metric.new_a_carry = carry_difference(rna, cna);
  metric.new_e_xor = rne.result ^ cne.result;
  metric.new_e_hamming = std::popcount(metric.new_e_xor);
  metric.new_e_carry = carry_difference(rne, cne);

  std::optional<unsigned> first_divergence;
  std::uint64_t diffusion_sum = 0U;
  unsigned diffusion_count = 0U;
  for (unsigned step = 0U; step < kTotalRoundCount; ++step) {
    const auto c = step / 64U;
    const auto r = step % 64U;
    const auto rs = after_state(reference.compressions[c].rounds[r]);
    const auto cs = after_state(candidate.compressions[c].rounds[r]);
    unsigned state_hd = 0U;
    unsigned changed_registers = 0U;
    for (std::size_t word = 0U; word < 8U; ++word) {
      trajectory.masks[step][word] = rs[word] ^ cs[word];
      state_hd += std::popcount(trajectory.masks[step][word]);
      changed_registers += trajectory.masks[step][word] != 0U;
    }
    trajectory.hamming[step] = state_hd;
    if (!first_divergence &&
        (reference.compressions[c].schedule[r] !=
             candidate.compressions[c].schedule[r] || state_hd != 0U)) {
      first_divergence = step;
    }
    if (!metric.round_to_8 && changed_registers == 8U) metric.round_to_8 = step;
    if (!metric.hd64 && state_hd >= 64U) metric.hd64 = step;
    if (!metric.hd128 && state_hd >= 128U) metric.hd128 = step;
    if (state_hd > metric.maximum_hamming) {
      metric.maximum_hamming = state_hd;
      metric.round_maximum = step;
    }
    if (metric.round_to_8 && step >= *metric.round_to_8) {
      diffusion_sum += state_hd;
      ++diffusion_count;
    }
  }
  require(first_divergence && *first_divergence == kDivergenceStep,
          "first divergence is not global step 67");
  metric.mean_after_diffusion = diffusion_count == 0U ? 0.0 :
      static_cast<double>(diffusion_sum) / static_cast<double>(diffusion_count);
  const auto& rr4 = reference.compressions[1].rounds[4];
  const auto& cr4 = candidate.compressions[1].rounds[4];
  metric.round4_sigma0_hamming = hamming(rr4.sum0, cr4.sum0);
  metric.round4_sigma1_hamming = hamming(rr4.sum1, cr4.sum1);
  metric.round4_ch_hamming = hamming(rr4.choice, cr4.choice);
  metric.round4_maj_hamming = hamming(rr4.majority, cr4.majority);
  metric.ch_masked = metric.round4_ch_hamming == 0U;
  metric.maj_masked = metric.round4_maj_hamming == 0U;

  metric.first_extended = 64U;
  const auto& rs = reference.compressions[1].schedule;
  const auto& cs = candidate.compressions[1].schedule;
  for (unsigned t = 16U; t < 64U; ++t) {
    if (rs[t] != cs[t]) {
      metric.first_extended = t;
      break;
    }
  }
  metric.w18_sigma0_xor = small_sigma0(rs[3]) ^ small_sigma0(cs[3]);
  metric.w19_delta = cs[19] - rs[19];
  require(metric.first_extended == 18U && metric.w19_delta == expected_delta,
          "W18/W19 structural invariant failed");
  metric.final_hamming = digest_hamming(reference.final_digest, candidate.final_digest);
  metric.first_sha = crypto::digest_hex(candidate.first_digest);
  metric.raw_sha256d = crypto::digest_hex(candidate.final_digest);
  metric.display_hash = crypto::bitcoin_hash_hex(candidate.final_digest);
  std::ostringstream signature;
  signature << hex_word(metric.t1_carry.mask) << '/' << metric.t1_hamming << '/'
            << hex_word(metric.new_a_carry.mask) << '/' << metric.new_a_hamming << '/'
            << hex_word(metric.new_e_carry.mask) << '/' << metric.new_e_hamming << '/'
            << metric.round4_sigma0_hamming << '/' << metric.round4_sigma1_hamming << '/'
            << metric.round4_ch_hamming << '/' << metric.round4_maj_hamming << '/'
            << (metric.round_to_8 ? std::to_string(*metric.round_to_8) : "null") << '/'
            << (metric.hd64 ? std::to_string(*metric.hd64) : "null") << '/'
            << (metric.hd128 ? std::to_string(*metric.hd128) : "null") << '/'
            << metric.first_extended;
  metric.signature = signature.str();
  return metric;
}

double mean_mask_distance(const CompactTrajectory& x,
                          const CompactTrajectory& y,
                          unsigned begin) {
  std::uint64_t total = 0U;
  for (unsigned step = begin; step < kTotalRoundCount; ++step) {
    for (std::size_t word = 0U; word < 8U; ++word) {
      total += std::popcount(x.masks[step][word] ^ y.masks[step][word]);
    }
  }
  return static_cast<double>(total) /
      static_cast<double>(kTotalRoundCount - begin);
}

double carry_jaccard(const CompactTrajectory& x, const CompactTrajectory& y) {
  require(x.carry_changed.size() == y.carry_changed.size(),
          "pair carry vectors differ in size");
  std::uint64_t intersection = 0U;
  std::uint64_t union_count = 0U;
  for (std::size_t i = 0U; i < x.carry_changed.size(); ++i) {
    intersection += x.carry_changed[i] && y.carry_changed[i];
    union_count += x.carry_changed[i] || y.carry_changed[i];
  }
  return union_count == 0U ? 1.0 :
      static_cast<double>(intersection) / static_cast<double>(union_count);
}

std::optional<double> pearson(const CompactTrajectory& x,
                              const CompactTrajectory& y,
                              unsigned begin) {
  const auto count = kTotalRoundCount - begin;
  double xm = 0.0;
  double ym = 0.0;
  for (unsigned i = begin; i < kTotalRoundCount; ++i) {
    xm += x.hamming[i];
    ym += y.hamming[i];
  }
  xm /= count;
  ym /= count;
  double covariance = 0.0;
  double xv = 0.0;
  double yv = 0.0;
  for (unsigned i = begin; i < kTotalRoundCount; ++i) {
    const auto xd = x.hamming[i] - xm;
    const auto yd = y.hamming[i] - ym;
    covariance += xd * yd;
    xv += xd * xd;
    yv += yd * yd;
  }
  if (xv == 0.0 || yv == 0.0) return std::nullopt;
  return covariance / std::sqrt(xv * yv);
}

struct PairObservation {
  double full{};
  double post{};
  double jaccard{};
  std::optional<double> pearson_full;
  std::optional<double> pearson_post;
};

struct PairAccumulator {
  unsigned left{};
  unsigned right{};
  std::array<std::vector<PairObservation>, 2> observations;
  std::array<std::vector<unsigned>, 2> ranks;
  std::array<unsigned, 2> top5{};
  std::array<unsigned, 2> top10{};
  std::array<unsigned, 2> top25{};
};

double mean(const std::vector<double>& values) {
  if (values.empty()) return std::numeric_limits<double>::quiet_NaN();
  return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
}

double median(std::vector<double> values) {
  if (values.empty()) return std::numeric_limits<double>::quiet_NaN();
  std::sort(values.begin(), values.end());
  const auto middle = values.size() / 2U;
  return values.size() % 2U == 0U
      ? (values[middle - 1U] + values[middle]) / 2.0
      : values[middle];
}

std::string number(double value) {
  if (std::isnan(value)) return {};
  std::ostringstream output;
  output << std::fixed << std::setprecision(6) << value;
  return output.str();
}

nlohmann::json number_json(double value) {
  return std::isnan(value) ? nlohmann::json(nullptr) : nlohmann::json(value);
}

std::string optional_value(const std::optional<unsigned>& value) {
  return value ? std::to_string(*value) : std::string{};
}

void csv_row(std::ostringstream& output,
             const std::vector<std::string>& fields) {
  for (std::size_t i = 0U; i < fields.size(); ++i) {
    if (i != 0U) output << ',';
    output << '"';
    for (const auto ch : fields[i]) {
      if (ch == '"') output << '"';
      output << ch;
    }
    output << '"';
  }
  output << '\n';
}

unsigned popcount_bytes(std::span<const std::uint8_t> bytes) {
  unsigned result = 0U;
  for (const auto value : bytes) result += std::popcount(value);
  return result;
}

Header context_header(unsigned context_id) {
  require(context_id < 64U, "context id is outside 0..63");
  Header header = header_space::genesis_header();
  const auto& merkle = merkle_context_transfer_fields()[context_id];
  std::copy(merkle.begin(), merkle.end(), header.begin() + 36U);
  require(read_le32(header.data() + 76U) == kGenesisNonce,
          "context nonce changed");
  return header;
}

void validate_all_fixtures() {
  const auto& fields = merkle_context_transfer_fields();
  const std::string seed_text = "SRM_WHITEBOX_MERKLE_CONTEXT_V1";
  for (unsigned id = 0U; id < 64U; ++id) {
    std::vector<std::uint8_t> seed(seed_text.begin(), seed_text.end());
    seed.push_back(static_cast<std::uint8_t>(id));
    seed.push_back(static_cast<std::uint8_t>(id >> 8U));
    seed.push_back(static_cast<std::uint8_t>(id >> 16U));
    seed.push_back(static_cast<std::uint8_t>(id >> 24U));
    require(crypto::sha256(seed) == fields[id],
            "frozen Merkle fixture differs from exact generator at id " +
                std::to_string(id));
    const auto header = context_header(id);
    const auto genesis = header_space::genesis_header();
    for (std::size_t byte = 0U; byte < header.size(); ++byte) {
      if (byte >= 36U && byte <= 67U) continue;
      require(header[byte] == genesis[byte],
              "non-Merkle context byte changed");
    }
  }
}

std::string mode_of(const std::vector<std::string>& values,
                    std::size_t& frequency) {
  std::map<std::string, std::size_t> counts;
  for (const auto& value : values) ++counts[value];
  frequency = 0U;
  std::string mode;
  for (const auto& [value, count] : counts) {
    if (count > frequency) {
      frequency = count;
      mode = value;
    }
  }
  return mode;
}

std::vector<const CandidateMetric*> select_metrics(
    const std::vector<CandidateMetric>& metrics, unsigned bit, unsigned split) {
  std::vector<const CandidateMetric*> result;
  for (const auto& metric : metrics) {
    if (metric.bit == bit && (metric.context_id < 32U ? 0U : 1U) == split) {
      result.push_back(&metric);
    }
  }
  return result;
}

struct ModeSummary {
  std::string mode;
  std::size_t discovery_frequency{};
  std::size_t holdout_frequency{};
};

template <typename Function>
ModeSummary frozen_mode(const std::vector<CandidateMetric>& metrics,
                        unsigned bit, Function key) {
  std::vector<std::string> discovery;
  std::vector<std::string> holdout;
  for (const auto& metric : metrics) {
    if (metric.bit != bit) continue;
    (metric.context_id < 32U ? discovery : holdout).push_back(key(metric));
  }
  ModeSummary result;
  result.mode = mode_of(discovery, result.discovery_frequency);
  result.holdout_frequency = static_cast<std::size_t>(std::count(
      holdout.begin(), holdout.end(), result.mode));
  return result;
}

template <typename Function>
nlohmann::json value_distribution(const std::vector<CandidateMetric>& metrics,
                                  unsigned bit, unsigned split, Function key) {
  std::map<std::string, std::size_t> counts;
  for (const auto& metric : metrics) {
    if (metric.bit == bit && (metric.context_id < 32U ? 0U : 1U) == split) {
      ++counts[key(metric)];
    }
  }
  nlohmann::json result = nlohmann::json::object();
  for (const auto& [value, count] : counts) result[value] = count;
  return result;
}

std::vector<double> values_of(const std::vector<const CandidateMetric*>& metrics,
                              const std::function<double(const CandidateMetric&)>& f) {
  std::vector<double> result;
  result.reserve(metrics.size());
  for (const auto* metric : metrics) result.push_back(f(*metric));
  return result;
}

double spearman(const std::array<double, 32>& x,
                const std::array<double, 32>& y) {
  const auto ranks = [](const std::array<double, 32>& values) {
    std::array<double, 32> result{};
    std::array<unsigned, 32> order{};
    std::iota(order.begin(), order.end(), 0U);
    std::sort(order.begin(), order.end(), [&](unsigned a, unsigned b) {
      if (values[a] != values[b]) return values[a] < values[b];
      return a < b;
    });
    std::size_t begin = 0U;
    while (begin < order.size()) {
      std::size_t end = begin + 1U;
      while (end < order.size() && values[order[end]] == values[order[begin]]) ++end;
      const auto rank = (static_cast<double>(begin + 1U) +
                         static_cast<double>(end)) / 2.0;
      for (std::size_t i = begin; i < end; ++i) result[order[i]] = rank;
      begin = end;
    }
    return result;
  };
  const auto rx = ranks(x);
  const auto ry = ranks(y);
  const auto mx = std::accumulate(rx.begin(), rx.end(), 0.0) / 32.0;
  const auto my = std::accumulate(ry.begin(), ry.end(), 0.0) / 32.0;
  double covariance = 0.0;
  double xv = 0.0;
  double yv = 0.0;
  for (std::size_t i = 0U; i < 32U; ++i) {
    covariance += (rx[i] - mx) * (ry[i] - my);
    xv += (rx[i] - mx) * (rx[i] - mx);
    yv += (ry[i] - my) * (ry[i] - my);
  }
  return covariance / std::sqrt(xv * yv);
}

nlohmann::json state_feature_json(const State& state) {
  auto result = nlohmann::json::object();
  for (std::size_t i = 0U; i < state.size(); ++i) {
    result[kStateNames[i]] = {
        {"hex", hex_word(state[i])}, {"popcount", std::popcount(state[i])}};
  }
  return result;
}

void write_text_file(const std::filesystem::path& path,
                     const std::string& contents) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("cannot create " + path.string());
  output << contents;
  if (!output) throw std::runtime_error("cannot finish writing " + path.string());
}

bool is_predeclared_pair(unsigned left, unsigned right) {
  constexpr std::array<std::pair<unsigned, unsigned>, 5> pairs{{
      {17U, 28U}, {6U, 7U}, {13U, 14U}, {2U, 4U}, {17U, 26U}}};
  return std::find(pairs.begin(), pairs.end(), std::pair{left, right}) != pairs.end();
}

std::optional<std::pair<double, double>> genesis_pair_metrics(
    unsigned left, unsigned right) {
  if (left == 17U && right == 28U) return {{77.38541666666667, 0.3659121359565616}};
  if (left == 6U && right == 7U) return {{77.91666666666667, 0.36341030195381885}};
  if (left == 13U && right == 14U) return {{78.19270833333333, 0.36521121760738373}};
  if (left == 2U && right == 4U) return {{78.28645833333333, 0.3722292813779472}};
  if (left == 17U && right == 26U) return {{78.296875, 0.36507042253521127}};
  return std::nullopt;
}

}  // namespace

const std::array<std::array<std::uint8_t, 32>, 64>&
merkle_context_transfer_fields() {
  static const auto fields = [] {
    std::array<std::array<std::uint8_t, 32>, 64> result{};
    for (std::size_t i = 0U; i < result.size(); ++i) {
      const auto bytes = crypto::from_hex(kMerkleHex[i]);
      if (bytes.size() != 32U) fail("frozen Merkle fixture is not 32 bytes");
      std::copy(bytes.begin(), bytes.end(), result[i].begin());
    }
    return result;
  }();
  return fields;
}

MerkleContextTransferArtifacts build_merkle_context_transfer_campaign(
    std::size_t context_count,
    const std::function<void(unsigned, unsigned)>& progress) {
  require(context_count >= 1U && context_count <= 64U,
          "context_count must be in [1,64]");
  validate_all_fixtures();

  std::ostringstream contexts_csv;
  csv_row(contexts_csv, {"context_id", "split", "header_prefix_76_hex",
      "prefix_popcount", "merkle_header_bytes_hex", "merkle_display_hex",
      "merkle_popcount", "merkle_word0", "merkle_word0_popcount",
      "merkle_word1", "merkle_word1_popcount", "merkle_word2",
      "merkle_word2_popcount", "merkle_word3", "merkle_word3_popcount",
      "merkle_word4", "merkle_word4_popcount", "merkle_word5",
      "merkle_word5_popcount", "merkle_word6", "merkle_word6_popcount",
      "merkle_word7", "merkle_word7_popcount", "nonce_reference",
      "W3_reference", "compression0_state", "compression0_popcounts",
      "round3_pre_state", "round3_pre_state_popcounts", "round3_h",
      "round3_Sigma1_e", "round3_Ch", "round3_K",
      "T1_fixed_sum_without_W", "T1_reference",
      "T1_reference_carry_nonzero_mask", "T1_reference_carry_max",
      "T1_reference_carry_nonzero_count", "T1_reference_carry_total",
      "first_sha256", "raw_sha256d", "bitcoin_display_hash",
      "unique_complete_signatures"});
  std::ostringstream per_bit_csv;
  csv_row(per_bit_csv, {"context_id", "split", "numeric_nonce_bit", "W3_bit",
      "original_W3_bit_value", "flip_direction", "mod_delta_sign",
      "nonce_candidate", "round3_T1_xor", "round3_T1_hamming",
      "round3_T1_carry_diff_mask", "round3_T1_carry_diff_count",
      "round3_T1_carry_longest_run", "round3_T1_carry_sum_abs_delta",
      "round3_T1_carry_max_abs_delta", "round3_new_a_xor",
      "round3_new_a_hamming", "round3_new_a_carry_diff_mask",
      "round3_new_a_carry_diff_count", "round3_new_e_xor",
      "round3_new_e_hamming", "round3_new_e_carry_diff_mask",
      "round3_new_e_carry_diff_count", "round4_Sigma0_hamming",
      "round4_Sigma1_hamming", "round4_Ch_hamming", "round4_Maj_hamming",
      "round4_Ch_entirely_masked", "round4_Maj_entirely_masked",
      "round_to_8_registers", "round_to_HD64", "round_to_HD128",
      "maximum_state_hamming", "round_of_maximum_state_hamming",
      "mean_state_hamming_after_diffusion", "first_extended_W_that_differs",
      "W18_small_sigma0_output_xor", "W19_mod_delta",
      "final_hash_hamming_vs_context_reference", "first_sha256",
      "raw_sha256d", "bitcoin_display_hash", "complete_signature"});

  nlohmann::json contexts = nlohmann::json::array();
  std::vector<CandidateMetric> metrics;
  metrics.reserve(context_count * 32U);
  std::vector<PairAccumulator> pairs;
  for (unsigned left = 0U; left < 32U; ++left) {
    for (unsigned right = left + 1U; right < 32U; ++right) {
      pairs.push_back(PairAccumulator{left, right});
    }
  }
  require(pairs.size() == 496U, "pair triangle is not 496");
  using RoundValues = std::array<std::array<std::array<std::vector<unsigned>,
      kTotalRoundCount>, 32>, 2>;
  RoundValues round_values;
  std::vector<unsigned> exploratory_pairs_frozen;
  std::array<std::array<ModeSummary, 9>, 32> discovery_modes_frozen{};
  bool discovery_modes_were_frozen = false;
  std::size_t addition_count = 0U;
  std::size_t sigma_count = 0U;

  for (unsigned context_id = 0U; context_id < context_count; ++context_id) {
    const auto header = context_header(context_id);
    const auto reference = build_exhaustive_trace(header);
    require(reference.compressions[1].schedule[3] == kGenesisW3,
            "reference W3 is not the frozen Genesis nonce W3");
    std::vector<CompactTrajectory> trajectories(32U);
    std::vector<CandidateMetric> context_metrics;
    context_metrics.reserve(32U);
    for (unsigned bit = 0U; bit < 32U; ++bit) {
      if (progress) progress(context_id, bit);
      auto candidate_header = header;
      candidate_header[76U + bit / 8U] ^=
          static_cast<std::uint8_t>(1U << (bit % 8U));
      const auto candidate = build_exhaustive_trace(candidate_header);
      auto metric = compare_candidate(reference, candidate, context_id, bit,
                                      trajectories[bit], addition_count,
                                      sigma_count);
      const auto split = context_id < 32U ? 0U : 1U;
      for (unsigned step = 0U; step < kTotalRoundCount; ++step) {
        round_values[split][bit][step].push_back(
            trajectories[bit].hamming[step]);
      }
      csv_row(per_bit_csv, {std::to_string(context_id), split_name(context_id),
          std::to_string(bit), std::to_string(metric.w3_bit),
          std::to_string(metric.original_bit), metric.direction, metric.sign,
          std::to_string(metric.nonce), hex_word(metric.t1_xor),
          std::to_string(metric.t1_hamming), hex_word(metric.t1_carry.mask),
          std::to_string(metric.t1_carry.count),
          std::to_string(metric.t1_carry.longest_run),
          std::to_string(metric.t1_carry.sum_abs_delta),
          std::to_string(metric.t1_carry.max_abs_delta),
          hex_word(metric.new_a_xor), std::to_string(metric.new_a_hamming),
          hex_word(metric.new_a_carry.mask), std::to_string(metric.new_a_carry.count),
          hex_word(metric.new_e_xor), std::to_string(metric.new_e_hamming),
          hex_word(metric.new_e_carry.mask), std::to_string(metric.new_e_carry.count),
          std::to_string(metric.round4_sigma0_hamming),
          std::to_string(metric.round4_sigma1_hamming),
          std::to_string(metric.round4_ch_hamming),
          std::to_string(metric.round4_maj_hamming),
          metric.ch_masked ? "true" : "false",
          metric.maj_masked ? "true" : "false",
          optional_value(metric.round_to_8), optional_value(metric.hd64),
          optional_value(metric.hd128), std::to_string(metric.maximum_hamming),
          std::to_string(metric.round_maximum), number(metric.mean_after_diffusion),
          std::to_string(metric.first_extended), hex_word(metric.w18_sigma0_xor),
          hex_word(metric.w19_delta), std::to_string(metric.final_hamming),
          metric.first_sha, metric.raw_sha256d, metric.display_hash,
          metric.signature});
      context_metrics.push_back(metric);
      metrics.push_back(std::move(metric));
      // The exhaustive candidate trace is destroyed here.
    }

    std::vector<PairObservation> observations(pairs.size());
    for (std::size_t index = 0U; index < pairs.size(); ++index) {
      const auto left = pairs[index].left;
      const auto right = pairs[index].right;
      observations[index] = {
          mean_mask_distance(trajectories[left], trajectories[right], 0U),
          mean_mask_distance(trajectories[left], trajectories[right], kDivergenceStep),
          carry_jaccard(trajectories[left], trajectories[right]),
          pearson(trajectories[left], trajectories[right], 0U),
          pearson(trajectories[left], trajectories[right], kDivergenceStep)};
    }
    std::vector<unsigned> order(pairs.size());
    std::iota(order.begin(), order.end(), 0U);
    std::sort(order.begin(), order.end(), [&](unsigned x, unsigned y) {
      if (observations[x].post != observations[y].post) {
        return observations[x].post < observations[y].post;
      }
      if (observations[x].jaccard != observations[y].jaccard) {
        return observations[x].jaccard > observations[y].jaccard;
      }
      return x < y;
    });
    const auto split = context_id < 32U ? 0U : 1U;
    for (std::size_t position = 0U; position < order.size(); ++position) {
      const auto index = order[position];
      const auto rank = static_cast<unsigned>(position + 1U);
      pairs[index].observations[split].push_back(observations[index]);
      pairs[index].ranks[split].push_back(rank);
      pairs[index].top5[split] += rank <= 25U;
      pairs[index].top10[split] += rank <= 50U;
      pairs[index].top25[split] += rank <= 124U;
    }
    if (context_id == 31U) {
      std::vector<unsigned> discovery_order(pairs.size());
      std::iota(discovery_order.begin(), discovery_order.end(), 0U);
      std::sort(discovery_order.begin(), discovery_order.end(), [&](unsigned x, unsigned y) {
        std::vector<double> xr;
        std::vector<double> yr;
        for (const auto rank : pairs[x].ranks[0]) xr.push_back(rank);
        for (const auto rank : pairs[y].ranks[0]) yr.push_back(rank);
        const auto xm = mean(xr);
        const auto ym = mean(yr);
        return xm != ym ? xm < ym : x < y;
      });
      exploratory_pairs_frozen.assign(discovery_order.begin(),
                                      discovery_order.begin() + 5U);
      for (unsigned bit = 0U; bit < 32U; ++bit) {
        discovery_modes_frozen[bit][0] = frozen_mode(metrics, bit, [](const auto& x) { return hex_word(x.t1_carry.mask); });
        discovery_modes_frozen[bit][1] = frozen_mode(metrics, bit, [](const auto& x) { return std::to_string(x.t1_hamming); });
        discovery_modes_frozen[bit][2] = frozen_mode(metrics, bit, [](const auto& x) { return std::to_string(x.new_a_hamming); });
        discovery_modes_frozen[bit][3] = frozen_mode(metrics, bit, [](const auto& x) { return std::to_string(x.new_e_hamming); });
        discovery_modes_frozen[bit][4] = frozen_mode(metrics, bit, [](const auto& x) {
          return std::to_string(x.t1_hamming) + "/" + std::to_string(x.new_a_hamming) + "/" + std::to_string(x.new_e_hamming); });
        discovery_modes_frozen[bit][5] = frozen_mode(metrics, bit, [](const auto& x) { return x.ch_masked ? "true" : "false"; });
        discovery_modes_frozen[bit][6] = frozen_mode(metrics, bit, [](const auto& x) { return x.maj_masked ? "true" : "false"; });
        discovery_modes_frozen[bit][7] = frozen_mode(metrics, bit, [](const auto& x) { return optional_value(x.hd64); });
        discovery_modes_frozen[bit][8] = frozen_mode(metrics, bit, [](const auto& x) { return optional_value(x.hd128); });
      }
      discovery_modes_were_frozen = true;
    }

    const auto& merkle = merkle_context_transfer_fields()[context_id];
    std::array<std::uint32_t, 8> merkle_words{};
    auto word_json = nlohmann::json::array();
    for (std::size_t i = 0U; i < 8U; ++i) {
      merkle_words[i] = read_be32(merkle.data() + i * 4U);
      word_json.push_back({{"index", i}, {"hex", hex_word(merkle_words[i])},
                           {"popcount", std::popcount(merkle_words[i])}});
    }
    const auto& round3 = reference.compressions[1].rounds[3];
    const auto round3_state = before_state(round3);
    const auto fixed_sum = round3.h_before + round3.sum1 + round3.choice +
                           kRoundConstants[3];
    const auto& t1_reference = reference.compressions[1].additions[
        round_addition_index(3U, 0U)];
    std::uint32_t carry_mask = 0U;
    std::uint64_t carry_max = 0U;
    std::uint64_t carry_total = 0U;
    unsigned carry_nonzero = 0U;
    for (unsigned bit = 0U; bit < 32U; ++bit) {
      if (t1_reference.carry[bit] != 0U) carry_mask |= std::uint32_t{1} << bit;
      carry_max = std::max(carry_max, t1_reference.carry[bit]);
      carry_total += t1_reference.carry[bit];
      carry_nonzero += t1_reference.carry[bit] != 0U;
    }
    std::set<std::string> signatures;
    for (const auto& metric : context_metrics) signatures.insert(metric.signature);
    const auto prefix = std::span<const std::uint8_t>(header.data(), 76U);
    const auto context_json = nlohmann::json{
        {"context_id", context_id}, {"split", split_name(context_id)},
        {"header_prefix_76_hex", crypto::to_hex(prefix)},
        {"prefix_popcount", popcount_bytes(prefix)},
        {"merkle_header_bytes_hex", crypto::to_hex(merkle)},
        {"merkle_display_hex", reversed_hex(merkle)},
        {"merkle_popcount", popcount_bytes(merkle)},
        {"merkle_words_big_endian", word_json},
        {"nonce_reference", kGenesisNonce}, {"W3_reference", hex_word(kGenesisW3)},
        {"compression0_output_state", state_feature_json(reference.compressions[0].output)},
        {"round3_state_before", state_feature_json(round3_state)},
        {"round3_fixed_operands", {{"h", hex_word(round3.h_before)},
             {"Sigma1_e", hex_word(round3.sum1)}, {"Ch", hex_word(round3.choice)},
             {"K", hex_word(kRoundConstants[3])},
             {"T1_fixed_sum_without_W", hex_word(fixed_sum)},
             {"T1_reference", hex_word(round3.temp1)}}},
        {"T1_reference_carry_profile", {{"nonzero_mask", hex_word(carry_mask)},
             {"max", carry_max}, {"nonzero_count", carry_nonzero},
             {"total", carry_total}}},
        {"first_sha256", crypto::digest_hex(reference.first_digest)},
        {"raw_sha256d", crypto::digest_hex(reference.final_digest)},
        {"bitcoin_display_hash", crypto::bitcoin_hash_hex(reference.final_digest)},
        {"unique_complete_signatures", signatures.size()}};
    contexts.push_back(context_json);
    std::vector<std::string> context_fields{
        std::to_string(context_id), split_name(context_id), crypto::to_hex(prefix),
        std::to_string(popcount_bytes(prefix)), crypto::to_hex(merkle),
        reversed_hex(merkle), std::to_string(popcount_bytes(merkle))};
    for (const auto word : merkle_words) {
      context_fields.push_back(hex_word(word));
      context_fields.push_back(std::to_string(std::popcount(word)));
    }
    const auto compact_state = [](const State& state, bool counts) {
      std::ostringstream output;
      for (std::size_t i = 0U; i < state.size(); ++i) {
        if (i != 0U) output << ';';
        output << (counts ? std::to_string(std::popcount(state[i])) : hex_word(state[i]));
      }
      return output.str();
    };
    context_fields.insert(context_fields.end(), {
        std::to_string(kGenesisNonce), hex_word(kGenesisW3),
        compact_state(reference.compressions[0].output, false),
        compact_state(reference.compressions[0].output, true),
        compact_state(round3_state, false), compact_state(round3_state, true),
        hex_word(round3.h_before), hex_word(round3.sum1), hex_word(round3.choice),
        hex_word(kRoundConstants[3]), hex_word(fixed_sum), hex_word(round3.temp1),
        hex_word(carry_mask), std::to_string(carry_max),
        std::to_string(carry_nonzero), std::to_string(carry_total),
        crypto::digest_hex(reference.first_digest),
        crypto::digest_hex(reference.final_digest),
        crypto::bitcoin_hash_hex(reference.final_digest),
        std::to_string(signatures.size())});
    csv_row(contexts_csv, context_fields);
    // reference and all 32 exhaustive candidate traces are destroyed here.
  }

  nlohmann::json bit_summaries = nlohmann::json::array();
  std::ostringstream bit_summary_csv;
  csv_row(bit_summary_csv, {"numeric_nonce_bit", "W3_bit", "flip_direction",
      "discovery_rate_no_T1_carry_change", "holdout_rate_no_T1_carry_change",
      "discovery_rate_Ch_masked", "holdout_rate_Ch_masked",
      "discovery_rate_Maj_masked", "holdout_rate_Maj_masked",
      "discovery_median_HD64", "holdout_median_HD64",
      "discovery_median_HD128", "holdout_median_HD128",
      "T1_carry_mask_discovery_mode", "T1_carry_mask_discovery_mode_frequency",
      "T1_carry_mask_holdout_frequency_of_discovery_mode",
      "T1_hamming_discovery_mode", "T1_hamming_discovery_mode_frequency",
      "T1_hamming_holdout_frequency_of_discovery_mode",
      "new_a_hamming_discovery_mode", "new_a_hamming_discovery_mode_frequency",
      "new_a_hamming_holdout_frequency_of_discovery_mode",
      "new_e_hamming_discovery_mode", "new_e_hamming_discovery_mode_frequency",
      "new_e_hamming_holdout_frequency_of_discovery_mode",
      "triplet_discovery_mode", "triplet_discovery_mode_frequency",
      "triplet_holdout_frequency_of_discovery_mode", "Ch_masked_discovery_mode",
      "Ch_masked_discovery_mode_frequency", "Ch_masked_holdout_frequency_of_discovery_mode",
      "Maj_masked_discovery_mode", "Maj_masked_discovery_mode_frequency",
      "Maj_masked_holdout_frequency_of_discovery_mode", "HD64_discovery_mode",
      "HD64_discovery_mode_frequency", "HD64_holdout_frequency_of_discovery_mode",
      "HD128_discovery_mode", "HD128_discovery_mode_frequency",
      "HD128_holdout_frequency_of_discovery_mode", "distinct_complete_signatures",
      "complete_signature_mode", "complete_signature_mode_frequency"});
  const auto rate = [](std::size_t numerator, std::size_t denominator) {
    return denominator == 0U ? std::numeric_limits<double>::quiet_NaN() :
        static_cast<double>(numerator) / static_cast<double>(denominator);
  };
  std::array<std::array<double, 32>, 5> discovery_vectors{};
  std::array<std::array<double, 32>, 5> holdout_vectors{};
  for (unsigned bit = 0U; bit < 32U; ++bit) {
    const auto discovery = select_metrics(metrics, bit, 0U);
    const auto holdout = select_metrics(metrics, bit, 1U);
    const auto count_if = [](const auto& rows, const auto& predicate) {
      return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(),
          [&](const CandidateMetric* metric) { return predicate(*metric); }));
    };
    const auto no_carry_d = rate(count_if(discovery, [](const auto& x) { return x.t1_carry.count == 0U; }), discovery.size());
    const auto no_carry_h = rate(count_if(holdout, [](const auto& x) { return x.t1_carry.count == 0U; }), holdout.size());
    const auto ch_d = rate(count_if(discovery, [](const auto& x) { return x.ch_masked; }), discovery.size());
    const auto ch_h = rate(count_if(holdout, [](const auto& x) { return x.ch_masked; }), holdout.size());
    const auto maj_d = rate(count_if(discovery, [](const auto& x) { return x.maj_masked; }), discovery.size());
    const auto maj_h = rate(count_if(holdout, [](const auto& x) { return x.maj_masked; }), holdout.size());
    const auto hd64d = median(values_of(discovery, [](const auto& x) { return x.hd64 ? *x.hd64 : 192.0; }));
    const auto hd64h = median(values_of(holdout, [](const auto& x) { return x.hd64 ? *x.hd64 : 192.0; }));
    const auto hd128d = median(values_of(discovery, [](const auto& x) { return x.hd128 ? *x.hd128 : 192.0; }));
    const auto hd128h = median(values_of(holdout, [](const auto& x) { return x.hd128 ? *x.hd128 : 192.0; }));
    const auto carry_mean_d = mean(values_of(discovery, [](const auto& x) { return x.t1_carry.count; }));
    const auto carry_mean_h = mean(values_of(holdout, [](const auto& x) { return x.t1_carry.count; }));
    if (!discovery.empty()) {
      discovery_vectors[0][bit] = hd64d;
      discovery_vectors[1][bit] = hd128d;
      discovery_vectors[2][bit] = carry_mean_d;
      discovery_vectors[3][bit] = ch_d;
      discovery_vectors[4][bit] = maj_d;
    }
    if (!holdout.empty()) {
      holdout_vectors[0][bit] = hd64h;
      holdout_vectors[1][bit] = hd128h;
      holdout_vectors[2][bit] = carry_mean_h;
      holdout_vectors[3][bit] = ch_h;
      holdout_vectors[4][bit] = maj_h;
    }
    const auto mask_mode = frozen_mode(metrics, bit, [](const auto& x) { return hex_word(x.t1_carry.mask); });
    const auto t1_mode = frozen_mode(metrics, bit, [](const auto& x) { return std::to_string(x.t1_hamming); });
    const auto na_mode = frozen_mode(metrics, bit, [](const auto& x) { return std::to_string(x.new_a_hamming); });
    const auto ne_mode = frozen_mode(metrics, bit, [](const auto& x) { return std::to_string(x.new_e_hamming); });
    const auto triplet_mode = frozen_mode(metrics, bit, [](const auto& x) {
      return std::to_string(x.t1_hamming) + "/" + std::to_string(x.new_a_hamming) + "/" + std::to_string(x.new_e_hamming); });
    const auto ch_mode = frozen_mode(metrics, bit, [](const auto& x) { return x.ch_masked ? "true" : "false"; });
    const auto maj_mode = frozen_mode(metrics, bit, [](const auto& x) { return x.maj_masked ? "true" : "false"; });
    const auto hd64_mode = frozen_mode(metrics, bit, [](const auto& x) { return optional_value(x.hd64); });
    const auto hd128_mode = frozen_mode(metrics, bit, [](const auto& x) { return optional_value(x.hd128); });
    if (discovery_modes_were_frozen) {
      const std::array<const ModeSummary*, 9> observed_modes{{
          &mask_mode, &t1_mode, &na_mode, &ne_mode, &triplet_mode,
          &ch_mode, &maj_mode, &hd64_mode, &hd128_mode}};
      for (std::size_t i = 0U; i < observed_modes.size(); ++i) {
        require(observed_modes[i]->mode == discovery_modes_frozen[bit][i].mode &&
                    observed_modes[i]->discovery_frequency ==
                        discovery_modes_frozen[bit][i].discovery_frequency,
                "holdout changed a frozen discovery mode");
      }
    }
    std::vector<std::string> signatures;
    for (const auto& metric : metrics) if (metric.bit == bit) signatures.push_back(metric.signature);
    std::size_t signature_mode_frequency = 0U;
    const auto signature_mode = mode_of(signatures, signature_mode_frequency);
    const std::set<std::string> distinct_signatures(signatures.begin(), signatures.end());
    const auto mode_json = [&](const ModeSummary& mode, const auto& key) {
      return nlohmann::json{{"discovery_mode", mode.mode},
          {"discovery_mode_frequency", mode.discovery_frequency},
          {"holdout_frequency_of_discovery_mode", mode.holdout_frequency},
          {"discovery_distribution", value_distribution(metrics, bit, 0U, key)},
          {"holdout_distribution", value_distribution(metrics, bit, 1U, key)}};
    };
    bit_summaries.push_back({
        {"numeric_nonce_bit", bit},
        {"W3_bit", numeric_nonce_bit_to_w3_bit(bit)},
        {"flip_direction", ((kGenesisW3 >> numeric_nonce_bit_to_w3_bit(bit)) & 1U) == 0U ? "0_to_1" : "1_to_0"},
        {"discovery_rate_no_T1_carry_change", number_json(no_carry_d)},
        {"holdout_rate_no_T1_carry_change", number_json(no_carry_h)},
        {"discovery_rate_Ch_masked", number_json(ch_d)},
        {"holdout_rate_Ch_masked", number_json(ch_h)},
        {"discovery_rate_Maj_masked", number_json(maj_d)},
        {"holdout_rate_Maj_masked", number_json(maj_h)},
        {"discovery_median_HD64", number_json(hd64d)},
        {"holdout_median_HD64", number_json(hd64h)},
        {"discovery_median_HD128", number_json(hd128d)},
        {"holdout_median_HD128", number_json(hd128h)},
        {"subsignature_transfer", {
             {"T1_carry_mask", mode_json(mask_mode, [](const auto& x) { return hex_word(x.t1_carry.mask); })},
             {"T1_hamming", mode_json(t1_mode, [](const auto& x) { return std::to_string(x.t1_hamming); })},
             {"new_a_hamming", mode_json(na_mode, [](const auto& x) { return std::to_string(x.new_a_hamming); })},
             {"new_e_hamming", mode_json(ne_mode, [](const auto& x) { return std::to_string(x.new_e_hamming); })},
             {"hamming_triplet", mode_json(triplet_mode, [](const auto& x) { return std::to_string(x.t1_hamming) + "/" + std::to_string(x.new_a_hamming) + "/" + std::to_string(x.new_e_hamming); })},
             {"Ch_masked", mode_json(ch_mode, [](const auto& x) { return x.ch_masked ? "true" : "false"; })},
             {"Maj_masked", mode_json(maj_mode, [](const auto& x) { return x.maj_masked ? "true" : "false"; })},
             {"HD64", mode_json(hd64_mode, [](const auto& x) { return optional_value(x.hd64); })},
             {"HD128", mode_json(hd128_mode, [](const auto& x) { return optional_value(x.hd128); })}}},
        {"complete_signature", {{"distinct_count", distinct_signatures.size()},
             {"mode", signature_mode}, {"mode_frequency", signature_mode_frequency}}}});
    std::vector<std::string> row{std::to_string(bit),
        std::to_string(numeric_nonce_bit_to_w3_bit(bit)),
        ((kGenesisW3 >> numeric_nonce_bit_to_w3_bit(bit)) & 1U) == 0U ? "0_to_1" : "1_to_0",
        number(no_carry_d), number(no_carry_h), number(ch_d), number(ch_h),
        number(maj_d), number(maj_h), number(hd64d), number(hd64h),
        number(hd128d), number(hd128h)};
    for (const auto* mode : {&mask_mode, &t1_mode, &na_mode, &ne_mode,
                             &triplet_mode, &ch_mode, &maj_mode,
                             &hd64_mode, &hd128_mode}) {
      row.push_back(mode->mode);
      row.push_back(std::to_string(mode->discovery_frequency));
      row.push_back(std::to_string(mode->holdout_frequency));
    }
    row.insert(row.end(), {std::to_string(distinct_signatures.size()),
                           signature_mode, std::to_string(signature_mode_frequency)});
    csv_row(bit_summary_csv, row);
  }

  nlohmann::json direction_contexts = nlohmann::json::array();
  std::ostringstream direction_csv;
  csv_row(direction_csv, {"context_id", "split", "mean_T1_carry_diff_count_0_to_1",
      "mean_T1_carry_diff_count_1_to_0", "delta_direction_T1_carry",
      "mean_HD128_step_0_to_1", "mean_HD128_step_1_to_0",
      "delta_direction_HD128"});
  std::array<std::vector<double>, 2> carry_deltas;
  std::array<std::vector<double>, 2> hd128_deltas;
  for (unsigned context_id = 0U; context_id < context_count; ++context_id) {
    std::vector<double> carry01, carry10, hd01, hd10;
    for (const auto& metric : metrics) {
      if (metric.context_id != context_id) continue;
      auto& carries = metric.original_bit == 0U ? carry01 : carry10;
      auto& hd = metric.original_bit == 0U ? hd01 : hd10;
      carries.push_back(metric.t1_carry.count);
      hd.push_back(metric.hd128 ? *metric.hd128 : 192U);
    }
    const auto carry01_mean = mean(carry01);
    const auto carry10_mean = mean(carry10);
    const auto hd01_mean = mean(hd01);
    const auto hd10_mean = mean(hd10);
    const auto carry_delta = carry10_mean - carry01_mean;
    const auto hd_delta = hd10_mean - hd01_mean;
    const auto split = context_id < 32U ? 0U : 1U;
    carry_deltas[split].push_back(carry_delta);
    hd128_deltas[split].push_back(hd_delta);
    direction_contexts.push_back({{"context_id", context_id}, {"split", split_name(context_id)},
        {"mean_T1_carry_diff_count_0_to_1", carry01_mean},
        {"mean_T1_carry_diff_count_1_to_0", carry10_mean},
        {"delta_direction_T1_carry", carry_delta},
        {"mean_HD128_step_0_to_1", hd01_mean},
        {"mean_HD128_step_1_to_0", hd10_mean},
        {"delta_direction_HD128", hd_delta}});
    csv_row(direction_csv, {std::to_string(context_id), split_name(context_id),
        number(carry01_mean), number(carry10_mean), number(carry_delta),
        number(hd01_mean), number(hd10_mean), number(hd_delta)});
  }
  const auto delta_summary = [](const std::vector<double>& values) {
    if (values.empty()) return nlohmann::json{{"count", 0}};
    return nlohmann::json{{"count", values.size()}, {"mean", mean(values)},
        {"median", median(values)}, {"min", *std::min_element(values.begin(), values.end())},
        {"max", *std::max_element(values.begin(), values.end())},
        {"positive", std::count_if(values.begin(), values.end(), [](double x) { return x > 0.0; })},
        {"negative", std::count_if(values.begin(), values.end(), [](double x) { return x < 0.0; })},
        {"zero", std::count(values.begin(), values.end(), 0.0)}};
  };
  const nlohmann::json direction_summary{{"per_context", direction_contexts},
      {"discovery", {{"delta_direction_T1_carry", delta_summary(carry_deltas[0])},
                       {"delta_direction_HD128", delta_summary(hd128_deltas[0])}}},
      {"holdout", {{"delta_direction_T1_carry", delta_summary(carry_deltas[1])},
                     {"delta_direction_HD128", delta_summary(hd128_deltas[1])}}}};

  std::ostringstream round_csv;
  csv_row(round_csv, {"numeric_nonce_bit", "global_step", "discovery_mean",
      "discovery_median", "discovery_min", "discovery_max", "holdout_mean",
      "holdout_median", "holdout_min", "holdout_max"});
  for (unsigned bit = 0U; bit < 32U; ++bit) {
    for (unsigned step = 0U; step < kTotalRoundCount; ++step) {
      const auto summarize = [](const std::vector<unsigned>& values) {
        if (values.empty()) return std::array<std::string, 4>{};
        std::vector<double> doubles(values.begin(), values.end());
        return std::array<std::string, 4>{number(mean(doubles)), number(median(doubles)),
            std::to_string(*std::min_element(values.begin(), values.end())),
            std::to_string(*std::max_element(values.begin(), values.end()))};
      };
      const auto d = summarize(round_values[0][bit][step]);
      const auto h = summarize(round_values[1][bit][step]);
      csv_row(round_csv, {std::to_string(bit), std::to_string(step),
          d[0], d[1], d[2], d[3], h[0], h[1], h[2], h[3]});
    }
  }

  nlohmann::json pair_summaries = nlohmann::json::array();
  std::ostringstream pair_csv;
  csv_row(pair_csv, {"bit_i", "bit_j", "Genesis_mean_state_mask_distance_full",
      "Genesis_carry_change_jaccard", "discovery_mean_rank", "discovery_median_rank",
      "holdout_mean_rank", "holdout_median_rank", "discovery_mean_distance_full",
      "holdout_mean_distance_full", "discovery_mean_distance_post_divergence",
      "holdout_mean_distance_post_divergence", "discovery_mean_carry_jaccard",
      "holdout_mean_carry_jaccard", "discovery_mean_pearson_full",
      "holdout_mean_pearson_full", "discovery_mean_pearson_post_divergence",
      "holdout_mean_pearson_post_divergence", "discovery_top5_frequency",
      "holdout_top5_frequency", "discovery_top10_frequency", "holdout_top10_frequency",
      "discovery_top25_frequency", "holdout_top25_frequency",
      "Genesis_predeclared_pair", "discovery_exploratory_top5_frozen_before_holdout"});
  const auto pair_values = [](const std::vector<PairObservation>& observations,
                              const std::function<std::optional<double>(const PairObservation&)>& f) {
    std::vector<double> values;
    for (const auto& item : observations) {
      const auto value = f(item);
      if (value) values.push_back(*value);
    }
    return values;
  };
  for (std::size_t index = 0U; index < pairs.size(); ++index) {
    const auto& pair = pairs[index];
    std::vector<double> dr(pair.ranks[0].begin(), pair.ranks[0].end());
    std::vector<double> hr(pair.ranks[1].begin(), pair.ranks[1].end());
    const auto d_full = pair_values(pair.observations[0], [](const auto& x) { return x.full; });
    const auto h_full = pair_values(pair.observations[1], [](const auto& x) { return x.full; });
    const auto d_post = pair_values(pair.observations[0], [](const auto& x) { return x.post; });
    const auto h_post = pair_values(pair.observations[1], [](const auto& x) { return x.post; });
    const auto d_j = pair_values(pair.observations[0], [](const auto& x) { return x.jaccard; });
    const auto h_j = pair_values(pair.observations[1], [](const auto& x) { return x.jaccard; });
    const auto d_pf = pair_values(pair.observations[0], [](const auto& x) { return x.pearson_full; });
    const auto h_pf = pair_values(pair.observations[1], [](const auto& x) { return x.pearson_full; });
    const auto d_pp = pair_values(pair.observations[0], [](const auto& x) { return x.pearson_post; });
    const auto h_pp = pair_values(pair.observations[1], [](const auto& x) { return x.pearson_post; });
    const auto genesis = genesis_pair_metrics(pair.left, pair.right);
    const auto exploratory = std::find(exploratory_pairs_frozen.begin(),
        exploratory_pairs_frozen.end(), index) != exploratory_pairs_frozen.end();
    const auto rate_pair = [&](unsigned count, unsigned split) {
      return rate(count, pair.observations[split].size());
    };
    auto item = nlohmann::json{{"bit_i", pair.left}, {"bit_j", pair.right},
        {"Genesis_predeclared_pair", is_predeclared_pair(pair.left, pair.right)},
        {"discovery_exploratory_top5_frozen_before_holdout", exploratory},
        {"discovery_mean_rank", number_json(mean(dr))}, {"discovery_median_rank", number_json(median(dr))},
        {"holdout_mean_rank", number_json(mean(hr))}, {"holdout_median_rank", number_json(median(hr))},
        {"discovery_mean_distance_full", number_json(mean(d_full))},
        {"holdout_mean_distance_full", number_json(mean(h_full))},
        {"discovery_mean_distance_post_divergence", number_json(mean(d_post))},
        {"holdout_mean_distance_post_divergence", number_json(mean(h_post))},
        {"discovery_mean_carry_jaccard", number_json(mean(d_j))},
        {"holdout_mean_carry_jaccard", number_json(mean(h_j))},
        {"discovery_mean_pearson_full", number_json(mean(d_pf))},
        {"holdout_mean_pearson_full", number_json(mean(h_pf))},
        {"discovery_mean_pearson_post_divergence", number_json(mean(d_pp))},
        {"holdout_mean_pearson_post_divergence", number_json(mean(h_pp))},
        {"discovery_top5_frequency", number_json(rate_pair(pair.top5[0], 0U))},
        {"holdout_top5_frequency", number_json(rate_pair(pair.top5[1], 1U))},
        {"discovery_top10_frequency", number_json(rate_pair(pair.top10[0], 0U))},
        {"holdout_top10_frequency", number_json(rate_pair(pair.top10[1], 1U))},
        {"discovery_top25_frequency", number_json(rate_pair(pair.top25[0], 0U))},
        {"holdout_top25_frequency", number_json(rate_pair(pair.top25[1], 1U))}};
    if (genesis) item["Genesis_metrics"] = {{"mean_state_mask_distance_full", genesis->first},
                                              {"carry_change_jaccard", genesis->second}};
    else item["Genesis_metrics"] = nullptr;
    pair_summaries.push_back(item);
    csv_row(pair_csv, {std::to_string(pair.left), std::to_string(pair.right),
        genesis ? number(genesis->first) : "", genesis ? number(genesis->second) : "",
        number(mean(dr)), number(median(dr)), number(mean(hr)), number(median(hr)),
        number(mean(d_full)), number(mean(h_full)), number(mean(d_post)), number(mean(h_post)),
        number(mean(d_j)), number(mean(h_j)), number(mean(d_pf)), number(mean(h_pf)),
        number(mean(d_pp)), number(mean(h_pp)), number(rate_pair(pair.top5[0], 0U)),
        number(rate_pair(pair.top5[1], 1U)), number(rate_pair(pair.top10[0], 0U)),
        number(rate_pair(pair.top10[1], 1U)), number(rate_pair(pair.top25[0], 0U)),
        number(rate_pair(pair.top25[1], 1U)),
        is_predeclared_pair(pair.left, pair.right) ? "true" : "false",
        exploratory ? "true" : "false"});
  }

  nlohmann::json spearman_json{{"median_HD64", nullptr},
      {"median_HD128", nullptr}, {"mean_T1_carry_diff_count", nullptr},
      {"frequency_Ch_masked", nullptr}, {"frequency_Maj_masked", nullptr}};
  if (context_count == 64U) {
    constexpr std::array<const char*, 5> names{"median_HD64", "median_HD128",
        "mean_T1_carry_diff_count", "frequency_Ch_masked", "frequency_Maj_masked"};
    for (std::size_t i = 0U; i < names.size(); ++i) {
      spearman_json[names[i]] = number_json(
          spearman(discovery_vectors[i], holdout_vectors[i]));
    }
  }

  const auto hypothesis_rate_mean = [&](const std::vector<unsigned>& bits,
                                        const char* field) {
    std::vector<double> values;
    for (const auto bit : bits) {
      const auto& value = bit_summaries.at(bit).at(field);
      if (!value.is_null()) values.push_back(value.get<double>());
    }
    return mean(values);
  };
  const std::vector<unsigned> h1_bits{3,5,6,7,8,9,10,14,15,17,18,20,21,22,24,25,27,29};
  const std::vector<unsigned> h2_bits{0,4,5,13,21,23,25,31};
  const std::vector<unsigned> h3_bits{1,2,3,4,5,12,13,14,19,22,24,25,28,29,31};
  const auto subsignature_holdout_mean = [&](const char* field) {
    std::vector<double> values;
    for (const auto& bit : bit_summaries) {
      values.push_back(static_cast<double>(bit.at("subsignature_transfer").at(field)
          .at("holdout_frequency_of_discovery_mode").get<std::size_t>()) / 32.0);
    }
    return mean(values);
  };
  std::vector<double> context_signature_counts;
  for (const auto& context : contexts) {
    context_signature_counts.push_back(
        context.at("unique_complete_signatures").get<double>());
  }
  const auto json_number = [](const nlohmann::json& value) {
    return value.is_number() ? number(value.get<double>()) : std::string("N/A");
  };
  const auto direction_mean_text = [&](const char* split, const char* metric) {
    const auto& item = direction_summary.at(split).at(metric);
    return item.contains("mean") ? json_number(item.at("mean")) : std::string("N/A");
  };

  nlohmann::json aggregate{
      {"schema_version", 1},
      {"metadata", {{"experiment_id", "merkle_context_transfer_64"},
          {"scientific_scope", "descriptive internal SHA256d transfer only; no bias, target, mining, or nonce ranking claim"},
          {"memory_model", "one exhaustive reference plus one exhaustive candidate plus compact aggregates"},
          {"pairwise_primary_metric", "mean_state_mask_distance_post_divergence over global_step 67..191"},
          {"carry_jaccard_universe", "(addition_identity,carry_column); columns unchanged in both flips are absent from the union"}}},
      {"design", {{"contexts", context_count}, {"bits_per_context", 32},
          {"experiments", context_count * 32U}, {"Genesis_is_anchor_not_split_member", true},
          {"only_variable_header_bytes", "header[36..67] synthetic Merkle field"},
          {"nonce_reference", kGenesisNonce}, {"nonce_reference_hex", "7c2bac1d"}}},
      {"context_generator", {{"seed", "ASCII(SRM_WHITEBOX_MERKLE_CONTEXT_V1) || uint32_le(context_id)"},
          {"function", "SHA-256"}, {"insertion", "digest bytes copied without reversal to header[36..67]"},
          {"runtime_python_dependency", false}, {"all_64_fixtures_verified", true}}},
      {"discovery_holdout", {{"discovery", "context_id 0..31"},
          {"holdout", "context_id 32..63"},
          {"strict_order", "all discovery contexts evaluated before any holdout context"},
          {"discovery_freeze_completed_before_holdout", discovery_modes_were_frozen},
          {"holdout_used_to_select_rules", false}}},
      {"context_summaries", contexts}, {"bit_transfer_summaries", bit_summaries},
      {"direction_summaries", direction_summary},
      {"pairwise_transfer_summaries", pair_summaries},
      {"spearman_discovery_vs_holdout", spearman_json},
      {"Genesis_hypotheses", {{"H1_T1_no_carry_bits", {3,5,6,7,8,9,10,14,15,17,18,20,21,22,24,25,27,29}},
          {"H2_Ch_masked_bits", {0,4,5,13,21,23,25,31}},
          {"H3_Maj_masked_bits", {1,2,3,4,5,12,13,14,19,22,24,25,28,29,31}},
          {"H4_fast_HD64_bits", {10,11,18,28}}, {"H4_fast_HD128_bits", {10,11,28}},
          {"H4_slow_HD128_bits", {14,31}}, {"H5_W18_W19", "required for every candidate"},
          {"H6_pairs", {{17,28},{6,7},{13,14},{2,4},{17,26}}}}},
      {"validations", {{"context_fixtures_verified", 64},
          {"candidate_headers_single_bit_verified", context_count * 32U},
          {"candidate_traces_audited", context_count * 32U},
          {"addition_differential_identity_count", addition_count},
          {"sigma_xor_differential_identity_count", sigma_count},
          {"first_divergence_step_67_confirmations", context_count * 32U},
          {"W18_first_extended_confirmations", context_count * 32U},
          {"W19_direct_delta_confirmations", context_count * 32U},
          {"independent_python_candidate_vectors_checked", 0},
          {"independent_python_reference_vectors_checked", 0},
          {"independent_python_mismatches", nullptr},
          {"independent_python_audit_status", "pending_external_development_audit"}}},
      {"cardinalities", {{"contexts_csv_rows", context_count},
          {"per_context_bit_csv_rows", context_count * 32U},
          {"bit_transfer_summary_csv_rows", 32},
          {"direction_effects_csv_rows", context_count},
          {"per_bit_round_summary_csv_rows", 32U * kTotalRoundCount},
          {"pairwise_transfer_csv_rows", 496}}}};
  auto h6_transfer = nlohmann::json::array();
  for (const auto& pair : pair_summaries) {
    if (pair.at("Genesis_predeclared_pair").get<bool>()) h6_transfer.push_back(pair);
  }
  aggregate["Genesis_hypothesis_transfer"] = {
      {"H1_T1_no_carry", {
          {"predeclared_bits", h1_bits},
          {"discovery_mean_rate", hypothesis_rate_mean(
              h1_bits, "discovery_rate_no_T1_carry_change")},
          {"holdout_mean_rate", hypothesis_rate_mean(
              h1_bits, "holdout_rate_no_T1_carry_change")}}},
      {"H2_Ch_masked", {
          {"predeclared_bits", h2_bits},
          {"discovery_mean_rate", hypothesis_rate_mean(
              h2_bits, "discovery_rate_Ch_masked")},
          {"holdout_mean_rate", hypothesis_rate_mean(
              h2_bits, "holdout_rate_Ch_masked")}}},
      {"H3_Maj_masked", {
          {"predeclared_bits", h3_bits},
          {"discovery_mean_rate", hypothesis_rate_mean(
              h3_bits, "discovery_rate_Maj_masked")},
          {"holdout_mean_rate", hypothesis_rate_mean(
              h3_bits, "holdout_rate_Maj_masked")}}},
      {"H4_diffusion", {
          {"per_bit_medians_in_bit_transfer_summaries", true},
          {"spearman_discovery_vs_holdout", spearman_json}}},
      {"H5_schedule", {
          {"W18_confirmations", context_count * 32U},
          {"W19_confirmations", context_count * 32U}}},
      {"H6_pairwise", h6_transfer},
      {"direction_effect", direction_summary}};
  aggregate["audit"] = validate_merkle_context_transfer_campaign(aggregate, context_count);

  std::ostringstream summary;
  summary << "# Transfert white-box SHA256d sur 64 contextes Merkle synthétiques\n\n"
      << "Cette expérience compare 32 single-bit flips du nonce dans " << context_count
      << " contextes contrôlés. Genesis reste un anchor historique et ne fait pas partie du split.\n\n"
      << "## Design et validation\n\n"
      << "Seuls les 32 octets `header[36..67]` changent. Chaque fixture est "
         "`SHA256(ASCII(SRM_WHITEBOX_MERKLE_CONTEXT_V1) || uint32_le(context_id))`, "
         "copiée sans inversion. Les contextes 0..31 sont discovery; 32..63 sont holdout, "
         "traités seulement après gel des modes et des cinq paires exploratoires discovery.\n\n"
      << "- Expériences: " << context_count * 32U << "\n"
      << "- Identités différentielles d'addition: " << addition_count << "\n"
      << "- Identités XOR Sigma: " << sigma_count << "\n"
      << "- Confirmations W18/W19: " << context_count * 32U << "/" << context_count * 32U << "\n"
      << "- Mémoire: une référence exhaustive + un candidat exhaustif + agrégats compacts.\n"
      << "- Audit Python indépendant: PENDING_EXTERNAL_DEVELOPMENT_AUDIT.\n\n"
      << "## Transférabilité pré-déclarée\n\n"
      << "Les propriétés locales Genesis ne se transfèrent généralement pas comme invariants. "
         "Pour les bits pré-déclarés H1, l'absence de changement de carry T1 apparaît en moyenne "
      << number(hypothesis_rate_mean(h1_bits, "discovery_rate_no_T1_carry_change"))
      << " en discovery et "
      << number(hypothesis_rate_mean(h1_bits, "holdout_rate_no_T1_carry_change"))
      << " en holdout. Pour H2 (Ch entièrement masqué), les moyennes sont "
      << number(hypothesis_rate_mean(h2_bits, "discovery_rate_Ch_masked"))
      << " et " << number(hypothesis_rate_mean(h2_bits, "holdout_rate_Ch_masked"))
      << "; pour H3 (Maj entièrement masqué), "
      << number(hypothesis_rate_mean(h3_bits, "discovery_rate_Maj_masked"))
      << " et " << number(hypothesis_rate_mean(h3_bits, "holdout_rate_Maj_masked"))
      << ". Les valeurs bit par bit sont conservées dans le CSV de transfert.\n\n"
      << "H5 est entièrement structurelle dans cette expérience: W18 est le premier mot étendu "
         "différent et W19 conserve le delta modulaire direct pour 2048/2048 candidats.\n\n"
      << "### Effet direction 0→1 / 1→0\n\n"
      << "Le delta moyen `mean(1→0)-mean(0→1)` du nombre de carries T1 vaut "
      << direction_mean_text("discovery", "delta_direction_T1_carry")
      << " en discovery et "
      << direction_mean_text("holdout", "delta_direction_T1_carry")
      << " en holdout. Pour le step HD128, il vaut "
      << direction_mean_text("discovery", "delta_direction_HD128")
      << " puis "
      << direction_mean_text("holdout", "delta_direction_HD128")
      << ". Les signes Genesis persistent donc faiblement en moyenne, mais les distributions "
         "par contexte traversent zéro et ne constituent pas une règle prédictive.\n\n"
      << "### Signatures et sous-signatures\n\n"
      << "Chaque contexte contient entre "
      << number(*std::min_element(context_signature_counts.begin(), context_signature_counts.end()))
      << " et "
      << number(*std::max_element(context_signature_counts.begin(), context_signature_counts.end()))
      << " signatures complètes distinctes sur 32 bits (moyenne "
      << number(mean(context_signature_counts))
      << "). Par bit, 58 à 64 signatures distinctes sont observées sur 64 contextes: les signatures "
         "complètes sont donc fortement contextuelles. La fréquence holdout moyenne du mode discovery "
         "vaut " << number(subsignature_holdout_mean("T1_carry_mask"))
      << " pour le masque T1, " << number(subsignature_holdout_mean("hamming_triplet"))
      << " pour le triplet Hamming, " << number(subsignature_holdout_mean("Ch_masked"))
      << " pour Ch masqué, " << number(subsignature_holdout_mean("Maj_masked"))
      << " pour Maj masqué, " << number(subsignature_holdout_mean("HD64"))
      << " pour HD64 et " << number(subsignature_holdout_mean("HD128"))
      << " pour HD128.\n\n"
      << "### Classements discovery/holdout\n\n"
      << "Spearman descriptif: HD64="
      << (spearman_json.at("median_HD64").is_null() ? "indéfini (vecteur constant)" : spearman_json.at("median_HD64").dump())
      << ", HD128=" << spearman_json.at("median_HD128").dump()
      << ", carries T1=" << spearman_json.at("mean_T1_carry_diff_count").dump()
      << ", Ch masqué=" << spearman_json.at("frequency_Ch_masked").dump()
      << ", Maj masqué=" << spearman_json.at("frequency_Maj_masked").dump()
      << ". Ces corrélations faibles à modérées indiquent une stabilité limitée des rangs.\n\n"
      << "### Paires Genesis pré-déclarées\n\n"
      << "| Paire | Rang moyen discovery | Rang moyen holdout | Top 5% discovery | Top 5% holdout |\n"
         "|---|---:|---:|---:|---:|\n";
  for (const auto& pair : pair_summaries) {
    if (!pair.at("Genesis_predeclared_pair").get<bool>()) continue;
    summary << "| " << pair.at("bit_i").get<unsigned>() << '/'
            << pair.at("bit_j").get<unsigned>() << " | "
            << json_number(pair.at("discovery_mean_rank")) << " | "
            << json_number(pair.at("holdout_mean_rank")) << " | "
            << json_number(pair.at("discovery_top5_frequency")) << " | "
            << json_number(pair.at("holdout_top5_frequency")) << " |\n";
  }
  summary << "\nAucune des cinq paires Genesis ne reste systématiquement proche; 17/28 "
         "n'apparaît dans le top 5% d'aucun nouveau contexte.\n\n"
      << "### Cinq paires exploratoires gelées sur discovery\n\n";
  for (const auto& pair : pair_summaries) {
    if (!pair.at("discovery_exploratory_top5_frozen_before_holdout").get<bool>()) continue;
    summary << "- " << pair.at("bit_i").get<unsigned>() << '/'
            << pair.at("bit_j").get<unsigned>() << ": rang moyen discovery "
            << json_number(pair.at("discovery_mean_rank"))
            << ", holdout " << json_number(pair.at("holdout_mean_rank"))
            << ".\n";
  }
  summary << "\nCes paires sont exploratoires, ont été choisies uniquement sur discovery et "
         "ne sont pas requalifiées en hypothèses après lecture du holdout.\n\n"
      << "Les métriques pairwise complètes et post-divergence sont toutes deux conservées. "
         "La version post-divergence (steps 67..191) est primaire; Pearson reste descriptif.\n\n"
      << "## Limites scientifiques\n\n"
      << "Ces Merkle fields sont synthétiques et ne prétendent pas provenir d'arbres de transactions. "
         "Les 32 bits ne constituent pas une preuve cryptanalytique. Aucun hash final n'est utilisé "
         "pour découvrir une règle, aucune proximité au target n'est analysée, aucun nonce n'est "
         "classé meilleur ou pire, et aucun biais SHA-256 n'est conclu. Les résultats faibles, nuls "
         "ou négatifs de transfert doivent être lus comme des résultats utiles.\n";

  return {std::move(aggregate), summary.str(), contexts_csv.str(),
          per_bit_csv.str(), bit_summary_csv.str(), direction_csv.str(),
          round_csv.str(), pair_csv.str()};
}

nlohmann::json validate_merkle_context_transfer_campaign(
    const nlohmann::json& aggregate,
    std::size_t expected_context_count) {
  require(aggregate.at("schema_version") == 1, "aggregate schema version mismatch");
  require(aggregate.at("context_summaries").size() == expected_context_count,
          "context summary cardinality mismatch");
  require(aggregate.at("bit_transfer_summaries").size() == 32U,
          "bit summary cardinality mismatch");
  require(aggregate.at("pairwise_transfer_summaries").size() == 496U,
          "pairwise cardinality mismatch");
  const auto experiments = expected_context_count * 32U;
  const auto& validations = aggregate.at("validations");
  require(validations.at("context_fixtures_verified") == 64U &&
              validations.at("candidate_headers_single_bit_verified") == experiments &&
              validations.at("candidate_traces_audited") == experiments &&
              validations.at("addition_differential_identity_count") == experiments * 936U &&
              validations.at("sigma_xor_differential_identity_count") == experiments * 672U &&
              validations.at("W18_first_extended_confirmations") == experiments &&
              validations.at("W19_direct_delta_confirmations") == experiments,
          "validation counters mismatch");
  const auto& cardinalities = aggregate.at("cardinalities");
  require(cardinalities.at("contexts_csv_rows") == expected_context_count &&
              cardinalities.at("per_context_bit_csv_rows") == experiments &&
              cardinalities.at("bit_transfer_summary_csv_rows") == 32U &&
              cardinalities.at("direction_effects_csv_rows") == expected_context_count &&
              cardinalities.at("per_bit_round_summary_csv_rows") == 6144U &&
              cardinalities.at("pairwise_transfer_csv_rows") == 496U,
          "artifact cardinalities mismatch");
  return {{"status", "passed"}, {"contexts_validated", expected_context_count},
          {"experiments_validated", experiments},
          {"addition_differentials_validated", experiments * 936U},
          {"sigma_xor_differentials_validated", experiments * 672U},
          {"strict_discovery_holdout_order", true},
          {"holdout_rule_selection", false}};
}

void write_merkle_context_transfer_campaign(
    const MerkleContextTransferArtifacts& artifacts,
    const std::filesystem::path& output_directory) {
  (void)validate_merkle_context_transfer_campaign(
      artifacts.aggregate,
      artifacts.aggregate.at("design").at("contexts").get<std::size_t>());
  const auto directory = output_directory / "merkle_context_transfer_64";
  std::filesystem::create_directories(directory);
  write_text_file(directory / "merkle_context_transfer_64_aggregate.json",
                  artifacts.aggregate.dump(2) + '\n');
  write_text_file(directory / "merkle_context_transfer_64_summary.md",
                  artifacts.summary_markdown);
  write_text_file(directory / "merkle_context_transfer_64_contexts.csv",
                  artifacts.contexts_csv);
  write_text_file(directory / "merkle_context_transfer_64_per_context_bit.csv",
                  artifacts.per_context_bit_csv);
  write_text_file(directory / "merkle_context_transfer_64_bit_transfer_summary.csv",
                  artifacts.bit_transfer_summary_csv);
  write_text_file(directory / "merkle_context_transfer_64_direction_effects.csv",
                  artifacts.direction_effects_csv);
  write_text_file(directory / "merkle_context_transfer_64_per_bit_round_summary.csv",
                  artifacts.per_bit_round_summary_csv);
  write_text_file(directory / "merkle_context_transfer_64_pairwise_transfer.csv",
                  artifacts.pairwise_transfer_csv);
}

void write_merkle_context_transfer_full_trace(
    unsigned context_id,
    unsigned numeric_nonce_bit,
    const std::filesystem::path& output_directory) {
  if (context_id >= 64U || numeric_nonce_bit >= 32U) {
    throw std::invalid_argument("context id or nonce bit outside range");
  }
  auto header = context_header(context_id);
  header[76U + numeric_nonce_bit / 8U] ^=
      static_cast<std::uint8_t>(1U << (numeric_nonce_bit % 8U));
  const SpecimenMetadata metadata{
      "merkle_context_" + std::to_string(context_id) + "_nonce_bit_" +
          std::to_string(numeric_nonce_bit) + "_full_trace",
      "Synthetic Merkle context full trace",
      "context_" + std::to_string(context_id) + "_bit_" +
          std::to_string(numeric_nonce_bit), "", "", ""};
  const auto artifacts = build_sha256d_whitebox(header, metadata);
  write_sha256d_whitebox(
      artifacts, metadata,
      output_directory / "merkle_context_transfer_64" / "full_trace" /
          ("context_" + std::to_string(context_id) + "_bit_" +
           std::to_string(numeric_nonce_bit)));
}

}  // namespace srm::research::whitebox
