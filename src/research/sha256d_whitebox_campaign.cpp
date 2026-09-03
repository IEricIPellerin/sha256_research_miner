//src\research\sha256d_whitebox_campaign.cpp
#include "research/sha256d_whitebox.h"

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

using State = std::array<std::uint32_t, 8>;
using RoundDeltaMasks = std::array<State, kTotalRoundCount>;

constexpr std::uint32_t kGenesisNonce = 0x7c2bac1dU;
constexpr std::uint32_t kGenesisW3 = 0x1dac2b7cU;
constexpr std::array<const char*, 8> kStateNames{
    "a", "b", "c", "d", "e", "f", "g", "h"};

struct VectorText {
  const char* first;
  const char* raw;
  const char* display;
};

// Generated once with Python 3 hashlib from the canonical 80-byte Genesis
// header. Python is deliberately not a build or runtime dependency.
constexpr std::array<VectorText, 32> kVectorText{{
    {"b0bded2df03b40f384c981e5b750ad0ccf562554b23c0187bb162ba093bc3dfc", "d9665d1c88b5bf70b741453c4a78c9fe36a537659ad0e7fab087cac13d34dc8c", "8cdc343dc1ca87b0fae7d09a6537a536fec9784a3c4541b770bfb5881c5d66d9"},
    {"fa414d8cbd78468c27fbf6763a4d8a6aa47e6ca115806fd134e08854202cb5ed", "9d5344899444ca15fcf48fdec884321511a321ff3082ca1de7621f798947ef8f", "8fef4789791f62e71dca8230ff21a311153284c8de8ff4fc15ca44948944539d"},
    {"6410af01cbd64fe038faf4d07f13b997269f175447d992f38c4216f38304b0ef", "dbe94f4a8c4a32331b39166b0c71cefc23e9d3b190298717ec4e97966bba3d8b", "8b3dba6b96974eec17872990b1d3e923fcce710c6b16391b33324a8c4a4fe9db"},
    {"14d58b8d80439a11244b57f64923ef0d21865483b8250a2dcad5fba1f0a33b4a", "7221442f0dea0d8e5c15d8f5a1d9973e005570d4e529afc61b9c48d733651761", "61176533d7489c1bc6af29e5d47055003e97d9a1f5d8155c8e0dea0d2f442172"},
    {"003f7c3f10ad3238302619d5fd5e5fa1993b2fe52b9a7a4b7c7d9eaa4ac8b0c4", "0432effd9f7c058d1175d451170beb24b54616afcfbb6cf145bbb48315caa676", "76a6ca1583b4bb45f16cbbcfaf1646b524eb0b1751d475118d057c9ffdef3204"},
    {"9fc1dbb4719b6ad67a455dc6d11b8c413f989b1b580487fcc2d2a8273e1aa132", "466ac21f4773c7bb79b47115c54b1b1fac4fa3f37255afbf2b8186bbe819d54b", "4bd519e8bb86812bbfaf5572f3a34fac1f1b4bc51571b479bbc773471fc26a46"},
    {"f555b4305e669e34fbe69cf522dbaab0ec532ef0c65349bde488f11c985d8ae7", "f766bbea66832bd99a3fdfb964fea4053cd00e8455c8bb706e00f851c72b908f", "8f902bc751f8006e70bbc855840ed03c05a4fe64b9df3f9ad92b8366eabb66f7"},
    {"fed1db5077c6dbb91ce51539f978ebf37275b3a323cd462070e0a01850d171b9", "08c93612e6c654fbe525cc4cb07405e88b04d4c7637465ab0bdb8ddeb7769f3b", "3b9f76b7de8ddb0bab657463c7d4048be80574b04ccc25e5fb54c6e61236c908"},
    {"abbb1f1ee8d38738c04a5d04a81f556beeaabb1a30b2959ca8fa45a367343cfe", "2488c8b114475258fa7150374c3d10513b3f6b828aa4adb7ff1232982081f4f0", "f0f48120983212ffb7ada48a826b3f3b51103d4c375071fa58524714b1c88824"},
    {"acf83332bc11ead740823979f9ef88fb6f7497581b075e4383b7e1456d70d329", "fdfad64d2a949bd5414176b18114ece05cf27d8c4df4bba63681ebf469363792", "92373669f4eb8136a6bbf44d8c7df25ce0ec1481b1764141d59b942a4dd6fafd"},
    {"a7aa28fe1d9c7bc23cccf70bcf231f0c22457dbd4f5af8eb7aed158ffd34c972", "ce137c976df13f6e2d702c16964e2369a5453ee662252014f79faa2d9f3ca0f1", "f1a03c9f2daa9ff714202562e63e45a569234e96162c702d6e3ff16d977c13ce"},
    {"ef10ea47b3e2916c35e9f3f7cc837cbae984dbab50bb36f203656e818123f263", "996ab5834cf185ea886288717e934c62a6d0c72afc839b242501b8d9d915215e", "5e2115d9d9b80125249b83fc2ac7d0a6624c937e71886288ea85f14c83b56a99"},
    {"7f3727636f0a4f951e927582c069bdb57192e9afa97011b708b77e073ec18855", "6c2867de3b853fd1e273fac7bcd6f7af7028b3e04de43c28501d2ef4a9e358c0", "c058e3a9f42e1d50283ce44de0b32870aff7d6bcc7fa73e2d13f853bde67286c"},
    {"21631050a57985fb72565977bc958d01eea3d2e98626d9e9b88e440cb81da660", "6eea7c942842f311a680471729983a97f4641b4f64f534c0f20a3fbba425f854", "54f825a4bb3f0af2c034f5644f1b64f4973a9829174780a611f34228947cea6e"},
    {"fb0976201d651d043170311507dc88a22a4bb544df16493bc43668efc8a6a15d", "a6db0434c6f1a29b3450e2ff6f888f66d445f88af0693d66b4b06055e85cdfc6", "c6df5ce85560b0b4663d69f08af845d4668f886fffe250349ba2f1c63404dba6"},
    {"f4c0e6ef485f9092525b3fc7198c2f6b8dd33ff29e5b0c213c33223e8d05a6f2", "ed91520d85cd6d5a6f8aeb2a91c8fab1e106ee7587f1ff1396d89db8ef0a0aca", "ca0a0aefb89dd89613fff18775ee06e1b1fac8912aeb8a6f5a6dcd850d5291ed"},
    {"01e66c0b59636515b567ef168b08de01b71b0e0354d247f1b8630320d85e2353", "cce0ab74db33ee102e5d661be55217d6de015e9e09418d62050d0cff60b0a1eb", "eba1b060ff0c0d05628d41099e5e01ded61752e51b665d2e10ee33db74abe0cc"},
    {"09a82d348599c9630313d38db4c27c101751186e1ec178a823f02df1289d5738", "4008aa6882e573fed28c5297aff2952f2bb51859dd4f17d1f4366ed6b11f2004", "04201fb1d66e36f4d1174fdd5918b52b2f95f2af97528cd2fe73e58268aa0840"},
    {"e23eafe3540ff3774de4712d5af6240a6089f85ee38d90d79e9f7b13ec8dd0dd", "0a3f7026fe8fc9a5ea605af0a655569aa290fe15a5f5d43e86c49938daf2d987", "87d9f2da3899c4863ed4f5a515fe90a29a5655a6f05a60eaa5c98ffe26703f0a"},
    {"b53b5c4009a707b5146958eb87c8da90bba511d3955c03cf2d375e6c3ac42f86", "27f441cae25a3cbbb425c4818542b6cf9b8b2e22bdf5e77bcfe8efc2c0cf1c06", "061ccfc0c2efe8cf7be7f5bd222e8b9bcfb6428581c425b4bb3c5ae2ca41f427"},
    {"c9d071a67a2c269a3bf54cee8bfa32b7e34d70179e11336ea0f68a3b55e5ca7d", "d58ef83168f2378c31ead172d4a24ec8db36de45dd89137b07dfc5eaa46f280f", "0f286fa4eac5df077b1389dd45de36dbc84ea2d472d1ea318c37f26831f88ed5"},
    {"c45ee1794c2ee540d9c3a2722a2ee70a4101516c6f805889d5f8bffb6f1573a8", "257d59c6222a68221a40e5232083506578dfcd58cebd3d2196d624b99a79b060", "60b0799ab924d696213dbdce58cddf786550832023e5401a22682a22c6597d25"},
    {"bf6aca8e31b406011346157f07cb3004ae408582435b3848127c32ea8b97073a", "14e7fa7b19cf860d9bcc38593ecce7b0cd1df46dc6e0ee2d3313d37bd88f16f4", "f4168fd87bd313332deee0c66df41dcdb0e7cc3e5938cc9b0d86cf197bfae714"},
    {"565fa9000f675b201034c4f5d21d47b3e9dbc1500e9b6ec13b0661bf778b7227", "00ecf00175e7ea0f043a0407fabb94ea47dd9634a99aeaba59250d8ac64fc324", "24c34fc68a0d2559baea9aa93496dd47ea94bbfa07043a040feae77501f0ec00"},
    {"406dea6e5edcf745c83c7fb088bd2461f44489cd37dbde58d0fa7eae8a477c50", "b4e17ade2648890a8f616aa863f3fb7102ed6c25b6d7fe638dd61a1cbbe92374", "7423e9bb1c1ad68d63fed7b6256ced0271fbf363a86a618f0a894826de7ae1b4"},
    {"8843f5423727f639f73416c0ec1341f41455f9cf25d6272176e44db847156a90", "a1e3374f90d7cebf4826fd676e7656b4dbe1d53d264cda7dc3172eb27b546b1a", "1a6b547bb22e17c37dda4c263dd5e1dbb456766e67fd2648bfced7904f37e3a1"},
    {"324ba879cbfaec41d5a2600e5592e2fc4167b532c06f244d9b31876763c23920", "3b758a0ff695658229634786b32a8b5f7fbab4a5a11a8220e812bbaba56b87da", "da876ba5abbb12e820821aa1a5b4ba7f5f8b2ab386476329826595f60f8a753b"},
    {"47ac680e658597e2a2e16f2f27a98d1952406a238d1719d69d23cba128c7532b", "bb2d3dba9b2774e04b5ac074291ec3c0d2fd50dc7e25d271bfd37f3687c786c7", "c786c787367fd3bf71d2257edc50fdd2c0c31e2974c05a4be074279bba3d2dbb"},
    {"6fb25f1d4040d681dabbe7bdb719471dcf6a76f1ae570164b2ffa1dbab8c96c3", "e1a07e88fb7a26703e68426802f986f4b1f246368e8fa7c2178cf1899bab02fb", "fb02ab9b89f18c17c2a78f8e3646f2b1f486f9026842683e70267afb887ea0e1"},
    {"222639263b46eb861b3e075de6c22682984ed6db46f75eec83459e38cf5a18c8", "0adaf523470a5d38f756d76fdff7d1ba46cc2c98ec9597be46c04e315b25aee0", "e0ae255b314ec046be9795ec982ccc46bad1f7df6fd756f7385d0a4723f5da0a"},
    {"2c7bd7ee397a4470c89efabbdca92c5686148b5b0bdc14ea6d07dd5d14dc63f8", "d2ea8dccde6a6ba10984ee2937fe6ce9c6f6cf3b0d3c9f65fdb88403daebf486", "86f4ebda0384b8fd659f3c0d3bcff6c6e96cfe3729ee8409a16b6adecc8dead2"},
    {"7eec39396a2db642af6614a25fef292c23eed5fe6df6c3b0a7f301a15b323530", "489c2266ae2a799e6f75b2986a1e4515e381b3e2dea03ffd5dced500f6a57c8d", "8d7ca5f600d5ce5dfd3fa0dee2b381e315451e6a98b2756f9e792aae66229c48"},
}};

struct CarryMetrics {
  std::uint32_t mask{};
  unsigned count{};
  unsigned appeared{};
  unsigned disappeared{};
  unsigned magnitude_changed{};
  std::optional<unsigned> first;
  std::optional<unsigned> last;
  unsigned longest_run{};
  std::uint64_t sum_abs_delta{};
  std::uint64_t max_abs_delta{};
  bool final_equal{};
  nlohmann::json changes = nlohmann::json::array();
};

struct TransitionCount {
  std::uint64_t count{};
  std::uint64_t output_same{};
  std::uint64_t output_changed{};
};

struct TrajectoryCompact {
  RoundDeltaMasks state_masks{};
  std::array<unsigned, kTotalRoundCount> state_hamming{};
  std::vector<bool> carry_changed;
};

struct PerBitRoundAnalysis {
  nlohmann::json rows = nlohmann::json::array();
  nlohmann::json diffusion;
  nlohmann::json round3;
  nlohmann::json round4;
  std::array<TransitionCount, 64> ch_histogram{};
  std::array<TransitionCount, 64> maj_histogram{};
  TrajectoryCompact trajectory;
};

[[noreturn]] void campaign_fail(const std::string& message) {
  throw std::runtime_error("nonce single-bit campaign validation failed: " + message);
}

void campaign_require(bool condition, const std::string& message) {
  if (!condition) campaign_fail(message);
}

std::string hex_word(std::uint32_t value) {
  std::ostringstream output;
  output << std::hex << std::nouppercase << std::setfill('0') << std::setw(8)
         << value;
  return output.str();
}

std::uint32_t json_word(const nlohmann::json& value) {
  return value.at("uint32").get<std::uint32_t>();
}

unsigned common_low_bits(std::uint32_t left, std::uint32_t right) {
  const auto delta = left ^ right;
  return delta == 0U ? 32U : std::countr_zero(delta);
}

unsigned word_hamming(std::uint32_t left, std::uint32_t right) {
  return std::popcount(left ^ right);
}

std::uint32_t big_sigma0(std::uint32_t value) {
  return std::rotr(value, 2) ^ std::rotr(value, 13) ^ std::rotr(value, 22);
}

std::uint32_t big_sigma1(std::uint32_t value) {
  return std::rotr(value, 6) ^ std::rotr(value, 11) ^ std::rotr(value, 25);
}

std::uint32_t small_sigma0(std::uint32_t value) {
  return std::rotr(value, 7) ^ std::rotr(value, 18) ^ (value >> 3U);
}

std::uint32_t small_sigma1(std::uint32_t value) {
  return std::rotr(value, 17) ^ std::rotr(value, 19) ^ (value >> 10U);
}

State state_words(const nlohmann::json& state) {
  State result{};
  for (std::size_t i = 0; i < result.size(); ++i) {
    result[i] = json_word(state.at(kStateNames[i]));
  }
  return result;
}

std::array<const nlohmann::json*, 3> trace_compressions(
    const nlohmann::json& trace) {
  return {
      &trace.at("sha256_first").at("compressions").at(0),
      &trace.at("sha256_first").at("compressions").at(1),
      &trace.at("sha256_second").at("compressions").at(0)};
}

std::string csv_escape(const std::string& value) {
  std::string result = "\"";
  for (const char character : value) {
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

std::string optional_unsigned(const std::optional<unsigned>& value) {
  return value ? std::to_string(*value) : std::string{};
}

nlohmann::json optional_json(const std::optional<unsigned>& value) {
  return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

std::string bit_list(const nlohmann::json& values) {
  std::ostringstream output;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0U) output << ',';
    output << values.at(i).get<unsigned>();
  }
  return output.str();
}

void write_text_file(const std::filesystem::path& path,
                     const std::string& contents) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) throw std::runtime_error("cannot create " + path.string());
  output << contents;
  if (!output) throw std::runtime_error("cannot finish writing " + path.string());
}

void write_round_csv_header(std::ostringstream& output);
std::size_t compare_all_additions(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit,
    unsigned w3_bit,
    std::ostringstream& carry_csv,
    std::vector<bool>& changed_columns);
std::size_t validate_sigma_differentials(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit);
PerBitRoundAnalysis analyze_rounds(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit,
    unsigned w3_bit,
    std::ostringstream& per_round_csv,
    std::array<TransitionCount, 64>& global_ch,
    std::array<TransitionCount, 64>& global_maj);
void validate_round3_invariants(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit,
    unsigned w3_bit,
    const nlohmann::json& round3);
nlohmann::json analyze_schedule(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit,
    unsigned w3_bit);
nlohmann::json transition_histogram_json(
    const std::array<TransitionCount, 64>& histogram);
unsigned leading_zero_nibbles(const std::string& hex);
unsigned leading_zero_bits(const std::string& hex);
unsigned digest_hamming(const std::string& reference,
                        const std::string& candidate);
double trajectory_mean_distance(const TrajectoryCompact& left,
                                const TrajectoryCompact& right);
double carry_jaccard(const TrajectoryCompact& left,
                     const TrajectoryCompact& right);
std::optional<double> pearson_curve(const TrajectoryCompact& left,
                                    const TrajectoryCompact& right);
nlohmann::json analyze_families(const nlohmann::json& specimens,
                                const nlohmann::json& pairwise);
std::string campaign_markdown(const nlohmann::json& aggregate);

}  // namespace

NonceSingleBitCampaignArtifacts build_genesis_nonce_single_bit_campaign(
    const std::function<void(unsigned)>& progress) {
  auto reference_artifacts = build_genesis_sha256d_whitebox();
  const auto& reference_trace = reference_artifacts.trace;
  (void)validate_genesis_sha256d_whitebox(reference_trace);
  const auto reference_header = crypto::from_hex(
      reference_trace.at("input").at("header_hex").get<std::string>());
  campaign_require(reference_header.size() == 80U,
                   "reference A header is not 80 bytes");
  const auto reference_w3 = json_word(
      reference_trace.at("sha256_first").at("compressions").at(1)
          .at("message_schedule").at("words").at(3).at("result"));
  campaign_require(reference_w3 == kGenesisW3,
                   "reference A W3 is not canonical");

  nlohmann::json aggregate = {
      {"schema_version", 1},
      {"metadata", {
          {"experiment_id", "bitcoin_genesis_nonce_single_bit_32_campaign"},
          {"design", "A XOR (uint32_t{1} << numeric_nonce_bit), one bit at a time"},
          {"numeric_nonce_bits", "0..31"},
          {"memory_model", "reference A plus one exhaustive candidate plus compact aggregates"},
          {"round_indexing", "global_step 0..191; SHA1/compression1/round3 is global_step 67"},
          {"diffusion_state", "state_after each round"},
          {"pairwise_rounds", "all 192 deterministic rounds"},
          {"carry_set_identity", "(addition sequence among 936, carry column 0..31)"},
          {"scientific_scope", "descriptive deterministic campaign; no bias, target, or mining claim"}}},
      {"reference_A", {
          {"nonce_uint32", kGenesisNonce},
          {"nonce_hex", hex_word(kGenesisNonce)},
          {"header_hex", reference_trace.at("input").at("header_hex")},
          {"W3", hex_word(reference_w3)},
          {"first_sha256", reference_trace.at("sha256_first").at("output").at("digest_hex")},
          {"raw_sha256d", reference_trace.at("final").at("raw_sha256d")},
          {"bitcoin_display_hash", reference_trace.at("final").at("bitcoin_display_hash")}}},
      {"baseline_B_nonce_plus_one", {
          {"member_of_single_bit_campaign", false},
          {"header_hamming_vs_A", 2},
          {"T1_carry_bit24", "3->2"},
          {"T1_xor", "01000000"},
          {"new_a_xor", "01000000"},
          {"new_e_xor", "0f000000"}}},
      {"reference_vectors", nlohmann::json::array()},
      {"specimens", nlohmann::json::array()},
      {"pairwise_metrics", nlohmann::json::array()}};
  for (const auto& vector : genesis_nonce_single_bit_reference_vectors()) {
    aggregate["reference_vectors"].push_back({
        {"numeric_nonce_bit", vector.numeric_nonce_bit},
        {"nonce_uint32", vector.nonce},
        {"W3", hex_word(vector.w3)},
        {"first_sha256", vector.first_sha256},
        {"raw_sha256d", vector.raw_sha256d},
        {"bitcoin_display_hash", vector.bitcoin_display_hash},
        {"provenance", "Python standard-library hashlib; fixed before C++ campaign execution"}});
  }

  std::ostringstream per_bit_csv;
  csv_row(per_bit_csv, {
      "numeric_nonce_bit", "W3_bit", "nonce_uint32", "nonce_hex",
      "original_W3_bit_value", "flip_direction", "mod_delta_sign",
      "header_hamming_vs_A", "round3_T1_carry_diff_mask",
      "round3_T1_carry_diff_count", "round3_T1_carry_longest_run",
      "round3_T1_hamming", "round3_new_a_carry_diff_mask",
      "round3_new_a_hamming", "round3_new_e_carry_diff_mask",
      "round3_new_e_hamming", "round4_Sigma0_hamming",
      "round4_Sigma1_hamming", "round4_Ch_hamming", "round4_Maj_hamming",
      "round_to_8_registers", "round_to_HD64", "round_to_HD128",
      "maximum_state_hamming", "round_of_maximum_state_hamming",
      "mean_state_hamming_after_diffusion", "first_schedule_W_diff",
      "W18_small_sigma0_output_xor", "W19_mod_delta", "first_sha256",
      "raw_sha256d", "bitcoin_display_hash", "final_hash_hamming_vs_A",
      "leading_zero_bits", "leading_zero_hex_nibbles"});
  std::ostringstream per_round_csv;
  write_round_csv_header(per_round_csv);
  std::ostringstream carry_csv;
  csv_row(carry_csv, {
      "numeric_nonce_bit", "W3_bit", "sha_pass", "compression_index",
      "phase", "position", "addition_identity", "result_A",
      "result_candidate", "result_mod_delta", "carry_diff_count",
      "carry_diff_mask_hex", "carry_appeared_count",
      "carry_disappeared_count", "carry_magnitude_changed_count",
      "carry_first_diff_bit", "carry_last_diff_bit",
      "carry_longest_diff_run", "carry_sum_abs_delta",
      "carry_max_abs_delta", "final_carry_equal"});
  std::ostringstream pairwise_csv;
  csv_row(pairwise_csv, {
      "bit_i", "bit_j", "mean_hamming_between_state_delta_masks",
      "carry_change_jaccard", "state_hamming_curve_pearson"});

  std::array<TransitionCount, 64> global_ch{};
  std::array<TransitionCount, 64> global_maj{};
  std::vector<TrajectoryCompact> trajectories;
  trajectories.reserve(32U);
  std::size_t addition_differentials_validated = 0U;
  std::size_t sigma_differentials_validated = 0U;

  for (unsigned numeric_bit = 0U; numeric_bit < 32U; ++numeric_bit) {
    if (progress) progress(numeric_bit);
    auto candidate_artifacts =
        build_genesis_nonce_single_bit_flip_sha256d_whitebox(numeric_bit);
    const auto& candidate_trace = candidate_artifacts.trace;
    const auto candidate_audit = validate_sha256d_whitebox(candidate_trace);
    campaign_require(candidate_audit.at("status") == "passed",
                     "candidate trace audit did not pass");
    const auto& fixed_vector =
        genesis_nonce_single_bit_reference_vectors()[numeric_bit];
    const auto candidate_header = crypto::from_hex(
        candidate_trace.at("input").at("header_hex").get<std::string>());
    campaign_require(candidate_header.size() == 80U,
                     "candidate header is not 80 bytes");
    campaign_require(std::equal(reference_header.begin(),
                                reference_header.begin() + 76,
                                candidate_header.begin()),
                     "candidate first 76 header bytes differ from A");
    unsigned header_hamming = 0U;
    std::vector<std::size_t> differing_header_bytes;
    for (std::size_t i = 0; i < reference_header.size(); ++i) {
      const auto delta = reference_header[i] ^ candidate_header[i];
      header_hamming += std::popcount(static_cast<unsigned>(delta));
      if (delta != 0U) differing_header_bytes.push_back(i);
    }
    campaign_require(header_hamming == 1U,
                     "candidate header Hamming distance is not one");
    campaign_require(differing_header_bytes ==
                         std::vector<std::size_t>{76U + numeric_bit / 8U},
                     "candidate differing nonce byte is incorrect");
    const auto candidate_nonce = candidate_trace.at("input").at("fields")
        .at("nonce").at("uint32").get<std::uint32_t>();
    campaign_require(candidate_nonce == fixed_vector.nonce &&
                         candidate_nonce ==
                             (kGenesisNonce ^ (std::uint32_t{1} << numeric_bit)),
                     "candidate numeric nonce relationship is incorrect");
    const auto w3_bit = numeric_nonce_bit_to_w3_bit(numeric_bit);
    const auto candidate_w3 = json_word(
        candidate_trace.at("sha256_first").at("compressions").at(1)
            .at("message_schedule").at("words").at(3).at("result"));
    campaign_require(candidate_w3 == fixed_vector.w3 &&
                         (reference_w3 ^ candidate_w3) ==
                             (std::uint32_t{1} << w3_bit),
                     "candidate W3 mapping is incorrect");
    campaign_require(
        candidate_trace.at("sha256_first").at("output").at("digest_hex") ==
            fixed_vector.first_sha256 &&
        candidate_trace.at("final").at("raw_sha256d") ==
            fixed_vector.raw_sha256d &&
        candidate_trace.at("final").at("bitcoin_display_hash") ==
            fixed_vector.bitcoin_display_hash,
        "candidate does not match its independent fixed vector");

    TrajectoryCompact trajectory;
    addition_differentials_validated += compare_all_additions(
        reference_trace, candidate_trace, numeric_bit, w3_bit, carry_csv,
        trajectory.carry_changed);
    sigma_differentials_validated += validate_sigma_differentials(
        reference_trace, candidate_trace, numeric_bit);
    auto round_analysis = analyze_rounds(
        reference_trace, candidate_trace, numeric_bit, w3_bit, per_round_csv,
        global_ch, global_maj);
    round_analysis.trajectory.carry_changed =
        std::move(trajectory.carry_changed);
    validate_round3_invariants(reference_trace, candidate_trace, numeric_bit,
                               w3_bit, round_analysis.round3);
    auto schedule = analyze_schedule(reference_trace, candidate_trace,
                                     numeric_bit, w3_bit);

    const auto original_w3_bit_value =
        static_cast<unsigned>((reference_w3 >> w3_bit) & 1U);
    const auto direction = original_w3_bit_value == 0U ? "0_to_1" : "1_to_0";
    const auto sign = original_w3_bit_value == 0U ? "+" : "-";
    const auto& round3 = round_analysis.round3;
    const auto& round4 = round_analysis.round4;
    const auto& diffusion = round_analysis.diffusion;
    std::ostringstream signature_key;
    signature_key
        << round3.at("T1_carry").at("carry_diff_mask_hex").get<std::string>() << '/'
        << round3.at("T1").at("hamming").get<unsigned>() << '/'
        << round3.at("new_a_carry").at("carry_diff_mask_hex").get<std::string>() << '/'
        << round3.at("new_a").at("hamming").get<unsigned>() << '/'
        << round3.at("new_e_carry").at("carry_diff_mask_hex").get<std::string>() << '/'
        << round3.at("new_e").at("hamming").get<unsigned>() << '/'
        << round4.at("Sigma0").at("hamming").get<unsigned>() << '/'
        << round4.at("Sigma1").at("hamming").get<unsigned>() << '/'
        << round4.at("Ch").at("hamming").get<unsigned>() << '/'
        << round4.at("Maj").at("hamming").get<unsigned>() << '/'
        << diffusion.at("round_first_8_registers_different").dump() << '/'
        << diffusion.at("round_first_state_hamming_ge_64").dump() << '/'
        << diffusion.at("round_first_state_hamming_ge_128").dump() << '/'
        << schedule.at("first_extended_W_that_differs").get<unsigned>();
    const nlohmann::json signature{
        {"numeric_nonce_bit", numeric_bit},
        {"W3_bit", w3_bit},
        {"original_W3_bit_value", original_w3_bit_value},
        {"flip_direction", direction},
        {"mod_delta_sign", sign},
        {"round3_T1_carry_diff_mask", round3.at("T1_carry").at("carry_diff_mask_hex")},
        {"round3_T1_carry_diff_count", round3.at("T1_carry").at("carry_diff_count")},
        {"round3_T1_carry_longest_run", round3.at("T1_carry").at("carry_longest_diff_run")},
        {"round3_T1_hamming", round3.at("T1").at("hamming")},
        {"round3_new_a_carry_diff_mask", round3.at("new_a_carry").at("carry_diff_mask_hex")},
        {"round3_new_a_hamming", round3.at("new_a").at("hamming")},
        {"round3_new_e_carry_diff_mask", round3.at("new_e_carry").at("carry_diff_mask_hex")},
        {"round3_new_e_hamming", round3.at("new_e").at("hamming")},
        {"round4_Sigma0_hamming", round4.at("Sigma0").at("hamming")},
        {"round4_Sigma1_hamming", round4.at("Sigma1").at("hamming")},
        {"round4_Ch_hamming", round4.at("Ch").at("hamming")},
        {"round4_Maj_hamming", round4.at("Maj").at("hamming")},
        {"round_to_8_registers", diffusion.at("round_first_8_registers_different")},
        {"round_to_HD64", diffusion.at("round_first_state_hamming_ge_64")},
        {"round_to_HD128", diffusion.at("round_first_state_hamming_ge_128")},
        {"first_schedule_W_diff", schedule.at("first_extended_W_that_differs")},
        {"declared_signature_key", signature_key.str()}};

    const auto final_display = candidate_trace.at("final")
        .at("bitcoin_display_hash").get<std::string>();
    const nlohmann::json final{
        {"first_sha256", fixed_vector.first_sha256},
        {"raw_sha256d", fixed_vector.raw_sha256d},
        {"bitcoin_display_hash", fixed_vector.bitcoin_display_hash},
        {"final_hash_hamming_vs_A", digest_hamming(
             reference_trace.at("final").at("raw_sha256d").get<std::string>(),
             fixed_vector.raw_sha256d)},
        {"leading_zero_bits", leading_zero_bits(final_display)},
        {"leading_zero_hex_nibbles", leading_zero_nibbles(final_display)},
        {"display_hash_high_64_bits", final_display.substr(0U, 16U)}};

    auto specimen = nlohmann::json{
        {"numeric_nonce_bit", numeric_bit}, {"W3_bit", w3_bit},
        {"nonce_uint32", candidate_nonce}, {"nonce_hex", hex_word(candidate_nonce)},
        {"header_hex", candidate_trace.at("input").at("header_hex")},
        {"header_hamming_vs_A", header_hamming},
        {"differing_header_byte_indices", differing_header_bytes},
        {"W3", hex_word(candidate_w3)},
        {"initial_signature", signature},
        {"round3", std::move(round_analysis.round3)},
        {"round4", std::move(round_analysis.round4)},
        {"diffusion", std::move(round_analysis.diffusion)},
        {"schedule", std::move(schedule)},
        {"Ch_transition_histogram", transition_histogram_json(round_analysis.ch_histogram)},
        {"Maj_transition_histogram", transition_histogram_json(round_analysis.maj_histogram)},
        {"round_comparisons", std::move(round_analysis.rows)},
        {"final", final},
        {"validations", {
            {"header_single_bit", true}, {"W3_mapping", true},
            {"fixed_crypto_vector", true}, {"trace_audited", true},
            {"first_divergence_round3", true},
            {"round3_modular_deltas", true},
            {"all_936_addition_differentials", true},
            {"all_672_sigma_xor_differentials", true}}}};

    csv_row(per_bit_csv, {
        std::to_string(numeric_bit), std::to_string(w3_bit),
        std::to_string(candidate_nonce), hex_word(candidate_nonce),
        std::to_string(original_w3_bit_value), direction, sign,
        std::to_string(header_hamming),
        signature.at("round3_T1_carry_diff_mask").get<std::string>(),
        std::to_string(signature.at("round3_T1_carry_diff_count").get<unsigned>()),
        std::to_string(signature.at("round3_T1_carry_longest_run").get<unsigned>()),
        std::to_string(signature.at("round3_T1_hamming").get<unsigned>()),
        signature.at("round3_new_a_carry_diff_mask").get<std::string>(),
        std::to_string(signature.at("round3_new_a_hamming").get<unsigned>()),
        signature.at("round3_new_e_carry_diff_mask").get<std::string>(),
        std::to_string(signature.at("round3_new_e_hamming").get<unsigned>()),
        std::to_string(signature.at("round4_Sigma0_hamming").get<unsigned>()),
        std::to_string(signature.at("round4_Sigma1_hamming").get<unsigned>()),
        std::to_string(signature.at("round4_Ch_hamming").get<unsigned>()),
        std::to_string(signature.at("round4_Maj_hamming").get<unsigned>()),
        specimen.at("diffusion").at("round_first_8_registers_different").is_null() ? "" :
            std::to_string(specimen.at("diffusion").at("round_first_8_registers_different").get<unsigned>()),
        specimen.at("diffusion").at("round_first_state_hamming_ge_64").is_null() ? "" :
            std::to_string(specimen.at("diffusion").at("round_first_state_hamming_ge_64").get<unsigned>()),
        specimen.at("diffusion").at("round_first_state_hamming_ge_128").is_null() ? "" :
            std::to_string(specimen.at("diffusion").at("round_first_state_hamming_ge_128").get<unsigned>()),
        std::to_string(specimen.at("diffusion").at("maximum_state_hamming").get<unsigned>()),
        std::to_string(specimen.at("diffusion").at("round_of_maximum_state_hamming").get<unsigned>()),
        specimen.at("diffusion").at("mean_state_hamming_after_diffusion").is_null() ? "" :
            std::to_string(specimen.at("diffusion").at("mean_state_hamming_after_diffusion").get<double>()),
        std::to_string(specimen.at("schedule").at("first_extended_W_that_differs").get<unsigned>()),
        specimen.at("schedule").at("W18_small_sigma0_output_xor").get<std::string>(),
        specimen.at("schedule").at("W19_mod_delta").get<std::string>(),
        fixed_vector.first_sha256, fixed_vector.raw_sha256d,
        fixed_vector.bitcoin_display_hash,
        std::to_string(final.at("final_hash_hamming_vs_A").get<unsigned>()),
        std::to_string(final.at("leading_zero_bits").get<unsigned>()),
        std::to_string(final.at("leading_zero_hex_nibbles").get<unsigned>())});

    trajectories.push_back(std::move(round_analysis.trajectory));
    aggregate["specimens"].push_back(std::move(specimen));
    // candidate_artifacts, including its ~30 MB trace, is destroyed here.
  }

  campaign_require(trajectories.size() == 32U,
                   "trajectory count is not 32");
  for (unsigned bit_i = 0U; bit_i < 32U; ++bit_i) {
    for (unsigned bit_j = 0U; bit_j < 32U; ++bit_j) {
      const auto mean = trajectory_mean_distance(trajectories[bit_i],
                                                 trajectories[bit_j]);
      const auto jaccard = carry_jaccard(trajectories[bit_i],
                                         trajectories[bit_j]);
      const auto pearson = pearson_curve(trajectories[bit_i],
                                         trajectories[bit_j]);
      nlohmann::json item{
          {"bit_i", bit_i}, {"bit_j", bit_j},
          {"mean_hamming_between_state_delta_masks", mean},
          {"carry_change_jaccard", jaccard},
          {"state_hamming_curve_pearson",
           pearson ? nlohmann::json(*pearson) : nlohmann::json(nullptr)}};
      aggregate["pairwise_metrics"].push_back(item);
      csv_row(pairwise_csv, {
          std::to_string(bit_i), std::to_string(bit_j), std::to_string(mean),
          std::to_string(jaccard), pearson ? std::to_string(*pearson) : ""});
    }
  }

  aggregate["transition_histograms"] = {
      {"Ch_global", transition_histogram_json(global_ch)},
      {"Maj_global", transition_histogram_json(global_maj)}};
  aggregate["validations"] = {
      {"all_32_headers_single_bit_validated", true},
      {"all_32_fixed_crypto_vectors_validated", true},
      {"all_32_traces_audited", true},
      {"all_first_divergences_round3_validated", true},
      {"all_round3_modular_deltas_validated", true},
      {"all_modular_addition_differentials_validated", true},
      {"all_sigma_xor_differentials_validated", true},
      {"addition_differential_identity_count", addition_differentials_validated},
      {"sigma_xor_differential_identity_count", sigma_differentials_validated},
      {"bit0_reproduces_historical_C", true},
      {"historical_A_B_C_not_written_by_campaign", true}};
  aggregate["cardinalities"] = {
      {"specimens", 32}, {"per_bit_data_rows", 32},
      {"per_round_data_rows", 32U * kTotalRoundCount},
      {"carry_summary_data_rows", 32U * 936U},
      {"pairwise_data_rows", 32U * 32U},
      {"rounds_per_specimen", kTotalRoundCount},
      {"additions_per_specimen", 936},
      {"sigma_identities_per_specimen", 672},
      {"Ch_transitions_per_specimen", kTotalRoundCount * 32U},
      {"Maj_transitions_per_specimen", kTotalRoundCount * 32U}};
  aggregate["summaries"] = {
      {"families", analyze_families(aggregate.at("specimens"),
                                    aggregate.at("pairwise_metrics"))}};
  aggregate["audit"] = validate_genesis_nonce_single_bit_campaign(aggregate);
  const auto summary = campaign_markdown(aggregate);
  return {
      std::move(aggregate), summary, per_bit_csv.str(), per_round_csv.str(),
      carry_csv.str(), pairwise_csv.str()};
}

nlohmann::json validate_genesis_nonce_single_bit_campaign(
    const nlohmann::json& aggregate) {
  campaign_require(aggregate.at("schema_version") == 1,
                   "unsupported aggregate schema version");
  const auto& specimens = aggregate.at("specimens");
  const auto& vectors = aggregate.at("reference_vectors");
  campaign_require(specimens.size() == 32U && vectors.size() == 32U,
                   "specimen or vector cardinality is not 32");
  std::size_t round_rows = 0U;
  std::uint64_t ch_transitions = 0U;
  std::uint64_t maj_transitions = 0U;
  for (unsigned bit = 0U; bit < 32U; ++bit) {
    const auto& specimen = specimens.at(bit);
    const auto& vector = genesis_nonce_single_bit_reference_vectors()[bit];
    campaign_require(specimen.at("numeric_nonce_bit") == bit &&
                         specimen.at("W3_bit") == numeric_nonce_bit_to_w3_bit(bit),
                     "specimen ordering or mapping mismatch");
    campaign_require(specimen.at("nonce_uint32") == vector.nonce &&
                         specimen.at("W3") == hex_word(vector.w3),
                     "specimen nonce or W3 differs from fixed vector");
    campaign_require(specimen.at("header_hamming_vs_A") == 1U,
                     "specimen header distance is not one");
    campaign_require(specimen.at("final").at("first_sha256") ==
                         vector.first_sha256 &&
                         specimen.at("final").at("raw_sha256d") ==
                         vector.raw_sha256d &&
                         specimen.at("final").at("bitcoin_display_hash") ==
                         vector.bitcoin_display_hash,
                     "specimen digest differs from fixed vector");
    campaign_require(specimen.at("diffusion").at("round_first_divergence") == 67U,
                     "specimen first divergence is not global step 67");
    campaign_require(specimen.at("round_comparisons").size() ==
                         kTotalRoundCount,
                     "specimen does not have 192 round comparisons");
    campaign_require(specimen.at("schedule").at("extended_words").size() == 48U &&
                         specimen.at("schedule").at("first_extended_W_that_differs") == 18U &&
                         specimen.at("schedule").at("W19_direct_modular_relation_validated") == true,
                     "specimen schedule summary is invalid");
    campaign_require(specimen.at("Ch_transition_histogram").size() == 64U &&
                         specimen.at("Maj_transition_histogram").size() == 64U,
                     "specimen transition histogram is not 64 entries");
    for (const auto& item : specimen.at("Ch_transition_histogram")) {
      ch_transitions += item.at("count").get<std::uint64_t>();
    }
    for (const auto& item : specimen.at("Maj_transition_histogram")) {
      maj_transitions += item.at("count").get<std::uint64_t>();
    }
    for (const auto& [name, value] : specimen.at("validations").items()) {
      campaign_require(value.get<bool>(), "specimen validation is false: " + name);
    }
    round_rows += specimen.at("round_comparisons").size();
  }
  campaign_require(round_rows == 32U * kTotalRoundCount,
                   "aggregate round cardinality is not 6144");
  campaign_require(aggregate.at("pairwise_metrics").size() == 1024U,
                   "pairwise cardinality is not 1024");
  campaign_require(ch_transitions == 32U * kTotalRoundCount * 32U &&
                       maj_transitions == 32U * kTotalRoundCount * 32U,
                   "transition count is not 32 x 192 x 32");
  const auto& validations = aggregate.at("validations");
  for (const auto* name : {
           "all_32_headers_single_bit_validated",
           "all_32_fixed_crypto_vectors_validated", "all_32_traces_audited",
           "all_first_divergences_round3_validated",
           "all_round3_modular_deltas_validated",
           "all_modular_addition_differentials_validated",
           "all_sigma_xor_differentials_validated",
           "bit0_reproduces_historical_C"}) {
    campaign_require(validations.at(name).get<bool>(),
                     std::string("global validation is false: ") + name);
  }
  campaign_require(
      validations.at("addition_differential_identity_count") == 32U * 936U,
      "addition differential identity count is not 29952");
  campaign_require(
      validations.at("sigma_xor_differential_identity_count") == 32U * 672U,
      "Sigma XOR differential identity count is not 21504");
  const auto& cardinalities = aggregate.at("cardinalities");
  campaign_require(cardinalities.at("per_bit_data_rows") == 32U &&
                       cardinalities.at("per_round_data_rows") == 6144U &&
                       cardinalities.at("carry_summary_data_rows") == 29952U &&
                       cardinalities.at("pairwise_data_rows") == 1024U,
                   "recorded artifact cardinalities are invalid");
  return {
      {"status", "passed"},
      {"specimens_validated", 32},
      {"round_rows_validated", round_rows},
      {"carry_summary_rows_expected", 29952},
      {"pairwise_rows_validated", aggregate.at("pairwise_metrics").size()},
      {"addition_differentials_validated", 29952},
      {"sigma_xor_differentials_validated", 21504},
      {"Ch_transitions_validated", ch_transitions},
      {"Maj_transitions_validated", maj_transitions},
      {"bit0_equals_C", true}};
}

void write_genesis_nonce_single_bit_campaign(
    const NonceSingleBitCampaignArtifacts& artifacts,
    const std::filesystem::path& output_directory) {
  (void)validate_genesis_nonce_single_bit_campaign(artifacts.aggregate);
  const auto campaign_directory = output_directory / "nonce_single_bit_campaign";
  std::filesystem::create_directories(campaign_directory);
  write_text_file(campaign_directory / "nonce_single_bit_32_aggregate.json",
                  artifacts.aggregate.dump(2) + '\n');
  write_text_file(campaign_directory / "nonce_single_bit_32_summary.md",
                  artifacts.summary_markdown);
  write_text_file(campaign_directory / "nonce_single_bit_32_per_bit.csv",
                  artifacts.per_bit_csv);
  write_text_file(campaign_directory / "nonce_single_bit_32_per_round.csv",
                  artifacts.per_round_csv);
  write_text_file(campaign_directory / "nonce_single_bit_32_carry_summary.csv",
                  artifacts.carry_summary_csv);
  write_text_file(campaign_directory / "nonce_single_bit_32_pairwise.csv",
                  artifacts.pairwise_csv);
}

void write_genesis_nonce_single_bit_full_trace(
    const unsigned numeric_nonce_bit,
    const std::filesystem::path& output_directory) {
  if (numeric_nonce_bit >= 32U) {
    throw std::invalid_argument("numeric nonce bit must be in [0,31]");
  }
  auto header = header_space::genesis_header();
  header[76U + numeric_nonce_bit / 8U] ^=
      static_cast<std::uint8_t>(1U << (numeric_nonce_bit % 8U));
  const auto& vector = genesis_nonce_single_bit_reference_vectors()[numeric_nonce_bit];
  std::ostringstream padded_bit;
  padded_bit << std::setfill('0') << std::setw(2) << numeric_nonce_bit;
  const SpecimenMetadata metadata{
      "bitcoin_genesis_nonce_single_bit_" + std::to_string(numeric_nonce_bit) +
          "_campaign_full_trace",
      "Bitcoin Genesis campaign full trace for nonce bit " +
          std::to_string(numeric_nonce_bit),
      "nonce_single_bit_" + padded_bit.str() + "_full_sha256d",
      vector.first_sha256, vector.raw_sha256d, vector.bitcoin_display_hash};
  const auto artifacts = build_sha256d_whitebox(header, metadata);
  write_sha256d_whitebox(
      artifacts, metadata,
      output_directory / "nonce_single_bit_campaign" /
          ("full_trace_bit_" + std::to_string(numeric_nonce_bit)));
}

unsigned numeric_nonce_bit_to_w3_bit(const unsigned numeric_nonce_bit) {
  if (numeric_nonce_bit >= 32U) {
    throw std::invalid_argument("numeric nonce bit must be in [0,31]");
  }
  const auto byte_index = numeric_nonce_bit / 8U;
  const auto bit_in_byte = numeric_nonce_bit % 8U;
  return (3U - byte_index) * 8U + bit_in_byte;
}

const std::array<NonceSingleBitReferenceVector, 32>&
genesis_nonce_single_bit_reference_vectors() {
  static const auto vectors = [] {
    std::array<NonceSingleBitReferenceVector, 32> result{};
    for (unsigned bit = 0; bit < result.size(); ++bit) {
      const auto w3_bit = numeric_nonce_bit_to_w3_bit(bit);
      result[bit] = {
          bit,
          kGenesisNonce ^ (std::uint32_t{1} << bit),
          kGenesisW3 ^ (std::uint32_t{1} << w3_bit),
          kVectorText[bit].first,
          kVectorText[bit].raw,
          kVectorText[bit].display};
    }
    return result;
  }();
  return vectors;
}

Artifacts build_genesis_nonce_single_bit_flip_sha256d_whitebox(
    const unsigned numeric_nonce_bit) {
  if (numeric_nonce_bit >= 32U) {
    throw std::invalid_argument("numeric nonce bit must be in [0,31]");
  }
  if (numeric_nonce_bit == 0U) {
    return build_genesis_nonce_bit0_flip_sha256d_whitebox();
  }
  auto header = header_space::genesis_header();
  header[76U + numeric_nonce_bit / 8U] ^=
      static_cast<std::uint8_t>(1U << (numeric_nonce_bit % 8U));
  const auto& vector = genesis_nonce_single_bit_reference_vectors()[numeric_nonce_bit];
  const SpecimenMetadata metadata{
      "bitcoin_genesis_nonce_single_bit_" + std::to_string(numeric_nonce_bit) +
          "_sha256d_whitebox_reference",
      "Bitcoin Genesis nonce single-bit " + std::to_string(numeric_nonce_bit) +
          " SHA256d white-box summary",
      "nonce_single_bit_" + std::to_string(numeric_nonce_bit) + "_sha256d",
      vector.first_sha256,
      vector.raw_sha256d,
      vector.bitcoin_display_hash};
  return build_sha256d_whitebox(header, metadata);
}

namespace {

nlohmann::json word_difference(std::uint32_t reference,
                               std::uint32_t candidate) {
  const auto xor_mask = reference ^ candidate;
  return {
      {"reference", hex_word(reference)},
      {"candidate", hex_word(candidate)},
      {"xor", hex_word(xor_mask)},
      {"hamming", std::popcount(xor_mask)},
      {"mod_delta", hex_word(candidate - reference)},
      {"common_low_bits", common_low_bits(reference, candidate)}};
}

nlohmann::json compact_bitwise_difference(const nlohmann::json& difference) {
  return {{"xor", difference.at("xor")},
          {"hamming", difference.at("hamming")}};
}

nlohmann::json compact_modular_difference(const nlohmann::json& difference) {
  return {{"xor", difference.at("xor")},
          {"hamming", difference.at("hamming")},
          {"mod_delta", difference.at("mod_delta")},
          {"common_low_bits", difference.at("common_low_bits")}};
}

CarryMetrics carry_difference(const nlohmann::json& reference,
                              const nlohmann::json& candidate) {
  const auto& reference_summary = reference.at("carry_summary");
  const auto& candidate_summary = candidate.at("carry_summary");
  const auto reference_profile =
      reference_summary.at("carry_profile").get<std::vector<std::uint64_t>>();
  const auto candidate_profile =
      candidate_summary.at("carry_profile").get<std::vector<std::uint64_t>>();
  campaign_require(reference_profile.size() == 32U &&
                       candidate_profile.size() == 32U,
                   "carry profile is not 32 columns");
  CarryMetrics result;
  unsigned current_run = 0;
  for (unsigned bit = 0; bit < 32U; ++bit) {
    if (reference_profile[bit] == candidate_profile[bit]) {
      current_run = 0;
      continue;
    }
    result.mask |= std::uint32_t{1} << bit;
    ++result.count;
    if (!result.first) result.first = bit;
    result.last = bit;
    result.longest_run = std::max(result.longest_run, ++current_run);
    const auto signed_delta =
        static_cast<std::int64_t>(candidate_profile[bit]) -
        static_cast<std::int64_t>(reference_profile[bit]);
    const auto absolute_delta = static_cast<std::uint64_t>(
        signed_delta < 0 ? -signed_delta : signed_delta);
    result.sum_abs_delta += absolute_delta;
    result.max_abs_delta = std::max(result.max_abs_delta, absolute_delta);
    std::string classification;
    if (reference_profile[bit] == 0U) {
      classification = "appeared";
      ++result.appeared;
    } else if (candidate_profile[bit] == 0U) {
      classification = "disappeared";
      ++result.disappeared;
    } else {
      classification = "magnitude_changed";
      ++result.magnitude_changed;
    }
    result.changes.push_back({
        {"bit", bit},
        {"carry_reference", reference_profile[bit]},
        {"carry_candidate", candidate_profile[bit]},
        {"delta_signed", signed_delta},
        {"classification", classification}});
  }
  result.final_equal =
      reference_summary.at("final_carry_out").get<std::uint64_t>() ==
      candidate_summary.at("final_carry_out").get<std::uint64_t>();
  return result;
}

nlohmann::json carry_metrics_json(const CarryMetrics& metrics,
                                  const bool include_profiles,
                                  const nlohmann::json* reference = nullptr,
                                  const nlohmann::json* candidate = nullptr) {
  nlohmann::json result{
      {"carry_diff_count", metrics.count},
      {"carry_diff_mask_hex", hex_word(metrics.mask)},
      {"carry_appeared_count", metrics.appeared},
      {"carry_disappeared_count", metrics.disappeared},
      {"carry_magnitude_changed_count", metrics.magnitude_changed},
      {"carry_first_diff_bit", optional_json(metrics.first)},
      {"carry_last_diff_bit", optional_json(metrics.last)},
      {"carry_longest_diff_run", metrics.longest_run},
      {"carry_sum_abs_delta", metrics.sum_abs_delta},
      {"carry_max_abs_delta", metrics.max_abs_delta},
      {"final_carry_equal", metrics.final_equal}};
  if (include_profiles) {
    campaign_require(reference != nullptr && candidate != nullptr,
                     "carry profiles requested without additions");
    result["carry_profile_reference"] =
        reference->at("carry_summary").at("carry_profile");
    result["carry_profile_candidate"] =
        candidate->at("carry_summary").at("carry_profile");
    result["changes"] = metrics.changes;
  }
  return result;
}

bool validate_addition_differential(const nlohmann::json& reference,
                                    const nlohmann::json& candidate) {
  const auto& reference_operands = reference.at("operands");
  const auto& candidate_operands = candidate.at("operands");
  if (reference_operands.size() != candidate_operands.size()) return false;
  std::uint32_t operand_delta_sum = 0U;
  for (std::size_t i = 0; i < reference_operands.size(); ++i) {
    if (reference_operands.at(i).at("name") !=
        candidate_operands.at(i).at("name")) {
      return false;
    }
    const auto reference_value =
        json_word(reference_operands.at(i).at("value"));
    const auto candidate_value =
        json_word(candidate_operands.at(i).at("value"));
    operand_delta_sum += candidate_value - reference_value;
  }
  return json_word(candidate.at("result")) - json_word(reference.at("result")) ==
         operand_delta_sum;
}

void append_carry_row(std::ostringstream& csv,
                      unsigned numeric_bit,
                      unsigned w3_bit,
                      unsigned sha_pass,
                      unsigned compression_index,
                      const std::string& phase,
                      const std::string& position,
                      const std::string& addition_name,
                      const nlohmann::json& reference,
                      const nlohmann::json& candidate,
                      const CarryMetrics& metrics) {
  csv_row(csv, {
      std::to_string(numeric_bit), std::to_string(w3_bit),
      std::to_string(sha_pass), std::to_string(compression_index), phase,
      position, addition_name,
      hex_word(json_word(reference.at("result"))),
      hex_word(json_word(candidate.at("result"))),
      hex_word(json_word(candidate.at("result")) -
               json_word(reference.at("result"))),
      std::to_string(metrics.count), hex_word(metrics.mask),
      std::to_string(metrics.appeared), std::to_string(metrics.disappeared),
      std::to_string(metrics.magnitude_changed),
      optional_unsigned(metrics.first), optional_unsigned(metrics.last),
      std::to_string(metrics.longest_run),
      std::to_string(metrics.sum_abs_delta),
      std::to_string(metrics.max_abs_delta),
      metrics.final_equal ? "true" : "false"});
}

std::size_t compare_all_additions(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit,
    unsigned w3_bit,
    std::ostringstream& carry_csv,
    std::vector<bool>& changed_columns) {
  const auto reference_compressions = trace_compressions(reference_trace);
  const auto candidate_compressions = trace_compressions(candidate_trace);
  std::size_t validated = 0U;
  const auto compare = [&](unsigned sha_pass, unsigned compression_index,
                           const std::string& phase,
                           const std::string& position,
                           const std::string& name,
                           const nlohmann::json& reference,
                           const nlohmann::json& candidate) {
    campaign_require(validate_addition_differential(reference, candidate),
                     "modular addition differential failed at bit " +
                         std::to_string(numeric_bit) + "/" + phase + "/" +
                         position + "/" + name);
    const auto metrics = carry_difference(reference, candidate);
    append_carry_row(carry_csv, numeric_bit, w3_bit, sha_pass,
                     compression_index, phase, position, name, reference,
                     candidate, metrics);
    for (unsigned column = 0; column < 32U; ++column) {
      changed_columns.push_back(((metrics.mask >> column) & 1U) != 0U);
    }
    ++validated;
  };

  for (std::size_t c = 0; c < reference_compressions.size(); ++c) {
    const auto& reference = *reference_compressions[c];
    const auto& candidate = *candidate_compressions[c];
    const auto sha_pass = reference.at("sha_pass").get<unsigned>();
    const auto compression_index =
        reference.at("compression_index").get<unsigned>();
    const auto& reference_schedule =
        reference.at("message_schedule").at("words");
    const auto& candidate_schedule =
        candidate.at("message_schedule").at("words");
    for (unsigned t = 16U; t < 64U; ++t) {
      compare(sha_pass, compression_index, "schedule", "W[" +
                  std::to_string(t) + "]", "W", reference_schedule.at(t).at("addition"),
              candidate_schedule.at(t).at("addition"));
    }
    const auto& reference_rounds = reference.at("rounds");
    const auto& candidate_rounds = candidate.at("rounds");
    for (unsigned round = 0; round < 64U; ++round) {
      for (const auto* name : {"T1", "T2", "new_a", "new_e"}) {
        compare(sha_pass, compression_index, "round",
                "round[" + std::to_string(round) + "]", name,
                reference_rounds.at(round).at("additions").at(name),
                candidate_rounds.at(round).at("additions").at(name));
      }
    }
    const auto& reference_feed = reference.at("feed_forward");
    const auto& candidate_feed = candidate.at("feed_forward");
    for (unsigned word = 0; word < 8U; ++word) {
      compare(sha_pass, compression_index, "feed_forward",
              "word[" + std::to_string(word) + "]", "H" +
                  std::to_string(word), reference_feed.at(word).at("addition"),
              candidate_feed.at(word).at("addition"));
    }
  }
  campaign_require(validated == 936U,
                   "addition count per candidate is not 936");
  campaign_require(changed_columns.size() == 936U * 32U,
                   "carry-change set does not have 936 x 32 positions");
  return validated;
}

std::size_t validate_sigma_differentials(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit) {
  const auto reference_compressions = trace_compressions(reference_trace);
  const auto candidate_compressions = trace_compressions(candidate_trace);
  std::size_t validated = 0U;
  const auto check = [&](std::uint32_t reference_input,
                         std::uint32_t candidate_input,
                         std::uint32_t reference_output,
                         std::uint32_t candidate_output,
                         const auto& function,
                         const std::string& identity) {
    campaign_require((reference_output ^ candidate_output) ==
                         function(reference_input ^ candidate_input),
                     "Sigma XOR differential failed at bit " +
                         std::to_string(numeric_bit) + "/" + identity);
    ++validated;
  };
  for (std::size_t c = 0; c < reference_compressions.size(); ++c) {
    const auto& reference_schedule =
        reference_compressions[c]->at("message_schedule").at("words");
    const auto& candidate_schedule =
        candidate_compressions[c]->at("message_schedule").at("words");
    for (unsigned t = 16U; t < 64U; ++t) {
      check(json_word(reference_schedule.at(t).at("small_sigma0").at("input")),
            json_word(candidate_schedule.at(t).at("small_sigma0").at("input")),
            json_word(reference_schedule.at(t).at("small_sigma0").at("result")),
            json_word(candidate_schedule.at(t).at("small_sigma0").at("result")),
            small_sigma0, "small_sigma0/W[" + std::to_string(t) + "]");
      check(json_word(reference_schedule.at(t).at("small_sigma1").at("input")),
            json_word(candidate_schedule.at(t).at("small_sigma1").at("input")),
            json_word(reference_schedule.at(t).at("small_sigma1").at("result")),
            json_word(candidate_schedule.at(t).at("small_sigma1").at("result")),
            small_sigma1, "small_sigma1/W[" + std::to_string(t) + "]");
    }
    const auto& reference_rounds = reference_compressions[c]->at("rounds");
    const auto& candidate_rounds = candidate_compressions[c]->at("rounds");
    for (unsigned round = 0U; round < 64U; ++round) {
      const auto reference_before =
          state_words(reference_rounds.at(round).at("state_before"));
      const auto candidate_before =
          state_words(candidate_rounds.at(round).at("state_before"));
      check(reference_before[0], candidate_before[0],
            json_word(reference_rounds.at(round).at("Sigma0").at("result")),
            json_word(candidate_rounds.at(round).at("Sigma0").at("result")),
            big_sigma0, "Sigma0/round[" + std::to_string(round) + "]");
      check(reference_before[4], candidate_before[4],
            json_word(reference_rounds.at(round).at("Sigma1").at("result")),
            json_word(candidate_rounds.at(round).at("Sigma1").at("result")),
            big_sigma1, "Sigma1/round[" + std::to_string(round) + "]");
    }
  }
  campaign_require(validated == 672U,
                   "Sigma identity count per candidate is not 672");
  return validated;
}

std::string transition_bits(unsigned value) {
  std::string result(3U, '0');
  for (unsigned bit = 0U; bit < 3U; ++bit) {
    if (((value >> bit) & 1U) != 0U) result[2U - bit] = '1';
  }
  return result;
}

void observe_transitions(const State& reference,
                         const State& candidate,
                         std::uint32_t reference_ch,
                         std::uint32_t candidate_ch,
                         std::uint32_t reference_maj,
                         std::uint32_t candidate_maj,
                         std::array<TransitionCount, 64>& ch,
                         std::array<TransitionCount, 64>& maj) {
  for (unsigned bit = 0; bit < 32U; ++bit) {
    const auto state_bit = [bit](std::uint32_t value) {
      return static_cast<unsigned>((value >> bit) & 1U);
    };
    const auto ch_reference =
        (state_bit(reference[4]) << 2U) |
        (state_bit(reference[5]) << 1U) | state_bit(reference[6]);
    const auto ch_candidate =
        (state_bit(candidate[4]) << 2U) |
        (state_bit(candidate[5]) << 1U) | state_bit(candidate[6]);
    auto& ch_entry = ch[ch_reference * 8U + ch_candidate];
    ++ch_entry.count;
    if (state_bit(reference_ch) == state_bit(candidate_ch)) {
      ++ch_entry.output_same;
    } else {
      ++ch_entry.output_changed;
    }
    const auto maj_reference =
        (state_bit(reference[0]) << 2U) |
        (state_bit(reference[1]) << 1U) | state_bit(reference[2]);
    const auto maj_candidate =
        (state_bit(candidate[0]) << 2U) |
        (state_bit(candidate[1]) << 1U) | state_bit(candidate[2]);
    auto& maj_entry = maj[maj_reference * 8U + maj_candidate];
    ++maj_entry.count;
    if (state_bit(reference_maj) == state_bit(candidate_maj)) {
      ++maj_entry.output_same;
    } else {
      ++maj_entry.output_changed;
    }
  }
}

nlohmann::json transition_histogram_json(
    const std::array<TransitionCount, 64>& histogram) {
  auto result = nlohmann::json::array();
  for (unsigned from = 0U; from < 8U; ++from) {
    for (unsigned to = 0U; to < 8U; ++to) {
      const auto& item = histogram[from * 8U + to];
      result.push_back({
          {"transition", transition_bits(from) + "->" + transition_bits(to)},
          {"reference_inputs", transition_bits(from)},
          {"candidate_inputs", transition_bits(to)},
          {"count", item.count},
          {"output_same", item.output_same},
          {"output_changed", item.output_changed}});
    }
  }
  return result;
}

unsigned leading_zero_nibbles(const std::string& hex) {
  return static_cast<unsigned>(
      std::find_if(hex.begin(), hex.end(), [](char value) { return value != '0'; }) -
      hex.begin());
}

unsigned leading_zero_bits(const std::string& hex) {
  unsigned result = 0U;
  for (const char character : hex) {
    unsigned nibble = character >= 'a'
        ? static_cast<unsigned>(character - 'a' + 10)
        : static_cast<unsigned>(character - '0');
    if (nibble == 0U) {
      result += 4U;
      continue;
    }
    result += std::countl_zero(nibble) -
              (std::numeric_limits<unsigned>::digits - 4U);
    break;
  }
  return result;
}

unsigned digest_hamming(const std::string& reference,
                        const std::string& candidate) {
  const auto reference_bytes = crypto::from_hex(reference);
  const auto candidate_bytes = crypto::from_hex(candidate);
  campaign_require(reference_bytes.size() == candidate_bytes.size(),
                   "digest length mismatch");
  unsigned result = 0U;
  for (std::size_t i = 0; i < reference_bytes.size(); ++i) {
    result += std::popcount(
        static_cast<unsigned>(reference_bytes[i] ^ candidate_bytes[i]));
  }
  return result;
}

void append_carry_metric_fields(std::vector<std::string>& fields,
                                const CarryMetrics& metrics) {
  fields.push_back(std::to_string(metrics.count));
  fields.push_back(hex_word(metrics.mask));
  fields.push_back(std::to_string(metrics.appeared));
  fields.push_back(std::to_string(metrics.disappeared));
  fields.push_back(std::to_string(metrics.magnitude_changed));
  fields.push_back(optional_unsigned(metrics.first));
  fields.push_back(optional_unsigned(metrics.last));
  fields.push_back(std::to_string(metrics.longest_run));
  fields.push_back(std::to_string(metrics.sum_abs_delta));
  fields.push_back(std::to_string(metrics.max_abs_delta));
  fields.push_back(metrics.final_equal ? "true" : "false");
}

void write_round_csv_header(std::ostringstream& output) {
  std::vector<std::string> fields{
      "numeric_nonce_bit", "W3_bit", "global_step", "sha_pass",
      "compression_index", "round_index", "W_A", "W_candidate", "W_xor",
      "W_hamming", "W_mod_delta", "W_common_low_bits",
      "state_hamming_before", "state_hamming_after"};
  for (const auto* name : kStateNames) {
    fields.push_back(std::string(name) + "_hamming_before");
  }
  for (const auto* name : kStateNames) {
    fields.push_back(std::string(name) + "_hamming_after");
  }
  for (const auto* name : {"Sigma0", "Sigma1", "Ch", "Maj"}) {
    fields.push_back(std::string(name) + "_xor");
    fields.push_back(std::string(name) + "_hamming");
  }
  for (const auto* name : {"T1", "T2", "new_a", "new_e"}) {
    fields.push_back(std::string(name) + "_A");
    fields.push_back(std::string(name) + "_candidate");
    fields.push_back(std::string(name) + "_xor");
    fields.push_back(std::string(name) + "_hamming");
    fields.push_back(std::string(name) + "_mod_delta");
    fields.push_back(std::string(name) + "_common_low_bits");
  }
  fields.push_back("a_after_common_low_bits");
  fields.push_back("e_after_common_low_bits");
  for (const auto* name : kStateNames) {
    fields.push_back(std::string(name) + "_xor");
  }
  for (const auto* addition : {"T1", "T2", "new_a", "new_e"}) {
    for (const auto* suffix : {
             "carry_diff_count", "carry_diff_mask_hex", "carry_appeared_count",
             "carry_disappeared_count", "carry_magnitude_changed_count",
             "carry_first_diff_bit", "carry_last_diff_bit",
             "carry_longest_diff_run", "carry_sum_abs_delta",
             "carry_max_abs_delta", "final_carry_equal"}) {
      fields.push_back(std::string(addition) + "_" + suffix);
    }
  }
  csv_row(output, fields);
}

PerBitRoundAnalysis analyze_rounds(
    const nlohmann::json& reference_trace,
    const nlohmann::json& candidate_trace,
    unsigned numeric_bit,
    unsigned w3_bit,
    std::ostringstream& per_round_csv,
    std::array<TransitionCount, 64>& global_ch,
    std::array<TransitionCount, 64>& global_maj) {
  PerBitRoundAnalysis result;
  const auto reference_compressions = trace_compressions(reference_trace);
  const auto candidate_compressions = trace_compressions(candidate_trace);
  std::optional<unsigned> first_divergence;
  std::array<std::optional<unsigned>, 4> first_register_counts;
  const std::array<unsigned, 4> register_thresholds{2U, 4U, 6U, 8U};
  std::array<std::optional<unsigned>, 5> first_hamming_thresholds;
  const std::array<unsigned, 5> hamming_thresholds{32U, 64U, 96U, 112U, 128U};
  unsigned maximum_hamming = 0U;
  unsigned maximum_round = 0U;

  unsigned global_step = 0U;
  for (std::size_t c = 0; c < reference_compressions.size(); ++c) {
    const auto& reference_rounds = reference_compressions[c]->at("rounds");
    const auto& candidate_rounds = candidate_compressions[c]->at("rounds");
    for (unsigned round_index = 0U; round_index < 64U;
         ++round_index, ++global_step) {
      const auto& reference_round = reference_rounds.at(round_index);
      const auto& candidate_round = candidate_rounds.at(round_index);
      const auto reference_before =
          state_words(reference_round.at("state_before"));
      const auto candidate_before =
          state_words(candidate_round.at("state_before"));
      const auto reference_after =
          state_words(reference_round.at("state_after"));
      const auto candidate_after =
          state_words(candidate_round.at("state_after"));
      State before_masks{};
      State after_masks{};
      std::array<unsigned, 8> before_hamming{};
      std::array<unsigned, 8> after_hamming{};
      unsigned state_before_hamming = 0U;
      unsigned state_after_hamming = 0U;
      unsigned different_registers = 0U;
      auto state_xor = nlohmann::json::object();
      auto before_hamming_json = nlohmann::json::object();
      auto after_hamming_json = nlohmann::json::object();
      for (std::size_t register_index = 0U; register_index < 8U;
           ++register_index) {
        before_masks[register_index] =
            reference_before[register_index] ^ candidate_before[register_index];
        after_masks[register_index] =
            reference_after[register_index] ^ candidate_after[register_index];
        before_hamming[register_index] = std::popcount(before_masks[register_index]);
        after_hamming[register_index] = std::popcount(after_masks[register_index]);
        state_before_hamming += before_hamming[register_index];
        state_after_hamming += after_hamming[register_index];
        if (after_masks[register_index] != 0U) ++different_registers;
        state_xor[kStateNames[register_index]] = hex_word(after_masks[register_index]);
        before_hamming_json[kStateNames[register_index]] =
            before_hamming[register_index];
        after_hamming_json[kStateNames[register_index]] =
            after_hamming[register_index];
      }
      result.trajectory.state_masks[global_step] = after_masks;
      result.trajectory.state_hamming[global_step] = state_after_hamming;

      const auto reference_w = json_word(reference_round.at("W"));
      const auto candidate_w = json_word(candidate_round.at("W"));
      const auto& reference_additions = reference_round.at("additions");
      const auto& candidate_additions = candidate_round.at("additions");
      const auto operation_difference = [&](const char* name) {
        return word_difference(
            json_word(reference_additions.at(name).at("result")),
            json_word(candidate_additions.at(name).at("result")));
      };
      const auto t1 = operation_difference("T1");
      const auto t2 = operation_difference("T2");
      const auto new_a = operation_difference("new_a");
      const auto new_e = operation_difference("new_e");
      const auto sigma0 = word_difference(
          json_word(reference_round.at("Sigma0").at("result")),
          json_word(candidate_round.at("Sigma0").at("result")));
      const auto sigma1 = word_difference(
          json_word(reference_round.at("Sigma1").at("result")),
          json_word(candidate_round.at("Sigma1").at("result")));
      const auto choice = word_difference(
          json_word(reference_round.at("Ch").at("result")),
          json_word(candidate_round.at("Ch").at("result")));
      const auto majority = word_difference(
          json_word(reference_round.at("Maj").at("result")),
          json_word(candidate_round.at("Maj").at("result")));
      std::array<CarryMetrics, 4> carry_metrics{
          carry_difference(reference_additions.at("T1"), candidate_additions.at("T1")),
          carry_difference(reference_additions.at("T2"), candidate_additions.at("T2")),
          carry_difference(reference_additions.at("new_a"), candidate_additions.at("new_a")),
          carry_difference(reference_additions.at("new_e"), candidate_additions.at("new_e"))};

      observe_transitions(
          reference_before, candidate_before,
          json_word(reference_round.at("Ch").at("result")),
          json_word(candidate_round.at("Ch").at("result")),
          json_word(reference_round.at("Maj").at("result")),
          json_word(candidate_round.at("Maj").at("result")),
          result.ch_histogram, result.maj_histogram);
      observe_transitions(
          reference_before, candidate_before,
          json_word(reference_round.at("Ch").at("result")),
          json_word(candidate_round.at("Ch").at("result")),
          json_word(reference_round.at("Maj").at("result")),
          json_word(candidate_round.at("Maj").at("result")),
          global_ch, global_maj);

      if (!first_divergence &&
          (reference_w != candidate_w || state_after_hamming != 0U)) {
        first_divergence = global_step;
      }
      for (std::size_t i = 0U; i < register_thresholds.size(); ++i) {
        if (!first_register_counts[i] &&
            different_registers >= register_thresholds[i]) {
          first_register_counts[i] = global_step;
        }
      }
      for (std::size_t i = 0U; i < hamming_thresholds.size(); ++i) {
        if (!first_hamming_thresholds[i] &&
            state_after_hamming >= hamming_thresholds[i]) {
          first_hamming_thresholds[i] = global_step;
        }
      }
      if (state_after_hamming > maximum_hamming) {
        maximum_hamming = state_after_hamming;
        maximum_round = global_step;
      }

      nlohmann::json carries = nlohmann::json::object();
      const std::array<const char*, 4> addition_names{"T1", "T2", "new_a", "new_e"};
      for (std::size_t i = 0; i < addition_names.size(); ++i) {
        carries[addition_names[i]] = carry_metrics_json(carry_metrics[i], false);
      }
      auto row = nlohmann::json{
          {"numeric_nonce_bit", numeric_bit},
          {"W3_bit", w3_bit},
          {"global_step", global_step},
          {"sha_pass", reference_round.at("sha_pass")},
          {"compression_index", reference_round.at("compression_index")},
          {"round_index", round_index},
          {"W", word_difference(reference_w, candidate_w)},
          {"state_hamming_before", state_before_hamming},
          {"state_hamming_after", state_after_hamming},
          {"register_hamming_before", std::move(before_hamming_json)},
          {"register_hamming_after", std::move(after_hamming_json)},
          {"state_xor_after", std::move(state_xor)},
          {"Sigma0", compact_bitwise_difference(sigma0)},
          {"Sigma1", compact_bitwise_difference(sigma1)},
          {"Ch", compact_bitwise_difference(choice)},
          {"Maj", compact_bitwise_difference(majority)},
          {"T1", compact_modular_difference(t1)},
          {"T2", compact_modular_difference(t2)},
          {"new_a", compact_modular_difference(new_a)},
          {"new_e", compact_modular_difference(new_e)},
          {"a_after_common_low_bits", common_low_bits(reference_after[0], candidate_after[0])},
          {"e_after_common_low_bits", common_low_bits(reference_after[4], candidate_after[4])},
          {"carries", std::move(carries)}};
      result.rows.push_back(std::move(row));

      std::vector<std::string> fields{
          std::to_string(numeric_bit), std::to_string(w3_bit),
          std::to_string(global_step),
          std::to_string(reference_round.at("sha_pass").get<unsigned>()),
          std::to_string(reference_round.at("compression_index").get<unsigned>()),
          std::to_string(round_index), hex_word(reference_w), hex_word(candidate_w),
          hex_word(reference_w ^ candidate_w),
          std::to_string(word_hamming(reference_w, candidate_w)),
          hex_word(candidate_w - reference_w),
          std::to_string(common_low_bits(reference_w, candidate_w)),
          std::to_string(state_before_hamming),
          std::to_string(state_after_hamming)};
      for (const auto value : before_hamming) fields.push_back(std::to_string(value));
      for (const auto value : after_hamming) fields.push_back(std::to_string(value));
      for (const auto* operation : {&sigma0, &sigma1, &choice, &majority}) {
        fields.push_back(operation->at("xor").get<std::string>());
        fields.push_back(std::to_string(operation->at("hamming").get<unsigned>()));
      }
      for (const auto* operation : {&t1, &t2, &new_a, &new_e}) {
        fields.push_back(operation->at("reference").get<std::string>());
        fields.push_back(operation->at("candidate").get<std::string>());
        fields.push_back(operation->at("xor").get<std::string>());
        fields.push_back(std::to_string(operation->at("hamming").get<unsigned>()));
        fields.push_back(operation->at("mod_delta").get<std::string>());
        fields.push_back(std::to_string(operation->at("common_low_bits").get<unsigned>()));
      }
      fields.push_back(std::to_string(common_low_bits(reference_after[0], candidate_after[0])));
      fields.push_back(std::to_string(common_low_bits(reference_after[4], candidate_after[4])));
      for (const auto value : after_masks) fields.push_back(hex_word(value));
      for (const auto& metrics : carry_metrics) {
        append_carry_metric_fields(fields, metrics);
      }
      csv_row(per_round_csv, fields);

      if (global_step == 67U) {
        result.round3 = {
            {"W", word_difference(reference_w, candidate_w)},
            {"T1", t1}, {"T2", t2}, {"new_a", new_a}, {"new_e", new_e},
            {"state_hamming_after", state_after_hamming},
            {"T1_carry", carry_metrics_json(carry_metrics[0], true,
                                             &reference_additions.at("T1"),
                                             &candidate_additions.at("T1"))},
            {"new_a_carry", carry_metrics_json(carry_metrics[2], true,
                                                &reference_additions.at("new_a"),
                                                &candidate_additions.at("new_a"))},
            {"new_e_carry", carry_metrics_json(carry_metrics[3], true,
                                                &reference_additions.at("new_e"),
                                                &candidate_additions.at("new_e"))}};
      }
      if (global_step == 68U) {
        result.round4 = {
            {"Sigma0", sigma0}, {"Sigma1", sigma1},
            {"Ch", choice}, {"Maj", majority}};
      }
    }
  }
  campaign_require(global_step == kTotalRoundCount,
                   "per-bit round analysis did not visit 192 rounds");
  campaign_require(first_divergence && *first_divergence == 67U,
                   "first divergence is not SHA1/compression1/round3");

  std::optional<double> mean_after_diffusion;
  if (first_register_counts[3]) {
    const auto first = *first_register_counts[3];
    const auto sum = std::accumulate(
        result.trajectory.state_hamming.begin() + first,
        result.trajectory.state_hamming.end(), std::uint64_t{0});
    mean_after_diffusion = static_cast<double>(sum) /
        static_cast<double>(kTotalRoundCount - first);
  }
  result.diffusion = {
      {"round_first_divergence", *first_divergence},
      {"round_first_divergence_label", "SHA1/compression1/round3"},
      {"round_first_2_registers_different", optional_json(first_register_counts[0])},
      {"round_first_4_registers_different", optional_json(first_register_counts[1])},
      {"round_first_6_registers_different", optional_json(first_register_counts[2])},
      {"round_first_8_registers_different", optional_json(first_register_counts[3])},
      {"round_first_state_hamming_ge_32", optional_json(first_hamming_thresholds[0])},
      {"round_first_state_hamming_ge_64", optional_json(first_hamming_thresholds[1])},
      {"round_first_state_hamming_ge_96", optional_json(first_hamming_thresholds[2])},
      {"round_first_state_hamming_ge_112", optional_json(first_hamming_thresholds[3])},
      {"round_first_state_hamming_ge_128", optional_json(first_hamming_thresholds[4])},
      {"maximum_state_hamming", maximum_hamming},
      {"round_of_maximum_state_hamming", maximum_round},
      {"mean_state_hamming_after_diffusion",
       mean_after_diffusion ? nlohmann::json(*mean_after_diffusion)
                            : nlohmann::json(nullptr)}};
  return result;
}

void validate_round3_invariants(const nlohmann::json& reference_trace,
                                const nlohmann::json& candidate_trace,
                                unsigned numeric_bit,
                                unsigned w3_bit,
                                const nlohmann::json& round3) {
  const auto reference_compressions = trace_compressions(reference_trace);
  const auto candidate_compressions = trace_compressions(candidate_trace);
  campaign_require(*reference_compressions[0] == *candidate_compressions[0],
                   "SHA1/compression0 differs for bit " +
                       std::to_string(numeric_bit));
  const auto& reference_rounds = reference_compressions[1]->at("rounds");
  const auto& candidate_rounds = candidate_compressions[1]->at("rounds");
  for (unsigned round = 0U; round < 3U; ++round) {
    campaign_require(reference_rounds.at(round) == candidate_rounds.at(round),
                     "pre-divergence round differs for bit " +
                         std::to_string(numeric_bit));
  }
  const auto& reference = reference_rounds.at(3);
  const auto& candidate = candidate_rounds.at(3);
  campaign_require(reference.at("state_before") == candidate.at("state_before"),
                   "round3 state_before differs");
  for (const auto* name : {"Sigma0", "Sigma1", "Ch", "Maj", "K"}) {
    campaign_require(reference.at(name) == candidate.at(name),
                     std::string("round3 ") + name + " differs");
  }
  const auto& reference_operands = reference.at("additions").at("T1").at("operands");
  const auto& candidate_operands = candidate.at("additions").at("T1").at("operands");
  campaign_require(reference_operands.size() == 5U && candidate_operands.size() == 5U,
                   "round3 T1 operand cardinality differs");
  for (std::size_t i = 0; i < 4U; ++i) {
    campaign_require(reference_operands.at(i) == candidate_operands.at(i),
                     "non-W T1 operand differs at round3");
  }
  const auto expected_delta = ((kGenesisW3 >> w3_bit) & 1U) == 0U
      ? std::uint32_t{1} << w3_bit
      : std::uint32_t{0} - (std::uint32_t{1} << w3_bit);
  for (const auto* name : {"W", "T1", "new_a", "new_e"}) {
    campaign_require(round3.at(name).at("mod_delta").get<std::string>() ==
                         hex_word(expected_delta),
                     std::string("round3 modular delta failed for ") + name);
  }
  campaign_require(round3.at("T2").at("mod_delta").get<std::string>() == "00000000",
                   "round3 T2 changed");
  campaign_require(round3.at("W").at("xor").get<std::string>() ==
                       hex_word(std::uint32_t{1} << w3_bit),
                   "round3 W XOR does not match mapped W3 bit");
  if (numeric_bit == 0U) {
    campaign_require(round3.at("T1").at("xor") == "03000000" &&
                         round3.at("new_a").at("xor") == "0f000000" &&
                         round3.at("new_e").at("xor") == "01000000",
                     "bit0 does not reproduce C XOR masks");
    campaign_require(round3.at("T1_carry").at("carry_diff_mask_hex") ==
                         "01000000" &&
                         round3.at("T1_carry").at("carry_diff_count") == 1U,
                     "bit0 does not reproduce C carry mask");
    const auto& change = round3.at("T1_carry").at("changes").at(0);
    campaign_require(change.at("bit") == 24U &&
                         change.at("carry_reference") == 3U &&
                         change.at("carry_candidate") == 2U,
                     "bit0 does not reproduce C carry 3 -> 2 at bit24");
  }
}

nlohmann::json analyze_schedule(const nlohmann::json& reference_trace,
                                const nlohmann::json& candidate_trace,
                                unsigned numeric_bit,
                                unsigned w3_bit) {
  const auto reference_compressions = trace_compressions(reference_trace);
  const auto candidate_compressions = trace_compressions(candidate_trace);
  const auto& reference =
      reference_compressions[1]->at("message_schedule").at("words");
  const auto& candidate =
      candidate_compressions[1]->at("message_schedule").at("words");
  std::optional<unsigned> first_extended;
  auto words = nlohmann::json::array();
  for (unsigned t = 16U; t < 64U; ++t) {
    const auto reference_value = json_word(reference.at(t).at("result"));
    const auto candidate_value = json_word(candidate.at(t).at("result"));
    const auto xor_mask = reference_value ^ candidate_value;
    if (xor_mask != 0U && !first_extended) first_extended = t;
    words.push_back({
        {"t", t},
        {"W", word_difference(reference_value, candidate_value)},
        {"lowest_differing_bit", xor_mask == 0U
             ? nlohmann::json(nullptr)
             : nlohmann::json(std::countr_zero(xor_mask))},
        {"highest_differing_bit", xor_mask == 0U
             ? nlohmann::json(nullptr)
             : nlohmann::json(31U - std::countl_zero(xor_mask))}});
  }
  campaign_require(first_extended && *first_extended == 18U,
                   "first extended schedule difference is not W18 for bit " +
                       std::to_string(numeric_bit));
  const auto w19_reference = json_word(reference.at(19).at("result"));
  const auto w19_candidate = json_word(candidate.at(19).at("result"));
  const auto expected_delta = ((kGenesisW3 >> w3_bit) & 1U) == 0U
      ? std::uint32_t{1} << w3_bit
      : std::uint32_t{0} - (std::uint32_t{1} << w3_bit);
  campaign_require(w19_candidate - w19_reference == expected_delta,
                   "W19 does not conserve the direct modular W3 delta");
  const auto& reference_w18_sigma0 = reference.at(18).at("small_sigma0");
  const auto& candidate_w18_sigma0 = candidate.at(18).at("small_sigma0");
  const auto sigma0_input_xor =
      json_word(reference_w18_sigma0.at("input")) ^
      json_word(candidate_w18_sigma0.at("input"));
  const auto sigma0_output_xor =
      json_word(reference_w18_sigma0.at("result")) ^
      json_word(candidate_w18_sigma0.at("result"));
  campaign_require(sigma0_output_xor == small_sigma0(sigma0_input_xor),
                   "W18 small_sigma0 XOR differential failed");
  return {
      {"first_extended_W_that_differs", *first_extended},
      {"W18_small_sigma0_input_xor", hex_word(sigma0_input_xor)},
      {"W18_small_sigma0_output_xor", hex_word(sigma0_output_xor)},
      {"W18_small_sigma0_output_hamming", std::popcount(sigma0_output_xor)},
      {"W19_direct_modular_relation_validated", true},
      {"W19_mod_delta", hex_word(w19_candidate - w19_reference)},
      {"extended_words", std::move(words)}};
}

double trajectory_mean_distance(const TrajectoryCompact& left,
                                const TrajectoryCompact& right) {
  std::uint64_t total = 0U;
  for (std::size_t round = 0; round < kTotalRoundCount; ++round) {
    for (std::size_t word = 0; word < 8U; ++word) {
      total += std::popcount(left.state_masks[round][word] ^
                             right.state_masks[round][word]);
    }
  }
  return static_cast<double>(total) /
         static_cast<double>(kTotalRoundCount);
}

double carry_jaccard(const TrajectoryCompact& left,
                     const TrajectoryCompact& right) {
  campaign_require(left.carry_changed.size() == right.carry_changed.size(),
                   "pairwise carry vectors have different sizes");
  std::uint64_t intersection = 0U;
  std::uint64_t union_count = 0U;
  for (std::size_t i = 0; i < left.carry_changed.size(); ++i) {
    intersection += left.carry_changed[i] && right.carry_changed[i];
    union_count += left.carry_changed[i] || right.carry_changed[i];
  }
  return union_count == 0U ? 1.0
                           : static_cast<double>(intersection) /
                                 static_cast<double>(union_count);
}

std::optional<double> pearson_curve(const TrajectoryCompact& left,
                                    const TrajectoryCompact& right) {
  const auto left_mean = std::accumulate(
      left.state_hamming.begin(), left.state_hamming.end(), 0.0) /
      static_cast<double>(kTotalRoundCount);
  const auto right_mean = std::accumulate(
      right.state_hamming.begin(), right.state_hamming.end(), 0.0) /
      static_cast<double>(kTotalRoundCount);
  double covariance = 0.0;
  double left_variance = 0.0;
  double right_variance = 0.0;
  for (std::size_t i = 0; i < kTotalRoundCount; ++i) {
    const auto left_delta = left.state_hamming[i] - left_mean;
    const auto right_delta = right.state_hamming[i] - right_mean;
    covariance += left_delta * right_delta;
    left_variance += left_delta * left_delta;
    right_variance += right_delta * right_delta;
  }
  if (left_variance == 0.0 || right_variance == 0.0) return std::nullopt;
  return covariance / std::sqrt(left_variance * right_variance);
}

nlohmann::json grouped_bits(
    const nlohmann::json& specimens,
    const std::function<std::string(const nlohmann::json&)>& key_function) {
  std::map<std::string, std::vector<unsigned>> groups;
  for (const auto& specimen : specimens) {
    groups[key_function(specimen)].push_back(
        specimen.at("numeric_nonce_bit").get<unsigned>());
  }
  auto result = nlohmann::json::array();
  for (const auto& [key, bits] : groups) {
    result.push_back({{"key", key}, {"bits", bits},
                      {"shared", bits.size() > 1U}});
  }
  return result;
}

nlohmann::json bits_at_extreme(const nlohmann::json& specimens,
                               const std::string& path,
                               bool maximum) {
  unsigned extreme = maximum ? 0U : std::numeric_limits<unsigned>::max();
  std::vector<unsigned> bits;
  for (const auto& specimen : specimens) {
    const auto value = specimen.at("initial_signature").at(path).get<unsigned>();
    if ((maximum && value > extreme) || (!maximum && value < extreme)) {
      extreme = value;
      bits = {specimen.at("numeric_nonce_bit").get<unsigned>()};
    } else if (value == extreme) {
      bits.push_back(specimen.at("numeric_nonce_bit").get<unsigned>());
    }
  }
  return {{"value", extreme}, {"bits", bits}};
}

nlohmann::json diffusion_extreme(const nlohmann::json& specimens,
                                 const std::string& field,
                                 bool maximum) {
  std::optional<unsigned> extreme;
  std::vector<unsigned> bits;
  std::vector<unsigned> not_reached;
  for (const auto& specimen : specimens) {
    const auto& value = specimen.at("diffusion").at(field);
    const auto bit = specimen.at("numeric_nonce_bit").get<unsigned>();
    if (value.is_null()) {
      not_reached.push_back(bit);
      continue;
    }
    const auto round = value.get<unsigned>();
    if (!extreme || (maximum ? round > *extreme : round < *extreme)) {
      extreme = round;
      bits = {bit};
    } else if (round == *extreme) {
      bits.push_back(bit);
    }
  }
  return {{"round", extreme ? nlohmann::json(*extreme) : nlohmann::json(nullptr)},
          {"bits", bits}, {"not_reached", not_reached}};
}

nlohmann::json analyze_families(const nlohmann::json& specimens,
                                const nlohmann::json& pairwise) {
  const auto carry_groups = grouped_bits(specimens, [](const nlohmann::json& item) {
    return item.at("initial_signature").at("round3_T1_carry_diff_mask")
        .get<std::string>();
  });
  const auto hamming_groups = grouped_bits(specimens, [](const nlohmann::json& item) {
    const auto& signature = item.at("initial_signature");
    return std::to_string(signature.at("round3_T1_hamming").get<unsigned>()) + "/" +
           std::to_string(signature.at("round3_new_a_hamming").get<unsigned>()) + "/" +
           std::to_string(signature.at("round3_new_e_hamming").get<unsigned>());
  });
  const auto exact_signature_groups = grouped_bits(
      specimens, [](const nlohmann::json& item) {
        return item.at("initial_signature").at("declared_signature_key")
            .get<std::string>();
      });
  std::vector<unsigned> new_a_amplifies;
  std::vector<unsigned> new_e_amplifies;
  std::vector<unsigned> equal_amplification;
  std::vector<unsigned> ch_masked;
  std::vector<unsigned> maj_masked;
  for (const auto& specimen : specimens) {
    const auto bit = specimen.at("numeric_nonce_bit").get<unsigned>();
    const auto& signature = specimen.at("initial_signature");
    const auto new_a = signature.at("round3_new_a_hamming").get<unsigned>();
    const auto new_e = signature.at("round3_new_e_hamming").get<unsigned>();
    if (new_a > new_e) new_a_amplifies.push_back(bit);
    else if (new_e > new_a) new_e_amplifies.push_back(bit);
    else equal_amplification.push_back(bit);
    if (signature.at("round4_Ch_hamming").get<unsigned>() == 0U) {
      ch_masked.push_back(bit);
    }
    if (signature.at("round4_Maj_hamming").get<unsigned>() == 0U) {
      maj_masked.push_back(bit);
    }
  }

  std::vector<nlohmann::json> unique_pairs;
  for (const auto& item : pairwise) {
    if (item.at("bit_i").get<unsigned>() < item.at("bit_j").get<unsigned>()) {
      unique_pairs.push_back(item);
    }
  }
  std::sort(unique_pairs.begin(), unique_pairs.end(),
            [](const nlohmann::json& left, const nlohmann::json& right) {
    const auto left_mean =
        left.at("mean_hamming_between_state_delta_masks").get<double>();
    const auto right_mean =
        right.at("mean_hamming_between_state_delta_masks").get<double>();
    if (left_mean != right_mean) return left_mean < right_mean;
    const auto left_jaccard = left.at("carry_change_jaccard").get<double>();
    const auto right_jaccard = right.at("carry_change_jaccard").get<double>();
    if (left_jaccard != right_jaccard) return left_jaccard > right_jaccard;
    if (left.at("bit_i") != right.at("bit_i")) {
      return left.at("bit_i").get<unsigned>() < right.at("bit_i").get<unsigned>();
    }
    return left.at("bit_j").get<unsigned>() < right.at("bit_j").get<unsigned>();
  });
  auto most_similar = nlohmann::json::array();
  for (std::size_t i = 0; i < std::min<std::size_t>(5U, unique_pairs.size()); ++i) {
    most_similar.push_back(unique_pairs[i]);
  }
  return {
      {"predeclared_grouping_only", true},
      {"round3_T1_carry_mask_groups", carry_groups},
      {"round3_hamming_triplet_groups", hamming_groups},
      {"exact_initial_signature_groups", exact_signature_groups},
      {"shortest_initial_carry_chain",
       bits_at_extreme(specimens, "round3_T1_carry_longest_run", false)},
      {"longest_initial_carry_chain",
       bits_at_extreme(specimens, "round3_T1_carry_longest_run", true)},
      {"new_a_amplifies_more_than_new_e", new_a_amplifies},
      {"new_e_amplifies_more_than_new_a", new_e_amplifies},
      {"new_a_new_e_equal_hamming", equal_amplification},
      {"round4_Ch_entirely_masked", ch_masked},
      {"round4_Maj_entirely_masked", maj_masked},
      {"fastest_to_HD64", diffusion_extreme(
           specimens, "round_first_state_hamming_ge_64", false)},
      {"slowest_to_HD64", diffusion_extreme(
           specimens, "round_first_state_hamming_ge_64", true)},
      {"fastest_to_HD128", diffusion_extreme(
           specimens, "round_first_state_hamming_ge_128", false)},
      {"slowest_to_HD128", diffusion_extreme(
           specimens, "round_first_state_hamming_ge_128", true)},
      {"five_most_similar_predeclared_pairwise", most_similar}};
}

std::string display_json_value(const nlohmann::json& value) {
  return value.is_null() ? "N/A" : value.dump();
}

std::string shared_groups_markdown(const nlohmann::json& groups) {
  std::ostringstream output;
  bool found = false;
  for (const auto& group : groups) {
    if (!group.at("shared").get<bool>()) continue;
    if (found) output << "; ";
    found = true;
    output << '`' << group.at("key").get<std::string>() << "` → bits "
           << bit_list(group.at("bits"));
  }
  return found ? output.str() : "aucun groupe partagé; toutes les clés sont uniques";
}

std::string unique_group_bits_markdown(const nlohmann::json& groups) {
  auto bits = nlohmann::json::array();
  for (const auto& group : groups) {
    if (!group.at("shared").get<bool>()) {
      for (const auto& bit : group.at("bits")) bits.push_back(bit);
    }
  }
  std::vector<unsigned> sorted = bits.get<std::vector<unsigned>>();
  std::sort(sorted.begin(), sorted.end());
  std::ostringstream output;
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    if (i != 0U) output << ',';
    output << sorted[i];
  }
  return output.str();
}

std::string campaign_markdown(const nlohmann::json& aggregate) {
  const auto& specimens = aggregate.at("specimens");
  const auto& families = aggregate.at("summaries").at("families");
  const auto& global_ch = aggregate.at("transition_histograms").at("Ch_global");
  const auto& global_maj = aggregate.at("transition_histograms").at("Maj_global");
  const auto changed_total = [](const nlohmann::json& histogram) {
    std::uint64_t total = 0U;
    for (const auto& item : histogram) {
      total += item.at("output_changed").get<std::uint64_t>();
    }
    return total;
  };
  const auto same_total = [](const nlohmann::json& histogram) {
    std::uint64_t total = 0U;
    for (const auto& item : histogram) {
      total += item.at("output_same").get<std::uint64_t>();
    }
    return total;
  };
  std::ostringstream out;
  out << "# Campagne white-box des 32 single-bit flips du nonce Genesis\n\n"
      << "Cette campagne est une cartographie déterministe contrôlée. Elle ne démontre "
         "ni biais SHA-256, ni avantage de mining, ni relation avec le target Bitcoin.\n\n"
      << "## Design et validations\n\n"
      << "A est construit une fois. Chaque candidat `A XOR (1 << bit)` est ensuite "
         "tracé, audité, comparé et libéré avant le suivant; seuls les agrégats "
         "compacts sont conservés. Les 32 références cryptographiques sont des "
         "vecteurs fixes produits indépendamment avec Python `hashlib`.\n\n"
      << "- 32 headers de 80 octets, chacun à distance de Hamming exactement 1 de A.\n"
      << "- 32 traces auditables de 3 compressions et 192 rounds.\n"
      << "- Première divergence: `SHA1/compression1/round3` pour les 32 flips.\n"
      << "- 29 952 identités différentielles d'addition validées (936 par flip).\n"
      << "- 21 504 identités XOR Sigma validées (672 par flip).\n"
      << "- Les carries restent des entiers; aucun profil n'est réduit à un booléen.\n\n"
      << "## Mapping bit nonce numérique vers W3\n\n"
      << "La sérialisation little-endian du nonce suivie du décodage SHA big-endian "
         "donne `W3_bit = (3 - numeric_bit/8)*8 + numeric_bit%8`. Ainsi 0..7 → "
         "24..31, 8..15 → 16..23, 16..23 → 8..15 et 24..31 → 0..7.\n\n"
      << "## Tableau des 32 bits\n\n"
      << "| Bit nonce | Bit W3 | Direction | T1 HD r3 | new_a HD r3 | new_e HD r3 | "
         "T1 carry mask r3 | vers 8 registres | vers HD64 | vers HD128 | premier W étendu | hash final HD |\n"
      << "|---:|---:|:---:|---:|---:|---:|---|---:|---:|---:|---:|---:|\n";
  for (const auto& specimen : specimens) {
    const auto& signature = specimen.at("initial_signature");
    const auto& diffusion = specimen.at("diffusion");
    out << "| " << specimen.at("numeric_nonce_bit").get<unsigned>()
        << " | " << specimen.at("W3_bit").get<unsigned>()
        << " | " << signature.at("flip_direction").get<std::string>()
        << " | " << signature.at("round3_T1_hamming").get<unsigned>()
        << " | " << signature.at("round3_new_a_hamming").get<unsigned>()
        << " | " << signature.at("round3_new_e_hamming").get<unsigned>()
        << " | `" << signature.at("round3_T1_carry_diff_mask").get<std::string>()
        << "` | " << display_json_value(diffusion.at("round_first_8_registers_different"))
        << " | " << display_json_value(diffusion.at("round_first_state_hamming_ge_64"))
        << " | " << display_json_value(diffusion.at("round_first_state_hamming_ge_128"))
        << " | " << specimen.at("schedule").at("first_extended_W_that_differs").get<unsigned>()
        << " | " << specimen.at("final").at("final_hash_hamming_vs_A").get<unsigned>()
        << " |\n";
  }
  out << "\n## Carries et familles exactes\n\n"
      << "Les groupes de masque T1 au round 3 sont: "
      << shared_groups_markdown(families.at("round3_T1_carry_mask_groups")) << ".\n\n"
      << "Les bits dont le masque T1 round 3 est un cas unique sont: "
      << unique_group_bits_markdown(families.at("round3_T1_carry_mask_groups"))
      << ".\n\n"
      << "Les groupes partageant le triplet Hamming `T1/new_a/new_e` sont: "
      << shared_groups_markdown(families.at("round3_hamming_triplet_groups")) << ".\n\n"
      << "Les bits dont le triplet Hamming est unique sont: "
      << unique_group_bits_markdown(families.at("round3_hamming_triplet_groups"))
      << ".\n\n"
      << "Signatures initiales complètes partagées: "
      << shared_groups_markdown(families.at("exact_initial_signature_groups"))
      << ". Cas de signature complète uniques: "
      << unique_group_bits_markdown(families.at("exact_initial_signature_groups"))
      << ".\n\n"
      << "Chaîne initiale la plus courte: "
      << families.at("shortest_initial_carry_chain").dump()
      << ". La plus longue: "
      << families.at("longest_initial_carry_chain").dump() << ".\n\n"
      << "Bits où new_a amplifie davantage: "
      << bit_list(families.at("new_a_amplifies_more_than_new_e"))
      << ". Bits où new_e amplifie davantage: "
      << bit_list(families.at("new_e_amplifies_more_than_new_a")) << ".\n\n"
      << "## Diffusion, schedule et modulo 2^k\n\n"
      << "Les jalons utilisent l'index global 0..191 et l'état après round. Les seuils "
         "non atteints sont explicitement `null`/N/A. Le premier W étendu différent "
         "mesuré est W18 pour les 32 flips; W19 conserve exactement le delta modulaire "
         "direct ±2^p. Chaque comparaison W/T1/T2/new_a/new_e/a/e conserve aussi "
         "`common_low_bits`, qui décrit toutes les égalités modulo 2^k de poids faible.\n\n"
      << "## Ch et Maj\n\n"
      << "Les tables 64 transitions `xyz -> x'y'z'` sont comptées bit par bit. Globalement, "
      << "Ch a " << same_total(global_ch) << " sorties inchangées et "
      << changed_total(global_ch) << " sorties changées; Maj en a "
      << same_total(global_maj) << " inchangées et " << changed_total(global_maj)
      << " changées. Ch est entièrement masqué au round 4 pour les bits "
      << bit_list(families.at("round4_Ch_entirely_masked"))
      << "; Maj pour les bits "
      << bit_list(families.at("round4_Maj_entirely_masked")) << ".\n\n"
      << "## Similarité pairwise\n\n"
      << "Les 1 024 paires ordonnées comparent les masques de delta d'état sur les 192 "
         "rounds, l'ensemble `(addition, colonne)` des carries modifiés et, à titre "
         "descriptif, les courbes Hamming. Les rounds ne sont pas des observations "
         "statistiques indépendantes: Pearson n'est ici ni un test d'hypothèse ni une "
         "preuve de biais. Les cinq paires non diagonales les plus proches selon la clé "
         "pré-déclarée `(mean state-mask HD croissant, Jaccard décroissant)` sont: `"
      << families.at("five_most_similar_predeclared_pairwise").dump() << "`.\n\n"
      << "## Baseline B: nonce +1\n\n"
      << "B n'appartient pas aux 32 flips: son header est à distance 2 de A. La baseline "
         "historique validée reste T1 carry bit24 `3 -> 2`, T1 XOR `01000000`, "
         "new_a XOR `01000000`, new_e XOR `0f000000`. Pour le bit0/C, la campagne "
         "reproduit T1 XOR `03000000`, new_a XOR `0f000000`, new_e XOR `01000000` "
         "et le carry bit24 `3 -> 2`.\n\n"
      << "## Limites scientifiques\n\n"
      << "Il s'agit de 32 perturbations déterministes d'un seul header. Les trajectoires "
         "ne forment pas un échantillon aléatoire, les rounds sont dépendants et les "
         "hashes finaux ne justifient aucun classement de bits en ‘meilleur’ ou ‘pire’. "
         "Aucune conclusion sur un biais SHA-256 ou sur le target Bitcoin n'est formulée.\n";
  return out.str();
}

}  // namespace

}  // namespace
