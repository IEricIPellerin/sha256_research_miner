//tests\test_sha256d_whitebox.cpp
#include "research/sha256d_whitebox.h"
#include "crypto/sha256.h"
#include "test_support.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

std::size_t total_rounds(const nlohmann::json& trace) {
  std::size_t count = 0;
  for (const auto& compression : trace.at("sha256_first").at("compressions")) {
    count += compression.at("rounds").size();
  }
  for (const auto& compression : trace.at("sha256_second").at("compressions")) {
    count += compression.at("rounds").size();
  }
  return count;
}

void require_exhaustive_shape(const nlohmann::json& trace) {
  REQUIRE_EQ(trace.at("input").at("header_byte_length").get<std::size_t>(), 80U);
  REQUIRE_EQ(trace.at("sha256_first").at("compressions").size(), 2U);
  REQUIRE_EQ(trace.at("sha256_second").at("compressions").size(), 1U);
  REQUIRE_EQ(total_rounds(trace), 192U);
  const auto verify_compression = [](const nlohmann::json& compression) {
    REQUIRE_EQ(compression.at("rounds").size(), 64U);
    REQUIRE_EQ(compression.at("message_schedule").at("words").size(), 64U);
    REQUIRE_EQ(compression.at("feed_forward").size(), 8U);
    std::size_t addition_count = 0;
    for (std::size_t t = 16; t < 64; ++t) {
      REQUIRE_EQ(compression.at("message_schedule").at("words").at(t)
                     .at("addition").at("bit_columns_lsb_to_msb").size(), 32U);
      ++addition_count;
    }
    for (const auto& round : compression.at("rounds")) {
      for (const auto* name : {"T1", "T2", "new_a", "new_e"}) {
        REQUIRE_EQ(round.at("additions").at(name)
                       .at("bit_columns_lsb_to_msb").size(), 32U);
        ++addition_count;
      }
    }
    for (const auto& feed_forward : compression.at("feed_forward")) {
      REQUIRE_EQ(feed_forward.at("addition").at("bit_columns_lsb_to_msb").size(), 32U);
      ++addition_count;
    }
    REQUIRE_EQ(addition_count, 312U);
  };
  for (const auto& compression : trace.at("sha256_first").at("compressions")) {
    verify_compression(compression);
  }
  for (const auto& compression : trace.at("sha256_second").at("compressions")) {
    verify_compression(compression);
  }
}

std::size_t csv_data_rows(const std::string& csv) {
  const auto lines = static_cast<std::size_t>(
      std::count(csv.begin(), csv.end(), '\n'));
  REQUIRE(lines >= 1U);
  return lines - 1U;
}

}  // namespace

TEST_CASE("Genesis SHA256d exhaustive white-box trace is canonical and independently auditable") {
  const auto artifacts = srm::research::whitebox::build_genesis_sha256d_whitebox();
  const auto& trace = artifacts.trace;
  require_exhaustive_shape(trace);

  for (const auto& compression : trace.at("sha256_first").at("compressions")) {
    REQUIRE_EQ(compression.at("rounds").size(), 64U);
    REQUIRE_EQ(compression.at("message_schedule").at("words").size(), 64U);
    REQUIRE_EQ(compression.at("feed_forward").size(), 8U);
  }
  for (const auto& compression : trace.at("sha256_second").at("compressions")) {
    REQUIRE_EQ(compression.at("rounds").size(), 64U);
    REQUIRE_EQ(compression.at("message_schedule").at("words").size(), 64U);
    REQUIRE_EQ(compression.at("feed_forward").size(), 8U);
  }

  const auto audit = srm::research::whitebox::validate_genesis_sha256d_whitebox(trace);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "passed");
  REQUIRE(audit.at("extended_schedules_reconstructed").get<bool>());
  REQUIRE(audit.at("round_primitives_recomputed").get<bool>());
  REQUIRE(audit.at("round_additions_recomputed").get<bool>());
  REQUIRE(audit.at("round_transfers_recomputed").get<bool>());
  REQUIRE(audit.at("feed_forwards_recomputed").get<bool>());
  REQUIRE(audit.at("all_carry_columns_reconstructed").get<bool>());
  REQUIRE(audit.at("all_modulo_projections_recomputed").get<bool>());
  REQUIRE(audit.at("multi_operand_carry_above_one_observed").get<bool>());
  REQUIRE_EQ(trace.at("final").at("bitcoin_display_hash").get<std::string>(),
             "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

  bool observed_integer_carry_above_one = false;
  for (const auto& compression : trace.at("sha256_first").at("compressions")) {
    for (const auto& round : compression.at("rounds")) {
      const auto& columns = round.at("additions").at("T1").at("bit_columns_lsb_to_msb");
      for (const auto& column : columns) {
        observed_integer_carry_above_one = observed_integer_carry_above_one ||
            column.at("carry_out").get<std::uint64_t>() > 1U;
      }
    }
  }
  REQUIRE(observed_integer_carry_above_one);
  REQUIRE(artifacts.summary_markdown.find("## All 192 rounds") != std::string::npos);
}

TEST_CASE("Genesis nonce plus one SHA256d white-box trace matches independent vectors") {
  const auto artifacts =
      srm::research::whitebox::build_genesis_nonce_plus_one_sha256d_whitebox();
  const auto& trace = artifacts.trace;
  require_exhaustive_shape(trace);
  REQUIRE_EQ(trace.at("input").at("header_hex").get<std::string>(),
      "0100000000000000000000000000000000000000000000000000000000000000"
      "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
      "4b1e5e4a29ab5f49ffff001d1eac2b7c");
  REQUIRE_EQ(trace.at("input").at("fields").at("nonce").at("uint32").get<std::uint32_t>(),
             2083236894U);
  REQUIRE_EQ(trace.at("input").at("fields").at("nonce")
                 .at("serialized_little_endian_hex").get<std::string>(), "1eac2b7c");
  REQUIRE_EQ(trace.at("sha256_first").at("compressions").at(1)
                 .at("message_schedule").at("words").at(3)
                 .at("result").at("hex").get<std::string>(), "1eac2b7c");
  REQUIRE_EQ(trace.at("sha256_first").at("output").at("digest_hex").get<std::string>(),
             "3f20e97bd2b9a79c76c6d8ec16883a3071fc8cf072ecf49ea9c66b7a510d4674");
  REQUIRE_EQ(trace.at("final").at("raw_sha256d").get<std::string>(),
             "1c1ba4714930063bebadce0a323e51d097775dbc444187e6ba0caa5d4a7a229b");
  REQUIRE_EQ(trace.at("final").at("bitcoin_display_hash").get<std::string>(),
             "9b227a4a5daa0cbae6874144bc5d7797d0513e320aceadeb3b06304971a41b1c");
  const auto audit =
      srm::research::whitebox::validate_genesis_nonce_plus_one_sha256d_whitebox(trace);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "passed");
  REQUIRE_EQ(audit.at("compression_count").get<std::size_t>(), 3U);
  REQUIRE_EQ(audit.at("total_round_count").get<std::size_t>(), 192U);
  REQUIRE_EQ(audit.at("total_schedule_word_count").get<std::size_t>(), 192U);
  REQUIRE(audit.at("all_carry_columns_reconstructed").get<bool>());
  REQUIRE(audit.at("all_modulo_projections_recomputed").get<bool>());
}

TEST_CASE("Genesis A/B first divergence and bit-24 T1 carry are exact") {
  const auto genesis = srm::research::whitebox::build_genesis_sha256d_whitebox();
  const auto nonce_plus_one =
      srm::research::whitebox::build_genesis_nonce_plus_one_sha256d_whitebox();
  const auto audit = srm::research::whitebox::validate_genesis_nonce_plus_one_invariants(
      genesis.trace, nonce_plus_one.trace);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "passed");
  REQUIRE_EQ(audit.at("first_divergence").get<std::string>(),
             "SHA1/compression1/round3");
  REQUIRE_EQ(audit.at("header_hamming_distance_bits").get<unsigned>(), 2U);
  REQUIRE_EQ(audit.at("round3_W_a").get<std::string>(), "1dac2b7c");
  REQUIRE_EQ(audit.at("round3_W_b").get<std::string>(), "1eac2b7c");
  REQUIRE_EQ(audit.at("T1_carry_bit24_a").get<unsigned>(), 3U);
  REQUIRE_EQ(audit.at("T1_carry_bit24_b").get<unsigned>(), 2U);
}

TEST_CASE("Genesis nonce bit 0 flip SHA256d white-box trace matches independent vectors") {
  const auto artifacts =
      srm::research::whitebox::build_genesis_nonce_bit0_flip_sha256d_whitebox();
  const auto& trace = artifacts.trace;
  require_exhaustive_shape(trace);
  REQUIRE_EQ(trace.at("input").at("header_hex").get<std::string>(),
      "0100000000000000000000000000000000000000000000000000000000000000"
      "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
      "4b1e5e4a29ab5f49ffff001d1cac2b7c");
  REQUIRE_EQ(trace.at("input").at("fields").at("nonce").at("uint32")
                 .get<std::uint32_t>(), 2083236892U);
  REQUIRE_EQ(trace.at("input").at("fields").at("nonce")
                 .at("serialized_little_endian_hex").get<std::string>(), "1cac2b7c");
  REQUIRE_EQ(trace.at("sha256_first").at("compressions").at(1)
                 .at("message_schedule").at("words").at(3)
                 .at("result").at("hex").get<std::string>(), "1cac2b7c");
  REQUIRE_EQ(trace.at("sha256_first").at("output").at("digest_hex").get<std::string>(),
             "b0bded2df03b40f384c981e5b750ad0ccf562554b23c0187bb162ba093bc3dfc");
  REQUIRE_EQ(trace.at("final").at("raw_sha256d").get<std::string>(),
             "d9665d1c88b5bf70b741453c4a78c9fe36a537659ad0e7fab087cac13d34dc8c");
  REQUIRE_EQ(trace.at("final").at("bitcoin_display_hash").get<std::string>(),
             "8cdc343dc1ca87b0fae7d09a6537a536fec9784a3c4541b770bfb5881c5d66d9");
  const auto audit =
      srm::research::whitebox::validate_genesis_nonce_bit0_flip_sha256d_whitebox(trace);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "passed");
  REQUIRE_EQ(audit.at("compression_count").get<std::size_t>(), 3U);
  REQUIRE_EQ(audit.at("total_round_count").get<std::size_t>(), 192U);
  REQUIRE_EQ(audit.at("total_schedule_word_count").get<std::size_t>(), 192U);
  REQUIRE(audit.at("all_carry_columns_reconstructed").get<bool>());
  REQUIRE(audit.at("all_modulo_projections_recomputed").get<bool>());
}

TEST_CASE("Genesis A/C single-bit first divergence and bit-24 T1 carry are exact") {
  const auto genesis = srm::research::whitebox::build_genesis_sha256d_whitebox();
  const auto nonce_bit0_flip =
      srm::research::whitebox::build_genesis_nonce_bit0_flip_sha256d_whitebox();
  const auto audit = srm::research::whitebox::validate_genesis_nonce_bit0_flip_invariants(
      genesis.trace, nonce_bit0_flip.trace);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "passed");
  REQUIRE_EQ(audit.at("first_divergence").get<std::string>(),
             "SHA1/compression1/round3");
  REQUIRE_EQ(audit.at("header_hamming_distance_bits").get<unsigned>(), 1U);
  REQUIRE_EQ(audit.at("differing_header_byte_indices").get<std::vector<std::size_t>>(),
             std::vector<std::size_t>{76U});
  REQUIRE_EQ(audit.at("round3_W_a").get<std::string>(), "1dac2b7c");
  REQUIRE_EQ(audit.at("round3_W_c").get<std::string>(), "1cac2b7c");
  REQUIRE_EQ(audit.at("modular_deltas").at("W").get<std::string>(), "ff000000");
  REQUIRE_EQ(audit.at("xor_deltas").at("W").get<std::string>(), "01000000");
  REQUIRE_EQ(audit.at("xor_deltas").at("T1").get<std::string>(), "03000000");
  REQUIRE_EQ(audit.at("xor_deltas").at("new_a").get<std::string>(), "0f000000");
  REQUIRE_EQ(audit.at("xor_deltas").at("new_e").get<std::string>(), "01000000");
  REQUIRE_EQ(audit.at("T1_differing_carry_columns").get<std::vector<unsigned>>(),
             std::vector<unsigned>{24U});
  REQUIRE_EQ(audit.at("T1_carry_bit24_a").get<unsigned>(), 3U);
  REQUIRE_EQ(audit.at("T1_carry_bit24_c").get<unsigned>(), 2U);
  REQUIRE(audit.at("T1_carry_bit25_equal").get<bool>());
}

TEST_CASE("All numeric nonce bits map exactly to serialized SHA W3 bits") {
  for (unsigned numeric_bit = 0U; numeric_bit < 32U; ++numeric_bit) {
    const auto expected =
        (3U - numeric_bit / 8U) * 8U + numeric_bit % 8U;
    REQUIRE_EQ(
        srm::research::whitebox::numeric_nonce_bit_to_w3_bit(numeric_bit),
        expected);
  }
  bool rejected = false;
  try {
    (void)srm::research::whitebox::numeric_nonce_bit_to_w3_bit(32U);
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  REQUIRE(rejected);
}

TEST_CASE("Genesis 32-bit nonce campaign is exhaustive compact and auditable") {
  unsigned progress_calls = 0U;
  const auto artifacts =
      srm::research::whitebox::build_genesis_nonce_single_bit_campaign(
          [&](const unsigned bit) {
            REQUIRE_EQ(bit, progress_calls);
            ++progress_calls;
          });
  REQUIRE_EQ(progress_calls, 32U);
  const auto& aggregate = artifacts.aggregate;
  const auto audit =
      srm::research::whitebox::validate_genesis_nonce_single_bit_campaign(
          aggregate);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "passed");
  REQUIRE_EQ(aggregate.at("specimens").size(), 32U);
  REQUIRE_EQ(aggregate.at("reference_vectors").size(), 32U);
  REQUIRE_EQ(aggregate.at("pairwise_metrics").size(), 1024U);
  REQUIRE_EQ(csv_data_rows(artifacts.per_bit_csv), 32U);
  REQUIRE_EQ(csv_data_rows(artifacts.per_round_csv), 6144U);
  REQUIRE_EQ(csv_data_rows(artifacts.carry_summary_csv), 29952U);
  REQUIRE_EQ(csv_data_rows(artifacts.pairwise_csv), 1024U);
  REQUIRE(aggregate.at("validations")
              .at("all_modular_addition_differentials_validated").get<bool>());
  REQUIRE(aggregate.at("validations")
              .at("all_sigma_xor_differentials_validated").get<bool>());
  REQUIRE_EQ(aggregate.at("validations")
                 .at("addition_differential_identity_count").get<std::size_t>(),
             29952U);
  REQUIRE_EQ(aggregate.at("validations")
                 .at("sigma_xor_differential_identity_count").get<std::size_t>(),
             21504U);

  const auto& vectors =
      srm::research::whitebox::genesis_nonce_single_bit_reference_vectors();
  for (unsigned bit = 0U; bit < 32U; ++bit) {
    const auto& specimen = aggregate.at("specimens").at(bit);
    REQUIRE_EQ(specimen.at("numeric_nonce_bit").get<unsigned>(), bit);
    REQUIRE_EQ(specimen.at("W3_bit").get<unsigned>(),
               srm::research::whitebox::numeric_nonce_bit_to_w3_bit(bit));
    REQUIRE_EQ(specimen.at("header_hamming_vs_A").get<unsigned>(), 1U);
    REQUIRE_EQ(specimen.at("nonce_uint32").get<std::uint32_t>(),
               vectors[bit].nonce);
    REQUIRE_EQ(specimen.at("W3").get<std::string>(), [&] {
      std::ostringstream value;
      value << std::hex << std::nouppercase << std::setfill('0')
            << std::setw(8) << vectors[bit].w3;
      return value.str();
    }());
    REQUIRE_EQ(specimen.at("final").at("first_sha256").get<std::string>(),
               vectors[bit].first_sha256);
    REQUIRE_EQ(specimen.at("final").at("raw_sha256d").get<std::string>(),
               vectors[bit].raw_sha256d);
    REQUIRE_EQ(specimen.at("final").at("bitcoin_display_hash").get<std::string>(),
               vectors[bit].bitcoin_display_hash);
    REQUIRE_EQ(specimen.at("round_comparisons").size(), 192U);
    REQUIRE_EQ(specimen.at("diffusion").at("round_first_divergence")
                   .get<unsigned>(), 67U);
    REQUIRE_EQ(specimen.at("schedule").at("first_extended_W_that_differs")
                   .get<unsigned>(), 18U);
    REQUIRE(specimen.at("schedule").at("W19_direct_modular_relation_validated")
                .get<bool>());
  }

  const auto& bit0 = aggregate.at("specimens").at(0);
  REQUIRE_EQ(bit0.at("nonce_uint32").get<std::uint32_t>(), 2083236892U);
  REQUIRE_EQ(bit0.at("W3_bit").get<unsigned>(), 24U);
  REQUIRE_EQ(bit0.at("W3").get<std::string>(), "1cac2b7c");
  REQUIRE_EQ(bit0.at("round3").at("T1").at("xor").get<std::string>(),
             "03000000");
  REQUIRE_EQ(bit0.at("round3").at("new_a").at("xor").get<std::string>(),
             "0f000000");
  REQUIRE_EQ(bit0.at("round3").at("new_e").at("xor").get<std::string>(),
             "01000000");
  REQUIRE_EQ(bit0.at("round3").at("T1_carry").at("carry_diff_mask_hex")
                 .get<std::string>(), "01000000");
}

TEST_CASE("Generic nonce bit0 builder is exactly historical specimen C") {
  const auto generic =
      srm::research::whitebox::build_genesis_nonce_single_bit_flip_sha256d_whitebox(0U);
  const auto historical =
      srm::research::whitebox::build_genesis_nonce_bit0_flip_sha256d_whitebox();
  REQUIRE_EQ(generic.trace, historical.trace);
  REQUIRE_EQ(generic.summary_markdown, historical.summary_markdown);
}

TEST_CASE("Synthetic Merkle context fixtures and compact transfer smoke campaign are deterministic") {
  const auto& fields =
      srm::research::whitebox::merkle_context_transfer_fields();
  REQUIRE_EQ(fields.size(), 64U);
  REQUIRE_EQ(srm::crypto::to_hex(fields.at(0)),
             "5b46b49fee3d11559452c005790fdc1c4c05826c888353acbbc4e739c6d8181c");
  REQUIRE_EQ(srm::crypto::to_hex(fields.at(63)),
             "f15917d442424a06da2699173c7037468e2ce0482e4da1f54d273b01000a5cc2");

  unsigned progress_calls = 0U;
  const auto artifacts =
      srm::research::whitebox::build_merkle_context_transfer_campaign(
          4U, [&](const unsigned context, const unsigned bit) {
            REQUIRE_EQ(context, progress_calls / 32U);
            REQUIRE_EQ(bit, progress_calls % 32U);
            ++progress_calls;
          });
  REQUIRE_EQ(progress_calls, 128U);
  const auto audit =
      srm::research::whitebox::validate_merkle_context_transfer_campaign(
          artifacts.aggregate, 4U);
  REQUIRE_EQ(audit.at("status").get<std::string>(), "passed");
  REQUIRE_EQ(artifacts.aggregate.at("context_summaries").size(), 4U);
  REQUIRE_EQ(artifacts.aggregate.at("bit_transfer_summaries").size(), 32U);
  REQUIRE_EQ(artifacts.aggregate.at("pairwise_transfer_summaries").size(), 496U);
  REQUIRE_EQ(artifacts.aggregate.at("validations")
                 .at("addition_differential_identity_count").get<std::size_t>(),
             128U * 936U);
  REQUIRE_EQ(artifacts.aggregate.at("validations")
                 .at("sigma_xor_differential_identity_count").get<std::size_t>(),
             128U * 672U);
  REQUIRE_EQ(csv_data_rows(artifacts.contexts_csv), 4U);
  REQUIRE_EQ(csv_data_rows(artifacts.per_context_bit_csv), 128U);
  REQUIRE_EQ(csv_data_rows(artifacts.bit_transfer_summary_csv), 32U);
  REQUIRE_EQ(csv_data_rows(artifacts.direction_effects_csv), 4U);
  REQUIRE_EQ(csv_data_rows(artifacts.per_bit_round_summary_csv), 6144U);
  REQUIRE_EQ(csv_data_rows(artifacts.pairwise_transfer_csv), 496U);
}

TEST_CASE("Genesis white-box audit rejects a corrupted carry column") {
  auto artifacts = srm::research::whitebox::build_genesis_sha256d_whitebox();
  auto& carry = artifacts.trace.at("sha256_first").at("compressions").at(0)
                    .at("rounds").at(0).at("additions").at("T1")
                    .at("bit_columns_lsb_to_msb").at(0).at("carry_out");
  carry = carry.get<std::uint64_t>() + 1U;
  bool rejected = false;
  try {
    (void)srm::research::whitebox::validate_genesis_sha256d_whitebox(artifacts.trace);
  } catch (const std::runtime_error&) {
    rejected = true;
  }
  REQUIRE(rejected);
}
