//tests\test_sha256d_whitebox.cpp
#include "research/sha256d_whitebox.h"
#include "test_support.h"

#include <cstdint>
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
