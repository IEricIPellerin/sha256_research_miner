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

}  // namespace

TEST_CASE("Genesis SHA256d exhaustive white-box trace is canonical and independently auditable") {
  const auto artifacts = srm::research::whitebox::build_genesis_sha256d_whitebox();
  const auto& trace = artifacts.trace;
  REQUIRE_EQ(trace.at("input").at("header_byte_length").get<std::size_t>(), 80U);
  REQUIRE_EQ(trace.at("sha256_first").at("compressions").size(), 2U);
  REQUIRE_EQ(trace.at("sha256_second").at("compressions").size(), 1U);
  REQUIRE_EQ(total_rounds(trace), 192U);

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
