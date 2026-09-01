//tests\test_genesis_block.cpp
#include "bitcoin/block_header.h"
#include "crypto/reduced_sha256.h"
#include "crypto/sha256d.h"
#include "test_support.h"

TEST_CASE("Bitcoin Genesis header and displayed hash") {
  const auto bytes = srm::crypto::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
  srm::bitcoin::Header header{};
  std::copy(bytes.begin(), bytes.end(), header.begin());
  REQUIRE_EQ(srm::bitcoin::get_nonce(header), 2083236893U);
  REQUIRE_EQ(srm::crypto::bitcoin_hash_hex(srm::crypto::sha256d(header)), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

  const auto trace = srm::crypto::trace_reduced_sha256d(header, 64);
  REQUIRE_EQ(trace.digest, srm::crypto::sha256d(header));
  REQUIRE_EQ(trace.first_sha.rounds.size(), 128U);
  REQUIRE_EQ(trace.second_sha.rounds.size(), 64U);
  REQUIRE_EQ(trace.first_sha.rounds.size() + trace.second_sha.rounds.size(), 192U);
  for (std::size_t i = 0; i < trace.first_sha.rounds.size(); ++i) {
    REQUIRE_EQ(trace.first_sha.rounds[i].compression_index, i / 64U);
    REQUIRE_EQ(trace.first_sha.rounds[i].round_index, i % 64U);
  }
  for (std::size_t i = 0; i < trace.second_sha.rounds.size(); ++i) {
    REQUIRE_EQ(trace.second_sha.rounds[i].compression_index, 0U);
    REQUIRE_EQ(trace.second_sha.rounds[i].round_index, i);
  }
  REQUIRE_EQ(srm::crypto::bitcoin_hash_hex(trace.digest), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
}
