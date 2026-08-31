//tests\test_genesis_block.cpp
#include "bitcoin/block_header.h"
#include "crypto/sha256d.h"
#include "test_support.h"

TEST_CASE("Bitcoin Genesis header and displayed hash") {
  const auto bytes = srm::crypto::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
  srm::bitcoin::Header header{};
  std::copy(bytes.begin(), bytes.end(), header.begin());
  REQUIRE_EQ(srm::bitcoin::get_nonce(header), 2083236893U);
  REQUIRE_EQ(srm::crypto::bitcoin_hash_hex(srm::crypto::sha256d(header)), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
}

