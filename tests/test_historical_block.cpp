#include "bitcoin/block_header.h"
#include "bitcoin/difficulty.h"
#include "crypto/sha256d.h"
#include "test_support.h"

TEST_CASE("Genesis known nonce satisfies compact network target") {
  const auto bytes = srm::crypto::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
  srm::bitcoin::Header header{};
  std::copy(bytes.begin(), bytes.end(), header.begin());
  REQUIRE(srm::bitcoin::hash_meets_target(srm::crypto::sha256d(header), srm::bitcoin::target_from_nbits("1d00ffff")));
}

