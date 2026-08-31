//tests\test_target.cpp
#include "bitcoin/difficulty.h"
#include "test_support.h"

TEST_CASE("nBits difficulty-one conversion is exact") {
  REQUIRE_EQ(srm::bitcoin::target_hex(srm::bitcoin::target_from_nbits("1d00ffff")), "00000000ffff0000000000000000000000000000000000000000000000000000");
}

TEST_CASE("share difficulty one target is exact") {
  REQUIRE_EQ(srm::bitcoin::target_hex(srm::bitcoin::share_target_from_difficulty(1.0)), "00000000ffff0000000000000000000000000000000000000000000000000000");
}

TEST_CASE("target comparison uses Bitcoin little-endian hash semantics") {
  auto target = srm::bitcoin::target_from_hex("0000000000000000000000000000000000000000000000000000000000000001");
  srm::crypto::Digest one{};
  one[0] = 1;  // reversed display value is ...0001
  REQUIRE(srm::bitcoin::hash_meets_target(one, target));
  one[0] = 2;
  REQUIRE(!srm::bitcoin::hash_meets_target(one, target));
}

