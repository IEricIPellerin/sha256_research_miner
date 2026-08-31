#include "bitcoin/merkle.h"
#include "crypto/sha256d.h"
#include "test_support.h"

TEST_CASE("Merkle branches are combined in supplied order") {
  const auto leaf = srm::crypto::sha256d(srm::crypto::from_hex("00"));
  const auto branch1 = srm::crypto::sha256d(srm::crypto::from_hex("01"));
  const auto branch2 = srm::crypto::sha256d(srm::crypto::from_hex("02"));
  std::array<std::uint8_t, 64> pair{};
  std::copy(leaf.begin(), leaf.end(), pair.begin());
  std::copy(branch1.begin(), branch1.end(), pair.begin() + 32);
  const auto first = srm::crypto::sha256d(pair);
  std::copy(first.begin(), first.end(), pair.begin());
  std::copy(branch2.begin(), branch2.end(), pair.begin() + 32);
  const auto expected = srm::crypto::sha256d(pair);
  REQUIRE_EQ(srm::bitcoin::build_merkle_root(leaf, {srm::crypto::digest_hex(branch1), srm::crypto::digest_hex(branch2)}), expected);
}

