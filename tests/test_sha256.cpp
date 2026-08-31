#include "crypto/reduced_sha256.h"
#include "crypto/sha256.h"
#include "test_support.h"

#include <string>

TEST_CASE("SHA-256 official empty vector") {
  const std::vector<std::uint8_t> empty;
  REQUIRE_EQ(srm::crypto::digest_hex(srm::crypto::sha256(empty)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("SHA-256 official abc vector") {
  const std::string text = "abc";
  const auto bytes = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
  REQUIRE_EQ(srm::crypto::digest_hex(srm::crypto::sha256(bytes)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("reduced SHA-256 N=64 equals reference") {
  const auto bytes = srm::crypto::from_hex("00010203040506070809");
  REQUIRE_EQ(srm::crypto::reduced_sha256(bytes, 64), srm::crypto::sha256(bytes));
}

