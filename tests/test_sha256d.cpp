#include "crypto/sha256d.h"
#include "test_support.h"

TEST_CASE("SHA256d empty vector") {
  const std::vector<std::uint8_t> empty;
  REQUIRE_EQ(srm::crypto::digest_hex(srm::crypto::sha256d(empty)), "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
}

