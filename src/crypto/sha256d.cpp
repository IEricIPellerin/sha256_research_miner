//src\crypto\sha256d.cpp
#include "crypto/sha256d.h"

namespace srm::crypto {

Digest sha256d(const std::span<const std::uint8_t> data) {
  const auto first = sha256(data);
  return sha256(first);
}

Digest sha256d_with_rounds(const std::span<const std::uint8_t> data, const unsigned rounds) {
  const auto first = sha256_with_rounds(data, rounds);
  return sha256_with_rounds(first, rounds);
}

}  // namespace srm::crypto

