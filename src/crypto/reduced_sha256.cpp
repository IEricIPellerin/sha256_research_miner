#include "crypto/reduced_sha256.h"

#include "crypto/sha256d.h"

#include <bit>

namespace srm::crypto {

Digest reduced_sha256(const std::span<const std::uint8_t> data, const unsigned rounds) {
  return sha256_with_rounds(data, rounds);
}

Digest reduced_sha256d(const std::span<const std::uint8_t> data, const unsigned rounds) {
  return sha256d_with_rounds(data, rounds);
}

unsigned hamming_weight(const Digest& value) {
  unsigned total = 0;
  for (const auto byte : value) total += std::popcount(byte);
  return total;
}

unsigned hamming_distance(const Digest& left, const Digest& right) {
  unsigned total = 0;
  for (std::size_t i = 0; i < left.size(); ++i) total += std::popcount(static_cast<unsigned>(left[i] ^ right[i]));
  return total;
}

}  // namespace srm::crypto

