//include\bitcoin\difficulty.h
#pragma once

#include "crypto/sha256.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace srm::bitcoin {

struct Target256 {
  std::array<std::uint8_t, 32> big_endian{};
};

Target256 target_from_nbits(std::string_view nbits_hex);
Target256 target_from_hex(std::string_view target_hex);
Target256 share_target_from_difficulty(double difficulty);
std::string target_hex(const Target256& target);
bool hash_meets_target(const crypto::Digest& digest, const Target256& target);
double difficulty_from_hash(const crypto::Digest& digest);
double difficulty_from_target(const Target256& target);

}  // namespace srm::bitcoin
