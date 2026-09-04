//src\bitcoin\difficulty.cpp
#include "bitcoin/difficulty.h"

#include "crypto/sha256.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace srm::bitcoin {
namespace {

struct Big384 {
  std::array<std::uint32_t, 12> limbs{};  // little-endian limbs
};

Big384 from_target(const Target256& target) {
  Big384 value{};
  for (std::size_t byte = 0; byte < 32; ++byte) {
    const auto little_index = 31 - byte;
    value.limbs[little_index / 4] |= static_cast<std::uint32_t>(target.big_endian[byte]) << ((little_index % 4) * 8U);
  }
  return value;
}

void shift_left(Big384& value, unsigned bits) {
  while (bits-- > 0) {
    std::uint32_t carry = 0;
    for (auto& limb : value.limbs) {
      const auto next = limb >> 31U;
      limb = (limb << 1U) | carry;
      carry = next;
    }
  }
}

void shift_right(Big384& value, unsigned bits) {
  while (bits-- > 0) {
    std::uint32_t carry = 0;
    for (std::size_t i = value.limbs.size(); i-- > 0;) {
      const auto next = value.limbs[i] & 1U;
      value.limbs[i] = (value.limbs[i] >> 1U) | (carry << 31U);
      carry = next;
    }
  }
}

Big384 divide(const Big384& numerator, const std::uint64_t denominator) {
  Big384 quotient{};
  std::uint64_t remainder = 0;
  for (std::size_t bit = 384; bit-- > 0;) {
    remainder = (remainder << 1U) | ((numerator.limbs[bit / 32] >> (bit % 32)) & 1U);
    if (remainder >= denominator) {
      remainder -= denominator;
      quotient.limbs[bit / 32] |= std::uint32_t{1} << (bit % 32);
    }
  }
  return quotient;
}

Target256 lower_target(const Big384& value) {
  for (std::size_t i = 8; i < value.limbs.size(); ++i) {
    if (value.limbs[i] != 0) {
      Target256 maximum{};
      maximum.big_endian.fill(0xff);
      return maximum;
    }
  }
  Target256 target{};
  for (std::size_t little_index = 0; little_index < 32; ++little_index) {
    target.big_endian[31 - little_index] = static_cast<std::uint8_t>(
        value.limbs[little_index / 4] >> ((little_index % 4) * 8U));
  }
  return target;
}

}  // namespace

Target256 target_from_nbits(const std::string_view nbits_hex) {
  const auto compact = crypto::from_hex(nbits_hex);
  if (compact.size() != 4) throw std::invalid_argument("nBits must contain exactly four bytes");
  if ((compact[1] & 0x80U) != 0) throw std::invalid_argument("negative compact targets are invalid");
  const unsigned exponent = compact[0];
  const std::array<std::uint8_t, 3> mantissa{compact[1], compact[2], compact[3]};
  Target256 result{};
  if (exponent == 0) return result;
  if (exponent <= 3) {
    const auto used = exponent;
    for (unsigned i = 0; i < used; ++i) result.big_endian[32 - used + i] = mantissa[i];
  } else {
    if (exponent > 32) throw std::invalid_argument("nBits target overflows 256 bits");
    const auto start = 32U - exponent;
    for (unsigned i = 0; i < 3; ++i) result.big_endian[start + i] = mantissa[i];
  }
  return result;
}

Target256 target_from_hex(const std::string_view target_hex_value) {
  const auto bytes = crypto::from_hex(target_hex_value);
  if (bytes.size() != 32) throw std::invalid_argument("target must contain exactly 32 bytes");
  Target256 target{};
  std::copy(bytes.begin(), bytes.end(), target.big_endian.begin());
  return target;
}

Target256 share_target_from_difficulty(const double difficulty) {
  if (!std::isfinite(difficulty) || difficulty <= 0.0) throw std::invalid_argument("share difficulty must be finite and positive");
  auto numerator = from_target(target_from_hex("00000000ffff0000000000000000000000000000000000000000000000000000"));

  int exponent = 0;
  const auto fraction = std::frexp(difficulty, &exponent);
  constexpr int mantissa_bits = 53;
  const auto mantissa = static_cast<std::uint64_t>(std::ldexp(fraction, mantissa_bits));
  const int shift = mantissa_bits - exponent;
  if (shift >= 0) shift_left(numerator, static_cast<unsigned>(shift));
  else shift_right(numerator, static_cast<unsigned>(-shift));
  return lower_target(divide(numerator, mantissa));
}

std::string target_hex(const Target256& target) { return crypto::to_hex(target.big_endian); }

bool hash_meets_target(const crypto::Digest& digest, const Target256& target) {
  // Bitcoin interprets the raw SHA-256 digest as a little-endian uint256.
  for (std::size_t i = 0; i < 32; ++i) {
    const auto hash_byte = digest[31 - i];
    if (hash_byte < target.big_endian[i]) return true;
    if (hash_byte > target.big_endian[i]) return false;
  }
  return true;
}

double difficulty_from_target(const Target256& target) {
  const auto diff1 = target_from_hex(
      "00000000ffff0000000000000000000000000000000000000000000000000000");
  long double numerator = 0.0L;
  long double denominator = 0.0L;
  for (std::size_t i = 0; i < 32; ++i) {
    numerator = numerator * 256.0L + diff1.big_endian[i];
    denominator = denominator * 256.0L + target.big_endian[i];
  }
  if (denominator == 0.0L) return std::numeric_limits<double>::infinity();
  return static_cast<double>(numerator / denominator);
}

double difficulty_from_hash(const crypto::Digest& digest) {
  Target256 hash_value{};
  for (std::size_t i = 0; i < digest.size(); ++i) {
    hash_value.big_endian[i] = digest[digest.size() - 1U - i];
  }
  return difficulty_from_target(hash_value);
}

}  // namespace srm::bitcoin
