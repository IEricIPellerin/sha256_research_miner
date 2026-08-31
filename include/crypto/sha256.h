#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace srm::crypto {

using Digest = std::array<std::uint8_t, 32>;

Digest sha256(std::span<const std::uint8_t> data);
Digest sha256_with_rounds(std::span<const std::uint8_t> data, unsigned rounds);

std::vector<std::uint8_t> from_hex(std::string_view hex);
std::string to_hex(std::span<const std::uint8_t> bytes);
std::string digest_hex(const Digest& digest);
std::string bitcoin_hash_hex(const Digest& digest);

}  // namespace srm::crypto

