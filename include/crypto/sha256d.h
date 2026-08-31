#pragma once

#include "crypto/sha256.h"

namespace srm::crypto {

Digest sha256d(std::span<const std::uint8_t> data);
Digest sha256d_with_rounds(std::span<const std::uint8_t> data, unsigned rounds);

}  // namespace srm::crypto

