//include\bitcoin\block_header.h
#pragma once

#include "crypto/sha256.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace srm::bitcoin {

using Header = std::array<std::uint8_t, 80>;

Header build_stratum_header(std::string_view version_hex,
                            std::string_view prevhash_hex,
                            const crypto::Digest& merkle_root,
                            std::string_view ntime_hex,
                            std::string_view nbits_hex,
                            std::uint32_t nonce);
void set_nonce(Header& header, std::uint32_t nonce);
std::uint32_t get_nonce(const Header& header);
std::string header_hex(const Header& header);

}  // namespace srm::bitcoin

