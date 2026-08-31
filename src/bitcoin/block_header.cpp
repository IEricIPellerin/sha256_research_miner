//src\bitcoin\block_header.cpp
#include "bitcoin/block_header.h"

#include "crypto/sha256.h"

#include <algorithm>
#include <stdexcept>

namespace srm::bitcoin {
namespace {

void copy_reversed_dword(const std::vector<std::uint8_t>& source, std::uint8_t* destination) {
  if (source.size() != 4) throw std::invalid_argument("header dword must be exactly four bytes");
  std::reverse_copy(source.begin(), source.end(), destination);
}

}  // namespace

Header build_stratum_header(const std::string_view version_hex,
                            const std::string_view prevhash_hex,
                            const crypto::Digest& merkle_root,
                            const std::string_view ntime_hex,
                            const std::string_view nbits_hex,
                            const std::uint32_t nonce) {
  const auto version = crypto::from_hex(version_hex);
  const auto prevhash = crypto::from_hex(prevhash_hex);
  const auto ntime = crypto::from_hex(ntime_hex);
  const auto nbits = crypto::from_hex(nbits_hex);
  if (prevhash.size() != 32) throw std::invalid_argument("Stratum prevhash must contain 32 bytes");

  Header header{};
  copy_reversed_dword(version, header.data());
  // CKPool publishes prevhash in Stratum word-reversed form. Reverse bytes
  // inside each 32-bit word to obtain the serialized header field.
  for (std::size_t word = 0; word < 8; ++word) {
    std::reverse_copy(prevhash.begin() + static_cast<std::ptrdiff_t>(word * 4),
                      prevhash.begin() + static_cast<std::ptrdiff_t>(word * 4 + 4),
                      header.begin() + static_cast<std::ptrdiff_t>(4 + word * 4));
  }
  std::copy(merkle_root.begin(), merkle_root.end(), header.begin() + 36);
  copy_reversed_dword(ntime, header.data() + 68);
  copy_reversed_dword(nbits, header.data() + 72);
  set_nonce(header, nonce);
  return header;
}

void set_nonce(Header& header, const std::uint32_t nonce) {
  header[76] = static_cast<std::uint8_t>(nonce);
  header[77] = static_cast<std::uint8_t>(nonce >> 8U);
  header[78] = static_cast<std::uint8_t>(nonce >> 16U);
  header[79] = static_cast<std::uint8_t>(nonce >> 24U);
}

std::uint32_t get_nonce(const Header& header) {
  return static_cast<std::uint32_t>(header[76]) |
         (static_cast<std::uint32_t>(header[77]) << 8U) |
         (static_cast<std::uint32_t>(header[78]) << 16U) |
         (static_cast<std::uint32_t>(header[79]) << 24U);
}

std::string header_hex(const Header& header) { return crypto::to_hex(header); }

}  // namespace srm::bitcoin

