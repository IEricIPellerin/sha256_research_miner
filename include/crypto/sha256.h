//include\crypto\sha256.h
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

struct Sha256RoundTrace {
  unsigned compression_index;
  unsigned round_index;

  std::uint32_t w;
  std::uint32_t sum0;
  std::uint32_t sum1;
  std::uint32_t choice;
  std::uint32_t majority;
  std::uint32_t temp1;
  std::uint32_t temp2;

  std::uint32_t a_before;
  std::uint32_t b_before;
  std::uint32_t c_before;
  std::uint32_t d_before;
  std::uint32_t e_before;
  std::uint32_t f_before;
  std::uint32_t g_before;
  std::uint32_t h_before;

  std::uint32_t a_after;
  std::uint32_t b_after;
  std::uint32_t c_after;
  std::uint32_t d_after;
  std::uint32_t e_after;
  std::uint32_t f_after;
  std::uint32_t g_after;
  std::uint32_t h_after;
};

struct Sha256TraceResult {
  Digest digest;
  std::vector<Sha256RoundTrace> rounds;
};

Digest sha256(std::span<const std::uint8_t> data);
Digest sha256_with_rounds(std::span<const std::uint8_t> data, unsigned rounds);
Sha256TraceResult sha256_with_trace(std::span<const std::uint8_t> data, unsigned rounds);

std::vector<std::uint8_t> from_hex(std::string_view hex);
std::string to_hex(std::span<const std::uint8_t> bytes);
std::string digest_hex(const Digest& digest);
std::string bitcoin_hash_hex(const Digest& digest);

}  // namespace srm::crypto
