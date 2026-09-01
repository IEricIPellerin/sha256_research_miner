//src\crypto\sha256.cpp
#include "crypto/sha256.h"

#include <algorithm>
#include <array>
#include <bit>
#include <stdexcept>

namespace srm::crypto {
namespace {

constexpr std::array<std::uint32_t, 64> kTable{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

constexpr std::array<std::uint32_t, 8> kInitial{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};

std::uint32_t read_be32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24U) |
         (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) |
         static_cast<std::uint32_t>(p[3]);
}

template <bool CollectTrace>
void compress(std::array<std::uint32_t, 8>& state,
              const std::uint8_t* block,
              const unsigned rounds,
              std::vector<Sha256RoundTrace>* round_traces = nullptr,
              const unsigned compression_index = 0) {
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t i = 0; i < 16; ++i) schedule[i] = read_be32(block + i * 4);
  for (std::size_t i = 16; i < schedule.size(); ++i) {
    const auto s0 = std::rotr(schedule[i - 15], 7) ^ std::rotr(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3U);
    const auto s1 = std::rotr(schedule[i - 2], 17) ^ std::rotr(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10U);
    schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
  }

  auto a = state[0]; auto b = state[1]; auto c = state[2]; auto d = state[3];
  auto e = state[4]; auto f = state[5]; auto g = state[6]; auto h = state[7];
  for (unsigned i = 0; i < rounds; ++i) {
    if constexpr (CollectTrace) {
      auto& trace = round_traces->emplace_back();
      trace.compression_index = compression_index;
      trace.round_index = i;
      trace.w = schedule[i];
      trace.a_before = a; trace.b_before = b; trace.c_before = c; trace.d_before = d;
      trace.e_before = e; trace.f_before = f; trace.g_before = g; trace.h_before = h;
    }
    const auto sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
    const auto choice = (e & f) ^ (~e & g);
    const auto temp1 = h + sum1 + choice + kTable[i] + schedule[i];
    const auto sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
    const auto majority = (a & b) ^ (a & c) ^ (b & c);
    const auto temp2 = sum0 + majority;
    h = g; g = f; f = e; e = d + temp1;
    d = c; c = b; b = a; a = temp1 + temp2;
    if constexpr (CollectTrace) {
      auto& trace = round_traces->back();
      trace.sum0 = sum0; trace.sum1 = sum1; trace.choice = choice; trace.majority = majority;
      trace.temp1 = temp1; trace.temp2 = temp2;
      trace.a_after = a; trace.b_after = b; trace.c_after = c; trace.d_after = d;
      trace.e_after = e; trace.f_after = f; trace.g_after = g; trace.h_after = h;
    }
  }

  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

int hex_digit(const char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw std::invalid_argument("invalid hexadecimal character");
}

template <bool CollectTrace>
Digest sha256_impl(const std::span<const std::uint8_t> data,
                   const unsigned rounds,
                   std::vector<Sha256RoundTrace>* round_traces = nullptr) {
  if (rounds < 1 || rounds > 64) throw std::invalid_argument("SHA-256 rounds must be in [1,64]");
  auto state = kInitial;
  unsigned compression_index = 0;
  const auto compress_block = [&](const std::uint8_t* block) {
    if constexpr (CollectTrace) {
      compress<true>(state, block, rounds, round_traces, compression_index++);
    } else {
      compress<false>(state, block, rounds);
    }
  };
  std::size_t offset = 0;
  while (data.size() - offset >= 64) {
    compress_block(data.data() + offset);
    offset += 64;
  }

  std::array<std::uint8_t, 128> tail{};
  const auto remainder = data.size() - offset;
  std::copy_n(data.data() + offset, remainder, tail.data());
  tail[remainder] = 0x80;
  const auto padded_size = remainder < 56 ? 64U : 128U;
  const auto bit_length = static_cast<std::uint64_t>(data.size()) * 8U;
  for (unsigned i = 0; i < 8; ++i) {
    tail[padded_size - 1U - i] = static_cast<std::uint8_t>(bit_length >> (i * 8U));
  }
  compress_block(tail.data());
  if (padded_size == 128) compress_block(tail.data() + 64);

  Digest digest{};
  for (std::size_t i = 0; i < state.size(); ++i) {
    digest[i * 4] = static_cast<std::uint8_t>(state[i] >> 24U);
    digest[i * 4 + 1] = static_cast<std::uint8_t>(state[i] >> 16U);
    digest[i * 4 + 2] = static_cast<std::uint8_t>(state[i] >> 8U);
    digest[i * 4 + 3] = static_cast<std::uint8_t>(state[i]);
  }
  return digest;
}

}  // namespace

Digest sha256_with_rounds(const std::span<const std::uint8_t> data, const unsigned rounds) {
  return sha256_impl<false>(data, rounds);
}

Sha256TraceResult sha256_with_trace(const std::span<const std::uint8_t> data, const unsigned rounds) {
  Sha256TraceResult result;
  result.digest = sha256_impl<true>(data, rounds, &result.rounds);
  return result;
}

Digest sha256(const std::span<const std::uint8_t> data) { return sha256_with_rounds(data, 64); }

std::vector<std::uint8_t> from_hex(const std::string_view hex) {
  if (hex.size() % 2 != 0) throw std::invalid_argument("hexadecimal input must have even length");
  std::vector<std::uint8_t> result(hex.size() / 2);
  for (std::size_t i = 0; i < result.size(); ++i) {
    result[i] = static_cast<std::uint8_t>((hex_digit(hex[i * 2]) << 4) | hex_digit(hex[i * 2 + 1]));
  }
  return result;
}

std::string to_hex(const std::span<const std::uint8_t> bytes) {
  constexpr char alphabet[] = "0123456789abcdef";
  std::string result(bytes.size() * 2, '0');
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    result[i * 2] = alphabet[bytes[i] >> 4U];
    result[i * 2 + 1] = alphabet[bytes[i] & 0x0fU];
  }
  return result;
}

std::string digest_hex(const Digest& digest) { return to_hex(digest); }

std::string bitcoin_hash_hex(const Digest& digest) {
  Digest reversed{};
  std::reverse_copy(digest.begin(), digest.end(), reversed.begin());
  return to_hex(reversed);
}

}  // namespace srm::crypto
