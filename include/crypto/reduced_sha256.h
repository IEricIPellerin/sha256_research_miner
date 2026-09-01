//include\crypto\reduced_sha256.h
#pragma once

#include "crypto/sha256.h"

namespace srm::crypto {

// Each SHA-256 compression call executes exactly the first N rounds.
// N=64 is byte-for-byte identical to standard SHA-256.
Digest reduced_sha256(std::span<const std::uint8_t> data, unsigned rounds);
Digest reduced_sha256d(std::span<const std::uint8_t> data, unsigned rounds);

struct ReducedSha256dTrace {
  Digest digest;
  Sha256TraceResult first_sha;
  Sha256TraceResult second_sha;
};

ReducedSha256dTrace trace_reduced_sha256d(std::span<const std::uint8_t> data, unsigned rounds);

unsigned hamming_weight(const Digest& value);
unsigned hamming_distance(const Digest& left, const Digest& right);

}  // namespace srm::crypto
