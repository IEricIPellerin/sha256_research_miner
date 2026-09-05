//src\research\header_space.cpp
#include "research/header_space.h"

#include "bitcoin/difficulty.h"
#include "crypto/sha256d.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace srm::research::header_space {
namespace {

std::uint32_t read_le32(const std::uint8_t* bytes) {
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::string reversed_hex(const std::uint8_t* bytes, const std::size_t size) {
  std::vector<std::uint8_t> reversed(size);
  std::reverse_copy(bytes, bytes + size, reversed.begin());
  return crypto::to_hex(reversed);
}

ZoneStats empty_zone(const ZoneRange& range) {
  ZoneStats zone;
  zone.range = range;
  zone.minimum_pow_value.fill(std::numeric_limits<std::uint32_t>::max());
  zone.minimum_nonce = std::numeric_limits<std::uint32_t>::max();
  return zone;
}

std::string hex_u32(const std::uint32_t value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0') << std::setw(8) << value;
  return output.str();
}

}  // namespace

bool GenesisValidation::passed() const noexcept {
  return header_serialization && nonce_little_endian && known_hash && pow_target;
}

bitcoin::Header genesis_header() {
  constexpr std::string_view serialized =
      "01000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
      "29ab5f49"
      "ffff001d"
      "1dac2b7c";
  return header_from_hex(serialized);
}

bitcoin::Header header_from_hex(const std::string_view header_hex) {
  const auto bytes = crypto::from_hex(header_hex);
  if (bytes.size() != 80) {
    throw std::invalid_argument("--header-hex must contain exactly 160 hexadecimal characters");
  }
  bitcoin::Header header{};
  std::copy(bytes.begin(), bytes.end(), header.begin());
  return header;
}

HeaderMetadata decode_header(const bitcoin::Header& input) {
  auto header = input;
  bitcoin::set_nonce(header, 0);
  HeaderMetadata metadata;
  metadata.version = read_le32(header.data());
  metadata.previous_block_hash = reversed_hex(header.data() + 4, 32);
  metadata.merkle_root = reversed_hex(header.data() + 36, 32);
  metadata.ntime = read_le32(header.data() + 68);
  metadata.nbits = read_le32(header.data() + 72);
  metadata.header_prefix_76_bytes_hex = crypto::to_hex(
      std::span<const std::uint8_t>(header.data(), 76));
  metadata.full_header_template_with_nonce_zero_hex = bitcoin::header_hex(header);
  return metadata;
}

PowValue pow_value(const crypto::Digest& raw_digest) {
  PowValue value{};
  for (std::size_t word = 0; word < value.size(); ++word) {
    const auto last = raw_digest.size() - 1U - word * 4U;
    value[word] = (static_cast<std::uint32_t>(raw_digest[last]) << 24U) |
                  (static_cast<std::uint32_t>(raw_digest[last - 1U]) << 16U) |
                  (static_cast<std::uint32_t>(raw_digest[last - 2U]) << 8U) |
                  static_cast<std::uint32_t>(raw_digest[last - 3U]);
  }
  return value;
}

std::string pow_value_hex(const PowValue& value) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const auto word : value) output << std::setw(8) << word;
  return output.str();
}

unsigned leading_zero_bits(const PowValue& value) {
  unsigned total = 0;
  for (const auto word : value) {
    const auto zeros = static_cast<unsigned>(std::countl_zero(word));
    total += zeros;
    if (zeros != 32U) break;
  }
  return total;
}

bool below_power_of_two_threshold(const PowValue& value,
                                  const unsigned threshold_bits) {
  if (threshold_bits == 0U || threshold_bits > 256U) {
    throw std::invalid_argument("threshold_bits must be in [1,256]");
  }
  return leading_zero_bits(value) >= threshold_bits;
}

TailCounts classify_tail(const PowValue& value) {
  TailCounts counts{};
  const auto zeros = leading_zero_bits(value);
  for (std::size_t i = 0; i < kThresholdBits.size(); ++i) {
    counts[i] = zeros >= kThresholdBits[i] ? 1U : 0U;
  }
  return counts;
}

bool minimum_precedes(const PowValue& left,
                      const std::uint32_t left_nonce,
                      const PowValue& right,
                      const std::uint32_t right_nonce) {
  if (left < right) return true;
  if (right < left) return false;
  return left_nonce < right_nonce;
}

std::vector<ZoneRange> make_zone_layout(const std::uint64_t nonce_start,
                                        const std::uint64_t nonce_count,
                                        const std::uint64_t zone_size) {
  if (nonce_count == 0) throw std::invalid_argument("nonce_count must be positive");
  if (zone_size == 0 || zone_size > kNonceSpaceSize) {
    throw std::invalid_argument("zone_size must be in [1, 2^32]");
  }
  if (nonce_start >= kNonceSpaceSize || nonce_count > kNonceSpaceSize - nonce_start) {
    throw std::invalid_argument("nonce range exceeds uint32 nonce space");
  }

  const auto range_end = nonce_start + nonce_count;
  const auto first_zone = nonce_start / zone_size;
  const auto last_zone = (range_end - 1U) / zone_size;
  std::vector<ZoneRange> zones;
  zones.reserve(static_cast<std::size_t>(last_zone - first_zone + 1U));
  for (auto index = first_zone; index <= last_zone; ++index) {
    const auto natural_start = index * zone_size;
    const auto natural_end = std::min(kNonceSpaceSize, natural_start + zone_size);
    const auto start = std::max(nonce_start, natural_start);
    const auto end = std::min(range_end, natural_end);
    zones.push_back({index, start, end - 1U, end - start});
  }
  return zones;
}

std::vector<ZoneStats> scan_cpu(const bitcoin::Header& input,
                                const std::uint64_t nonce_start,
                                const std::uint64_t nonce_count,
                                const std::uint64_t zone_size) {
  const auto layout = make_zone_layout(nonce_start, nonce_count, zone_size);
  std::vector<ZoneStats> result;
  result.reserve(layout.size());
  auto header = input;
  const auto network_target = bitcoin::target_from_nbits(hex_u32(decode_header(input).nbits));
  for (const auto& range : layout) {
    auto zone = empty_zone(range);
    for (std::uint64_t nonce64 = range.nonce_start; nonce64 <= range.nonce_end; ++nonce64) {
      const auto nonce = static_cast<std::uint32_t>(nonce64);
      bitcoin::set_nonce(header, nonce);
      const auto digest = crypto::sha256d(header);
      const auto value = pow_value(digest);
      const auto classified = classify_tail(value);
      for (std::size_t i = 0; i < zone.counts.size(); ++i) zone.counts[i] += classified[i];
      if (bitcoin::hash_meets_target(digest, network_target)) ++zone.network_hits;
      if (minimum_precedes(value, nonce, zone.minimum_pow_value, zone.minimum_nonce)) {
        zone.minimum_pow_value = value;
        zone.minimum_nonce = nonce;
      }
    }
    result.push_back(zone);
  }
  return result;
}

SparseHitResult scan_sparse_hits_cpu(const bitcoin::Header& input,
                                     const std::uint64_t nonce_start,
                                     const std::uint64_t nonce_count,
                                     const unsigned threshold_bits,
                                     const std::size_t capacity) {
  (void)make_zone_layout(nonce_start, nonce_count, nonce_count);
  if (capacity == 0U) throw std::invalid_argument("sparse capacity must be positive");
  // Validate even when the range happens to contain no hits.
  PowValue zero{};
  (void)below_power_of_two_threshold(zero, threshold_bits);
  SparseHitResult result;
  result.nonce_count = nonce_count;
  result.capacity = capacity;
  result.threshold_bits = threshold_bits;
  result.nonces.reserve(std::min<std::uint64_t>(capacity, nonce_count));
  auto header = input;
  const auto started = std::chrono::steady_clock::now();
  const auto end = nonce_start + nonce_count;
  for (auto nonce64 = nonce_start; nonce64 < end; ++nonce64) {
    const auto nonce = static_cast<std::uint32_t>(nonce64);
    bitcoin::set_nonce(header, nonce);
    const auto value = pow_value(crypto::sha256d(header));
    if (!below_power_of_two_threshold(value, threshold_bits)) continue;
    ++result.total_hit_count;
    if (result.nonces.size() < capacity) result.nonces.push_back(nonce);
  }
  result.captured_count = result.nonces.size();
  result.overflow = result.total_hit_count > result.captured_count;
  result.elapsed_seconds = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - started).count();
  return result;
}

SparseHitResult scan_sparse_hits_cpu_complete(const bitcoin::Header& header,
                                              const std::uint64_t nonce_start,
                                              const std::uint64_t nonce_count,
                                              const unsigned threshold_bits,
                                              const std::size_t initial_capacity) {
  auto capacity = initial_capacity;
  std::size_t retries = 0;
  for (;;) {
    auto result = scan_sparse_hits_cpu(header, nonce_start, nonce_count,
                                       threshold_bits, capacity);
    if (!result.overflow) {
      result.overflow_retries = retries;
      return result;
    }
    if (capacity > std::numeric_limits<std::size_t>::max() / 2U) {
      throw std::overflow_error("sparse capture capacity cannot be doubled");
    }
    capacity *= 2U;
    ++retries;
  }
}

GlobalStats aggregate_zones(const std::vector<ZoneStats>& zones) {
  if (zones.empty()) throw std::invalid_argument("cannot aggregate an empty zone collection");
  GlobalStats result;
  result.minimum_pow_value.fill(std::numeric_limits<std::uint32_t>::max());
  result.minimum_nonce = std::numeric_limits<std::uint32_t>::max();
  result.minimum_zone = zones.front().range.zone_index;
  for (const auto& zone : zones) {
    result.total_nonce_count += zone.range.nonce_count;
    for (std::size_t i = 0; i < result.counts.size(); ++i) result.counts[i] += zone.counts[i];
    result.network_hits += zone.network_hits;
    if (minimum_precedes(zone.minimum_pow_value, zone.minimum_nonce,
                         result.minimum_pow_value, result.minimum_nonce)) {
      result.minimum_pow_value = zone.minimum_pow_value;
      result.minimum_nonce = zone.minimum_nonce;
      result.minimum_zone = zone.range.zone_index;
    }
  }
  return result;
}

bool same_statistics(const std::vector<ZoneStats>& left,
                     const std::vector<ZoneStats>& right) {
  if (left.size() != right.size()) return false;
  for (std::size_t i = 0; i < left.size(); ++i) {
    const auto& a = left[i];
    const auto& b = right[i];
    if (a.range.zone_index != b.range.zone_index ||
        a.range.nonce_start != b.range.nonce_start ||
        a.range.nonce_end != b.range.nonce_end ||
        a.range.nonce_count != b.range.nonce_count ||
        a.minimum_pow_value != b.minimum_pow_value ||
        a.minimum_nonce != b.minimum_nonce || a.counts != b.counts ||
        a.network_hits != b.network_hits) {
      return false;
    }
  }
  return true;
}

GenesisValidation validate_genesis() {
  constexpr std::string_view expected_header =
      "0100000000000000000000000000000000000000000000000000000000000000"
      "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
      "4b1e5e4a29ab5f49ffff001d1dac2b7c";
  constexpr std::string_view expected_hash =
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
  auto header = genesis_header();
  GenesisValidation validation;
  validation.header_serialization = bitcoin::header_hex(header) == expected_header;
  validation.nonce_little_endian = bitcoin::get_nonce(header) == 2083236893U &&
      header[76] == 0x1dU && header[77] == 0xacU && header[78] == 0x2bU && header[79] == 0x7cU;
  const auto digest = crypto::sha256d(header);
  validation.displayed_hash = crypto::bitcoin_hash_hex(digest);
  validation.known_hash = validation.displayed_hash == expected_hash &&
      pow_value_hex(pow_value(digest)) == expected_hash;
  const auto target = bitcoin::target_from_nbits("1d00ffff");
  validation.target = bitcoin::target_hex(target);
  validation.pow_target = bitcoin::hash_meets_target(digest, target);
  return validation;
}

}  // namespace srm::research::header_space
