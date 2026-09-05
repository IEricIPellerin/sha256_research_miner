//include\research\header_space.h
#pragma once

#include "bitcoin/block_header.h"
#include "crypto/sha256.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace srm::research::header_space {

constexpr std::uint64_t kNonceSpaceSize = std::uint64_t{1} << 32U;
constexpr std::uint64_t kDefaultZoneSize = std::uint64_t{1} << 20U;
// Pre-registered tail regimes for one complete 2^32-nonce block: expected
// counts 64, 16, 4, 1, 1/4, 1/16, and 1/64 respectively.
constexpr std::array<unsigned, 7> kThresholdBits{26, 28, 30, 32, 34, 36, 38};

// Big-endian 32-bit words of the integer used by Bitcoin's PoW comparison.
// Its hexadecimal encoding is also the conventional displayed block hash.
using PowValue = std::array<std::uint32_t, 8>;
using TailCounts = std::array<std::uint64_t, kThresholdBits.size()>;

struct HeaderMetadata {
  std::uint32_t version{0};
  std::string previous_block_hash;
  std::string merkle_root;
  std::uint32_t ntime{0};
  std::uint32_t nbits{0};
  std::string header_prefix_76_bytes_hex;
  std::string full_header_template_with_nonce_zero_hex;
};

struct ZoneRange {
  std::uint64_t zone_index{0};
  std::uint64_t nonce_start{0};
  std::uint64_t nonce_end{0};
  std::uint64_t nonce_count{0};
};

struct ZoneStats {
  ZoneRange range;
  PowValue minimum_pow_value{};
  std::uint32_t minimum_nonce{0};
  TailCounts counts{};
  std::uint64_t network_hits{0};
};

struct GlobalStats {
  std::uint64_t total_nonce_count{0};
  PowValue minimum_pow_value{};
  std::uint32_t minimum_nonce{0};
  std::uint64_t minimum_zone{0};
  TailCounts counts{};
  std::uint64_t network_hits{0};
};

struct GenesisValidation {
  bool header_serialization{false};
  bool nonce_little_endian{false};
  bool known_hash{false};
  bool pow_target{false};
  std::string displayed_hash;
  std::string target;

  [[nodiscard]] bool passed() const noexcept;
};

struct GpuDeviceInfo {
  std::size_t index{0};
  std::size_t platform_index{0};
  std::size_t device_index{0};
  std::string platform;
  std::string name;
  std::string board_name;
  std::string vendor;
  std::string driver;
  std::uint32_t compute_units{0};
  std::uint64_t global_memory_bytes{0};
  std::uint64_t local_memory_bytes{0};
  std::size_t max_workgroup_size{0};
};

struct GpuScanResult {
  std::vector<ZoneStats> zones;
  GpuDeviceInfo device;
  std::size_t local_size{0};
  std::size_t maximum_global_size{0};
  std::size_t batch_zones{0};
  std::size_t kernel_launches{0};
  double elapsed_seconds{0.0};
  double kernel_seconds{0.0};
};

// Opt-in sparse capture result.  The historical zone scanner above never uses
// this path.  A one-shot capture may overflow; callers must reject it or retry
// with a larger capacity.  `nonces` contains only the captured prefix.
struct SparseHitResult {
  std::vector<std::uint32_t> nonces;
  GpuDeviceInfo device;
  std::uint64_t nonce_count{0};
  std::uint64_t total_hit_count{0};
  std::size_t captured_count{0};
  std::size_t capacity{0};
  unsigned threshold_bits{0};
  bool overflow{false};
  std::size_t overflow_retries{0};
  double elapsed_seconds{0.0};
  double kernel_seconds{0.0};
};

bitcoin::Header genesis_header();
bitcoin::Header header_from_hex(std::string_view header_hex);
HeaderMetadata decode_header(const bitcoin::Header& header);

PowValue pow_value(const crypto::Digest& raw_digest);
std::string pow_value_hex(const PowValue& value);
unsigned leading_zero_bits(const PowValue& value);
// Exact strict predicate Y < 2^(256-threshold_bits).
bool below_power_of_two_threshold(const PowValue& value, unsigned threshold_bits);
TailCounts classify_tail(const PowValue& value);
bool minimum_precedes(const PowValue& left,
                      std::uint32_t left_nonce,
                      const PowValue& right,
                      std::uint32_t right_nonce);

std::vector<ZoneRange> make_zone_layout(std::uint64_t nonce_start,
                                        std::uint64_t nonce_count,
                                        std::uint64_t zone_size);
std::vector<ZoneStats> scan_cpu(const bitcoin::Header& header,
                                std::uint64_t nonce_start,
                                std::uint64_t nonce_count,
                                std::uint64_t zone_size);
SparseHitResult scan_sparse_hits_cpu(const bitcoin::Header& header,
                                     std::uint64_t nonce_start,
                                     std::uint64_t nonce_count,
                                     unsigned threshold_bits,
                                     std::size_t capacity);
SparseHitResult scan_sparse_hits_cpu_complete(const bitcoin::Header& header,
                                              std::uint64_t nonce_start,
                                              std::uint64_t nonce_count,
                                              unsigned threshold_bits,
                                              std::size_t initial_capacity);
GlobalStats aggregate_zones(const std::vector<ZoneStats>& zones);
bool same_statistics(const std::vector<ZoneStats>& left,
                     const std::vector<ZoneStats>& right);
GenesisValidation validate_genesis();

bool opencl_compiled() noexcept;
std::vector<GpuDeviceInfo> enumerate_gpu_devices();

class GpuScanner {
 public:
  GpuScanner(std::string device_selector,
             std::filesystem::path kernel_path,
             std::size_t local_size);
  ~GpuScanner();
  GpuScanner(const GpuScanner&) = delete;
  GpuScanner& operator=(const GpuScanner&) = delete;
  GpuScanner(GpuScanner&&) noexcept;
  GpuScanner& operator=(GpuScanner&&) noexcept;

  [[nodiscard]] const GpuDeviceInfo& device() const;
  [[nodiscard]] std::size_t local_size() const noexcept;
  GpuScanResult scan(const bitcoin::Header& header,
                     std::uint64_t nonce_start,
                     std::uint64_t nonce_count,
                     std::uint64_t zone_size,
                     std::size_t batch_zones);
  SparseHitResult scan_sparse_hits(const bitcoin::Header& header,
                                   std::uint64_t nonce_start,
                                   std::uint64_t nonce_count,
                                   unsigned threshold_bits,
                                   std::size_t capacity);
  SparseHitResult scan_sparse_hits_complete(const bitcoin::Header& header,
                                            std::uint64_t nonce_start,
                                            std::uint64_t nonce_count,
                                            unsigned threshold_bits,
                                            std::size_t initial_capacity);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace srm::research::header_space
