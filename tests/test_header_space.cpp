//tests\test_header_space.cpp
#include "research/header_space.h"

#include "crypto/sha256d.h"
#include "test_support.h"

#include <filesystem>
#include <limits>

namespace hs = srm::research::header_space;

TEST_CASE("Header-space Genesis construction, PoW value, and target validation") {
  const auto header = hs::genesis_header();
  const auto metadata = hs::decode_header(header);
  REQUIRE_EQ(srm::bitcoin::get_nonce(header), 2083236893U);
  REQUIRE_EQ(header[76], 0x1dU);
  REQUIRE_EQ(header[77], 0xacU);
  REQUIRE_EQ(header[78], 0x2bU);
  REQUIRE_EQ(header[79], 0x7cU);
  REQUIRE_EQ(metadata.version, 1U);
  REQUIRE_EQ(metadata.previous_block_hash,
             "0000000000000000000000000000000000000000000000000000000000000000");
  REQUIRE_EQ(metadata.merkle_root,
             "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
  REQUIRE_EQ(metadata.ntime, 1231006505U);
  REQUIRE_EQ(metadata.nbits, 0x1d00ffffU);
  REQUIRE_EQ(metadata.header_prefix_76_bytes_hex.size(), 152U);
  REQUIRE_EQ(metadata.full_header_template_with_nonce_zero_hex.size(), 160U);

  const auto validation = hs::validate_genesis();
  REQUIRE(validation.passed());
  REQUIRE_EQ(validation.displayed_hash,
             "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
  const auto digest = srm::crypto::sha256d(header);
  REQUIRE_EQ(hs::pow_value_hex(hs::pow_value(digest)), validation.displayed_hash);
}

TEST_CASE("Header-space leading-zero thresholds use the Bitcoin PoW integer") {
  srm::crypto::Digest raw{};
  raw[0] = 1U;
  const auto one = hs::pow_value(raw);
  REQUIRE_EQ(hs::pow_value_hex(one),
             "0000000000000000000000000000000000000000000000000000000000000001");

  hs::PowValue value{};
  value.fill(std::numeric_limits<std::uint32_t>::max());
  value[0] = 0x000fffffU;
  REQUIRE_EQ(hs::leading_zero_bits(value), 12U);
  const auto counts12 = hs::classify_tail(value);
  REQUIRE_EQ(counts12[0], 1U);
  REQUIRE_EQ(counts12[1], 1U);
  REQUIRE_EQ(counts12[2], 0U);

  value[0] = 0U;
  REQUIRE_EQ(hs::leading_zero_bits(value), 32U);
  const auto counts32 = hs::classify_tail(value);
  for (const auto count : counts32) REQUIRE_EQ(count, 1U);
}

TEST_CASE("Header-space zone layout is absolute, contiguous, and includes uint32 max") {
  const auto full = hs::make_zone_layout(0, hs::kNonceSpaceSize, hs::kDefaultZoneSize);
  REQUIRE_EQ(full.size(), 4096U);
  REQUIRE_EQ(full.front().zone_index, 0U);
  REQUIRE_EQ(full.front().nonce_start, 0U);
  REQUIRE_EQ(full.front().nonce_end, hs::kDefaultZoneSize - 1U);
  REQUIRE_EQ(full.back().zone_index, 4095U);
  REQUIRE_EQ(full.back().nonce_end, 0xffffffffULL);
  REQUIRE_EQ(full.back().nonce_count, hs::kDefaultZoneSize);

  const auto partial = hs::make_zone_layout(hs::kDefaultZoneSize - 1U, 3U,
                                             hs::kDefaultZoneSize);
  REQUIRE_EQ(partial.size(), 2U);
  REQUIRE_EQ(partial[0].nonce_count, 1U);
  REQUIRE_EQ(partial[1].nonce_count, 2U);

  const auto upper = hs::make_zone_layout(0xfffffffeULL, 2U, 1U);
  REQUIRE_EQ(upper.size(), 2U);
  REQUIRE_EQ(upper[0].nonce_start, 0xfffffffeULL);
  REQUIRE_EQ(upper[1].nonce_end, 0xffffffffULL);
}

TEST_CASE("Header-space CPU reference covers nonce zero, one, Genesis, and uint32 max") {
  const auto header = hs::genesis_header();
  const auto low = hs::scan_cpu(header, 0U, 2U, 1U);
  REQUIRE_EQ(low.size(), 2U);
  REQUIRE_EQ(low[0].minimum_nonce, 0U);
  REQUIRE_EQ(low[1].minimum_nonce, 1U);

  const auto genesis = hs::scan_cpu(header, 2083236893U, 1U, 1U);
  REQUIRE_EQ(genesis.size(), 1U);
  REQUIRE_EQ(genesis[0].minimum_nonce, 2083236893U);
  REQUIRE_EQ(hs::pow_value_hex(genesis[0].minimum_pow_value),
             "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");

  const auto high = hs::scan_cpu(header, 0xfffffffeULL, 2U, 1U);
  REQUIRE_EQ(high.size(), 2U);
  REQUIRE_EQ(high[0].minimum_nonce, 0xfffffffeU);
  REQUIRE_EQ(high[1].minimum_nonce, 0xffffffffU);
  REQUIRE_EQ(hs::aggregate_zones(high).total_nonce_count, 2U);
}

TEST_CASE("Header-space aggregation sums exact counts and applies deterministic tie-break") {
  hs::ZoneStats first;
  first.range = {0U, 0U, 9U, 10U};
  first.minimum_pow_value.fill(0U);
  first.minimum_nonce = 7U;
  first.counts = {5U, 4U, 3U, 2U, 1U, 1U, 0U};
  hs::ZoneStats second;
  second.range = {1U, 10U, 19U, 10U};
  second.minimum_pow_value = first.minimum_pow_value;
  second.minimum_nonce = 3U;
  second.counts = {6U, 5U, 4U, 3U, 2U, 1U, 1U};
  const auto global = hs::aggregate_zones({first, second});
  REQUIRE_EQ(global.total_nonce_count, 20U);
  REQUIRE_EQ(global.minimum_nonce, 3U);
  REQUIRE_EQ(global.minimum_zone, 1U);
  REQUIRE_EQ(global.counts[0], 11U);
  REQUIRE_EQ(global.counts[6], 1U);
}

TEST_CASE("Header-space OpenCL zone statistics equal CPU including upper nonce edge") {
  if (!hs::opencl_compiled() || hs::enumerate_gpu_devices().empty()) {
    REQUIRE(true);
    return;
  }
  hs::GpuScanner scanner("auto",
                         std::filesystem::path(SRM_SOURCE_DIR) / "kernels" / "header_space_map.cl",
                         64U);
  const auto header = hs::genesis_header();
  const auto gpu = scanner.scan(header, 0x12340000U, 8192U, 1024U, 8U);
  const auto cpu = hs::scan_cpu(header, 0x12340000U, 8192U, 1024U);
  REQUIRE(hs::same_statistics(cpu, gpu.zones));

  const auto gpu_edge = scanner.scan(header, 0xfffffffeULL, 2U, 1U, 2U);
  const auto cpu_edge = hs::scan_cpu(header, 0xfffffffeULL, 2U, 1U);
  REQUIRE(hs::same_statistics(cpu_edge, gpu_edge.zones));
}
