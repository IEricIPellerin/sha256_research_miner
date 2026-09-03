//include\research\sha256d_whitebox.h
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <span>
#include <string>

namespace srm::research::whitebox {

inline constexpr std::size_t kCompressionCount = 3;
inline constexpr std::size_t kRoundsPerCompression = 64;
inline constexpr std::size_t kTotalRoundCount =
    kCompressionCount * kRoundsPerCompression;

struct Artifacts {
  nlohmann::json trace;
  std::string summary_markdown;
};

struct SpecimenMetadata {
  std::string experiment_id;
  std::string summary_title;
  std::string artifact_stem;
  std::string expected_first_sha256;
  std::string expected_raw_sha256d;
  std::string expected_bitcoin_display_hash;
};

// Builds the exhaustive forward trace for one serialized 80-byte Bitcoin
// header. Non-empty expected digests are independent guards: generation fails
// when production SHA-256/SHA256d does not match them.
Artifacts build_sha256d_whitebox(std::span<const std::uint8_t> header,
                                 const SpecimenMetadata& metadata);

// Reconstructs and audits every cryptographic detail recorded in a generic
// 80-byte-header trace, independently of specimen identity.
nlohmann::json validate_sha256d_whitebox(const nlohmann::json& trace);

// Writes JSON, Markdown, and the four deterministic tabular views using
// metadata.artifact_stem. Existing files with the same names are replaced.
void write_sha256d_whitebox(const Artifacts& artifacts,
                            const SpecimenMetadata& metadata,
                            const std::filesystem::path& output_directory);

// Builds the one-header, forward-only Bitcoin Genesis SHA256d reference trace.
// The production SHA-256 implementation remains the observed source of round
// states; this research module reconstructs and audits every recorded detail.
Artifacts build_genesis_sha256d_whitebox();

// Builds Genesis with its numeric nonce incremented by exactly one.
Artifacts build_genesis_nonce_plus_one_sha256d_whitebox();

// Independently recomputes schedules, round transitions, feed-forwards,
// bit-column carries, modulo projections, digests, and the final Genesis hash.
// Throws std::runtime_error on the first mismatch and otherwise returns the
// deterministic audit report embedded in generated artifacts.
nlohmann::json validate_genesis_sha256d_whitebox(const nlohmann::json& trace);

// Applies the strict independent reference vectors for specimen B.
nlohmann::json validate_genesis_nonce_plus_one_sha256d_whitebox(
    const nlohmann::json& trace);

// Validates only the targeted A/B causal invariants through the first
// divergent round. It deliberately does not interpret later propagation.
nlohmann::json validate_genesis_nonce_plus_one_invariants(
    const nlohmann::json& genesis_trace,
    const nlohmann::json& nonce_plus_one_trace);

const SpecimenMetadata& genesis_specimen_metadata();
const SpecimenMetadata& genesis_nonce_plus_one_specimen_metadata();

// Writes stable UTF-8 artifacts, creating output_directory when necessary.
void write_genesis_sha256d_whitebox(const Artifacts& artifacts,
                                    const std::filesystem::path& output_directory);

void write_genesis_nonce_plus_one_sha256d_whitebox(
    const Artifacts& artifacts,
    const std::filesystem::path& output_directory);

}  // namespace srm::research::whitebox
