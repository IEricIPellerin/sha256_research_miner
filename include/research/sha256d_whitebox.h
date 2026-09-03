//include\research\sha256d_whitebox.h
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <nlohmann/json.hpp>
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

// Builds the one-header, forward-only Bitcoin Genesis SHA256d reference trace.
// The production SHA-256 implementation remains the observed source of round
// states; this research module reconstructs and audits every recorded detail.
Artifacts build_genesis_sha256d_whitebox();

// Independently recomputes schedules, round transitions, feed-forwards,
// bit-column carries, modulo projections, digests, and the final Genesis hash.
// Throws std::runtime_error on the first mismatch and otherwise returns the
// deterministic audit report embedded in generated artifacts.
nlohmann::json validate_genesis_sha256d_whitebox(const nlohmann::json& trace);

// Writes stable UTF-8 artifacts, creating output_directory when necessary.
void write_genesis_sha256d_whitebox(const Artifacts& artifacts,
                                    const std::filesystem::path& output_directory);

}  // namespace srm::research::whitebox
