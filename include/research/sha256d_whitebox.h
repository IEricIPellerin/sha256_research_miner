//include\research\sha256d_whitebox.h
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
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

struct NonceSingleBitReferenceVector {
  unsigned numeric_nonce_bit{};
  std::uint32_t nonce{};
  std::uint32_t w3{};
  std::string first_sha256;
  std::string raw_sha256d;
  std::string bitcoin_display_hash;
};

struct NonceSingleBitCampaignArtifacts {
  nlohmann::json aggregate;
  std::string summary_markdown;
  std::string per_bit_csv;
  std::string per_round_csv;
  std::string carry_summary_csv;
  std::string pairwise_csv;
};

struct MerkleContextTransferArtifacts {
  nlohmann::json aggregate;
  std::string summary_markdown;
  std::string contexts_csv;
  std::string per_context_bit_csv;
  std::string bit_transfer_summary_csv;
  std::string direction_effects_csv;
  std::string per_bit_round_summary_csv;
  std::string pairwise_transfer_csv;
};

using Sha256State = std::array<std::uint32_t, 8>;

// Compact, exact view of one nonce-independent compression-1 round. This is
// intentionally separate from the exhaustive 192-round artifact format: it is
// suitable for bulk PRE_SCAN feature extraction without retaining large traces.
struct PrescanRound {
  unsigned round_index{};
  Sha256State before{};
  Sha256State after{};
  std::uint32_t w{};
  std::uint32_t k{};
  std::uint32_t sigma0_a{};
  std::uint32_t sigma1_e{};
  std::uint32_t choice{};
  std::uint32_t majority{};
  std::uint32_t temp1{};
  std::uint32_t temp2{};
};

struct PrescanCompression1 {
  Sha256State midstate{};
  std::array<std::uint32_t, 16> fixed_chunk_words{};
  std::array<PrescanRound, 3> rounds{};
  std::uint32_t round3_c3{};
  std::uint32_t round3_t2{};
  std::uint32_t w16{};
  std::uint32_t w17{};
  std::uint32_t w16_sigma0_w1{};
  std::uint32_t w17_sigma0_w2{};
  std::uint32_t w17_sigma1_w15{};
  bool w16_nonce_independent{};
  bool w17_nonce_independent{};
  bool w18_nonce_dependent{};
};

// Reconstructs only information that is fixed by a serialized 76-byte Bitcoin
// header prefix. W3 is deliberately not assigned a nonce value. The returned
// rounds 0..2, C3, T2_round3, W16 and W17 are exact PRE_SCAN quantities.
PrescanCompression1 build_prescan_compression1(
    std::span<const std::uint8_t> header_prefix_76);

// Frozen hashlib fixtures for synthetic Merkle-field context ids 0..63.
const std::array<std::array<std::uint8_t, 32>, 64>&
merkle_context_transfer_fields();

// Runs the first context_count contexts in deterministic id order. The full
// campaign uses 64; smaller prefixes support fast permanent tests. Discovery
// (0..31) is always completed and frozen before holdout (32..63) is evaluated.
MerkleContextTransferArtifacts build_merkle_context_transfer_campaign(
    std::size_t context_count = 64U,
    const std::function<void(unsigned, unsigned)>& progress = {});

nlohmann::json validate_merkle_context_transfer_campaign(
    const nlohmann::json& aggregate,
    std::size_t expected_context_count = 64U);

void write_merkle_context_transfer_campaign(
    const MerkleContextTransferArtifacts& artifacts,
    const std::filesystem::path& output_directory);

// Explicit opt-in exhaustive JSON trace for one synthetic context/bit.
void write_merkle_context_transfer_full_trace(
    unsigned context_id,
    unsigned numeric_nonce_bit,
    const std::filesystem::path& output_directory);

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

// Builds Genesis with exactly numeric nonce bit 0 flipped.
Artifacts build_genesis_nonce_bit0_flip_sha256d_whitebox();

// Maps a numeric little-endian nonce bit to its bit position in SHA-256 W3.
// Throws std::invalid_argument unless numeric_nonce_bit is in [0, 31].
unsigned numeric_nonce_bit_to_w3_bit(unsigned numeric_nonce_bit);

// Independent hashlib-generated fixed vectors for all 32 elementary nonce
// perturbations. These are test/build guards, not values derived from a trace.
const std::array<NonceSingleBitReferenceVector, 32>&
genesis_nonce_single_bit_reference_vectors();

// Builds one generic Genesis single-bit nonce specimen. Bit 0 deliberately
// reuses specimen C's historical metadata and strict validator.
Artifacts build_genesis_nonce_single_bit_flip_sha256d_whitebox(
    unsigned numeric_nonce_bit);

// Runs the controlled 32-bit campaign sequentially. The optional callback is
// invoked once before each candidate and is intended for compact CLI progress.
NonceSingleBitCampaignArtifacts build_genesis_nonce_single_bit_campaign(
    const std::function<void(unsigned)>& progress = {});

// Audits aggregate cardinalities, fixed vectors, mapping, milestones, and all
// exact differential-validation flags without reconstructing 32 large traces.
nlohmann::json validate_genesis_nonce_single_bit_campaign(
    const nlohmann::json& aggregate);

// Writes only the six compact aggregate campaign artifacts into a dedicated
// nonce_single_bit_campaign child directory.
void write_genesis_nonce_single_bit_campaign(
    const NonceSingleBitCampaignArtifacts& artifacts,
    const std::filesystem::path& output_directory);

// Explicit opt-in helper for one exhaustive candidate trace. Its campaign
// stem cannot overwrite the historical A/B/C artifact names.
void write_genesis_nonce_single_bit_full_trace(
    unsigned numeric_nonce_bit,
    const std::filesystem::path& output_directory);

// Independently recomputes schedules, round transitions, feed-forwards,
// bit-column carries, modulo projections, digests, and the final Genesis hash.
// Throws std::runtime_error on the first mismatch and otherwise returns the
// deterministic audit report embedded in generated artifacts.
nlohmann::json validate_genesis_sha256d_whitebox(const nlohmann::json& trace);

// Applies the strict independent reference vectors for specimen B.
nlohmann::json validate_genesis_nonce_plus_one_sha256d_whitebox(
    const nlohmann::json& trace);

// Applies the strict independent reference vectors for specimen C.
nlohmann::json validate_genesis_nonce_bit0_flip_sha256d_whitebox(
    const nlohmann::json& trace);

// Validates only the targeted A/B causal invariants through the first
// divergent round. It deliberately does not interpret later propagation.
nlohmann::json validate_genesis_nonce_plus_one_invariants(
    const nlohmann::json& genesis_trace,
    const nlohmann::json& nonce_plus_one_trace);

// Validates only the targeted A/C causal invariants through the first
// divergent round. It deliberately does not interpret later propagation.
nlohmann::json validate_genesis_nonce_bit0_flip_invariants(
    const nlohmann::json& genesis_trace,
    const nlohmann::json& nonce_bit0_flip_trace);

const SpecimenMetadata& genesis_specimen_metadata();
const SpecimenMetadata& genesis_nonce_plus_one_specimen_metadata();
const SpecimenMetadata& genesis_nonce_bit0_flip_specimen_metadata();

// Writes stable UTF-8 artifacts, creating output_directory when necessary.
void write_genesis_sha256d_whitebox(const Artifacts& artifacts,
                                    const std::filesystem::path& output_directory);

void write_genesis_nonce_plus_one_sha256d_whitebox(
    const Artifacts& artifacts,
    const std::filesystem::path& output_directory);

void write_genesis_nonce_bit0_flip_sha256d_whitebox(
    const Artifacts& artifacts,
    const std::filesystem::path& output_directory);

}  // namespace srm::research::whitebox
