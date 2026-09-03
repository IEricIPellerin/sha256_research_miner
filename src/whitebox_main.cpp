//src\whitebox_main.cpp
#include "research/sha256d_whitebox.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
  try {
    std::filesystem::path output_directory = "results/whitebox";
    std::string specimen = "genesis";
    for (int i = 1; i < argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--output-dir" && i + 1 < argc) {
        output_directory = argv[++i];
      } else if (argument == "--specimen" && i + 1 < argc) {
        specimen = argv[++i];
      } else if (argument == "--help") {
        std::cout << "Usage: sha256_whitebox [--output-dir PATH] "
                     "[--specimen genesis|genesis-nonce-plus-1|"
                     "genesis-nonce-bit0-flip|all]\n";
        return 0;
      } else {
        throw std::invalid_argument("unknown or incomplete argument: " + argument);
      }
    }
    const auto report = [&](const srm::research::whitebox::Artifacts& artifacts,
                            const srm::research::whitebox::SpecimenMetadata& metadata) {
      std::cout << "[WHITEBOX] specimen: " << metadata.artifact_stem << '\n'
                << "[WHITEBOX] validation: "
                << artifacts.trace.at("validation").at("status").get<std::string>() << '\n'
                << "[WHITEBOX] compressions: 3, rounds: 192, schedule words: 3 x 64\n"
                << "[WHITEBOX] Bitcoin hash: "
                << artifacts.trace.at("final").at("bitcoin_display_hash").get<std::string>() << '\n'
                << "[WHITEBOX] JSON: "
                << std::filesystem::absolute(output_directory /
                     (metadata.artifact_stem + "_whitebox.json")).string() << '\n'
                << "[WHITEBOX] summary: "
                << std::filesystem::absolute(output_directory /
                     (metadata.artifact_stem + "_whitebox_summary.md")).string() << '\n';
    };
    if (specimen == "genesis") {
      const auto artifacts = srm::research::whitebox::build_genesis_sha256d_whitebox();
      srm::research::whitebox::write_genesis_sha256d_whitebox(artifacts, output_directory);
      report(artifacts, srm::research::whitebox::genesis_specimen_metadata());
    } else if (specimen == "genesis-nonce-plus-1") {
      const auto artifacts =
          srm::research::whitebox::build_genesis_nonce_plus_one_sha256d_whitebox();
      srm::research::whitebox::write_genesis_nonce_plus_one_sha256d_whitebox(
          artifacts, output_directory);
      report(artifacts,
             srm::research::whitebox::genesis_nonce_plus_one_specimen_metadata());
    } else if (specimen == "genesis-nonce-bit0-flip") {
      const auto artifacts =
          srm::research::whitebox::build_genesis_nonce_bit0_flip_sha256d_whitebox();
      srm::research::whitebox::write_genesis_nonce_bit0_flip_sha256d_whitebox(
          artifacts, output_directory);
      report(artifacts,
             srm::research::whitebox::genesis_nonce_bit0_flip_specimen_metadata());
    } else if (specimen == "all") {
      const auto genesis = srm::research::whitebox::build_genesis_sha256d_whitebox();
      const auto nonce_plus_one =
          srm::research::whitebox::build_genesis_nonce_plus_one_sha256d_whitebox();
      const auto invariants =
          srm::research::whitebox::validate_genesis_nonce_plus_one_invariants(
              genesis.trace, nonce_plus_one.trace);
      const auto nonce_bit0_flip =
          srm::research::whitebox::build_genesis_nonce_bit0_flip_sha256d_whitebox();
      const auto bit0_flip_invariants =
          srm::research::whitebox::validate_genesis_nonce_bit0_flip_invariants(
              genesis.trace, nonce_bit0_flip.trace);
      srm::research::whitebox::write_genesis_sha256d_whitebox(genesis, output_directory);
      srm::research::whitebox::write_genesis_nonce_plus_one_sha256d_whitebox(
          nonce_plus_one, output_directory);
      srm::research::whitebox::write_genesis_nonce_bit0_flip_sha256d_whitebox(
          nonce_bit0_flip, output_directory);
      report(genesis, srm::research::whitebox::genesis_specimen_metadata());
      report(nonce_plus_one,
             srm::research::whitebox::genesis_nonce_plus_one_specimen_metadata());
      report(nonce_bit0_flip,
             srm::research::whitebox::genesis_nonce_bit0_flip_specimen_metadata());
      std::cout << "[WHITEBOX] A/B invariants: "
                << invariants.at("status").get<std::string>() << '\n'
                << "[WHITEBOX] first divergence: "
                << invariants.at("first_divergence").get<std::string>() << '\n'
                << "[WHITEBOX] T1 carry bit24: "
                << invariants.at("T1_carry_bit24_a").get<unsigned>() << " -> "
                << invariants.at("T1_carry_bit24_b").get<unsigned>() << '\n'
                << "[WHITEBOX] A/C invariants: "
                << bit0_flip_invariants.at("status").get<std::string>() << '\n'
                << "[WHITEBOX] first divergence: "
                << bit0_flip_invariants.at("first_divergence").get<std::string>() << '\n'
                << "[WHITEBOX] T1 carry bit24: "
                << bit0_flip_invariants.at("T1_carry_bit24_a").get<unsigned>()
                << " -> "
                << bit0_flip_invariants.at("T1_carry_bit24_c").get<unsigned>() << '\n';
    } else {
      throw std::invalid_argument("unknown specimen: " + specimen);
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "[WHITEBOX] error: " << error.what() << '\n';
    return 1;
  }
}
