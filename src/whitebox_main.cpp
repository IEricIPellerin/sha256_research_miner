//src\whitebox_main.cpp
#include "research/sha256d_whitebox.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv) {
  try {
    std::filesystem::path output_directory = "results/whitebox";
    for (int i = 1; i < argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--output-dir" && i + 1 < argc) {
        output_directory = argv[++i];
      } else if (argument == "--help") {
        std::cout << "Usage: sha256_whitebox [--output-dir PATH]\n";
        return 0;
      } else {
        throw std::invalid_argument("unknown or incomplete argument: " + argument);
      }
    }
    const auto artifacts = srm::research::whitebox::build_genesis_sha256d_whitebox();
    srm::research::whitebox::write_genesis_sha256d_whitebox(artifacts, output_directory);
    std::cout << "[WHITEBOX] validation: "
              << artifacts.trace.at("validation").at("status").get<std::string>() << '\n'
              << "[WHITEBOX] compressions: 3, rounds: 192, schedule words: 3 x 64\n"
              << "[WHITEBOX] Bitcoin hash: "
              << artifacts.trace.at("final").at("bitcoin_display_hash").get<std::string>() << '\n'
              << "[WHITEBOX] JSON: "
              << std::filesystem::absolute(output_directory / "genesis_sha256d_whitebox.json").string() << '\n'
              << "[WHITEBOX] summary: "
              << std::filesystem::absolute(output_directory / "genesis_sha256d_whitebox_summary.md").string() << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "[WHITEBOX] error: " << error.what() << '\n';
    return 1;
  }
}
