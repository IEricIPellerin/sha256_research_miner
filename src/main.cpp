//src\main.cpp
#include "config/config.h"
#include "mining/mining_controller.h"
#include "platform/windows_utf8.h"

#include <atomic>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>

namespace {
std::atomic_bool interrupted{false};
void handle_signal(int) { interrupted.store(true, std::memory_order_release); }
}

int main(int argc, char** argv) {
  srm::platform::configure_utf8_console();

  try {
    std::filesystem::path config_path = "config/miner.json";
    bool check_only = false;
    for (int i = 1; i < argc; ++i) {
      const std::string argument = argv[i];
      if (argument == "--config" && i + 1 < argc) config_path = argv[++i];
      else if (argument == "--check-config") check_only = true;
      else if (argument == "--help" || argument == "-h") {
        std::cout << "Usage: sha256_research_miner [--config FILE] [--check-config]\n";
        return 0;
      } else throw std::invalid_argument("unknown argument: " + argument);
    }
    const auto config = srm::config::load(config_path);
    std::cout << "sha256_research_miner 0.1.0 | mode=" << srm::config::mode_name(config.mode) << '\n';
    if (check_only) { std::cout << "Configuration valide: " << config.source_path << '\n'; return 0; }
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    srm::mining::MiningController controller(config);
    return controller.run(interrupted);
  } catch (const std::exception& error) {
    std::cerr << "ERREUR: " << error.what() << '\n';
    return 1;
  }
}
