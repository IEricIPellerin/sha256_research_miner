//tests\test_config.cpp
#include "config/config.h"
#include "test_support.h"

#include <filesystem>
#include <fstream>

TEST_CASE("benchmark mode and configuration are parsed") {
  REQUIRE_EQ(srm::config::mode_name(srm::config::Mode::Benchmark), std::string("benchmark"));
  REQUIRE(srm::config::LoggingConfig{}.save_share_audits);
  const auto root = std::filesystem::temp_directory_path() / "srm_benchmark_config_test";
  const auto directory = root / "config";
  std::filesystem::create_directories(directory);
  const auto path = directory / "benchmark.json";
  {
    std::ofstream output(path);
    output << R"({
      "mode": "benchmark",
      "cpu": {"enabled": true, "threads": 30},
      "gpu": {"enabled": true, "platform": "AMD Platform", "device": "AMD Radeon RX 7900 XTX", "auto_tune": true},
      "logging": {"directory": "results", "save_share_audits": false},
      "benchmark": {
        "cpu_threads": [28, 29, 30, 31, 32],
        "warmup_ms": 250,
        "measurement_ms": 1000,
        "header_hex": "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d00000000",
        "performance_profile": "config/performance_profile.json"
      }
    })";
  }
  const auto config = srm::config::load(path);
  REQUIRE(config.mode == srm::config::Mode::Benchmark);
  REQUIRE_EQ(config.benchmark.cpu_threads, std::vector<unsigned>({28, 29, 30, 31, 32}));
  REQUIRE_EQ(config.benchmark.warmup_ms, 250U);
  REQUIRE_EQ(config.benchmark.measurement_ms, 1000U);
  REQUIRE_EQ(config.gpu.platform, std::string("AMD Platform"));
  REQUIRE_EQ(config.gpu.device, std::string("AMD Radeon RX 7900 XTX"));
  REQUIRE(!config.logging.save_share_audits);
  REQUIRE_EQ(config.benchmark.performance_profile, root / "config" / "performance_profile.json");
  std::filesystem::remove_all(root);
}
