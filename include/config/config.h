//include\config\config.h
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace srm::config {

enum class Mode { Live, HistoricalTest, Research, MockStratum };

struct CkpoolConfig {
  std::string host{"stratum.ckpool.org"};
  std::uint16_t port{3333};
  std::string username{"CHANGE_ME"};
  std::string password{"x"};
  bool reconnect{true};
  unsigned reconnect_delay_ms{2000};
};

struct CpuConfig { bool enabled{true}; unsigned threads{30}; };
struct GpuConfig {
  bool enabled{true};
  std::string platform{"auto"};
  std::string device{"auto"};
  bool auto_tune{true};
};
struct ConsoleConfig {
  unsigned refresh_ms{1000};
  bool show_job_events{true};
  bool show_best_hash{true};
};
struct LoggingConfig {
  std::filesystem::path directory{"results"};
  bool save_session_log{true};
  bool save_block_candidates{true};
};
struct HistoricalConfig {
  std::string header_hex;
  std::optional<std::uint32_t> known_nonce;
  std::string expected_hash;
  std::string target_hex;
  bool scan_full_nonce_space{true};
  std::uint64_t nonce_start{0};
  std::uint64_t nonce_end{0x100000000ULL};
};
struct ResearchConfig {
  bool enabled{false};
  unsigned round_start{1};
  unsigned round_end{64};
  std::uint64_t sample_count{4096};
};

struct AppConfig {
  Mode mode{Mode::Live};
  CkpoolConfig ckpool;
  CpuConfig cpu;
  GpuConfig gpu;
  ConsoleConfig console;
  LoggingConfig logging;
  HistoricalConfig historical;
  ResearchConfig research;
  unsigned checkpoint_interval_ms{2000};
  std::filesystem::path source_path;
  std::filesystem::path project_root;
};

AppConfig load(const std::filesystem::path& path);
std::string mode_name(Mode mode);

}  // namespace srm::config

