//src\config\config.cpp
#include "config/config.h"

#include <algorithm>
#include <fstream>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace srm::config {
namespace {

Mode parse_mode(const std::string& value) {
  if (value == "live") return Mode::Live;
  if (value == "historical_test") return Mode::HistoricalTest;
  if (value == "research") return Mode::Research;
  if (value == "mock_stratum") return Mode::MockStratum;
  if (value == "benchmark") return Mode::Benchmark;
  throw std::invalid_argument("unknown mode: " + value);
}

template <typename T>
void assign_if(const nlohmann::json& object, const char* key, T& value) {
  if (object.contains(key)) object.at(key).get_to(value);
}

}  // namespace

AppConfig load(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot open configuration: " + path.string());
  nlohmann::json json;
  input >> json;

  AppConfig config;
  config.source_path = std::filesystem::absolute(path);
  config.project_root = config.source_path.parent_path().parent_path();
  config.mode = parse_mode(json.at("mode").get<std::string>());

  if (json.contains("ckpool")) {
    const auto& item = json.at("ckpool");
    assign_if(item, "host", config.ckpool.host);
    assign_if(item, "port", config.ckpool.port);
    assign_if(item, "username", config.ckpool.username);
    assign_if(item, "password", config.ckpool.password);
    assign_if(item, "reconnect", config.ckpool.reconnect);
    assign_if(item, "reconnect_delay_ms", config.ckpool.reconnect_delay_ms);
  }
  if (json.contains("cpu")) {
    assign_if(json.at("cpu"), "enabled", config.cpu.enabled);
    assign_if(json.at("cpu"), "threads", config.cpu.threads);
  }
  if (json.contains("gpu")) {
    const auto& item = json.at("gpu");
    assign_if(item, "enabled", config.gpu.enabled);
    assign_if(item, "platform", config.gpu.platform);
    assign_if(item, "device", config.gpu.device);
    assign_if(item, "auto_tune", config.gpu.auto_tune);
    std::string profile = config.gpu.profile.string();
    assign_if(item, "profile", profile);
    config.gpu.profile = profile;
  }
  if (json.contains("console")) {
    const auto& item = json.at("console");
    assign_if(item, "refresh_ms", config.console.refresh_ms);
    assign_if(item, "show_job_events", config.console.show_job_events);
    assign_if(item, "show_best_hash", config.console.show_best_hash);
  }
  if (json.contains("logging")) {
    const auto& item = json.at("logging");
    std::string directory = config.logging.directory.string();
    assign_if(item, "directory", directory);
    config.logging.directory = config.project_root / directory;
    assign_if(item, "save_session_log", config.logging.save_session_log);
    assign_if(item, "save_block_candidates", config.logging.save_block_candidates);
  } else {
    config.logging.directory = config.project_root / config.logging.directory;
  }
  if (json.contains("checkpoint")) assign_if(json.at("checkpoint"), "interval_ms", config.checkpoint_interval_ms);

  if (json.contains("historical")) {
    const auto& item = json.at("historical");
    assign_if(item, "header_hex", config.historical.header_hex);
    if (item.contains("known_nonce") && !item.at("known_nonce").is_null()) config.historical.known_nonce = item.at("known_nonce").get<std::uint32_t>();
    assign_if(item, "expected_hash", config.historical.expected_hash);
    assign_if(item, "target_hex", config.historical.target_hex);
    assign_if(item, "scan_full_nonce_space", config.historical.scan_full_nonce_space);
    assign_if(item, "nonce_start", config.historical.nonce_start);
    assign_if(item, "nonce_end", config.historical.nonce_end);
  }
  if (json.contains("research")) {
    const auto& item = json.at("research");
    assign_if(item, "enabled", config.research.enabled);
    assign_if(item, "round_start", config.research.round_start);
    assign_if(item, "round_end", config.research.round_end);
    assign_if(item, "sample_count", config.research.sample_count);
    if (item.contains("trace_analysis")) {
      const auto& analysis = item.at("trace_analysis");
      assign_if(analysis, "enabled", config.research.trace_analysis.enabled);
      assign_if(analysis, "single_bit_flips", config.research.trace_analysis.single_bit_flips);
      assign_if(analysis, "neighbor_radius", config.research.trace_analysis.neighbor_radius);
      assign_if(analysis, "control_nonces", config.research.trace_analysis.control_nonces);
      assign_if(analysis, "save_full_trajectories", config.research.trace_analysis.save_full_trajectories);
    }
  }
  if (json.contains("benchmark")) {
    const auto& item = json.at("benchmark");
    assign_if(item, "cpu_threads", config.benchmark.cpu_threads);
    assign_if(item, "warmup_ms", config.benchmark.warmup_ms);
    assign_if(item, "measurement_ms", config.benchmark.measurement_ms);
    assign_if(item, "header_hex", config.benchmark.header_hex);
    std::string profile = config.benchmark.performance_profile.string();
    assign_if(item, "performance_profile", profile);
    config.benchmark.performance_profile = profile;
  }

  if (config.gpu.profile.is_relative()) config.gpu.profile = config.project_root / config.gpu.profile;
  if (config.benchmark.performance_profile.is_relative()) {
    config.benchmark.performance_profile = config.project_root / config.benchmark.performance_profile;
  }

  if (config.cpu.enabled && config.cpu.threads == 0) throw std::invalid_argument("cpu.threads must be positive");
  if (config.checkpoint_interval_ms < 250) throw std::invalid_argument("checkpoint.interval_ms must be at least 250");
  if (config.mode == Mode::Live && config.ckpool.username == "CHANGE_ME") {
    throw std::invalid_argument("live mode is locked: replace ckpool.username with your Bitcoin address[.worker]");
  }
  if ((config.mode == Mode::HistoricalTest || config.mode == Mode::Research) && config.historical.header_hex.size() != 160) {
    throw std::invalid_argument("offline modes require historical.header_hex with exactly 80 bytes (160 hex characters)");
  }
  if (config.mode == Mode::HistoricalTest && config.historical.target_hex.size() != 64) {
    throw std::invalid_argument("historical_test requires a 256-bit target_hex");
  }
  if (config.mode == Mode::Benchmark) {
    if (!config.cpu.enabled && !config.gpu.enabled) {
      throw std::invalid_argument("benchmark requires at least one enabled worker");
    }
    if (config.benchmark.header_hex.size() != 160) {
      throw std::invalid_argument("benchmark requires benchmark.header_hex with exactly 80 bytes (160 hex characters)");
    }
    if (config.benchmark.warmup_ms < 100) {
      throw std::invalid_argument("benchmark.warmup_ms must be at least 100");
    }
    if (config.benchmark.measurement_ms < 500) {
      throw std::invalid_argument("benchmark.measurement_ms must be at least 500");
    }
    if (config.cpu.enabled && (config.benchmark.cpu_threads.empty() ||
        std::any_of(config.benchmark.cpu_threads.begin(), config.benchmark.cpu_threads.end(),
                    [](const unsigned threads) { return threads == 0; }))) {
      throw std::invalid_argument("benchmark.cpu_threads must contain positive values");
    }
  }
  if (config.historical.nonce_end > 0x100000000ULL || config.historical.nonce_start >= config.historical.nonce_end) {
    throw std::invalid_argument("historical nonce range must be non-empty and contained in [0,2^32)");
  }
  if (config.research.round_start < 1 || config.research.round_end > 64 || config.research.round_start > config.research.round_end) {
    throw std::invalid_argument("research rounds must form a range inside [1,64]");
  }
  return config;
}

std::string mode_name(const Mode mode) {
  switch (mode) {
    case Mode::Live: return "live";
    case Mode::HistoricalTest: return "historical_test";
    case Mode::Research: return "research";
    case Mode::MockStratum: return "mock_stratum";
    case Mode::Benchmark: return "benchmark";
  }
  return "unknown";
}

}  // namespace srm::config
