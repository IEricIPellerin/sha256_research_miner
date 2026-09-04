//include\logging\best_pow_tracker.h
#pragma once

#include "mining/solution.h"

#include <chrono>
#include <filesystem>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

namespace srm::logging {

struct BestPowUpdate {
  bool is_record{false};
  std::string previous_hash;
  double previous_difficulty{0.0};
};

class BestPowTracker {
 public:
  explicit BestPowTracker(std::filesystem::path results_directory);

  BestPowUpdate observe(mining::Solution& solution,
                        std::uint64_t total_hashes,
                        std::uint64_t uptime_ms);
  [[nodiscard]] std::string best_hash() const;
  [[nodiscard]] nlohmann::json snapshot() const;

 private:
  static nlohmann::json record_json(const mining::Solution& solution,
                                    const std::string& previous_hash,
                                    double previous_difficulty,
                                    std::uint64_t hashes_since_previous,
                                    double seconds_since_previous);
  void append_record(const nlohmann::json& value) const;

  std::filesystem::path statistics_directory_;
  std::filesystem::path current_path_;
  std::filesystem::path records_path_;
  mutable std::mutex mutex_;
  nlohmann::json current_{nlohmann::json::object()};
  std::chrono::steady_clock::time_point last_record_time_{};
  bool record_seen_this_session_{false};
};

}  // namespace srm::logging
