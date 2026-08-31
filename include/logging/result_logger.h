#pragma once

#include "mining/solution.h"

#include <filesystem>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

namespace srm::logging {

class ResultLogger {
 public:
  ResultLogger(std::filesystem::path directory, bool session_log, bool block_candidates);

  void event(const std::string& text);
  std::filesystem::path save_candidate(mining::Solution& solution);
  void update_candidate(const mining::Solution& solution);
  void save_json_atomic(const std::filesystem::path& path, const nlohmann::json& value) const;

  static std::string utc_now();

 private:
  static nlohmann::json to_json(const mining::Solution& solution);

  std::filesystem::path directory_;
  std::filesystem::path session_path_;
  bool session_log_;
  bool block_candidates_;
  mutable std::mutex mutex_;
};

}  // namespace srm::logging

