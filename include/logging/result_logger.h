//include\logging\result_logger.h
#pragma once

#include "mining/solution.h"

#include <filesystem>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

namespace srm::logging {

class ResultLogger {
 public:
  ResultLogger(std::filesystem::path directory,
               bool session_log,
               bool block_candidates,
               bool share_audits = true,
               unsigned share_audit_retention_hours = 24,
               double permanent_high_difficulty_threshold = 10000.0);

  void event(const std::string& text);
  std::filesystem::path save_candidate(mining::Solution& solution);
  void update_candidate(const mining::Solution& solution);
  std::filesystem::path save_share_audit(mining::Solution& solution);
  void update_share_audit(const mining::Solution& solution);
  void save_permanent_event(const mining::Solution& solution, const std::string& reason);
  std::size_t purge_expired_share_audits();
  void save_json_atomic(const std::filesystem::path& path, const nlohmann::json& value) const;
  void append_jsonl(const std::filesystem::path& filename,
                    const nlohmann::json& value) const;

  static std::string utc_now();

 private:
  static nlohmann::json candidate_json(const mining::Solution& solution);
  static nlohmann::json share_audit_json(const mining::Solution& solution);
  std::filesystem::path unique_result_path(const std::string& prefix) const;

  std::filesystem::path directory_;
  std::filesystem::path session_path_;
  bool session_log_;
  bool block_candidates_;
  bool share_audits_;
  unsigned share_audit_retention_hours_;
  double permanent_high_difficulty_threshold_;
  mutable std::mutex mutex_;
};

}  // namespace srm::logging
