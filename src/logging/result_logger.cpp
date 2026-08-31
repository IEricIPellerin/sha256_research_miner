#include "logging/result_logger.h"

#include "checkpoint/state_store.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>

namespace srm::logging {
namespace {

std::string file_timestamp() {
  const auto now = std::chrono::system_clock::now();
  const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
  const auto time = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &time);
#else
  gmtime_r(&time, &utc);
#endif
  std::ostringstream output;
  output << std::put_time(&utc, "%Y%m%d_%H%M%S_") << std::setfill('0') << std::setw(3) << millis.count();
  return output.str();
}

}  // namespace

ResultLogger::ResultLogger(std::filesystem::path directory, const bool session_log, const bool block_candidates)
    : directory_(std::move(directory)), session_log_(session_log), block_candidates_(block_candidates) {
  std::filesystem::create_directories(directory_);
  session_path_ = directory_ / ("session_" + file_timestamp() + ".log");
}

void ResultLogger::event(const std::string& text) {
  if (!session_log_) return;
  std::scoped_lock lock(mutex_);
  std::ofstream output(session_path_, std::ios::app);
  output << utc_now() << ' ' << text << '\n';
}

std::filesystem::path ResultLogger::save_candidate(mining::Solution& solution) {
  if (!block_candidates_) return {};
  std::scoped_lock lock(mutex_);
  do {
    solution.result_file = directory_ / ("block_candidate_" + file_timestamp() + ".json");
    if (std::filesystem::exists(solution.result_file)) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  } while (std::filesystem::exists(solution.result_file));
  checkpoint::StateStore(solution.result_file).save(to_json(solution));
  return solution.result_file;
}

void ResultLogger::update_candidate(const mining::Solution& solution) {
  if (!solution.result_file.empty()) checkpoint::StateStore(solution.result_file).save(to_json(solution));
}

void ResultLogger::save_json_atomic(const std::filesystem::path& path, const nlohmann::json& value) const {
  checkpoint::StateStore(path).save(value);
}

std::string ResultLogger::utc_now() {
  const auto now = std::chrono::system_clock::now();
  const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
  const auto time = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &time);
#else
  gmtime_r(&time, &utc);
#endif
  std::ostringstream output;
  output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S.") << std::setfill('0') << std::setw(3) << millis.count() << 'Z';
  return output.str();
}

nlohmann::json ResultLogger::to_json(const mining::Solution& value) {
  nlohmann::json result = {
      {"job_id", value.job_id}, {"username", value.username}, {"extranonce1", value.extranonce1},
      {"extranonce2", value.extranonce2}, {"version", value.version}, {"prevhash", value.prevhash},
      {"merkle_root", value.merkle_root}, {"ntime", value.ntime}, {"nbits", value.nbits},
      {"nonce", value.nonce}, {"header_hex", value.header_hex}, {"hash", value.hash},
      {"network_target", value.network_target}, {"share_target", value.share_target},
      {"detected_timestamp_utc", value.detected_timestamp_utc},
      {"submitted_timestamp_utc", value.submitted_timestamp_utc},
      {"submission_latency_us", value.submission_latency_us},
      {"network_candidate", value.network_candidate}, {"offline", value.offline}};
  result["server_response"] = value.server_response ? nlohmann::json(*value.server_response) : nlohmann::json(nullptr);
  return result;
}

}  // namespace srm::logging
