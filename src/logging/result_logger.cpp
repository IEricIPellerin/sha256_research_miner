//src\logging\result_logger.cpp
#include "logging/result_logger.h"

#include "checkpoint/state_store.h"
#include "platform/windows_utf8.h"

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

ResultLogger::ResultLogger(std::filesystem::path directory,
                           const bool session_log,
                           const bool block_candidates,
                           const bool share_audits,
                           const unsigned share_audit_retention_hours,
                           const double permanent_high_difficulty_threshold)
    : directory_(std::move(directory)), session_log_(session_log),
      block_candidates_(block_candidates), share_audits_(share_audits),
      share_audit_retention_hours_(share_audit_retention_hours),
      permanent_high_difficulty_threshold_(permanent_high_difficulty_threshold) {
  std::error_code error;
  std::filesystem::create_directories(directory_, error);
  if (error) {
    throw checkpoint::PersistenceError(
        "cannot create result directory " + platform::path_utf8(directory_) + ": " +
        platform::error_message_utf8(error));
  }
  session_path_ = directory_ / ("session_" + file_timestamp() + ".log");
  purge_expired_share_audits();
}

void ResultLogger::event(const std::string& text) {
  if (!session_log_) return;
  std::scoped_lock lock(mutex_);
  std::ofstream output(session_path_, std::ios::binary | std::ios::app);
  output << utc_now() << ' ' << text << '\n';
}

std::filesystem::path ResultLogger::unique_result_path(const std::string& prefix) const {
  std::filesystem::path path;
  do {
    path = directory_ / (prefix + file_timestamp() + ".json");
    std::error_code error;
    const auto exists = std::filesystem::exists(path, error);
    if (error) {
      throw checkpoint::PersistenceError(
          "cannot inspect result path " + platform::path_utf8(path) + ": " +
          platform::error_message_utf8(error));
    }
    if (!exists) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  } while (true);
  return path;
}

std::filesystem::path ResultLogger::save_candidate(mining::Solution& solution) {
  if (!block_candidates_) return {};
  std::scoped_lock lock(mutex_);
  solution.result_file = unique_result_path("block_candidate_");
  checkpoint::StateStore(solution.result_file).save(candidate_json(solution));
  return solution.result_file;
}

void ResultLogger::update_candidate(const mining::Solution& solution) {
  if (solution.result_file.empty()) return;
  std::scoped_lock lock(mutex_);
  checkpoint::StateStore(solution.result_file).save(candidate_json(solution));
}

std::filesystem::path ResultLogger::save_share_audit(mining::Solution& solution) {
  if (!share_audits_) return {};
  std::scoped_lock lock(mutex_);
  const auto timestamp = file_timestamp();
  const auto segment = timestamp.substr(0, 11) + "00";
  solution.share_audit_file = directory_ / "share_audit_recent" / ("shares_" + segment + ".jsonl");
  std::error_code error;
  std::filesystem::create_directories(solution.share_audit_file.parent_path(), error);
  if (error) throw checkpoint::PersistenceError("cannot create recent share audit directory");
  std::ofstream output(solution.share_audit_file, std::ios::binary | std::ios::app);
  if (!output) throw checkpoint::PersistenceError("cannot append recent share audit segment");
  auto value = share_audit_json(solution);
  value["lifecycle_event"] = "detected";
  output << value.dump() << '\n';
  output.flush();
  if (!output) throw checkpoint::PersistenceError("cannot flush recent share audit segment");
  return solution.share_audit_file;
}

void ResultLogger::update_share_audit(const mining::Solution& solution) {
  if (solution.share_audit_file.empty()) return;
  std::scoped_lock lock(mutex_);
  std::ofstream output(solution.share_audit_file, std::ios::binary | std::ios::app);
  if (!output) throw checkpoint::PersistenceError("cannot update recent share audit segment");
  auto value = share_audit_json(solution);
  value["lifecycle_event"] = "submission_update";
  output << value.dump() << '\n';
  output.flush();
  if (!output) throw checkpoint::PersistenceError("cannot flush recent share audit update");
}

void ResultLogger::save_permanent_event(const mining::Solution& solution, const std::string& reason) {
  if (!solution.network_candidate && !solution.personal_record &&
      solution.hash_difficulty < permanent_high_difficulty_threshold_) return;
  auto value = share_audit_json(solution);
  value["schema_version"] = 1;
  value["permanent_reason"] = reason;
  append_jsonl(std::filesystem::path("statistics") / "high_difficulty_shares.jsonl", value);
}

std::size_t ResultLogger::purge_expired_share_audits() {
  if (share_audit_retention_hours_ == 0) return 0;
  std::scoped_lock lock(mutex_);
  const auto cutoff = std::filesystem::file_time_type::clock::now() -
      std::chrono::hours(share_audit_retention_hours_);
  std::size_t removed = 0;
  const auto purge_directory = [&](const std::filesystem::path& root, const bool legacy_only) {
    std::error_code iterator_error;
    if (!std::filesystem::exists(root, iterator_error) || iterator_error) return;
    for (std::filesystem::directory_iterator it(root, iterator_error), end;
         !iterator_error && it != end; it.increment(iterator_error)) {
      if (!it->is_regular_file()) continue;
      const auto name = it->path().filename().string();
      if (legacy_only && !name.starts_with("share_audit_")) continue;
      std::error_code time_error;
      const auto modified = it->last_write_time(time_error);
      if (time_error || modified >= cutoff) continue;
      std::error_code remove_error;
      if (std::filesystem::remove(it->path(), remove_error) && !remove_error) ++removed;
    }
  };
  purge_directory(directory_ / "share_audit_recent", false);
  purge_directory(directory_, true);
  return removed;
}

void ResultLogger::save_json_atomic(const std::filesystem::path& path, const nlohmann::json& value) const {
  std::scoped_lock lock(mutex_);
  checkpoint::StateStore(path).save(value);
}

void ResultLogger::append_jsonl(
    const std::filesystem::path& filename,
    const nlohmann::json& value) const {
  std::scoped_lock lock(mutex_);

  const auto path = directory_ / filename;

  std::error_code directory_error;
  std::filesystem::create_directories(path.parent_path(), directory_error);
  if (directory_error) {
    throw checkpoint::PersistenceError(
        "cannot create JSONL archive directory " + platform::path_utf8(path.parent_path()));
  }

  std::ofstream output(
      path,
      std::ios::binary | std::ios::app);

  if (!output) {
    throw checkpoint::PersistenceError(
        "cannot open JSONL archive " +
        platform::path_utf8(path));
  }

  output << value.dump() << '\n';
  output.flush();

  if (!output) {
    throw checkpoint::PersistenceError(
        "cannot append JSONL archive " +
        platform::path_utf8(path));
  }
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

nlohmann::json ResultLogger::candidate_json(const mining::Solution& value) {
  nlohmann::json result = {
      {"job_id", value.job_id}, {"username", value.username}, {"extranonce1", value.extranonce1},
      {"extranonce2", value.extranonce2}, {"version", value.version}, {"prevhash", value.prevhash},
      {"merkle_root", value.merkle_root}, {"ntime", value.ntime}, {"nbits", value.nbits},
      {"nonce", value.nonce}, {"nonce_uint32", value.nonce_value},
      {"nonce_header_le", value.nonce_header_le}, {"header_hex", value.header_hex}, {"hash", value.hash},
      {"network_target", value.network_target}, {"share_target", value.share_target},
      {"hash_difficulty", value.hash_difficulty},
      {"network_difficulty", value.network_difficulty},
      {"best_to_network_ratio", value.network_difficulty_ratio},
      {"worker", value.worker},
      {"detected_timestamp_utc", value.detected_timestamp_utc},
      {"submitted_timestamp_utc", value.submitted_timestamp_utc.empty()
          ? nlohmann::json(nullptr) : nlohmann::json(value.submitted_timestamp_utc)},
      {"response_timestamp_utc", value.response_timestamp_utc.empty()
          ? nlohmann::json(nullptr) : nlohmann::json(value.response_timestamp_utc)},
      {"submission_status", value.submission_status},
      {"submission_latency_us", value.submission_latency_us},
      {"network_candidate", value.network_candidate}, {"share_candidate", value.share_candidate},
      {"personal_record", value.personal_record}, {"offline", value.offline}};
  result["submission_id"] = value.submission_id ? nlohmann::json(*value.submission_id) : nlohmann::json(nullptr);
  result["accepted"] = value.accepted ? nlohmann::json(*value.accepted) : nlohmann::json(nullptr);
  result["server_response"] = value.server_response ? *value.server_response : nlohmann::json(nullptr);
  result["local_submission_error"] = value.local_submission_error
      ? nlohmann::json(*value.local_submission_error) : nlohmann::json(nullptr);
  return result;
}

nlohmann::json ResultLogger::share_audit_json(const mining::Solution& value) {
  const auto nullable_timestamp = [](const std::string& timestamp) {
    return timestamp.empty() ? nlohmann::json(nullptr) : nlohmann::json(timestamp);
  };
  return {
      {"schema_version", 1},
      {"metadata", {
          {"detected_timestamp_utc", value.detected_timestamp_utc},
          {"submitted_timestamp_utc", nullable_timestamp(value.submitted_timestamp_utc)},
          {"response_timestamp_utc", nullable_timestamp(value.response_timestamp_utc)}}},
      {"stratum_job", {
          {"job_id", value.job_id}, {"clean_jobs", value.clean_jobs},
          {"prevhash", value.prevhash}, {"coinbase1", value.coinbase1},
          {"coinbase2", value.coinbase2}, {"merkle_branches", value.merkle_branches},
          {"version", value.version}, {"nbits", value.nbits}, {"ntime", value.ntime},
          {"extranonce1", value.extranonce1}, {"extranonce2", value.extranonce2},
          {"extranonce2_size", value.extranonce2_size},
          {"work_fingerprint", value.work_fingerprint}}},
      {"targets", {
          {"share_difficulty", value.share_difficulty}, {"share_target", value.share_target},
          {"network_target", value.network_target}, {"hash_difficulty", value.hash_difficulty},
          {"network_difficulty", value.network_difficulty}}},
      {"work", {
          {"merkle_root", value.merkle_root}, {"header_hex", value.header_hex},
          {"hash_bitcoin_display", value.hash}, {"network_candidate", value.network_candidate},
          {"share_candidate", value.share_candidate}, {"personal_record", value.personal_record},
          {"worker", value.worker}}},
      {"nonce", {
          {"uint32", value.nonce_value}, {"stratum_hex", value.nonce},
          {"header_little_endian_hex", value.nonce_header_le}}},
      {"submission", {
          {"status", value.submission_status}, {"username", value.username},
          {"job_id", value.job_id}, {"extranonce2", value.extranonce2},
          {"ntime", value.ntime}, {"nonce", value.nonce},
          {"submission_id", value.submission_id ? nlohmann::json(*value.submission_id) : nlohmann::json(nullptr)},
          {"accepted", value.accepted ? nlohmann::json(*value.accepted) : nlohmann::json(nullptr)},
          {"server_response", value.server_response ? *value.server_response : nlohmann::json(nullptr)},
          {"submission_latency_us", value.response_timestamp_utc.empty()
              ? nlohmann::json(nullptr) : nlohmann::json(value.submission_latency_us)},
          {"local_error", value.local_submission_error
              ? nlohmann::json(*value.local_submission_error) : nlohmann::json(nullptr)}}}};
}

}  // namespace srm::logging
