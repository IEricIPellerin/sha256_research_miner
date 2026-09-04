//src\logging\best_pow_tracker.cpp
#include "logging/best_pow_tracker.h"

#include "bitcoin/difficulty.h"
#include "checkpoint/state_store.h"
#include "logging/result_logger.h"
#include "platform/windows_utf8.h"

#include <fstream>
#include <limits>
#include <stdexcept>

namespace srm::logging {

BestPowTracker::BestPowTracker(std::filesystem::path results_directory)
    : statistics_directory_(std::move(results_directory) / "statistics"),
      current_path_(statistics_directory_ / "best_pow_all_time.json"),
      records_path_(statistics_directory_ / "best_pow_records.jsonl") {
  current_ = checkpoint::StateStore(current_path_).load_or(nlohmann::json::object());
  const auto hash = current_.value("hash", "");
  if (!hash.empty() && hash.size() != 64U) {
    throw std::runtime_error("invalid persisted best PoW hash in " +
                             platform::path_utf8(current_path_));
  }
}

std::string BestPowTracker::best_hash() const {
  std::scoped_lock lock(mutex_);
  return current_.value("hash", "");
}

nlohmann::json BestPowTracker::snapshot() const {
  std::scoped_lock lock(mutex_);
  return current_;
}

nlohmann::json BestPowTracker::record_json(
    const mining::Solution& value,
    const std::string& previous_hash,
    const double previous_difficulty,
    const std::uint64_t hashes_since_previous,
    const double seconds_since_previous) {
  const auto nullable = [](const std::string& text) {
    return text.empty() ? nlohmann::json(nullptr) : nlohmann::json(text);
  };
  nlohmann::json result = {
      {"schema_version", 1},
      {"timestamp_utc", value.detected_timestamp_utc},
      {"hash", value.hash},
      {"hash_difficulty", value.hash_difficulty},
      {"network_difficulty", value.network_difficulty},
      {"best_to_network_ratio", value.network_difficulty_ratio},
      {"network_candidate", value.network_candidate},
      {"share_candidate", value.share_candidate},
      {"total_hashes_at_record", value.total_hashes_at_detection},
      {"uptime_ms_at_record", value.uptime_ms_at_detection},
      {"worker", value.worker},
      {"job_id", value.job_id},
      {"work_fingerprint", nullable(value.work_fingerprint)},
      {"prevhash", nullable(value.prevhash)},
      {"version", nullable(value.version)},
      {"nbits", nullable(value.nbits)},
      {"ntime", nullable(value.ntime)},
      {"extranonce1", nullable(value.extranonce1)},
      {"extranonce2", nullable(value.extranonce2)},
      {"extranonce2_size", value.extranonce2_size},
      {"nonce", value.nonce},
      {"nonce_uint32", value.nonce_value},
      {"nonce_header_le", value.nonce_header_le},
      {"header_hex", value.header_hex},
      {"merkle_root", nullable(value.merkle_root)},
      {"previous_best_hash", nullable(previous_hash)},
      {"previous_best_difficulty", previous_hash.empty()
          ? nlohmann::json(nullptr) : nlohmann::json(previous_difficulty)},
      {"hashes_since_previous_record", previous_hash.empty()
          ? nlohmann::json(nullptr) : nlohmann::json(hashes_since_previous)},
      {"seconds_since_previous_record", previous_hash.empty() || seconds_since_previous < 0.0
          ? nlohmann::json(nullptr) : nlohmann::json(seconds_since_previous)},
      {"improvement_ratio", previous_difficulty > 0.0
          ? nlohmann::json(value.hash_difficulty / previous_difficulty) : nlohmann::json(nullptr)},
  };
  return result;
}

void BestPowTracker::append_record(const nlohmann::json& value) const {
  std::error_code error;
  std::filesystem::create_directories(statistics_directory_, error);
  if (error) throw checkpoint::PersistenceError("cannot create statistics directory");
  std::ofstream output(records_path_, std::ios::binary | std::ios::app);
  if (!output) {
    throw checkpoint::PersistenceError("cannot append best PoW record history");
  }
  output << value.dump() << '\n';
  output.flush();
  if (!output) throw checkpoint::PersistenceError("cannot flush best PoW record history");
}

BestPowUpdate BestPowTracker::observe(mining::Solution& solution,
                                      const std::uint64_t total_hashes,
                                      const std::uint64_t uptime_ms) {
  std::scoped_lock lock(mutex_);
  if (solution.hash.size() != 64U) throw std::invalid_argument("best PoW hash must contain 64 hex characters");
  const auto hash_target = bitcoin::target_from_hex(solution.hash);
  const auto previous_hash = current_.value("hash", "");
  if (!previous_hash.empty()) {
    const auto previous_target = bitcoin::target_from_hex(previous_hash);
    if (!(hash_target.big_endian < previous_target.big_endian)) return {};
  }

  solution.hash_difficulty = bitcoin::difficulty_from_target(hash_target);
  const auto network_target = bitcoin::target_from_hex(solution.network_target);
  solution.network_difficulty = bitcoin::difficulty_from_target(network_target);
  solution.network_difficulty_ratio = solution.network_difficulty > 0.0
      ? solution.hash_difficulty / solution.network_difficulty : 0.0;
  solution.total_hashes_at_detection = total_hashes;
  solution.uptime_ms_at_detection = uptime_ms;
  solution.personal_record = true;

  const auto previous_difficulty = current_.value("hash_difficulty", 0.0);
  const auto previous_total = current_.value("total_hashes_at_record", 0ULL);
  const auto hashes_since = total_hashes >= previous_total ? total_hashes - previous_total : 0ULL;
  const auto now = std::chrono::steady_clock::now();
  const auto seconds_since = record_seen_this_session_
      ? std::chrono::duration<double>(now - last_record_time_).count() : -1.0;
  auto record = record_json(solution, previous_hash, previous_difficulty,
                            hashes_since, seconds_since);
  checkpoint::StateStore(current_path_).save(record);
  current_ = record;
  append_record(record);
  last_record_time_ = now;
  record_seen_this_session_ = true;
  return {true, previous_hash, previous_difficulty};
}

}  // namespace srm::logging
