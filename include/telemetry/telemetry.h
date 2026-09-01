//include\telemetry\telemetry.h
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace srm::telemetry {

class Telemetry {
 public:
  explicit Telemetry(unsigned refresh_ms = 1000);
  ~Telemetry();

  void start();
  void stop();
  void event(const std::string& text);
  void set_connection(bool connected, bool authorized, std::string endpoint);
  void set_job(std::string job_id, std::string prevhash, bool clean_jobs, double share_difficulty, std::string network_target);
  void set_worker_state(unsigned cpu_threads, std::string cpu_extranonce2,
                        std::string gpu_name, std::string gpu_extranonce2);
  void set_cpu_extranonce2(std::string extranonce2);
  void set_gpu_extranonce2(std::string extranonce2);
  void set_gpu_progress(std::uint64_t nonce_start,
                        std::uint64_t nonce_next,
                        std::uint64_t nonce_end);
  void observe_best(const std::string& hash);

  std::atomic<std::uint64_t> cpu_hashes{0};
  std::atomic<std::uint64_t> gpu_hashes{0};
  std::atomic<std::uint64_t> headers_complete{0};
  std::atomic<std::uint64_t> shares{0};
  std::atomic<std::uint64_t> accepted{0};
  std::atomic<std::uint64_t> rejected{0};
  std::atomic<std::uint64_t> stale_jobs{0};

 private:
  void render(std::stop_token token);

  unsigned refresh_ms_;
  std::chrono::steady_clock::time_point started_{std::chrono::steady_clock::now()};
  std::jthread thread_;
  mutable std::mutex mutex_;
  bool connected_{false};
  bool authorized_{false};
  bool clean_jobs_{false};
  std::string endpoint_;
  std::string job_id_;
  std::string prevhash_;
  std::string network_target_;
  std::string cpu_extranonce2_;
  std::string gpu_extranonce2_;
  std::string gpu_name_{"absent"};
  std::string best_hash_;
  double share_difficulty_{1.0};
  unsigned cpu_threads_{0};
  std::atomic<std::uint64_t> gpu_nonce_start_{0};
  std::atomic<std::uint64_t> gpu_nonce_next_{0};
  std::atomic<std::uint64_t> gpu_nonce_end_{0};
};

}  // namespace srm::telemetry
