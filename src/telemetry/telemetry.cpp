//src\telemetry\telemetry.cpp
#include "telemetry/telemetry.h"

#include <algorithm>
#include <iomanip>
#include <iostream>

namespace srm::telemetry {

Telemetry::Telemetry(const unsigned refresh_ms) : refresh_ms_(refresh_ms) {}
Telemetry::~Telemetry() { stop(); }

void Telemetry::start() {
  if (!thread_.joinable()) thread_ = std::jthread([this](const std::stop_token token) { render(token); });
}

void Telemetry::stop() {
  if (!thread_.joinable()) return;
  thread_.request_stop();
  thread_.join();
}

void Telemetry::event(const std::string& text) {
  std::scoped_lock lock(mutex_);
  std::cout << text << std::endl;
}

void Telemetry::set_connection(const bool connected, const bool authorized, std::string endpoint) {
  std::scoped_lock lock(mutex_);
  connected_ = connected;
  authorized_ = authorized;
  endpoint_ = std::move(endpoint);
}

void Telemetry::set_job(std::string job_id, std::string prevhash, const bool clean_jobs,
                        const double share_difficulty, std::string network_target) {
  std::scoped_lock lock(mutex_);
  job_id_ = std::move(job_id);
  prevhash_ = std::move(prevhash);
  clean_jobs_ = clean_jobs;
  share_difficulty_ = share_difficulty;
  network_target_ = std::move(network_target);
}

void Telemetry::set_worker_state(const unsigned cpu_threads, std::string cpu_extranonce2,
                                 std::string gpu_name, std::string gpu_extranonce2) {
  std::scoped_lock lock(mutex_);
  cpu_threads_ = cpu_threads;
  cpu_extranonce2_ = std::move(cpu_extranonce2);
  gpu_name_ = std::move(gpu_name);
  gpu_extranonce2_ = std::move(gpu_extranonce2);
}

void Telemetry::observe_best(const std::string& hash) {
  std::scoped_lock lock(mutex_);
  if (best_hash_.empty() || hash < best_hash_) best_hash_ = hash;
}

void Telemetry::set_progress(const std::uint64_t nonce_start, const std::uint64_t nonce_next,
                             const std::uint64_t nonce_end) {
  nonce_start_.store(nonce_start, std::memory_order_relaxed);
  nonce_next_.store(nonce_next, std::memory_order_relaxed);
  nonce_end_.store(nonce_end, std::memory_order_relaxed);
}

void Telemetry::render(const std::stop_token token) {
  auto previous_time = std::chrono::steady_clock::now();
  std::uint64_t previous_cpu = 0;
  std::uint64_t previous_gpu = 0;
  while (!token.stop_requested()) {
    auto remaining = std::chrono::milliseconds(refresh_ms_);
    while (!token.stop_requested() && remaining.count() > 0) {
      const auto slice = std::min(remaining, std::chrono::milliseconds(100));
      std::this_thread::sleep_for(slice);
      remaining -= slice;
    }
    if (token.stop_requested()) break;
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration<double>(now - previous_time).count();
    const auto cpu = cpu_hashes.load(std::memory_order_relaxed);
    const auto gpu = gpu_hashes.load(std::memory_order_relaxed);
    const auto cpu_rate = elapsed > 0 ? (cpu - previous_cpu) / elapsed : 0.0;
    const auto gpu_rate = elapsed > 0 ? (gpu - previous_gpu) / elapsed : 0.0;
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - started_).count();
    const auto range_start = nonce_start_.load(std::memory_order_relaxed);
    const auto range_next = nonce_next_.load(std::memory_order_relaxed);
    const auto range_end = nonce_end_.load(std::memory_order_relaxed);
    const auto range_length = range_end > range_start ? range_end - range_start : 0;
    const auto range_done = range_next > range_start ? std::min(range_next, range_end) - range_start : 0;
    const auto progress = range_length > 0 ? 100.0 * static_cast<double>(range_done) / static_cast<double>(range_length) : 0.0;
    const auto total_rate = cpu_rate + gpu_rate;
    const auto eta = total_rate > 0.0 && range_end > range_next
                         ? static_cast<std::uint64_t>(static_cast<double>(range_end - range_next) / total_rate)
                         : 0ULL;
    previous_time = now; previous_cpu = cpu; previous_gpu = gpu;

    std::scoped_lock lock(mutex_);
    const auto short_prev = prevhash_.size() > 16 ? prevhash_.substr(0, 16) + "…" : prevhash_;
    const auto short_best = best_hash_.size() > 20 ? best_hash_.substr(0, 20) + "…" : best_hash_;
    const auto short_target = network_target_.size() > 16 ? network_target_.substr(0, 16) + "…" : network_target_;
    std::cout << "[STAT] " << (connected_ ? "connecté" : "hors-ligne")
              << '/' << (authorized_ ? "autorisé" : "non-autorisé")
              << " job=" << (job_id_.empty() ? "-" : job_id_)
              << " prev=" << (short_prev.empty() ? "-" : short_prev)
              << " endpoint=" << (endpoint_.empty() ? "-" : endpoint_)
              << " clean=" << (clean_jobs_ ? "true" : "false")
              << " diff=" << share_difficulty_
              << " target=" << (short_target.empty() ? "-" : short_target)
              << " ex2(C/G)=" << (cpu_extranonce2_.empty() ? "-" : cpu_extranonce2_)
              << '/' << (gpu_extranonce2_.empty() ? "-" : gpu_extranonce2_)
              << " CPU=" << std::fixed << std::setprecision(2) << cpu_rate / 1e6 << " MH/s(" << cpu_threads_ << ')'
              << " GPU=" << gpu_rate / 1e6 << " MH/s(" << gpu_name_ << ')'
              << " total_rate=" << total_rate / 1e6 << " MH/s"
              << " total=" << (cpu + gpu)
              << " headers=" << headers_complete.load()
              << " progress=" << progress << "% ETA=" << eta << 's'
              << " shares=" << shares.load() << '/' << accepted.load() << '/' << rejected.load()
              << " stale=" << stale_jobs.load()
              << " best=" << (short_best.empty() ? "-" : short_best)
              << " uptime=" << uptime << "s" << std::endl;
  }
}

}  // namespace srm::telemetry
