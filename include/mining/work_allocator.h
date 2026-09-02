//include\mining\work_allocator.h
#pragma once

#include "checkpoint/state_store.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace srm::mining {

enum class WorkStatus { Pending, InProgress, Complete, Stale };
enum class WorkerKind { Cpu, Gpu };

struct WorkUnit {
  std::string id;
  std::string job_id;
  std::string prevhash;
  std::string extranonce2;
  std::uint64_t nonce_start{0};
  std::uint64_t nonce_end{0};  // exclusive, may equal 2^32
  std::uint64_t nonce_next{0};
  WorkStatus status{WorkStatus::Pending};
  WorkerKind worker{WorkerKind::Cpu};
  std::uint64_t generation{0};
  std::uint64_t hashes_tested{0};
  std::string best_hash;
  std::optional<std::uint32_t> best_nonce;
};

class WorkAllocator {
 public:
  WorkAllocator(checkpoint::StateStore store, std::string mode);

  bool prepare_live_job(const std::string& job_id,
                        const std::string& prevhash,
                        const std::string& extranonce1,
                        unsigned extranonce2_size,
                        const std::string& work_fingerprint,
                        unsigned cpu_workers,
                        bool gpu_enabled,
                        std::uint64_t generation);
  bool prepare_historical(const std::string& header_id,
                          std::uint64_t nonce_start,
                          std::uint64_t nonce_end,
                          unsigned workers,
                          unsigned round);

  std::optional<WorkUnit> acquire(WorkerKind kind);
  void update_progress(const std::string& id,
                       std::uint64_t nonce_next,
                       std::uint64_t hashes_delta,
                       const std::string& best_hash = {},
                       std::optional<std::uint32_t> best_nonce = std::nullopt);
  void complete(const std::string& id);
  void release(const std::string& id);
  void mark_generation_stale(std::uint64_t generation);
  void mark_all_stale();

  nlohmann::json snapshot() const;
  void checkpoint(const nlohmann::json& extra = nlohmann::json::object()) const;
  std::vector<WorkUnit> units() const;

 private:
  static std::string encode_extranonce2(std::uint64_t value, unsigned size);
  void load_existing();
  void create_units(const std::string& job_id,
                    const std::string& prevhash,
                    unsigned extranonce2_size,
                    unsigned cpu_workers,
                    bool gpu_enabled,
                    std::uint64_t generation);
  void append_live_group(WorkerKind kind,
                         const std::string& job_id,
                         const std::string& prevhash,
                         unsigned extranonce2_size,
                         unsigned cpu_workers,
                         std::uint64_t generation,
                         std::uint64_t extranonce_counter);

  checkpoint::StateStore store_;
  std::string mode_;
  mutable std::mutex checkpoint_mutex_;
  mutable std::mutex mutex_;
  std::vector<WorkUnit> units_;
  nlohmann::json metadata_;
};

std::string status_name(WorkStatus status);
std::string worker_name(WorkerKind worker);

}  // namespace srm::mining
