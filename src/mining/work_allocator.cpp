#include "mining/work_allocator.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>

namespace srm::mining {
namespace {

WorkStatus parse_status(const std::string& value) {
  if (value == "PENDING") return WorkStatus::Pending;
  if (value == "IN_PROGRESS") return WorkStatus::InProgress;
  if (value == "COMPLETE") return WorkStatus::Complete;
  if (value == "STALE") return WorkStatus::Stale;
  throw std::invalid_argument("unknown work status: " + value);
}

WorkerKind parse_worker(const std::string& value) {
  if (value == "CPU") return WorkerKind::Cpu;
  if (value == "GPU") return WorkerKind::Gpu;
  throw std::invalid_argument("unknown worker kind: " + value);
}

nlohmann::json to_json(const WorkUnit& unit) {
  nlohmann::json value = {
      {"id", unit.id}, {"job_id", unit.job_id}, {"prevhash", unit.prevhash},
      {"extranonce2", unit.extranonce2}, {"nonce_start", unit.nonce_start},
      {"nonce_end", unit.nonce_end}, {"nonce_next", unit.nonce_next},
      {"status", status_name(unit.status)}, {"worker", worker_name(unit.worker)},
      {"generation", unit.generation}, {"hashes_tested", unit.hashes_tested},
      {"best_hash", unit.best_hash}};
  value["best_nonce"] = unit.best_nonce ? nlohmann::json(*unit.best_nonce) : nlohmann::json(nullptr);
  return value;
}

WorkUnit from_json(const nlohmann::json& item) {
  WorkUnit unit;
  unit.id = item.at("id").get<std::string>();
  unit.job_id = item.at("job_id").get<std::string>();
  unit.prevhash = item.value("prevhash", "");
  unit.extranonce2 = item.value("extranonce2", "");
  unit.nonce_start = item.at("nonce_start").get<std::uint64_t>();
  unit.nonce_end = item.at("nonce_end").get<std::uint64_t>();
  unit.nonce_next = item.at("nonce_next").get<std::uint64_t>();
  unit.status = parse_status(item.at("status").get<std::string>());
  unit.worker = parse_worker(item.value("worker", "CPU"));
  unit.generation = item.value("generation", 0ULL);
  unit.hashes_tested = item.value("hashes_tested", 0ULL);
  unit.best_hash = item.value("best_hash", "");
  if (item.contains("best_nonce") && !item.at("best_nonce").is_null()) unit.best_nonce = item.at("best_nonce").get<std::uint32_t>();
  return unit;
}

}  // namespace

std::string status_name(const WorkStatus status) {
  switch (status) {
    case WorkStatus::Pending: return "PENDING";
    case WorkStatus::InProgress: return "IN_PROGRESS";
    case WorkStatus::Complete: return "COMPLETE";
    case WorkStatus::Stale: return "STALE";
  }
  return "STALE";
}

std::string worker_name(const WorkerKind worker) { return worker == WorkerKind::Cpu ? "CPU" : "GPU"; }

WorkAllocator::WorkAllocator(checkpoint::StateStore store, std::string mode)
    : store_(std::move(store)), mode_(std::move(mode)) {
  load_existing();
}

void WorkAllocator::load_existing() {
  const auto state = store_.load_or(nlohmann::json{{"schema_version", 1}, {"mode", mode_}, {"work_units", nlohmann::json::array()}});
  metadata_ = state;
  units_.clear();
  for (const auto& item : state.value("work_units", nlohmann::json::array())) {
    auto unit = from_json(item);
    if (unit.status == WorkStatus::InProgress) unit.status = WorkStatus::Pending;
    units_.push_back(std::move(unit));
  }
}

std::string WorkAllocator::encode_extranonce2(const std::uint64_t value, const unsigned size) {
  if (size > 8) throw std::invalid_argument("extranonce2_size greater than 8 is not supported by the allocator counter");
  if (size < 8 && value >= (std::uint64_t{1} << (size * 8U))) throw std::overflow_error("extranonce2 counter exhausted");
  std::ostringstream stream;
  stream << std::hex << std::setfill('0') << std::setw(static_cast<int>(size * 2U)) << value;
  return stream.str();
}

bool WorkAllocator::prepare_live_job(const std::string& job_id,
                                     const std::string& prevhash,
                                     const std::string& extranonce1,
                                     const unsigned extranonce2_size,
                                     const unsigned cpu_workers,
                                     const bool gpu_enabled,
                                     const std::uint64_t generation) {
  std::scoped_lock lock(mutex_);
  const bool compatible = metadata_.value("last_job_id", "") == job_id &&
                          metadata_.value("last_prevhash", "") == prevhash &&
                          metadata_.value("extranonce1", "") == extranonce1 &&
                          metadata_.value("extranonce2_size", 0U) == extranonce2_size &&
                          std::any_of(units_.begin(), units_.end(), [&](const WorkUnit& unit) {
                            return unit.job_id == job_id && unit.status != WorkStatus::Stale;
                          });
  if (!compatible) {
    for (auto& unit : units_) {
      if (unit.status != WorkStatus::Complete) unit.status = WorkStatus::Stale;
    }
    create_units(job_id, prevhash, extranonce2_size, cpu_workers, gpu_enabled, generation);
  } else {
    for (auto& unit : units_) {
      if (unit.status == WorkStatus::InProgress) unit.status = WorkStatus::Pending;
      if (unit.status == WorkStatus::Pending) unit.generation = generation;
    }
    if (extranonce2_size > 0) {
      auto next_counter = metadata_.value("next_extranonce2_counter", 0ULL);
      const auto has_cpu = std::any_of(units_.begin(), units_.end(), [&](const WorkUnit& unit) {
        return unit.job_id == job_id && unit.worker == WorkerKind::Cpu &&
               (unit.status == WorkStatus::Pending || unit.status == WorkStatus::InProgress);
      });
      if (!has_cpu) append_live_group(WorkerKind::Cpu, job_id, prevhash, extranonce2_size,
                                      cpu_workers, generation, next_counter++);
      const auto has_gpu = std::any_of(units_.begin(), units_.end(), [&](const WorkUnit& unit) {
        return unit.job_id == job_id && unit.worker == WorkerKind::Gpu &&
               (unit.status == WorkStatus::Pending || unit.status == WorkStatus::InProgress);
      });
      if (gpu_enabled && !has_gpu) append_live_group(WorkerKind::Gpu, job_id, prevhash,
                                                     extranonce2_size, cpu_workers, generation, next_counter++);
      metadata_["next_extranonce2_counter"] = next_counter;
    }
  }
  metadata_["last_job_id"] = job_id;
  metadata_["last_prevhash"] = prevhash;
  metadata_["extranonce1"] = extranonce1;
  metadata_["extranonce2_size"] = extranonce2_size;
  metadata_["cpu_workers"] = cpu_workers;
  metadata_["gpu_enabled"] = gpu_enabled;
  return compatible;
}

void WorkAllocator::create_units(const std::string& job_id,
                                 const std::string& prevhash,
                                 const unsigned extranonce2_size,
                                 const unsigned cpu_workers,
                                 const bool gpu_enabled,
                                 const std::uint64_t generation) {
  const auto cpu_count = std::max(1U, cpu_workers);
  const bool shared_nonce_space = extranonce2_size == 0 && gpu_enabled;
  const auto partitions = cpu_count + (shared_nonce_space ? 1U : 0U);
  const auto cpu_extranonce = encode_extranonce2(0, extranonce2_size);
  for (unsigned i = 0; i < cpu_count; ++i) {
    const auto start = (0x100000000ULL * i) / partitions;
    const auto end = (0x100000000ULL * (i + 1U)) / partitions;
    units_.push_back({job_id + "-g" + std::to_string(generation) + "-cpu-" + std::to_string(i),
                      job_id, prevhash, cpu_extranonce, start, end, start, WorkStatus::Pending,
                      WorkerKind::Cpu, generation, 0, "", std::nullopt});
  }
  if (gpu_enabled) {
    const auto gpu_extranonce = encode_extranonce2(extranonce2_size == 0 ? 0 : 1, extranonce2_size);
    const auto start = shared_nonce_space ? (0x100000000ULL * cpu_count) / partitions : 0ULL;
    units_.push_back({job_id + "-g" + std::to_string(generation) + "-gpu-0", job_id, prevhash,
                      gpu_extranonce, start, 0x100000000ULL, start, WorkStatus::Pending,
                      WorkerKind::Gpu, generation, 0, "", std::nullopt});
  }
  metadata_["next_extranonce2_counter"] = extranonce2_size == 0 ? 0ULL : (gpu_enabled ? 2ULL : 1ULL);
}

void WorkAllocator::append_live_group(const WorkerKind kind,
                                      const std::string& job_id,
                                      const std::string& prevhash,
                                      const unsigned extranonce2_size,
                                      const unsigned cpu_workers,
                                      const std::uint64_t generation,
                                      const std::uint64_t extranonce_counter) {
  const auto extranonce = encode_extranonce2(extranonce_counter, extranonce2_size);
  const auto suffix = "-g" + std::to_string(generation) + "-x" + extranonce;
  if (kind == WorkerKind::Gpu) {
    units_.push_back({job_id + suffix + "-gpu", job_id, prevhash, extranonce, 0, 0x100000000ULL,
                      0, WorkStatus::Pending, WorkerKind::Gpu, generation, 0, "", std::nullopt});
    return;
  }
  const auto count = std::max(1U, cpu_workers);
  for (unsigned i = 0; i < count; ++i) {
    const auto start = (0x100000000ULL * i) / count;
    const auto end = (0x100000000ULL * (i + 1U)) / count;
    units_.push_back({job_id + suffix + "-cpu-" + std::to_string(i), job_id, prevhash, extranonce,
                      start, end, start, WorkStatus::Pending, WorkerKind::Cpu, generation, 0, "", std::nullopt});
  }
}

bool WorkAllocator::prepare_historical(const std::string& header_id,
                                       const std::uint64_t nonce_start,
                                       const std::uint64_t nonce_end,
                                       const unsigned workers,
                                       const unsigned round) {
  std::scoped_lock lock(mutex_);
  const bool compatible = metadata_.value("header_id", "") == header_id &&
                          metadata_.value("current_round", 0U) == round &&
                          metadata_.value("nonce_start", 0ULL) == nonce_start &&
                          metadata_.value("nonce_end", 0ULL) == nonce_end &&
                          std::any_of(units_.begin(), units_.end(), [&](const WorkUnit& unit) {
                            return unit.job_id == header_id && unit.generation == round && unit.status != WorkStatus::Stale;
                          });
  if (!compatible) {
    for (auto& unit : units_) if (unit.status != WorkStatus::Complete) unit.status = WorkStatus::Stale;
    const auto count = std::max(1U, workers);
    const auto length = nonce_end - nonce_start;
    for (unsigned i = 0; i < count; ++i) {
      const auto start = nonce_start + (length * i) / count;
      const auto end = nonce_start + (length * (i + 1U)) / count;
      units_.push_back({header_id + "-r" + std::to_string(round) + "-cpu-" + std::to_string(i),
                        header_id, "", "", start, end, start, WorkStatus::Pending, WorkerKind::Cpu,
                        round, 0, "", std::nullopt});
    }
  }
  metadata_["header_id"] = header_id;
  metadata_["current_round"] = round;
  metadata_["nonce_start"] = nonce_start;
  metadata_["nonce_end"] = nonce_end;
  return compatible;
}

std::optional<WorkUnit> WorkAllocator::acquire(const WorkerKind kind) {
  std::scoped_lock lock(mutex_);
  for (auto& unit : units_) {
    if (unit.worker == kind && unit.status == WorkStatus::Pending && unit.nonce_next < unit.nonce_end) {
      unit.status = WorkStatus::InProgress;
      return unit;
    }
  }
  return std::nullopt;
}

void WorkAllocator::update_progress(const std::string& id,
                                    const std::uint64_t nonce_next,
                                    const std::uint64_t hashes_delta,
                                    const std::string& best_hash,
                                    const std::optional<std::uint32_t> best_nonce) {
  std::scoped_lock lock(mutex_);
  const auto found = std::find_if(units_.begin(), units_.end(), [&](const WorkUnit& unit) { return unit.id == id; });
  if (found == units_.end()) throw std::invalid_argument("unknown work unit: " + id);
  if (found->status == WorkStatus::Complete || found->status == WorkStatus::Stale) return;
  found->nonce_next = std::clamp(nonce_next, found->nonce_start, found->nonce_end);
  found->hashes_tested += hashes_delta;
  if (!best_hash.empty() && (found->best_hash.empty() || best_hash < found->best_hash)) {
    found->best_hash = best_hash;
    found->best_nonce = best_nonce;
  }
}

void WorkAllocator::complete(const std::string& id) {
  std::scoped_lock lock(mutex_);
  for (auto& unit : units_) if (unit.id == id) {
    unit.nonce_next = unit.nonce_end;
    unit.status = WorkStatus::Complete;
    if ((mode_ == "live" || mode_ == "mock_stratum") && metadata_.value("extranonce2_size", 0U) > 0) {
      const auto kind = unit.worker;
      const auto generation = unit.generation;
      const auto job_id = unit.job_id;
      const auto prevhash = unit.prevhash;
      const auto has_open = std::any_of(units_.begin(), units_.end(), [&](const WorkUnit& candidate) {
        return candidate.job_id == job_id && candidate.generation == generation && candidate.worker == kind &&
               (candidate.status == WorkStatus::Pending || candidate.status == WorkStatus::InProgress);
      });
      if (!has_open) {
        auto counter = metadata_.value("next_extranonce2_counter", 0ULL);
        append_live_group(kind, job_id, prevhash, metadata_.value("extranonce2_size", 0U),
                          metadata_.value("cpu_workers", 1U), generation, counter++);
        metadata_["next_extranonce2_counter"] = counter;
      }
    }
    return;
  }
  throw std::invalid_argument("unknown work unit: " + id);
}

void WorkAllocator::release(const std::string& id) {
  std::scoped_lock lock(mutex_);
  for (auto& unit : units_) if (unit.id == id && unit.status == WorkStatus::InProgress) { unit.status = WorkStatus::Pending; return; }
}

void WorkAllocator::mark_generation_stale(const std::uint64_t generation) {
  std::scoped_lock lock(mutex_);
  for (auto& unit : units_) if (unit.generation == generation && unit.status != WorkStatus::Complete) unit.status = WorkStatus::Stale;
}

void WorkAllocator::mark_all_stale() {
  std::scoped_lock lock(mutex_);
  for (auto& unit : units_) if (unit.status != WorkStatus::Complete) unit.status = WorkStatus::Stale;
}

nlohmann::json WorkAllocator::snapshot() const {
  std::scoped_lock lock(mutex_);
  auto state = metadata_;
  state["schema_version"] = 1;
  state["mode"] = mode_;
  state["work_units"] = nlohmann::json::array();
  std::uint64_t hashes_tested = 0;
  std::string best_hash;
  std::optional<std::uint32_t> best_nonce;
  nlohmann::json completed_ranges = nlohmann::json::array();
  std::map<std::string, bool> completed_extranonces;
  for (const auto& unit : units_) {
    state["work_units"].push_back(to_json(unit));
    hashes_tested += unit.hashes_tested;
    if (!unit.best_hash.empty() && (best_hash.empty() || unit.best_hash < best_hash)) {
      best_hash = unit.best_hash;
      best_nonce = unit.best_nonce;
    }
    if (unit.status == WorkStatus::Complete) {
      completed_ranges.push_back({{"job_id", unit.job_id}, {"extranonce2", unit.extranonce2},
                                  {"nonce_start", unit.nonce_start}, {"nonce_end", unit.nonce_end}});
    }
    if (!unit.extranonce2.empty() && unit.status != WorkStatus::Stale) {
      auto [entry, inserted] = completed_extranonces.emplace(unit.extranonce2, true);
      entry->second = entry->second && unit.status == WorkStatus::Complete;
    }
  }
  state["hashes_tested"] = hashes_tested;
  state["best_hash"] = best_hash;
  state["best_nonce"] = best_nonce ? nlohmann::json(*best_nonce) : nlohmann::json(nullptr);
  state["completed_ranges"] = std::move(completed_ranges);
  state["completed_extranonce2"] = nlohmann::json::array();
  for (const auto& [extranonce, complete] : completed_extranonces) if (complete) state["completed_extranonce2"].push_back(extranonce);
  return state;
}

void WorkAllocator::checkpoint(const nlohmann::json& extra) const {
  auto state = snapshot();
  state.update(extra, true);
  store_.save(state);
}

std::vector<WorkUnit> WorkAllocator::units() const {
  std::scoped_lock lock(mutex_);
  return units_;
}

}  // namespace srm::mining
