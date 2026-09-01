//src\mining\mining_controller.cpp
#include "mining/mining_controller.h"

#include "bitcoin/block_header.h"
#include "bitcoin/difficulty.h"
#include "checkpoint/state_store.h"
#include "crypto/reduced_sha256.h"
#include "crypto/sha256d.h"
#include "logging/result_logger.h"
#include "mining/benchmark.h"
#include "mining/cpu_miner.h"
#include "mining/gpu_miner.h"
#include "mining/work_allocator.h"
#include "stratum/stratum_client.h"
#include "telemetry/telemetry.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace srm::mining {
namespace {

std::string hex_nonce_bytes(const bitcoin::Header& header) {
  return crypto::to_hex(std::span<const std::uint8_t>(header.data() + 76, 4));
}

std::string reverse_hex(std::span<const std::uint8_t> bytes) {
  std::vector<std::uint8_t> reversed(bytes.rbegin(), bytes.rend());
  return crypto::to_hex(reversed);
}

std::string allocator_state_name(const config::Mode mode) {
  if (mode == config::Mode::Live) return "live_state.json";
  if (mode == config::Mode::HistoricalTest) return "historical_state.json";
  if (mode == config::Mode::MockStratum) return "mock_state.json";
  if (mode == config::Mode::Benchmark) return "benchmark_state.json";
  return "research_state.json";
}

}  // namespace

struct MiningController::Impl {
  config::AppConfig config;
  telemetry::Telemetry telemetry;
  logging::ResultLogger logger;
  WorkAllocator allocator;
  std::atomic<std::uint64_t> active_generation{0};
  std::unique_ptr<CpuMiner> cpu;
  std::unique_ptr<GpuMiner> gpu;
  std::unique_ptr<stratum::StratumClient> client;
  std::mutex control_mutex;
  std::mutex submissions_mutex;
  std::map<std::int64_t, Solution> pending_submissions;
  std::string extranonce1;
  unsigned extranonce2_size{0};
  bool subscribed{false};
  bool authorized{false};
  double share_difficulty{1.0};
  std::optional<stratum::StratumJob> pending_job;
  std::string previous_prevhash;
  std::chrono::steady_clock::time_point started{std::chrono::steady_clock::now()};
  std::uint64_t prior_uptime_ms{0};

  explicit Impl(config::AppConfig value)
      : config(std::move(value)), telemetry(config.console.refresh_ms),
        logger(config.logging.directory, config.logging.save_session_log, config.logging.save_block_candidates),
        allocator(checkpoint::StateStore(config.project_root / "state" / allocator_state_name(config.mode)),
                  config::mode_name(config.mode)) {
    const auto saved = allocator.snapshot();
    prior_uptime_ms = saved.value("uptime_ms", 0ULL);
    const auto counters = saved.value("counters", nlohmann::json::object());
    telemetry.cpu_hashes.store(counters.value("cpu_hashes", 0ULL));
    telemetry.gpu_hashes.store(counters.value("gpu_hashes", 0ULL));
    telemetry.shares.store(counters.value("shares", 0ULL));
    telemetry.accepted.store(counters.value("accepted", 0ULL));
    telemetry.rejected.store(counters.value("rejected", 0ULL));
    telemetry.stale_jobs.store(counters.value("stale_jobs", 0ULL));
    telemetry.headers_complete.store(counters.value("headers_complete", 0ULL));
    const auto best = saved.value("best_hash", "");
    if (!best.empty()) telemetry.observe_best(best);
  }

  void event(const std::string& text) {
    telemetry.event(text);
    logger.event(text);
  }

  nlohmann::json counters_json() const {
    return {
        {"counters", {
            {"hashes", telemetry.cpu_hashes.load() + telemetry.gpu_hashes.load()},
            {"cpu_hashes", telemetry.cpu_hashes.load()}, {"gpu_hashes", telemetry.gpu_hashes.load()},
            {"shares", telemetry.shares.load()}, {"accepted", telemetry.accepted.load()},
            {"rejected", telemetry.rejected.load()}, {"stale_jobs", telemetry.stale_jobs.load()},
            {"headers_complete", telemetry.headers_complete.load()}}},
        {"uptime_ms", prior_uptime_ms + static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count())}};
  }

  Solution make_solution(const Candidate& candidate) {
    Solution solution;
    solution.job_id = candidate.context.job.job_id;
    solution.username = config.ckpool.username;
    solution.extranonce1 = candidate.context.extranonce1;
    solution.extranonce2 = candidate.extranonce2;
    solution.version = candidate.context.job.version;
    solution.prevhash = candidate.context.job.prevhash;
    solution.merkle_root = crypto::bitcoin_hash_hex(candidate.merkle_root);
    solution.ntime = candidate.context.job.ntime;
    solution.nbits = candidate.context.job.nbits;
    solution.nonce = hex_nonce_bytes(candidate.header);
    solution.header_hex = bitcoin::header_hex(candidate.header);
    solution.hash = crypto::bitcoin_hash_hex(candidate.digest);
    solution.network_target = bitcoin::target_hex(candidate.context.network_target);
    solution.share_target = bitcoin::target_hex(candidate.context.share_target);
    solution.detected_timestamp_utc = logging::ResultLogger::utc_now();
    solution.network_candidate = candidate.network_candidate;
    return solution;
  }

  void on_candidate(Candidate candidate) {
    if (candidate.context.generation != active_generation.load(std::memory_order_acquire)) {
      return;
    }
    auto solution = make_solution(candidate);
    telemetry.shares.fetch_add(1, std::memory_order_relaxed);
    telemetry.observe_best(solution.hash);
    event("[SHARE] trouvée hash=" + solution.hash + " nonce=" + solution.nonce);
    if (solution.network_candidate) {
      event("[BLOCK] candidat réseau détecté");
      solution.submitted_timestamp_utc = logging::ResultLogger::utc_now();
      logger.save_candidate(solution);  // durable before any network submission
      event("[BLOCK] soumission immédiate");
    } else {
      solution.submitted_timestamp_utc = logging::ResultLogger::utc_now();
    }

    if (!client || !client->connected() || !client->authorized()) {
      event("[SHARE] non soumise: connexion CKPool inactive");
      if (solution.network_candidate) logger.update_candidate(solution);
      return;
    }
    try {
      std::scoped_lock lock(submissions_mutex);
      const auto id = client->submit(solution.username, solution.job_id, solution.extranonce2, solution.ntime, solution.nonce);
      pending_submissions.emplace(id, std::move(solution));
    } catch (const std::exception& error) {
      solution.server_response = std::string("local submission error: ") + error.what();
      if (solution.network_candidate) logger.update_candidate(solution);
      event("[SHARE] erreur de soumission: " + std::string(error.what()));
    }
  }

  void stop_workers() {
    if (cpu) cpu->stop();
    if (gpu) gpu->stop();
  }

  void launch_job(const stratum::StratumJob& job) {
    if (!subscribed || !authorized) { pending_job = job; return; }
    active_generation.fetch_add(1, std::memory_order_acq_rel);
    stop_workers();
    if (job.clean_jobs) {
      allocator.mark_all_stale();
      event("[JOB] clean_jobs=true -> ancien travail interrompu");
    }

    if (previous_prevhash.empty() || previous_prevhash != job.prevhash) event("[JOB] NOUVEAU BLOC / NOUVEAU PREVHASH");
    else event("[JOB] MISE À JOUR DU JOB");
    previous_prevhash = job.prevhash;
    const auto generation = active_generation.load(std::memory_order_acquire);
    const auto resumed = allocator.prepare_live_job(job.job_id, job.prevhash, extranonce1, extranonce2_size,
                                                    config.cpu.enabled ? config.cpu.threads : 1U,
                                                    config.gpu.enabled, generation);
    event(resumed ? "[CHECKPOINT] travail CKPool compatible repris" : "[CHECKPOINT] nouveau travail; ancien état incompatible marqué STALE");
    const LiveMiningJob mining_job{job, extranonce1, bitcoin::share_target_from_difficulty(share_difficulty),
                                   bitcoin::target_from_nbits(job.nbits), generation};
    telemetry.set_job(job.job_id, job.prevhash, job.clean_jobs, share_difficulty, bitcoin::target_hex(mining_job.network_target));

    std::string cpu_ex2;
    std::string gpu_ex2;
    for (const auto& unit : allocator.units()) {
      if (unit.generation != generation || unit.status == WorkStatus::Stale) continue;
      if (unit.worker == WorkerKind::Cpu && cpu_ex2.empty()) cpu_ex2 = unit.extranonce2;
      if (unit.worker == WorkerKind::Gpu && gpu_ex2.empty()) gpu_ex2 = unit.extranonce2;
    }
    auto gpu_name = std::string("désactivé");
    if (config.gpu.enabled) {
      const auto info = gpu->detect(config.gpu.platform, config.gpu.device);
      gpu_name = info.available ? info.name : "OpenCL absent";
    }
    telemetry.set_worker_state(config.cpu.enabled ? config.cpu.threads : 0, cpu_ex2, gpu_name, gpu_ex2);
    if (config.cpu.enabled) cpu->start(mining_job, config.cpu.threads);
    if (config.gpu.enabled) gpu->start(mining_job, config.gpu.auto_tune);
    allocator.checkpoint(counters_json());
  }

  void on_job(const stratum::StratumJob& job) {
    std::scoped_lock lock(control_mutex);
    launch_job(job);
  }

  int run_live(std::atomic_bool& stop_requested) {
    cpu = std::make_unique<CpuMiner>(allocator, telemetry, active_generation, [this](Candidate candidate) { on_candidate(std::move(candidate)); });
    gpu = std::make_unique<GpuMiner>(allocator, telemetry, active_generation,
                                    [this](Candidate candidate) { on_candidate(std::move(candidate)); },
                                    config.project_root / "kernels" / "sha256d.cl",
                                    config.gpu.profile);
    stratum::StratumClient::Callbacks callbacks;
    callbacks.event = [this](const std::string& text) { event(text); };
    callbacks.subscribed = [this](const std::string& value, const unsigned size) {
      std::scoped_lock lock(control_mutex);
      extranonce1 = value; extranonce2_size = size; subscribed = true;
      if (pending_job && authorized) { auto job = *pending_job; pending_job.reset(); launch_job(job); }
    };
    callbacks.authorized = [this](const bool accepted) {
      std::scoped_lock lock(control_mutex);
      authorized = accepted;
      telemetry.set_connection(client && client->connected(), accepted, config.ckpool.host + ":" + std::to_string(config.ckpool.port));
      if (accepted && pending_job && subscribed) { auto job = *pending_job; pending_job.reset(); launch_job(job); }
    };
    callbacks.difficulty = [this](const double value) { std::scoped_lock lock(control_mutex); share_difficulty = value; };
    callbacks.job = [this](const stratum::StratumJob& job) { on_job(job); };
    callbacks.submission = [this](const std::int64_t id, const bool accepted, const nlohmann::json& response, const std::uint64_t latency) {
      Solution solution;
      bool found = false;
      {
        std::scoped_lock lock(submissions_mutex);
        const auto item = pending_submissions.find(id);
        if (item != pending_submissions.end()) { solution = std::move(item->second); pending_submissions.erase(item); found = true; }
      }
      if (accepted) { telemetry.accepted.fetch_add(1); event("[SHARE] acceptée id=" + std::to_string(id)); }
      else { telemetry.rejected.fetch_add(1); event("[SHARE] rejetée id=" + std::to_string(id) + " réponse=" + response.dump()); }
      if (found) {
        solution.submission_latency_us = latency;
        solution.server_response = response.dump();
        if (solution.network_candidate) logger.update_candidate(solution);
      }
    };
    callbacks.disconnected = [this]() {
      std::scoped_lock lock(control_mutex);
      active_generation.fetch_add(1, std::memory_order_acq_rel);
      stop_workers();
      authorized = false; subscribed = false;
      telemetry.set_connection(false, false, config.ckpool.host + ":" + std::to_string(config.ckpool.port));
      try { allocator.checkpoint(counters_json()); } catch (const std::exception& error) { event(std::string("[CHECKPOINT] erreur: ") + error.what()); }
    };

    client = std::make_unique<stratum::StratumClient>(config.ckpool, std::move(callbacks));
    telemetry.start();
    telemetry.set_connection(false, false, config.ckpool.host + ":" + std::to_string(config.ckpool.port));
    client->start();
    auto next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
    while (!stop_requested.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (std::chrono::steady_clock::now() >= next_checkpoint) {
        try { allocator.checkpoint(counters_json()); }
        catch (const std::exception& error) { event(std::string("[CHECKPOINT] disque non accessible: ") + error.what()); }
        next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
      }
    }
    active_generation.fetch_add(1);
    stop_workers();
    client->stop();
    allocator.checkpoint(counters_json());
    telemetry.stop();
    return 0;
  }

  Solution offline_solution(const bitcoin::Header& header, const crypto::Digest& digest,
                            const bitcoin::Target256& target, const std::string& header_id) {
    Solution value;
    value.job_id = header_id;
    value.username = "OFFLINE";
    value.version = reverse_hex(std::span<const std::uint8_t>(header.data(), 4));
    value.prevhash = reverse_hex(std::span<const std::uint8_t>(header.data() + 4, 32));
    value.merkle_root = reverse_hex(std::span<const std::uint8_t>(header.data() + 36, 32));
    value.ntime = reverse_hex(std::span<const std::uint8_t>(header.data() + 68, 4));
    value.nbits = reverse_hex(std::span<const std::uint8_t>(header.data() + 72, 4));
    value.nonce = hex_nonce_bytes(header);
    value.header_hex = bitcoin::header_hex(header);
    value.hash = crypto::bitcoin_hash_hex(digest);
    value.network_target = bitcoin::target_hex(target);
    value.share_target = value.network_target;
    value.detected_timestamp_utc = logging::ResultLogger::utc_now();
    value.network_candidate = true;
    value.offline = true;
    return value;
  }

  int run_historical(std::atomic_bool& stop_requested) {
    auto bytes = crypto::from_hex(config.historical.header_hex);
    bitcoin::Header base{};
    std::copy(bytes.begin(), bytes.end(), base.begin());
    const auto target = bitcoin::target_from_hex(config.historical.target_hex);
    const auto original_nonce = bitcoin::get_nonce(base);
    bitcoin::set_nonce(base, 0);
    const auto header_id = crypto::digest_hex(crypto::sha256(std::span<const std::uint8_t>(base.data(), 76)));

    if (config.historical.known_nonce) {
      auto validation = base;
      bitcoin::set_nonce(validation, *config.historical.known_nonce);
      const auto actual = crypto::bitcoin_hash_hex(crypto::sha256d(validation));
      if (!config.historical.expected_hash.empty() && actual != config.historical.expected_hash) {
        throw std::runtime_error("historical expected_hash mismatch: computed " + actual);
      }
      event("[HISTORICAL] vecteur connu validé: " + actual);
    }
    const auto start_nonce = config.historical.scan_full_nonce_space ? 0ULL : config.historical.nonce_start;
    const auto end_nonce = config.historical.scan_full_nonce_space ? 0x100000000ULL : config.historical.nonce_end;
    allocator.prepare_historical(header_id, start_nonce, end_nonce, config.cpu.threads, 64);
    telemetry.start();
    std::atomic_bool found{false};
    std::mutex save_mutex;
    std::vector<std::jthread> threads;
    for (unsigned index = 0; index < config.cpu.threads; ++index) {
      threads.emplace_back([&, index](const std::stop_token token) {
        (void)index;
        while (!token.stop_requested() && !stop_requested.load() && !found.load()) {
          auto unit = allocator.acquire(WorkerKind::Cpu);
          if (!unit) return;
          auto header = base;
          std::uint64_t pending = 0;
          auto nonce = unit->nonce_next;
          for (; nonce < unit->nonce_end && !found.load() && !stop_requested.load(); ++nonce) {
            bitcoin::set_nonce(header, static_cast<std::uint32_t>(nonce));
            const auto digest = crypto::sha256d(header);
            ++pending;
            if (bitcoin::hash_meets_target(digest, target)) {
              bool expected = false;
              if (found.compare_exchange_strong(expected, true)) {
                std::scoped_lock lock(save_mutex);
                auto solution = offline_solution(header, digest, target, header_id);
                logger.save_candidate(solution);
                event("[BLOCK] BLOCK_FOUND hors ligne hash=" + solution.hash + " nonce=" + std::to_string(nonce));
              }
            }
            if (pending >= 65536) {
              allocator.update_progress(unit->id, nonce + 1, pending);
              telemetry.cpu_hashes.fetch_add(pending);
              pending = 0;
            }
          }
          if (pending) { allocator.update_progress(unit->id, nonce, pending); telemetry.cpu_hashes.fetch_add(pending); }
          if (nonce >= unit->nonce_end) allocator.complete(unit->id); else allocator.release(unit->id);
        }
      });
    }
    auto next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
    while (!found.load() && !stop_requested.load()) {
      const auto work_snapshot = allocator.units();
      const bool any_work = std::any_of(work_snapshot.begin(), work_snapshot.end(), [](const WorkUnit& unit) {
        return unit.status == WorkStatus::Pending || unit.status == WorkStatus::InProgress;
      });
      if (!any_work) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (std::chrono::steady_clock::now() >= next_checkpoint) {
        allocator.checkpoint(counters_json());
        next_checkpoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.checkpoint_interval_ms);
      }
    }
    for (auto& thread : threads) thread.request_stop();
    threads.clear();
    allocator.checkpoint(counters_json());
    telemetry.stop();
    bitcoin::set_nonce(base, original_nonce);
    if (!found.load() && !stop_requested.load()) event("[HISTORICAL] plage terminée sans candidat");
    return found.load() ? 0 : 2;
  }

  int run_research(std::atomic_bool& stop_requested) {
    const auto bytes = crypto::from_hex(config.historical.header_hex);
    bitcoin::Header header{};
    std::copy(bytes.begin(), bytes.end(), header.begin());
    bitcoin::set_nonce(header, 0);
    const auto header_id = crypto::digest_hex(crypto::sha256(std::span<const std::uint8_t>(header.data(), 76)));
    checkpoint::StateStore state_store(config.project_root / "state" / allocator_state_name(config.mode));
    auto state = state_store.load_or(nlohmann::json::object());
    if (state.value("header_id", "") != header_id) state = nlohmann::json::object();
    std::vector<unsigned> completed = state.value("completed_rounds", std::vector<unsigned>{});

    for (unsigned round = config.research.round_start; round <= config.research.round_end && !stop_requested.load(); ++round) {
      if (std::find(completed.begin(), completed.end(), round) != completed.end()) continue;
      std::array<std::uint64_t, 256> bit_counts{};
      std::uint64_t hamming_total = 0;
      std::uint64_t tested = 0;
      std::uint64_t nonce_next = 0;
      crypto::Digest previous{};
      bool has_previous = false;
      std::string best_hash;
      std::uint32_t best_nonce = 0;
      if (state.value("header_id", "") == header_id && state.value("current_round", 0U) == round &&
          state.value("nonce_next", 0ULL) > 0) {
        nonce_next = state.value("nonce_next", 0ULL);
        tested = state.value("hashes_tested", 0ULL);
        hamming_total = state.value("hamming_total", 0ULL);
        best_hash = state.value("best_hash", "");
        best_nonce = state.value("best_nonce", 0U);
        const auto saved_counts = state.value("bit_counts", std::vector<std::uint64_t>{});
        if (saved_counts.size() == bit_counts.size()) std::copy(saved_counts.begin(), saved_counts.end(), bit_counts.begin());
        const auto previous_hex = state.value("previous_digest", "");
        if (previous_hex.size() == 64) { const auto value = crypto::from_hex(previous_hex); std::copy(value.begin(), value.end(), previous.begin()); has_previous = true; }
      }
      event("[RESEARCH] round=" + std::to_string(round) + " reprise nonce=" + std::to_string(nonce_next));
      for (std::uint64_t nonce = nonce_next; nonce < config.research.sample_count && !stop_requested.load(); ++nonce) {
        bitcoin::set_nonce(header, static_cast<std::uint32_t>(nonce));
        const auto digest = crypto::reduced_sha256d(header, round);
        for (std::size_t byte = 0; byte < digest.size(); ++byte) {
          for (unsigned bit = 0; bit < 8; ++bit) bit_counts[byte * 8 + bit] += (digest[byte] >> bit) & 1U;
        }
        if (has_previous) hamming_total += crypto::hamming_distance(previous, digest);
        previous = digest; has_previous = true; ++tested;
        const auto text = crypto::bitcoin_hash_hex(digest);
        if (best_hash.empty() || text < best_hash) { best_hash = text; best_nonce = static_cast<std::uint32_t>(nonce); }
        if ((nonce + 1) % 65536 == 0) {
          state = {{"schema_version", 1}, {"mode", "research"}, {"header_id", header_id}, {"current_round", round},
                   {"nonce_next", nonce + 1}, {"nonce_end", config.research.sample_count}, {"hashes_tested", tested},
                   {"best_hash", best_hash}, {"best_nonce", best_nonce}, {"hamming_total", hamming_total},
                   {"previous_digest", crypto::digest_hex(previous)}, {"bit_counts", bit_counts}, {"completed_rounds", completed}};
          state_store.save(state);
        }
      }
      if (stop_requested.load()) break;
      nlohmann::json statistics = {
          {"header_id", header_id}, {"round", round}, {"samples", tested}, {"bit_counts", bit_counts},
          {"mean_hamming_distance", tested > 1 ? static_cast<double>(hamming_total) / static_cast<double>(tested - 1) : 0.0},
          {"best_hash", best_hash}, {"best_nonce", best_nonce}};
      logger.save_json_atomic(config.logging.directory / ("research_round_" + std::to_string(round) + ".json"), statistics);
      completed.push_back(round);
      state = {{"schema_version", 1}, {"mode", "research"}, {"header_id", header_id}, {"current_round", round + 1},
               {"nonce_next", 0}, {"nonce_end", config.research.sample_count}, {"hashes_tested", 0},
               {"best_hash", ""}, {"best_nonce", nullptr}, {"statistics", statistics}, {"completed_rounds", completed}};
      state_store.save(state);
    }
    return stop_requested.load() ? 130 : 0;
  }

  int run_benchmark(std::atomic_bool& stop_requested) {
    const auto bytes = crypto::from_hex(config.benchmark.header_hex);
    bitcoin::Header header{};
    std::copy(bytes.begin(), bytes.end(), header.begin());

    gpu = std::make_unique<GpuMiner>(allocator, telemetry, active_generation,
                                    [](Candidate) {}, config.project_root / "kernels" / "sha256d.cl",
                                    config.gpu.profile);
    const auto devices = gpu->enumerate();
    std::cout << "[BENCHMARK] Périphériques OpenCL détectés: " << devices.size() << '\n';
    for (const auto& device : devices) {
      std::cout << "[GPU " << device.index << "] platform_index=" << device.platform_index
                << " device_index=" << device.device_index << " plateforme=\"" << device.platform
                << "\" nom_opencl=\"" << device.name << "\" nom_carte=\"" << device.board_name
                << "\" vendor=\"" << device.vendor
                << "\" driver=\"" << device.driver << "\" compute_units=" << device.compute_units
                << " mémoire=" << device.global_memory << " octets max_work_group="
                << device.max_workgroup_size << '\n';
    }
    std::cout << "[BENCHMARK] warm-up=" << config.benchmark.warmup_ms
              << " ms mesure=" << config.benchmark.measurement_ms << " ms par configuration\n";

    CpuBenchmarkResult cpu_result;
    if (config.cpu.enabled) {
      std::cout << "\n[BENCHMARK CPU]\n";
      cpu_result = benchmark_cpu_sha256d(header, config.benchmark.cpu_threads,
                                         config.benchmark.warmup_ms, config.benchmark.measurement_ms,
                                         stop_requested);
      for (const auto& sample : cpu_result.samples) {
        std::cout << "threads=" << sample.threads << " hashes=" << sample.hashes
                  << " durée=" << std::fixed << std::setprecision(6) << sample.seconds
                  << " s H/s=" << std::setprecision(2) << sample.hash_rate
                  << " (" << format_hash_rate(sample.hash_rate) << ")\n";
      }
      if (!cpu_result.samples.empty()) {
        std::cout << "meilleur=" << cpu_result.best.threads << " threads, "
                  << format_hash_rate(cpu_result.best.hash_rate) << '\n';
      }
    }
    if (stop_requested.load(std::memory_order_acquire)) return 130;

    GpuBenchmarkResult gpu_result;
    if (config.gpu.enabled) {
      if (devices.empty()) throw std::runtime_error("benchmark GPU requested but no OpenCL GPU was detected");
      std::cout << "\n[BENCHMARK GPU]\n";
      gpu_result = gpu->benchmark(header, config.gpu.platform, config.gpu.device, config.gpu.auto_tune,
                                  config.benchmark.warmup_ms, config.benchmark.measurement_ms);
      const auto display_name = gpu_result.device.board_name.empty() ? gpu_result.device.name : gpu_result.device.board_name;
      std::cout << "GPU sélectionné: [GPU " << gpu_result.device.index << "] " << display_name
                << " | nom OpenCL=" << gpu_result.device.name << " | plateforme=" << gpu_result.device.platform
                << " | platform_index=" << gpu_result.device.platform_index
                << " | device_index=" << gpu_result.device.device_index
                << " | driver=" << gpu_result.device.driver << '\n';
      std::cout << "validation CPU/GPU 4096 vecteurs: " << (gpu_result.validated ? "OK" : "ÉCHEC") << '\n';
      for (const auto& sample : gpu_result.samples) {
        std::cout << "local=" << sample.local_work_size << " global=" << sample.global_work_size
                  << " batch=" << sample.batch_size << " hashes=" << sample.hashes
                  << " durée=" << std::fixed << std::setprecision(6) << sample.seconds
                  << " s H/s=" << std::setprecision(2) << sample.hash_rate
                  << " (" << format_hash_rate(sample.hash_rate) << ")\n";
      }
      std::cout << "meilleur=local=" << gpu_result.best.local_work_size
                << " global=" << gpu_result.best.global_work_size
                << " batch=" << gpu_result.best.batch_size << " "
                << format_hash_rate(gpu_result.best.hash_rate) << '\n';
    }

    nlohmann::json profile = {
        {"schema_version", 1},
        {"timestamp_utc", logging::ResultLogger::utc_now()},
        {"mode", "benchmark"},
        {"warmup_ms", config.benchmark.warmup_ms},
        {"measurement_ms", config.benchmark.measurement_ms},
        {"combined_hash_rate_hps", nullptr}};
    profile["cpu"] = {
        {"enabled", config.cpu.enabled},
        {"best_threads", cpu_result.best.threads},
        {"hash_rate_hps", cpu_result.best.hash_rate}};
    profile["gpu"] = {
        {"enabled", config.gpu.enabled},
        {"tuned", gpu_result.validated},
        {"index", gpu_result.device.index},
        {"platform", gpu_result.device.platform},
        {"device_name", gpu_result.device.name},
        {"board_name", gpu_result.device.board_name},
        {"vendor", gpu_result.device.vendor},
        {"driver", gpu_result.device.driver},
        {"compute_units", gpu_result.device.compute_units},
        {"global_memory_bytes", gpu_result.device.global_memory},
        {"max_work_group_size", gpu_result.device.max_workgroup_size},
        {"local_work_size", gpu_result.best.local_work_size},
        {"global_work_size", gpu_result.best.global_work_size},
        {"batch_size", gpu_result.best.batch_size},
        {"hash_rate_hps", gpu_result.best.hash_rate}};
    checkpoint::StateStore(config.benchmark.performance_profile).save(profile);

    std::cout << "\n[BENCHMARK FINAL]\n";
    std::cout << "CPU " << (config.cpu.enabled ? format_hash_rate(cpu_result.best.hash_rate) : "désactivé") << '\n';
    std::cout << "GPU " << (config.gpu.enabled ? format_hash_rate(gpu_result.best.hash_rate) : "désactivé") << '\n';
    std::cout << "TOTAL non mesuré: le test combiné est volontairement séparé de cette première version fiable\n";
    std::cout << "Profil atomique: " << config.benchmark.performance_profile << '\n';
    return 0;
  }

  int run(std::atomic_bool& stop_requested) {
    if (config.mode == config::Mode::Benchmark) return run_benchmark(stop_requested);
    if (config.mode == config::Mode::Live || config.mode == config::Mode::MockStratum) return run_live(stop_requested);
    if (config.mode == config::Mode::HistoricalTest) return run_historical(stop_requested);
    return run_research(stop_requested);
  }
};

MiningController::MiningController(config::AppConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}
MiningController::~MiningController() = default;
int MiningController::run(std::atomic_bool& stop_requested) { return impl_->run(stop_requested); }

}  // namespace srm::mining
