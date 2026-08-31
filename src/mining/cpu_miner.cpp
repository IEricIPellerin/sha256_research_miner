//src\mining\cpu_miner.cpp
#include "mining/cpu_miner.h"

#include "bitcoin/block_header.h"
#include "crypto/sha256d.h"

#include <algorithm>
#include <array>

namespace srm::mining {
namespace {

bool better_hash(const crypto::Digest& candidate, const crypto::Digest& best) {
  for (std::size_t i = 0; i < candidate.size(); ++i) {
    const auto left = candidate[candidate.size() - 1 - i];
    const auto right = best[best.size() - 1 - i];
    if (left != right) return left < right;
  }
  return false;
}

}  // namespace

CpuMiner::CpuMiner(WorkAllocator& allocator,
                   telemetry::Telemetry& telemetry,
                   std::atomic<std::uint64_t>& active_generation,
                   CandidateHandler handler)
    : allocator_(allocator), telemetry_(telemetry), active_generation_(active_generation), handler_(std::move(handler)) {}

CpuMiner::~CpuMiner() { stop(); }

void CpuMiner::start(const LiveMiningJob& job, const unsigned threads) {
  stop();
  workers_.reserve(threads);
  for (unsigned i = 0; i < threads; ++i) {
    workers_.emplace_back([this, job](const std::stop_token token) { worker(token, job); });
  }
}

void CpuMiner::stop() {
  for (auto& worker_thread : workers_) worker_thread.request_stop();
  workers_.clear();
}

void CpuMiner::worker(const std::stop_token token, LiveMiningJob job) {
  constexpr std::uint64_t checkpoint_batch = 65536;
  while (!token.stop_requested() && active_generation_.load(std::memory_order_acquire) == job.generation) {
    auto unit = allocator_.acquire(WorkerKind::Cpu);
    if (!unit) return;
    auto built = stratum::build_work(job.job, job.extranonce1, unit->extranonce2, 0);
    crypto::Digest best{};
    best.fill(0xff);
    std::uint32_t best_nonce = static_cast<std::uint32_t>(unit->nonce_next);
    std::uint64_t pending = 0;
    auto nonce = unit->nonce_next;

    for (; nonce < unit->nonce_end; ++nonce) {
      if ((pending & 4095U) == 0 && (token.stop_requested() || active_generation_.load(std::memory_order_relaxed) != job.generation)) break;
      bitcoin::set_nonce(built.header, static_cast<std::uint32_t>(nonce));
      const auto digest = crypto::sha256d(built.header);
      ++pending;
      if (better_hash(digest, best)) { best = digest; best_nonce = static_cast<std::uint32_t>(nonce); }

      const bool share = bitcoin::hash_meets_target(digest, job.share_target);
      const bool network = bitcoin::hash_meets_target(digest, job.network_target);
      if ((share || network) && active_generation_.load(std::memory_order_relaxed) == job.generation) {
        handler_(Candidate{job, unit->extranonce2, built.header, built.merkle_root, digest,
                           static_cast<std::uint32_t>(nonce), network});
      }

      if (pending >= checkpoint_batch) {
        const auto best_text = crypto::bitcoin_hash_hex(best);
        allocator_.update_progress(unit->id, nonce + 1, pending, best_text, best_nonce);
        telemetry_.set_progress(unit->nonce_start, nonce + 1, unit->nonce_end);
        telemetry_.cpu_hashes.fetch_add(pending, std::memory_order_relaxed);
        telemetry_.observe_best(best_text);
        pending = 0;
      }
    }

    if (pending != 0) {
      const auto best_text = crypto::bitcoin_hash_hex(best);
      allocator_.update_progress(unit->id, nonce, pending, best_text, best_nonce);
      telemetry_.set_progress(unit->nonce_start, nonce, unit->nonce_end);
      telemetry_.cpu_hashes.fetch_add(pending, std::memory_order_relaxed);
      telemetry_.observe_best(best_text);
    }
    if (nonce >= unit->nonce_end) {
      allocator_.complete(unit->id);
      telemetry_.headers_complete.fetch_add(1, std::memory_order_relaxed);
    } else {
      allocator_.release(unit->id);
    }
  }
}

}  // namespace srm::mining
