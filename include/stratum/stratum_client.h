//include\stratum\stratum_client.h
#pragma once

#include "config/config.h"
#include "stratum/stratum_job.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace srm::stratum {

class StratumClient {
 public:
  struct Callbacks {
    std::function<void(const std::string&)> event;
    std::function<void(const std::string&, unsigned)> subscribed;
    std::function<void(bool)> authorized;
    std::function<void(double)> difficulty;
    std::function<void(const StratumJob&)> job;
    std::function<void(std::int64_t, bool, const nlohmann::json&, std::uint64_t)> submission;
    std::function<void()> disconnected;
  };

  StratumClient(config::CkpoolConfig config, Callbacks callbacks);
  ~StratumClient();
  StratumClient(const StratumClient&) = delete;
  StratumClient& operator=(const StratumClient&) = delete;

  void start();
  void stop();
  std::int64_t submit(const std::string& username,
                      const std::string& job_id,
                      const std::string& extranonce2,
                      const std::string& ntime,
                      const std::string& nonce);
  bool connected() const noexcept;
  bool authorized() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace srm::stratum

