#pragma once

#include "config/config.h"

#include <atomic>
#include <memory>

namespace srm::mining {

class MiningController {
 public:
  explicit MiningController(config::AppConfig config);
  ~MiningController();

  int run(std::atomic_bool& stop_requested);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace srm::mining

