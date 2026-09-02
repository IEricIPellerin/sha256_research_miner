//include\checkpoint\state_store.h
#pragma once

#include <filesystem>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace srm::checkpoint {

class PersistenceError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class StateStore {
 public:
  explicit StateStore(std::filesystem::path path);

  nlohmann::json load_or(const nlohmann::json& fallback) const;
  void save(const nlohmann::json& state) const;
  const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

}  // namespace srm::checkpoint
