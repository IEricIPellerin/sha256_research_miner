#pragma once

#include <filesystem>
#include <nlohmann/json.hpp>

namespace srm::checkpoint {

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

