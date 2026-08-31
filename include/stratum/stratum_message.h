//include\stratum\stratum_message.h
#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace srm::stratum {

struct StratumMessage {
  nlohmann::json raw;
  std::optional<std::int64_t> id;
  std::string method;
  nlohmann::json params{nlohmann::json::array()};
  nlohmann::json result;
  nlohmann::json error;

  bool is_notification() const noexcept { return !method.empty(); }
  bool is_response() const noexcept { return id.has_value(); }
};

StratumMessage parse_message(const std::string& line);
nlohmann::json make_request(std::int64_t id, std::string method, nlohmann::json params);

}  // namespace srm::stratum

