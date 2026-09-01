//src\stratum\stratum_message.cpp
#include "stratum/stratum_message.h"

#include <stdexcept>

namespace srm::stratum {

StratumMessage parse_message(const std::string& line) {
  StratumMessage message;
  message.raw = nlohmann::json::parse(line);
  if (!message.raw.is_object()) throw std::invalid_argument("Stratum message must be a JSON object");
  if (message.raw.contains("id") && !message.raw.at("id").is_null()) {
    if (!message.raw.at("id").is_number_integer()) throw std::invalid_argument("Stratum id must be an integer or null");
    message.id = message.raw.at("id").get<std::int64_t>();
  }
  if (message.raw.contains("method")) message.method = message.raw.at("method").get<std::string>();
  if (message.raw.contains("params")) message.params = message.raw.at("params");
  if (message.raw.contains("result")) message.result = message.raw.at("result");
  if (message.raw.contains("error")) message.error = message.raw.at("error");
  if (!message.id.has_value() && message.method.empty()) throw std::invalid_argument("Stratum message is neither response nor notification");
  return message;
}

nlohmann::json make_request(const std::int64_t id, std::string method, nlohmann::json params) {
  return {{"id", id}, {"method", std::move(method)}, {"params", std::move(params)}};
}

}  // namespace srm::stratum
