//include\bitcoin\coinbase.h
#pragma once

#include "crypto/sha256.h"

#include <string_view>
#include <vector>

namespace srm::bitcoin {

std::vector<std::uint8_t> build_coinbase(std::string_view coinbase1,
                                         std::string_view extranonce1,
                                         std::string_view extranonce2,
                                         std::string_view coinbase2);
crypto::Digest coinbase_hash(std::string_view coinbase1,
                             std::string_view extranonce1,
                             std::string_view extranonce2,
                             std::string_view coinbase2);

}  // namespace srm::bitcoin
