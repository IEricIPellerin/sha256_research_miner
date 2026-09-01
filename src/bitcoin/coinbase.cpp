//src\bitcoin\coinbase.cpp
#include "bitcoin/coinbase.h"

#include "crypto/sha256d.h"

namespace srm::bitcoin {

std::vector<std::uint8_t> build_coinbase(const std::string_view coinbase1,
                                         const std::string_view extranonce1,
                                         const std::string_view extranonce2,
                                         const std::string_view coinbase2) {
  const auto joined = std::string(coinbase1) + std::string(extranonce1) +
                      std::string(extranonce2) + std::string(coinbase2);
  return crypto::from_hex(joined);
}

crypto::Digest coinbase_hash(const std::string_view coinbase1,
                             const std::string_view extranonce1,
                             const std::string_view extranonce2,
                             const std::string_view coinbase2) {
  const auto coinbase = build_coinbase(coinbase1, extranonce1, extranonce2, coinbase2);
  return crypto::sha256d(coinbase);
}

}  // namespace srm::bitcoin
