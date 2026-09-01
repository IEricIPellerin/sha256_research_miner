//include\bitcoin\merkle.h
#pragma once

#include "crypto/sha256.h"

#include <string>
#include <vector>

namespace srm::bitcoin {

crypto::Digest build_merkle_root(const crypto::Digest& coinbase_hash,
                                 const std::vector<std::string>& branches_hex);

}  // namespace srm::bitcoin
