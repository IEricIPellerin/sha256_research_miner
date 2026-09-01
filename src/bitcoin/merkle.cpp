//src\bitcoin\merkle.cpp
#include "bitcoin/merkle.h"

#include "crypto/sha256d.h"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace srm::bitcoin {

crypto::Digest build_merkle_root(const crypto::Digest& coinbase_hash,
                                 const std::vector<std::string>& branches_hex) {
  auto root = coinbase_hash;
  for (const auto& branch_hex : branches_hex) {
    const auto branch = crypto::from_hex(branch_hex);
    if (branch.size() != 32) throw std::invalid_argument("Merkle branch must contain exactly 32 bytes");
    std::array<std::uint8_t, 64> pair{};
    std::copy(root.begin(), root.end(), pair.begin());
    std::copy(branch.begin(), branch.end(), pair.begin() + 32);
    root = crypto::sha256d(pair);
  }
  return root;
}

}  // namespace srm::bitcoin
