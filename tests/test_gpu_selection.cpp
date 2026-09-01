//tests\test_gpu_selection.cpp
#include "mining/gpu_miner.h"
#include "test_support.h"

#include <stdexcept>

namespace {

srm::mining::GpuInfo device(const std::size_t index, const std::size_t platform_index,
                            std::string platform, std::string name, std::string board_name,
                            const std::uint32_t compute_units, const std::uint64_t memory) {
  srm::mining::GpuInfo value;
  value.available = true;
  value.index = index;
  value.platform_index = platform_index;
  value.platform = std::move(platform);
  value.name = std::move(name);
  value.board_name = std::move(board_name);
  value.vendor = "Advanced Micro Devices, Inc.";
  value.compute_units = compute_units;
  value.global_memory = memory;
  value.max_workgroup_size = 256;
  return value;
}

}  // namespace

TEST_CASE("explicit GPU name selects RX 7900 XTX instead of integrated graphics") {
  const std::vector devices{
      device(0, 0, "AMD Accelerated Parallel Processing", "gfx1036", "AMD Radeon(TM) Graphics", 2,
             512ULL << 20U),
      device(1, 0, "AMD Accelerated Parallel Processing", "gfx1100", "AMD Radeon RX 7900 XTX", 96,
             24ULL << 30U)};
  REQUIRE_EQ(srm::mining::GpuMiner::select_device_index(devices, "auto", "AMD Radeon RX 7900 XTX"),
             static_cast<std::size_t>(1));
  REQUIRE_EQ(srm::mining::GpuMiner::select_device_index(devices, "AMD Accelerated Parallel Processing", "auto"),
             static_cast<std::size_t>(1));
}

TEST_CASE("ambiguous GPU selector is rejected") {
  const std::vector devices{
      device(0, 0, "Platform A", "gfx1100", "AMD Radeon RX 7900 XTX", 96, 24ULL << 30U),
      device(1, 1, "Platform B", "gfx1100", "AMD Radeon RX 7900 XTX", 96, 24ULL << 30U)};
  REQUIRE_EQ(srm::mining::GpuMiner::select_device_index(devices, "index:0", "AMD Radeon RX 7900 XTX"),
             static_cast<std::size_t>(0));
  bool rejected = false;
  try {
    (void)srm::mining::GpuMiner::select_device_index(devices, "auto", "AMD Radeon RX 7900 XTX");
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  REQUIRE(rejected);

  rejected = false;
  try {
    (void)srm::mining::GpuMiner::select_device_index(
        devices, "Platform", "auto");
  } catch (const std::invalid_argument&) {
    rejected = true;
  }
  REQUIRE(rejected);
}
