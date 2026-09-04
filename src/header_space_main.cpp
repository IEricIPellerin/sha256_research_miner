//src\header_space_main.cpp
#include "research/header_space.h"

#include "bitcoin/difficulty.h"
#include "crypto/sha256.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace hs = srm::research::header_space;

namespace {

struct Arguments {
  std::optional<std::string> preset;
  std::optional<std::string> header_hex;
  bool full_space{false};
  bool overwrite{false};
  bool list_devices{false};
  bool help{false};
  std::uint64_t nonce_start{0};
  std::optional<std::uint64_t> nonce_count;
  std::uint64_t zone_size{hs::kDefaultZoneSize};
  std::filesystem::path output_prefix{"results/header_space"};
  std::string device{"auto"};
  std::size_t local_size{64};
  std::size_t batch_zones{256};
  std::uint64_t cpu_verify_count{65536};
  std::filesystem::path kernel{"kernels/header_space_map.cl"};
};

std::uint64_t parse_u64(const std::string& text, const char* option) {
  if (text.empty() || text.front() == '-') throw std::invalid_argument(std::string(option) + " must be non-negative");
  std::size_t consumed = 0;
  const auto value = std::stoull(text, &consumed, 0);
  if (consumed != text.size()) throw std::invalid_argument(std::string(option) + " is not an integer");
  return value;
}

std::size_t parse_size(const std::string& text, const char* option) {
  const auto value = parse_u64(text, option);
  if (value > std::numeric_limits<std::size_t>::max()) {
    throw std::invalid_argument(std::string(option) + " exceeds size_t");
  }
  return static_cast<std::size_t>(value);
}

Arguments parse_arguments(const int argc, char** argv) {
  Arguments args;
  const auto value_after = [&](int& index, const char* option) -> std::string {
    if (++index >= argc) throw std::invalid_argument(std::string("missing value after ") + option);
    return argv[index];
  };
  for (int i = 1; i < argc; ++i) {
    const std::string option = argv[i];
    if (option == "--preset") args.preset = value_after(i, "--preset");
    else if (option == "--header-hex") args.header_hex = value_after(i, "--header-hex");
    else if (option == "--full-space") args.full_space = true;
    else if (option == "--nonce-start") args.nonce_start = parse_u64(value_after(i, "--nonce-start"), "--nonce-start");
    else if (option == "--nonce-count") args.nonce_count = parse_u64(value_after(i, "--nonce-count"), "--nonce-count");
    else if (option == "--zone-size") args.zone_size = parse_u64(value_after(i, "--zone-size"), "--zone-size");
    else if (option == "--output-prefix") args.output_prefix = value_after(i, "--output-prefix");
    else if (option == "--device") args.device = value_after(i, "--device");
    else if (option == "--local-size") args.local_size = parse_size(value_after(i, "--local-size"), "--local-size");
    else if (option == "--batch-zones") args.batch_zones = parse_size(value_after(i, "--batch-zones"), "--batch-zones");
    else if (option == "--cpu-verify-count") args.cpu_verify_count = parse_u64(value_after(i, "--cpu-verify-count"), "--cpu-verify-count");
    else if (option == "--kernel") args.kernel = value_after(i, "--kernel");
    else if (option == "--overwrite") args.overwrite = true;
    else if (option == "--list-devices") args.list_devices = true;
    else if (option == "--help" || option == "-h") args.help = true;
    else throw std::invalid_argument("unknown option: " + option);
  }
  return args;
}

void print_help() {
  std::cout <<
      "SHA-256 header-space mapper (research only)\n\n"
      "Input (choose exactly one):\n"
      "  --preset genesis\n"
      "  --header-hex <160 serialized hexadecimal characters>\n\n"
      "Range (choose --full-space or --nonce-count):\n"
      "  --full-space                   exact range 0..0xffffffff\n"
      "  --nonce-start <u64>            default 0\n"
      "  --nonce-count <u64>\n\n"
      "Mapping:\n"
      "  --zone-size <u64>              default 1048576 (2^20)\n"
      "  --device <auto|index:N|name>   default auto\n"
      "  --local-size <power-of-two>    default 64\n"
      "  --batch-zones <count>          default 256\n"
      "  --cpu-verify-count <count>     default 65536; 0 disables\n"
      "  --output-prefix <directory>    default results/header_space\n"
      "  --kernel <path>                default kernels/header_space_map.cl\n"
      "  --overwrite                    replace the same deterministic result\n"
      "  --list-devices\n";
}

std::string hex_u32(const std::uint32_t value) {
  std::ostringstream output;
  output << std::hex << std::setw(8) << std::setfill('0') << value;
  return output.str();
}

std::string utc_timestamp() {
  const auto now = std::chrono::system_clock::now();
  const auto time = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &time);
#else
  gmtime_r(&time, &utc);
#endif
  const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
      now.time_since_epoch()).count() % 1000;
  std::ostringstream output;
  output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << '.'
         << std::setw(3) << std::setfill('0') << milliseconds << 'Z';
  return output.str();
}

std::filesystem::path resolve_kernel(const std::filesystem::path& configured, const char* executable) {
  if (std::filesystem::exists(configured)) return configured;
  const auto beside_executable = std::filesystem::absolute(executable).parent_path() / configured;
  if (std::filesystem::exists(beside_executable)) return beside_executable;
  throw std::runtime_error("OpenCL kernel not found: " + configured.string());
}

void write_atomic(const std::filesystem::path& path, const std::string& text, const bool overwrite) {
  std::filesystem::create_directories(path.parent_path());
  if (std::filesystem::exists(path) && !overwrite) {
    throw std::runtime_error("result already exists (use --overwrite): " + path.string());
  }
  auto temporary = path;
  temporary += ".tmp";
  std::error_code ignored;
  std::filesystem::remove(temporary, ignored);
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot create output: " + temporary.string());
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    output.flush();
    if (!output) throw std::runtime_error("cannot durably finish output: " + temporary.string());
  }
  if (overwrite) std::filesystem::remove(path, ignored);
  std::filesystem::rename(temporary, path);
}

nlohmann::json device_json(const hs::GpuDeviceInfo& device) {
  return {
      {"index", device.index},
      {"platform_index", device.platform_index},
      {"device_index", device.device_index},
      {"platform", device.platform},
      {"name", device.name},
      {"board_name", device.board_name},
      {"vendor", device.vendor},
      {"driver", device.driver},
      {"compute_units", device.compute_units},
      {"global_memory_bytes", device.global_memory_bytes},
      {"local_memory_bytes", device.local_memory_bytes},
      {"max_workgroup_size", device.max_workgroup_size},
  };
}

nlohmann::json counts_json(const hs::TailCounts& counts) {
  nlohmann::json result = nlohmann::json::object();
  for (std::size_t i = 0; i < hs::kThresholdBits.size(); ++i) {
    result["T" + std::to_string(hs::kThresholdBits[i])] = counts[i];
  }
  return result;
}

nlohmann::json theoretical_json(const std::uint64_t nonce_count, const hs::TailCounts& observed) {
  nlohmann::json result = nlohmann::json::object();
  for (std::size_t i = 0; i < hs::kThresholdBits.size(); ++i) {
    const auto expected = std::ldexp(static_cast<double>(nonce_count),
                                     -static_cast<int>(hs::kThresholdBits[i]));
    const auto difference = static_cast<double>(observed[i]) - expected;
    result["T" + std::to_string(hs::kThresholdBits[i])] = {
        {"observed", observed[i]},
        {"expected", expected},
        {"difference", difference},
        {"relative_difference", difference / expected},
    };
  }
  return result;
}

std::string zones_csv(const std::string& space_id, const std::vector<hs::ZoneStats>& zones) {
  std::ostringstream output;
  output << "space_id,zone_index,nonce_start,nonce_end,nonce_count,minimum_pow_value,"
            "minimum_hash_display,minimum_nonce,T26,T28,T30,T32,T34,T36,T38,network_hits\n";
  for (const auto& zone : zones) {
    const auto minimum = hs::pow_value_hex(zone.minimum_pow_value);
    output << space_id << ',' << zone.range.zone_index << ',' << zone.range.nonce_start << ','
           << zone.range.nonce_end << ',' << zone.range.nonce_count << ",0x" << minimum << ','
           << minimum << ',' << zone.minimum_nonce;
    for (const auto count : zone.counts) output << ',' << count;
    output << ',' << zone.network_hits;
    output << '\n';
  }
  return output.str();
}

struct Integrity {
  bool layout_exact{false};
  bool nonce_count_sum{false};
  bool threshold_sums{false};
  bool network_hit_sum{false};
  bool minimum_merge{false};
  bool records_valid{false};

  [[nodiscard]] bool passed() const noexcept {
    return layout_exact && nonce_count_sum && threshold_sums && network_hit_sum &&
        minimum_merge && records_valid;
  }
};

Integrity validate_integrity(const std::vector<hs::ZoneStats>& zones,
                             const std::uint64_t nonce_start,
                             const std::uint64_t nonce_count,
                             const std::uint64_t zone_size,
                             const hs::GlobalStats& global) {
  const auto expected = hs::make_zone_layout(nonce_start, nonce_count, zone_size);
  Integrity integrity;
  integrity.layout_exact = zones.size() == expected.size();
  std::uint64_t summed_nonces = 0;
  hs::TailCounts summed_counts{};
  std::uint64_t summed_network_hits = 0;
  integrity.records_valid = true;
  for (std::size_t i = 0; i < zones.size(); ++i) {
    const auto& zone = zones[i];
    if (i >= expected.size() || zone.range.zone_index != expected[i].zone_index ||
        zone.range.nonce_start != expected[i].nonce_start ||
        zone.range.nonce_end != expected[i].nonce_end ||
        zone.range.nonce_count != expected[i].nonce_count) {
      integrity.layout_exact = false;
    }
    summed_nonces += zone.range.nonce_count;
    summed_network_hits += zone.network_hits;
    if (zone.minimum_nonce < zone.range.nonce_start || zone.minimum_nonce > zone.range.nonce_end) {
      integrity.records_valid = false;
    }
    std::uint64_t previous = zone.range.nonce_count;
    for (std::size_t threshold = 0; threshold < zone.counts.size(); ++threshold) {
      summed_counts[threshold] += zone.counts[threshold];
      if (zone.counts[threshold] > previous) integrity.records_valid = false;
      previous = zone.counts[threshold];
    }
  }
  integrity.nonce_count_sum = summed_nonces == nonce_count && global.total_nonce_count == nonce_count;
  integrity.threshold_sums = summed_counts == global.counts;
  integrity.network_hit_sum = summed_network_hits == global.network_hits;
  const auto merged = hs::aggregate_zones(zones);
  integrity.minimum_merge = merged.minimum_pow_value == global.minimum_pow_value &&
      merged.minimum_nonce == global.minimum_nonce && merged.minimum_zone == global.minimum_zone;
  return integrity;
}

void list_devices() {
  if (!hs::opencl_compiled()) {
    std::cout << "[HEADER-SPACE] OpenCL support was not compiled\n";
    return;
  }
  const auto devices = hs::enumerate_gpu_devices();
  if (devices.empty()) {
    std::cout << "[HEADER-SPACE] no OpenCL GPU detected\n";
    return;
  }
  for (const auto& device : devices) {
    std::cout << "[HEADER-SPACE] index=" << device.index << " platform=\"" << device.platform
              << "\" name=\"" << device.name << "\" board=\"" << device.board_name
              << "\" vendor=\"" << device.vendor << "\"\n";
  }
}

int run(const int argc, char** argv) {
  const auto args = parse_arguments(argc, argv);
  if (args.help) {
    print_help();
    return 0;
  }
  if (args.list_devices) {
    list_devices();
    return 0;
  }
  if (args.preset.has_value() == args.header_hex.has_value()) {
    throw std::invalid_argument("choose exactly one of --preset or --header-hex");
  }
  if (args.full_space && args.nonce_count.has_value()) {
    throw std::invalid_argument("--full-space and --nonce-count are mutually exclusive");
  }
  if (!args.full_space && !args.nonce_count.has_value()) {
    throw std::invalid_argument("choose --full-space or provide --nonce-count");
  }
  if (args.full_space && args.nonce_start != 0) {
    throw std::invalid_argument("--full-space requires nonce_start=0");
  }
  const auto nonce_start = args.full_space ? 0U : args.nonce_start;
  const auto nonce_count = args.full_space ? hs::kNonceSpaceSize : *args.nonce_count;
  (void)hs::make_zone_layout(nonce_start, nonce_count, args.zone_size);

  srm::bitcoin::Header header{};
  std::string preset_name;
  if (args.preset) {
    if (*args.preset != "genesis") throw std::invalid_argument("unknown preset: " + *args.preset);
    header = hs::genesis_header();
    preset_name = *args.preset;
  } else {
    header = hs::header_from_hex(*args.header_hex);
  }
  srm::bitcoin::set_nonce(header, 0);
  const auto metadata = hs::decode_header(header);
  const auto prefix_digest = srm::crypto::sha256(
      std::span<const std::uint8_t>(header.data(), 76));
  const auto space_id = "hs_" + srm::crypto::digest_hex(prefix_digest);
  const auto experiment_id = space_id + "_n" + std::to_string(nonce_start) +
      "_c" + std::to_string(nonce_count) + "_z" + std::to_string(args.zone_size);
  const auto output_directory = args.output_prefix / experiment_id;
  const auto summary_path = output_directory / "summary.json";
  const auto zones_path = output_directory / "zones.csv";
  if (!args.overwrite && (std::filesystem::exists(summary_path) || std::filesystem::exists(zones_path))) {
    throw std::runtime_error("deterministic result already exists (use --overwrite): " + output_directory.string());
  }

  const auto genesis = hs::validate_genesis();
  if (!genesis.passed()) throw std::runtime_error("mandatory Genesis self-validation failed");
  const auto kernel_path = resolve_kernel(args.kernel, argv[0]);
  hs::GpuScanner scanner(args.device, kernel_path, args.local_size);
  std::cout << "[HEADER-SPACE] preset=" << (preset_name.empty() ? "custom" : preset_name) << '\n';
  std::cout << "[HEADER-SPACE] device="
            << (scanner.device().board_name.empty() ? scanner.device().name : scanner.device().board_name) << '\n';
  std::cout << "[HEADER-SPACE] range=" << nonce_start << ".." << nonce_start + nonce_count - 1U << '\n';
  const auto zone_count = hs::make_zone_layout(nonce_start, nonce_count, args.zone_size).size();
  std::cout << "[HEADER-SPACE] zones=" << zone_count << " zone_size=" << args.zone_size << '\n';

  bool cpu_gpu_performed = false;
  bool cpu_gpu_equal = false;
  std::uint64_t verified_count = 0;
  double cpu_verify_seconds = 0.0;
  double gpu_verify_seconds = 0.0;
  std::optional<hs::GpuScanResult> scan;
  if (args.cpu_verify_count > 0) {
    verified_count = std::min(nonce_count, args.cpu_verify_count);
    if (verified_count == nonce_count) {
      scan = scanner.scan(header, nonce_start, nonce_count, args.zone_size, args.batch_zones);
      gpu_verify_seconds = scan->elapsed_seconds;
      const auto before = std::chrono::steady_clock::now();
      const auto cpu = hs::scan_cpu(header, nonce_start, nonce_count, args.zone_size);
      cpu_verify_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - before).count();
      cpu_gpu_equal = hs::same_statistics(cpu, scan->zones);
    } else {
      const auto gpu_verification = scanner.scan(header, nonce_start, verified_count,
                                                 args.zone_size, args.batch_zones);
      gpu_verify_seconds = gpu_verification.elapsed_seconds;
      const auto before = std::chrono::steady_clock::now();
      const auto cpu = hs::scan_cpu(header, nonce_start, verified_count, args.zone_size);
      cpu_verify_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - before).count();
      cpu_gpu_equal = hs::same_statistics(cpu, gpu_verification.zones);
    }
    cpu_gpu_performed = true;
    if (!cpu_gpu_equal) throw std::runtime_error("CPU/GPU exact statistics validation failed");
  }
  if (!scan) scan = scanner.scan(header, nonce_start, nonce_count, args.zone_size, args.batch_zones);

  const auto global = hs::aggregate_zones(scan->zones);
  const auto integrity = validate_integrity(scan->zones, nonce_start, nonce_count, args.zone_size, global);
  if (!integrity.passed()) throw std::runtime_error("zone/global integrity validation failed");
  const auto hash_rate = scan->elapsed_seconds > 0.0
      ? static_cast<double>(nonce_count) / scan->elapsed_seconds : 0.0;
  const auto minimum_hex = hs::pow_value_hex(global.minimum_pow_value);
  const auto finished_at = utc_timestamp();

  nlohmann::json header_json = {
      {"version", metadata.version},
      {"version_hex", hex_u32(metadata.version)},
      {"previous_block_hash", metadata.previous_block_hash},
      {"merkle_root", metadata.merkle_root},
      {"ntime", metadata.ntime},
      {"ntime_hex", hex_u32(metadata.ntime)},
      {"nbits", metadata.nbits},
      {"nbits_hex", hex_u32(metadata.nbits)},
      {"header_prefix_76_bytes_hex", metadata.header_prefix_76_bytes_hex},
      {"full_header_template_with_nonce_zero_hex", metadata.full_header_template_with_nonce_zero_hex},
  };
  try {
    header_json["target_from_nbits"] = srm::bitcoin::target_hex(
        srm::bitcoin::target_from_nbits(hex_u32(metadata.nbits)));
    header_json["nbits_target_decoded"] = true;
  } catch (const std::exception& error) {
    header_json["target_from_nbits"] = nullptr;
    header_json["nbits_target_decoded"] = false;
    header_json["nbits_target_error"] = error.what();
  }

  const bool validation_passed = genesis.passed() && integrity.passed() &&
      (!cpu_gpu_performed || cpu_gpu_equal);
  nlohmann::json report = {
      {"schema_version", 1},
      {"status", "COMPLETE"},
      {"analysis", "exact_sha256d_header_space_zone_map"},
      {"space_id", space_id},
      {"experiment_id", experiment_id},
      {"experiment_class", preset_name == "genesis" ? "REFERENCE_BITCOIN" : "UNCLASSIFIED_HEADER"},
      {"preset", preset_name.empty() ? nlohmann::json(nullptr) : nlohmann::json(preset_name)},
      {"completed_at_utc", finished_at},
      {"header", header_json},
      {"pow_definition", {
          {"raw_digest_byte_order", "SHA-256 digest bytes"},
          {"pow_value", "raw SHA256d digest interpreted as a little-endian uint256"},
          {"comparison", "pow_value <= target"},
          {"display", "32 raw digest bytes reversed; identical hex digits to pow_value in big-endian notation"},
          {"minimum_comparison", "exact lexicographic comparison of eight big-endian uint32 words"},
          {"equal_hash_tie_break", "smallest nonce"},
      }},
      {"range", {
          {"full_space", args.full_space},
          {"nonce_start", nonce_start},
          {"nonce_end", nonce_start + nonce_count - 1U},
          {"nonce_count", nonce_count},
      }},
      {"zone_map", {
          {"zone_size", args.zone_size},
          {"zone_count", scan->zones.size()},
          {"zone_index_definition", "floor(nonce / zone_size), independent of scan start and header"},
          {"partial_boundary_zones_allowed", true},
          {"offline_multiscale_aggregation", "sum adjacent counts and choose the exact minimum with the same tie-break"},
      }},
      {"gpu", {
          {"device", device_json(scan->device)},
          {"local_size", scan->local_size},
          {"batch_zones", scan->batch_zones},
          {"maximum_global_size", scan->maximum_global_size},
          {"kernel_launches", scan->kernel_launches},
          {"kernel_path", kernel_path.string()},
          {"reduction", "one workgroup per zone; private counters -> local-memory reduction -> one compact zone record"},
          {"global_atomics_per_hash", 0},
          {"counter_width_bits", 64},
      }},
      {"performance", {
          {"elapsed_seconds", scan->elapsed_seconds},
          {"kernel_seconds", scan->kernel_seconds},
          {"total_hashes", nonce_count},
          {"effective_hashrate_hps", hash_rate},
      }},
      {"global_statistics", {
          {"total_nonce_count", global.total_nonce_count},
          {"global_minimum_pow_value", "0x" + minimum_hex},
          {"global_minimum_hash_display", minimum_hex},
          {"global_minimum_nonce", global.minimum_nonce},
          {"global_minimum_zone", global.minimum_zone},
          {"tail_counts", counts_json(global.counts)},
          {"network_target_hits", global.network_hits},
      }},
      {"theoretical_tail_expectations", theoretical_json(nonce_count, global.counts)},
      {"validations", {
          {"all_passed", validation_passed},
          {"genesis", {
              {"header_serialization", genesis.header_serialization},
              {"nonce_little_endian", genesis.nonce_little_endian},
              {"known_hash", genesis.known_hash},
              {"pow_value_le_target", genesis.pow_target},
              {"displayed_hash", genesis.displayed_hash},
              {"target", genesis.target},
          }},
          {"cpu_gpu_exact", {
              {"performed", cpu_gpu_performed},
              {"equal", cpu_gpu_performed ? nlohmann::json(cpu_gpu_equal) : nlohmann::json(nullptr)},
              {"nonce_start", cpu_gpu_performed ? nlohmann::json(nonce_start) : nlohmann::json(nullptr)},
              {"nonce_count", cpu_gpu_performed ? nlohmann::json(verified_count) : nlohmann::json(nullptr)},
              {"cpu_seconds", cpu_gpu_performed ? nlohmann::json(cpu_verify_seconds) : nlohmann::json(nullptr)},
              {"gpu_seconds", cpu_gpu_performed ? nlohmann::json(gpu_verify_seconds) : nlohmann::json(nullptr)},
          }},
          {"logical_allocation", {
              {"layout_exact", integrity.layout_exact},
              {"no_holes", integrity.layout_exact && integrity.nonce_count_sum},
              {"no_duplicates", integrity.layout_exact && integrity.nonce_count_sum},
              {"last_nonce_included", scan->zones.back().range.nonce_end == nonce_start + nonce_count - 1U},
              {"nonce_zero_included", nonce_start == 0},
              {"nonce_0xffffffff_included", nonce_start + nonce_count == hs::kNonceSpaceSize},
          }},
          {"zone_to_global", {
              {"nonce_count_sum", integrity.nonce_count_sum},
              {"threshold_sums", integrity.threshold_sums},
              {"network_target_hit_sum", integrity.network_hit_sum},
              {"minimum_merge", integrity.minimum_merge},
              {"records_valid", integrity.records_valid},
          }},
      }},
      {"protocol", {
          {"measurement_only", true},
          {"declares_favorable_zones", false},
          {"cryptanalytic_claim", false},
          {"future_campaign_split_required", {"DISCOVERY", "HOLDOUT"}},
          {"multiple_testing_warning", "4096 zones x multiple thresholds x many header-spaces will create chance extremes"},
      }},
      {"resume", {
          {"intra_space_resume_supported", false},
          {"completed_space_outputs_atomic", true},
          {"completion_marker", "summary.json status=COMPLETE is written after zones.csv"},
      }},
      {"optional_histograms", {
          {"leading_zero_histogram", "deferred to avoid additional reduction state"},
          {"top_8_bit_histogram", "deferred to avoid per-hash global atomics and larger local reductions"},
      }},
  };

  const auto csv = zones_csv(space_id, scan->zones);
  const auto json = report.dump(2) + '\n';
  write_atomic(zones_path, csv, args.overwrite);
  write_atomic(summary_path, json, args.overwrite);

  std::cout << "[HEADER-SPACE] hashes=" << nonce_count << '\n';
  std::cout << "[HEADER-SPACE] elapsed=" << scan->elapsed_seconds << " s\n";
  std::cout << "[HEADER-SPACE] hashrate=" << hash_rate << " H/s\n";
  std::cout << "[HEADER-SPACE] minimum=" << minimum_hex << '\n';
  std::cout << "[HEADER-SPACE] minimum_nonce=" << global.minimum_nonce << '\n';
  for (std::size_t i = 0; i < hs::kThresholdBits.size(); ++i) {
    std::cout << "[HEADER-SPACE] T" << hs::kThresholdBits[i] << '=' << global.counts[i] << '\n';
  }
  std::cout << "[HEADER-SPACE] network_hits=" << global.network_hits << '\n';
  std::cout << "[HEADER-SPACE] validation=" << (validation_passed ? "PASS" : "FAIL") << '\n';
  std::cout << "[HEADER-SPACE] summary=" << summary_path.string() << '\n';
  std::cout << "[HEADER-SPACE] zones=" << zones_path.string() << '\n';
  return validation_passed ? 0 : 2;
}

}  // namespace

int main(const int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::cerr << "[HEADER-SPACE] ERROR: " << error.what() << '\n';
    return 1;
  }
}
