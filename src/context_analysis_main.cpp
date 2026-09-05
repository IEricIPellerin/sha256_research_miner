//src\context_analysis_main.cpp
#include "research/context_campaign.h"
#include "research/context_phase2.h"

#include <algorithm>
#include <cmath>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>

namespace cc = srm::research::context_campaign;
namespace phase2 = srm::research::context_phase2;

namespace {

struct Arguments {
  std::string command{"help"};
  std::string profile{"CUSTOM"};
  std::filesystem::path config{"config/context_analysis.json"};
  std::optional<std::filesystem::path> archive;
  std::optional<std::filesystem::path> output;
  std::optional<std::filesystem::path> campaign;
  std::optional<std::uint64_t> total_blocks;
  std::optional<double> minutes;
  std::optional<std::size_t> blocks_per_context;
  std::optional<std::size_t> prevhashes;
  std::optional<std::size_t> contexts;
  std::optional<std::uint64_t> seed;
  std::optional<std::uint64_t> benchmark_nonces;
  std::uint64_t smoke_nonces{65536U};
  std::string device;
  bool yes{false};
  bool finalize_holdout{false};
  bool phase2_check{false};
  std::optional<std::string> partition;
  std::optional<std::size_t> folds;
  std::optional<std::size_t> bootstrap_replicates;
  std::optional<std::size_t> permutation_replicates;
  std::optional<std::size_t> selected_features;
};

std::uint64_t u64(const std::string& value, const char* name) {
  std::size_t consumed = 0;
  const auto result = std::stoull(value, &consumed, 0);
  if (consumed != value.size()) throw std::invalid_argument(std::string("invalid ") + name);
  return result;
}

double real(const std::string& value, const char* name) {
  std::size_t consumed = 0;
  const auto result = std::stod(value, &consumed);
  if (consumed != value.size() || !std::isfinite(result) || result <= 0.0) {
    throw std::invalid_argument(std::string("invalid ") + name);
  }
  return result;
}

Arguments parse(const int argc, char** argv) {
  Arguments args;
  if (argc > 1) args.command = argv[1];
  for (int i = 2; i < argc; ++i) {
    const std::string key = argv[i];
    const auto next = [&]() -> std::string {
      if (++i >= argc) throw std::invalid_argument("missing value after " + key);
      return argv[i];
    };
    if (key == "--config") args.config = next();
    else if (key == "--profile") args.profile = next();
    else if (key == "--archive") args.archive = next();
    else if (key == "--output-root") args.output = next();
    else if (key == "--campaign") args.campaign = next();
    else if (key == "--total-blocks") args.total_blocks = u64(next(), "total blocks");
    else if (key == "--minutes") args.minutes = real(next(), "time budget");
    else if (key == "--blocks-per-context") args.blocks_per_context = static_cast<std::size_t>(u64(next(), "blocks per context"));
    else if (key == "--prevhashes") args.prevhashes = static_cast<std::size_t>(u64(next(), "prevhash count"));
    else if (key == "--contexts") args.contexts = static_cast<std::size_t>(u64(next(), "context count"));
    else if (key == "--seed") args.seed = u64(next(), "seed");
    else if (key == "--device") args.device = next();
    else if (key == "--benchmark-nonces") args.benchmark_nonces = u64(next(), "benchmark nonce count");
    else if (key == "--smoke-nonces") args.smoke_nonces = u64(next(), "smoke nonce count");
    else if (key == "--yes") args.yes = true;
    else if (key == "--finalize-holdout") args.finalize_holdout = true;
    else if (key == "--check" || key == "--dry-run") args.phase2_check = true;
    else if (key == "--partition") args.partition = next();
    else if (key == "--folds") args.folds = static_cast<std::size_t>(u64(next(), "fold count"));
    else if (key == "--bootstrap-replicates") args.bootstrap_replicates = static_cast<std::size_t>(u64(next(), "bootstrap replicate count"));
    else if (key == "--permutation-replicates") args.permutation_replicates = static_cast<std::size_t>(u64(next(), "permutation replicate count"));
    else if (key == "--selected-features") args.selected_features = static_cast<std::size_t>(u64(next(), "selected feature count"));
    else throw std::invalid_argument("unknown argument: " + key);
  }
  return args;
}

nlohmann::json read_json(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot open configuration: " + path.string());
  nlohmann::json value;
  input >> value;
  return value;
}

std::filesystem::path absolute_from(const std::filesystem::path& root,
                                    const std::filesystem::path& value) {
  return value.is_absolute() ? value : root / value;
}

std::filesystem::path project_root(const std::filesystem::path& config) {
  const auto absolute = std::filesystem::absolute(config);
  return absolute.parent_path().parent_path();
}

cc::CampaignRequest request_from(const Arguments& args, const nlohmann::json& config) {
  cc::CampaignRequest request;
  request.profile = args.profile;
  const auto scientific = config.value("scientific", nlohmann::json::object());
  request.discovery_fraction = scientific.value("discovery_fraction", 0.60);
  request.validation_fraction = scientific.value("validation_fraction", 0.20);
  request.holdout_fraction = scientific.value("holdout_fraction", 0.20);
  const auto profiles = config.value("profiles", nlohmann::json::object());
  if (args.profile != "CUSTOM") {
    if (!profiles.contains(args.profile)) throw std::invalid_argument("unknown profile: " + args.profile);
    const auto& profile = profiles.at(args.profile);
    request.prevhash_count = profile.value("prevhash_count", 0U);
    request.context_count = profile.value("context_count", 0U);
    const auto sizing = profile.value("sizing", "total_blocks");
    if (sizing == "total_blocks") request.total_blocks = profile.at("total_blocks").get<std::uint64_t>();
    else if (sizing == "time_budget_minutes") request.time_budget_minutes = profile.at("time_budget_minutes").get<double>();
    else if (sizing == "blocks_per_context") request.blocks_per_context = profile.at("blocks_per_context").get<std::size_t>();
    else throw std::invalid_argument("unknown profile sizing: " + sizing);
  }
  if (args.seed) request.seed = *args.seed;
  if (args.prevhashes) request.prevhash_count = *args.prevhashes;
  if (args.contexts) request.context_count = *args.contexts;
  if (args.total_blocks || args.minutes || args.blocks_per_context) {
    request.total_blocks.reset();
    request.time_budget_minutes.reset();
    request.blocks_per_context.reset();
    if (args.total_blocks) request.total_blocks = args.total_blocks;
    if (args.minutes) request.time_budget_minutes = args.minutes;
    if (args.blocks_per_context) request.blocks_per_context = args.blocks_per_context;
  }
  return request;
}

void print_help() {
  std::cout <<
      "Analyseur contextuel offline B(J,e)\n\n"
      "Commandes:\n"
      "  corpus                         Résumer l'archive Stratum\n"
      "  plan --profile QUICK|PILOT|FULL|CUSTOM [dimensionnement]\n"
      "  new  --profile ...             Benchmark, aperçu, confirmation, campagne\n"
      "  resume --campaign <dossier>    Reprendre sans rescanner les blocs complets\n"
      "  analyze --campaign <dossier> [--finalize-holdout]\n"
      "  phase2 --campaign <dossier> [--check] [--yes]\n"
      "         Phase 2A discovery-only; ranking primaire intra-contexte;\n"
      "         refuse validation/holdout/finalisation\n"
      "  smoke [--smoke-nonces N]       Test court, jamais une vérité terrain\n\n"
      "Dimensionnement (au choix):\n"
      "  --total-blocks N\n"
      "  --minutes N\n"
      "  --prevhashes N --contexts N --blocks-per-context N\n\n"
      "Tous les profils sont des exemples visibles et modifiables. FULL n'impose jamais 10 000 blocs.\n";
}

void print_preview(const cc::CampaignPlan& plan) {
  const auto value = cc::plan_preview_json(plan);
  std::cout << "\n=== APERÇU AVANT CONFIRMATION ===\n"
            << "Profil                         : " << value["profile"].get<std::string>() << '\n'
            << "Seed                           : " << value["seed"].get<std::uint64_t>() << '\n'
            << "Prevhash distincts             : " << value["distinct_prevhashes"].get<std::size_t>() << '\n'
            << "Contextes Stratum              : " << value["stratum_contexts"].get<std::size_t>() << '\n'
            << "B(J,e) par contexte            : " << value["blocks_per_context_min"].get<std::size_t>()
            << " à " << value["blocks_per_context_max"].get<std::size_t>() << '\n'
            << "Total B(J,e)                   : " << value["total_blocks_B_J_e"].get<std::uint64_t>() << '\n'
            << "Total hashes prévu             : " << value["total_hashes"].get<std::uint64_t>() << '\n'
            << "Débit mesuré                   : " << value["measured_hashes_per_second"].get<double>() / 1e9 << " GH/s\n"
            << "Backend / matériel             : " << value["benchmark"]["backend"].get<std::string>() << " / "
            << value["benchmark"]["device"].get<std::string>() << '\n'
            << "Durée estimée                  : " << value["estimated_duration"].get<std::string>() << '\n'
            << "Espace disque estimé           : " << value["estimated_disk_bytes"].get<std::uint64_t>() / 1048576.0 << " MiB\n";
  for (const auto& warning : value["warnings"]) {
    std::cout << "AVERTISSEMENT: " << warning.get<std::string>() << '\n';
  }
}

void prompt_sizing(cc::CampaignRequest& request) {
  std::cout << "\nMode de dimensionnement:\n"
               "  [1] Total de B(J,e)\n"
               "  [2] Prevhash + contextes + B(J,e) par contexte\n"
               "  [3] Budget de temps en minutes\n"
               "Choix: ";
  std::string choice;
  std::getline(std::cin, choice);
  request.total_blocks.reset();
  request.time_budget_minutes.reset();
  request.blocks_per_context.reset();
  const auto ask_u64 = [](const char* prompt) {
    std::cout << prompt;
    std::string value;
    std::getline(std::cin, value);
    return u64(value, prompt);
  };
  if (choice == "1") request.total_blocks = ask_u64("Nombre total de B(J,e): ");
  else if (choice == "2") {
    request.prevhash_count = static_cast<std::size_t>(ask_u64("Nombre de prevhash: "));
    request.context_count = static_cast<std::size_t>(ask_u64("Nombre total de contextes Stratum: "));
    request.blocks_per_context = static_cast<std::size_t>(ask_u64("B(J,e) par contexte: "));
  } else if (choice == "3") {
    std::cout << "Budget en minutes: ";
    std::string value;
    std::getline(std::cin, value);
    request.time_budget_minutes = real(value, "time budget");
  } else throw std::invalid_argument("choix de dimensionnement invalide");
  if (choice != "2") {
    const auto prevhash = ask_u64("Nombre de prevhash (0 = maximum disponible): ");
    const auto contexts = ask_u64("Nombre total de contextes (0 = un par prevhash): ");
    request.prevhash_count = static_cast<std::size_t>(prevhash);
    request.context_count = static_cast<std::size_t>(contexts);
  }
}

std::filesystem::path latest_campaign(const std::filesystem::path& root) {
  std::filesystem::path result;
  std::filesystem::file_time_type newest{};
  if (!std::filesystem::exists(root)) throw std::runtime_error("no campaign output directory");
  for (const auto& entry : std::filesystem::directory_iterator(root)) {
    if (!entry.is_directory() || !std::filesystem::exists(entry.path() / "manifest.json")) continue;
    const auto time = entry.last_write_time();
    if (result.empty() || time > newest) { result = entry.path(); newest = time; }
  }
  if (result.empty()) throw std::runtime_error("no campaign manifest found");
  return result;
}

std::filesystem::path latest_complete_campaign(const std::filesystem::path& root) {
  std::filesystem::path result;
  std::filesystem::file_time_type newest{};
  if (!std::filesystem::exists(root)) throw std::runtime_error("no campaign output directory");
  for (const auto& entry : std::filesystem::directory_iterator(root)) {
    const auto checkpoint = entry.path() / "checkpoint.json";
    if (!entry.is_directory() || !std::filesystem::exists(entry.path() / "manifest.json") ||
        !std::filesystem::exists(checkpoint)) continue;
    if (read_json(checkpoint).value("status", "") != "COMPLETE") continue;
    const auto time = entry.last_write_time();
    if (result.empty() || time > newest) { result = entry.path(); newest = time; }
  }
  if (result.empty()) throw std::runtime_error("no complete campaign found");
  return result;
}

int run(const int argc, char** argv) {
  auto args = parse(argc, argv);
  if (args.command != "phase2" &&
      (args.phase2_check || args.partition || args.folds ||
       args.bootstrap_replicates || args.permutation_replicates ||
       args.selected_features)) {
    throw std::invalid_argument("Phase 2 options are accepted only by the phase2 command");
  }
  if (args.command == "help" || args.command == "--help" || args.command == "-h") {
    print_help();
    return 0;
  }
  const auto config = read_json(args.config);
  const auto root = project_root(args.config);
  const auto archive = args.archive.value_or(absolute_from(root, config.at("archive").get<std::string>()));
  const auto output = args.output.value_or(absolute_from(root, config.at("output_root").get<std::string>()));
  const auto kernel = root / "kernels" / "header_space_map.cl";
  const auto& gpu = config.at("gpu");
  const auto device = args.device.empty() ? gpu.value("device", "auto") : args.device;
  const auto local_size = gpu.value("local_size", 64U);
  const auto zone_size = gpu.value("zone_size", 1048576ULL);
  const auto batch_zones = gpu.value("batch_zones", 256U);

  if (args.command == "resume") {
    const auto campaign = args.campaign.value_or(latest_campaign(output));
    std::cout << "Reprise: " << campaign.string() << '\n';
    return cc::run_campaign(campaign, kernel, device, zone_size, batch_zones, local_size);
  }
  if (args.command == "analyze") {
    const auto campaign = args.campaign.value_or(latest_campaign(output));
    std::cout << cc::analyze_campaign(campaign, args.finalize_holdout).dump(2) << '\n';
    return 0;
  }
  if (args.command == "phase2") {
    if (args.finalize_holdout) {
      throw std::invalid_argument(
          "Phase 2A refuses --finalize-holdout; holdout is invisible");
    }
    if (args.partition && *args.partition != "discovery") {
      throw std::invalid_argument(
          "Phase 2A refuses --partition " + *args.partition +
          "; only discovery is admissible");
    }
    phase2::Options options;
    const auto campaign = args.campaign.value_or(
        output / options.expected_campaign_id);
    std::cout << "\nCAMPAGNE: " << campaign.string() << '\n'
              << "MODE: PHASE 2A DISCOVERY ONLY\n"
              << "OBJECTIF PRIMAIRE: ranking intra-contexte des extranonce2\n"
              << "Discovery utilise: oui\n"
              << "Validation utilisee: NON\n"
              << "Holdout utilise: NON\n"
              << "Aucun scan GPU: oui\n"
              << "Donnees sources modifiees: NON\n";
    options.check_only = args.phase2_check;
    if (args.seed) options.seed = *args.seed;
    if (args.folds) options.outer_folds = *args.folds;
    if (args.bootstrap_replicates) options.bootstrap_replicates = *args.bootstrap_replicates;
    if (args.permutation_replicates) options.permutation_replicates = *args.permutation_replicates;
    if (args.selected_features) options.selected_feature_count = *args.selected_features;
    if (!options.check_only && !args.yes) {
      std::cout << "Confirmer la creation de phase2_discovery_v1 [O/N]: ";
      std::string choice;
      std::getline(std::cin, choice);
      std::transform(choice.begin(), choice.end(), choice.begin(), ::toupper);
      if (choice != "O" && choice != "OUI" && choice != "Y" && choice != "YES") {
        std::cout << "Phase 2A annulee; aucun artefact cree.\n";
        return 0;
      }
    }
    std::cout << phase2::run(campaign, options).dump(2) << '\n';
    return 0;
  }

  std::size_t rejected = 0;
  const auto contexts = cc::load_archive(archive, &rejected);
  std::set<std::string> prevhashes;
  for (const auto& context : contexts) prevhashes.insert(context.job.prevhash);
  if (args.command == "corpus") {
    std::cout << "Archive: " << archive.string() << "\nContextes replayables: " << contexts.size()
              << "\nPrevhash distincts: " << prevhashes.size() << "\nLignes notify rejetées: " << rejected << '\n';
    return 0;
  }

  auto request = request_from(args, config);
  if (args.command == "smoke") {
    request.profile = "SMOKE";
    request.total_blocks = 1;
    request.time_budget_minutes.reset();
    request.blocks_per_context.reset();
    request.prevhash_count = std::min<std::size_t>(3U, prevhashes.size());
    request.context_count = request.prevhash_count;
  } else if (!request.total_blocks && !request.time_budget_minutes && !request.blocks_per_context) {
    if (args.yes) throw std::invalid_argument("CUSTOM requires an explicit sizing option with --yes");
    prompt_sizing(request);
  }

  const auto& benchmark_config = config.at("benchmark");
  const auto benchmark_nonces = args.benchmark_nonces.value_or(
      benchmark_config.value("nonce_count", 268435456ULL));
  std::cout << "Benchmark court du débit réel...\n";
  const auto measured = cc::benchmark(contexts.front(), kernel, device, benchmark_nonces,
      benchmark_config.value("zone_size", 1048576ULL),
      benchmark_config.value("batch_zones", 256U), local_size);
  auto plan = cc::make_plan(contexts, request, measured);
  print_preview(plan);

  if (args.command == "plan") return 0;
  if (args.command == "smoke") {
    return cc::run_smoke(plan, output, kernel, device, args.smoke_nonces,
                         std::min(zone_size, args.smoke_nonces), batch_zones, local_size);
  }
  if (args.command != "new") throw std::invalid_argument("unknown command: " + args.command);

  if (!args.yes) {
    for (;;) {
      std::cout << "\n[A] Accepter  [M] Modifier  [C] Annuler : ";
      std::string choice;
      std::getline(std::cin, choice);
      std::transform(choice.begin(), choice.end(), choice.begin(), ::toupper);
      if (choice == "A") break;
      if (choice == "C") { std::cout << "Campagne annulée; aucun manifeste créé.\n"; return 0; }
      if (choice == "M") {
        prompt_sizing(request);
        plan = cc::make_plan(contexts, request, measured);
        print_preview(plan);
        continue;
      }
      std::cout << "Choix invalide.\n";
    }
  }
  const auto directory = cc::create_campaign(plan, output, archive);
  std::cout << "Manifeste créé: " << (directory / "manifest.json").string() << '\n';
  return cc::run_campaign(directory, kernel, device, zone_size, batch_zones, local_size);
}

}  // namespace

int main(const int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::cerr << "[ANALYSEUR CONTEXTE] ERREUR: " << error.what() << '\n';
    return 1;
  }
}
