//tests\mock_stratum_server.cpp
#include "bitcoin/difficulty.h"
#include "crypto/sha256d.h"
#include "stratum/stratum_job.h"

#include <algorithm>
#include <asio.hpp>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

namespace {

void send(asio::ip::tcp::socket& socket, const nlohmann::json& value) {
  const auto line = value.dump() + "\n";
  asio::write(socket, asio::buffer(line));
}

nlohmann::json receive(asio::ip::tcp::socket& socket, asio::streambuf& buffer) {
  asio::read_until(socket, buffer, '\n');
  std::istream input(&buffer);
  std::string line;
  std::getline(input, line);
  return nlohmann::json::parse(line);
}

srm::stratum::StratumJob notify(
    asio::ip::tcp::socket& socket,
    const std::string& id,
    const bool clean) {
  srm::stratum::StratumJob job{
      id,
      "0000000000000000000000000000000000000000000000000000000000000000",
      "01000000", "00000000", {}, "20000000", "1d00ffff", "65000000", clean};
  send(socket, {{"id", nullptr}, {"method", "mining.notify"}, {"params", nlohmann::json::array({
      job.job_id, job.prevhash, job.coinbase1, job.coinbase2, job.merkle_branches,
      job.version, job.nbits, job.ntime, job.clean_jobs})}});
  return job;
}

std::uint32_t parse_nonce(const std::string& value) {
  if (value.size() != 8 ||
      !std::all_of(value.begin(), value.end(), [](const unsigned char c) {
        return std::isdigit(c) != 0 || (c >= 'a' && c <= 'f');
      })) {
    throw std::runtime_error("mining.submit nonce must be eight lowercase hexadecimal characters");
  }
  std::uint32_t nonce = 0;
  const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), nonce, 16);
  if (error != std::errc{} || end != value.data() + value.size()) {
    throw std::runtime_error("cannot parse mining.submit nonce");
  }
  return nonce;
}

std::uint32_t first_valid_nonce(
    const srm::stratum::StratumJob& job,
    const std::string& extranonce1,
    const std::string& extranonce2,
    const srm::bitcoin::Target256& target) {
  auto built = srm::stratum::build_work(job, extranonce1, extranonce2, 0);
  for (std::uint64_t nonce = 0; nonce <= 0xffffffffULL; ++nonce) {
    srm::bitcoin::set_nonce(built.header, static_cast<std::uint32_t>(nonce));
    if (srm::bitcoin::hash_meets_target(srm::crypto::sha256d(built.header), target)) {
      return static_cast<std::uint32_t>(nonce);
    }
  }
  throw std::runtime_error("mock target unexpectedly has no valid nonce");
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto port = static_cast<unsigned short>(argc > 1 ? std::stoi(argv[1]) : 3334);
    asio::io_context context;
    asio::ip::tcp::acceptor acceptor(context, {asio::ip::make_address("127.0.0.1"), port});
    std::cout << "mock Stratum listening on 127.0.0.1:" << port << std::endl;
    asio::ip::tcp::socket socket(context);
    acceptor.accept(socket);
    asio::streambuf buffer;
    bool subscribed = false;
    bool authorized = false;
    unsigned submits = 0;
    constexpr double share_difficulty = 0.00001;
    const auto share_target = srm::bitcoin::share_target_from_difficulty(share_difficulty);
    const std::string extranonce1 = "01020304";
    std::string active_job = "mock-job-1";
    auto active_job_data = srm::stratum::StratumJob{};
    while (submits < 2) {
      const auto request = receive(socket, buffer);
      const auto method = request.value("method", "");
      if (method == "mining.subscribe") {
        send(socket, {{"id", request.at("id")}, {"error", nullptr}, {"result", nlohmann::json::array({
            nlohmann::json::array({nlohmann::json::array({"mining.notify", "mock-subscription"})}), extranonce1, 4})}});
        subscribed = true;
      } else if (method == "mining.authorize") {
        send(socket, {{"id", request.at("id")}, {"error", nullptr}, {"result", true}});
        authorized = true;
        send(socket, {{"id", nullptr}, {"method", "mining.set_difficulty"}, {"params", nlohmann::json::array({share_difficulty})}});
        active_job_data = notify(socket, "mock-job-1", true);
      } else if (method == "mining.submit") {
        if (!subscribed || !authorized) {
          throw std::runtime_error("submit before handshake");
        }

        const auto& params = request.at("params");

        if (!params.is_array() || params.size() != 5) {
          throw std::runtime_error("mining.submit must contain exactly five parameters");
        }

        const auto username = params.at(0).get<std::string>();
        const auto job_id = params.at(1).get<std::string>();
        const auto extranonce2 = params.at(2).get<std::string>();
        const auto ntime = params.at(3).get<std::string>();
        const auto nonce = params.at(4).get<std::string>();

        if (username.empty()) {
          throw std::runtime_error("mining.submit username is empty");
        }

        if (job_id != active_job) {
          send(socket, {
              {"id", request.at("id")},
              {"error", nlohmann::json::array({21, "Stale", nullptr})},
              {"result", false}
          });
          continue;
        }

        if (extranonce2.size() != 8) {
          throw std::runtime_error("mining.submit extranonce2 must contain exactly four bytes");
        }

        if (ntime != "65000000") {
          throw std::runtime_error("mining.submit ntime does not match the active job");
        }

        const auto numeric_nonce = parse_nonce(nonce);
        const auto expected_nonce = first_valid_nonce(
            active_job_data, extranonce1, extranonce2, share_target);
        const auto endian_inverted_nonce =
            ((expected_nonce & 0x000000ffU) << 24U) |
            ((expected_nonce & 0x0000ff00U) << 8U) |
            ((expected_nonce & 0x00ff0000U) >> 8U) |
            ((expected_nonce & 0xff000000U) >> 24U);
        if (expected_nonce == endian_inverted_nonce) {
          throw std::runtime_error("mock fixture nonce does not exercise endian inversion");
        }
        if (numeric_nonce != expected_nonce) {
          throw std::runtime_error(
              "mining.submit nonce does not reconstruct the first mined valid header; possible endian inversion");
        }
        const auto reconstructed = srm::stratum::build_work(
            active_job_data, extranonce1, extranonce2, numeric_nonce);
        if (!srm::bitcoin::hash_meets_target(
                srm::crypto::sha256d(reconstructed.header), share_target)) {
          throw std::runtime_error("reconstructed mining.submit header is above the announced share target");
        }

        ++submits;
        if (submits == 1) {
          send(socket, {
              {"id", request.at("id")},
              {"error", nullptr},
              {"result", true}
          });
        } else {
          send(socket, {
              {"id", request.at("id")},
              {"error", nlohmann::json::array({23, "Mock rejection", nullptr})},
              {"result", false}
          });
        }

        std::cout << "validated mock submit " << submits
                  << " extranonce2=" << extranonce2
                  << " ntime=" << ntime
                  << " nonce=" << nonce
                  << std::endl;

        if (submits == 1) {
          active_job = "mock-job-2";
          active_job_data = notify(socket, active_job, true);
        } else {
          std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
      }
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "mock server error: " << error.what() << '\n';
    return 1;
  }
}
