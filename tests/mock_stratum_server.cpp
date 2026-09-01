//tests\mock_stratum_server.cpp
#include <asio.hpp>
#include <chrono>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

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

void notify(asio::ip::tcp::socket& socket, const std::string& id, const bool clean) {
  send(socket, {{"id", nullptr}, {"method", "mining.notify"}, {"params", nlohmann::json::array({
      id,
      "0000000000000000000000000000000000000000000000000000000000000000",
      "01000000", "00000000", nlohmann::json::array(), "20000000", "207fffff", "65000000", clean})}});
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
    std::string active_job = "mock-job-1";
    while (submits < 2) {
      const auto request = receive(socket, buffer);
      const auto method = request.value("method", "");
      if (method == "mining.subscribe") {
        send(socket, {{"id", request.at("id")}, {"error", nullptr}, {"result", nlohmann::json::array({
            nlohmann::json::array({nlohmann::json::array({"mining.notify", "mock-subscription"})}), "01020304", 4})}});
        subscribed = true;
      } else if (method == "mining.authorize") {
        send(socket, {{"id", request.at("id")}, {"error", nullptr}, {"result", true}});
        authorized = true;
        send(socket, {{"id", nullptr}, {"method", "mining.set_difficulty"}, {"params", nlohmann::json::array({1e-20})}});
        notify(socket, "mock-job-1", true);
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

        if (nonce.size() != 8) {
          throw std::runtime_error("mining.submit nonce must contain exactly four bytes");
        }

        send(socket, {
            {"id", request.at("id")},
            {"error", nullptr},
            {"result", true}
        });

        ++submits;
        std::cout << "accepted mock submit " << submits
                  << " extranonce2=" << extranonce2
                  << " ntime=" << ntime
                  << " nonce=" << nonce
                  << std::endl;

        if (submits == 1) {
          active_job = "mock-job-2";
          notify(socket, active_job, true);
        }
      }
    }
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "mock server error: " << error.what() << '\n';
    return 1;
  }
}
