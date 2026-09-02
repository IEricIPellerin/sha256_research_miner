//src\stratum\stratum_client.cpp
#include "stratum/stratum_client.h"

#include "platform/windows_utf8.h"
#include "stratum/stratum_message.h"

#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace srm::stratum {
namespace {

std::string asio_error_utf8(const asio::error_code& error) {
#ifdef _WIN32
  if (error.category() == asio::error::get_system_category()) {
    return platform::windows_error_message_utf8(error.value());
  }
#endif
  return error.message();
}

}  // namespace

struct StratumClient::Impl {
  config::CkpoolConfig config;
  Callbacks callbacks;
  asio::io_context context;
  std::unique_ptr<asio::ip::tcp::socket> socket;
  std::jthread thread;
  mutable std::mutex write_mutex;
  mutable std::mutex pending_mutex;
  std::map<std::int64_t, std::chrono::steady_clock::time_point> pending_submissions;
  std::atomic<bool> is_connected{false};
  std::atomic<bool> is_authorized{false};
  std::atomic<std::int64_t> next_id{100};

  Impl(config::CkpoolConfig value, Callbacks handlers)
      : config(std::move(value)), callbacks(std::move(handlers)) {}

  void emit(const std::string& text) const { if (callbacks.event) callbacks.event(text); }

  void send(const nlohmann::json& message) {
    const auto line = message.dump() + "\n";
    std::scoped_lock lock(write_mutex);
    if (!socket || !socket->is_open()) throw std::runtime_error("Stratum socket is not connected");
    try {
      asio::write(*socket, asio::buffer(line));
    } catch (const asio::system_error& error) {
      throw std::runtime_error(
          "Stratum write failed (code " + std::to_string(error.code().value()) + "): " +
          asio_error_utf8(error.code()));
    }
  }

  void handle(const StratumMessage& message) {
    if (message.is_notification()) {
      if (message.method == "mining.set_difficulty") {
        if (!message.params.is_array() || message.params.empty()) throw std::invalid_argument("invalid mining.set_difficulty");
        const auto value = message.params.at(0).get<double>();
        emit("[CKPOOL] mining.set_difficulty " + std::to_string(value));
        if (callbacks.difficulty) callbacks.difficulty(value);
      } else if (message.method == "mining.notify") {
        const auto job = parse_notify(message.params);
        emit("[CKPOOL] mining.notify job_id=" + job.job_id);
        if (callbacks.job) callbacks.job(job);
      } else if (message.method == "client.show_message") {
        const auto text = message.params.is_array() && !message.params.empty() ? message.params.at(0).get<std::string>() : "";
        emit("[CKPOOL] message: " + text);
      }
      return;
    }

    const auto id = *message.id;
    if (id == 1) {
      if (!message.error.is_null() && !message.error.empty()) throw std::runtime_error("mining.subscribe rejected: " + message.error.dump());
      if (!message.result.is_array() || message.result.size() < 3) throw std::runtime_error("invalid mining.subscribe response");
      const auto extranonce1 = message.result.at(1).get<std::string>();
      const auto extranonce2_size = message.result.at(2).get<unsigned>();
      emit("[CKPOOL] abonné extranonce2_size=" + std::to_string(extranonce2_size));
      if (callbacks.subscribed) callbacks.subscribed(extranonce1, extranonce2_size);
    } else if (id == 2) {
      const bool accepted = message.error.is_null() && message.result.is_boolean() && message.result.get<bool>();
      is_authorized.store(accepted, std::memory_order_release);
      emit(accepted ? "[CKPOOL] autorisé" : "[CKPOOL] autorisation refusée");
      if (callbacks.authorized) callbacks.authorized(accepted);
      if (!accepted) throw std::runtime_error("CKPool authorization failed");
    } else {
      std::chrono::steady_clock::time_point started;
      {
        std::scoped_lock lock(pending_mutex);
        const auto found = pending_submissions.find(id);
        if (found == pending_submissions.end()) return;
        started = found->second;
        pending_submissions.erase(found);
      }
      const auto latency = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count();
      const bool accepted = message.error.is_null() && message.result.is_boolean() && message.result.get<bool>();
      if (callbacks.submission) {
        callbacks.submission(id, accepted, message.raw, static_cast<std::uint64_t>(latency));
      }
    }
  }

  void run(std::stop_token stop_token) {
    while (!stop_token.stop_requested()) {
      try {
        context.restart();
        asio::ip::tcp::resolver resolver(context);
        const auto endpoints = resolver.resolve(config.host, std::to_string(config.port));
        socket = std::make_unique<asio::ip::tcp::socket>(context);
        asio::connect(*socket, endpoints);
        socket->set_option(asio::ip::tcp::no_delay(true));
        is_connected.store(true, std::memory_order_release);
        emit("[CKPOOL] connexion " + config.host + ":" + std::to_string(config.port));
        send(make_request(1, "mining.subscribe", nlohmann::json::array({"sha256_research_miner/0.1.0"})));
        send(make_request(2, "mining.authorize", nlohmann::json::array({config.username, config.password})));

        asio::streambuf buffer;
        while (!stop_token.stop_requested()) {
          asio::read_until(*socket, buffer, '\n');
          std::istream input(&buffer);
          std::string line;
          std::getline(input, line);
          if (line.empty()) continue;
          try { handle(parse_message(line)); }
          catch (const nlohmann::json::exception& error) { emit(std::string("[NETWORK] JSON Stratum invalide: ") + error.what()); }
          catch (const std::invalid_argument& error) { emit(std::string("[NETWORK] message Stratum invalide: ") + error.what()); }
        }
      } catch (const asio::system_error& error) {
        if (!stop_token.stop_requested()) {
          emit("[NETWORK] déconnexion: code " + std::to_string(error.code().value()) + ": " +
               asio_error_utf8(error.code()));
        }
      } catch (const std::exception& error) {
        if (!stop_token.stop_requested()) emit(std::string("[NETWORK] déconnexion: ") + error.what());
      }
      is_connected.store(false, std::memory_order_release);
      is_authorized.store(false, std::memory_order_release);
      if (socket) { asio::error_code ignored; socket->close(ignored); }
      if (callbacks.disconnected) callbacks.disconnected();
      if (stop_token.stop_requested() || !config.reconnect) break;
      emit("[NETWORK] reconnexion dans " + std::to_string(config.reconnect_delay_ms) + " ms");
      auto remaining = std::chrono::milliseconds(config.reconnect_delay_ms);
      while (!stop_token.stop_requested() && remaining.count() > 0) {
        const auto slice = std::min(remaining, std::chrono::milliseconds(100));
        std::this_thread::sleep_for(slice);
        remaining -= slice;
      }
    }
  }
};

StratumClient::StratumClient(config::CkpoolConfig config, Callbacks callbacks)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(callbacks))) {}

StratumClient::~StratumClient() { stop(); }

void StratumClient::start() {
  if (impl_->thread.joinable()) return;
  impl_->thread = std::jthread([this](const std::stop_token token) { impl_->run(token); });
}

void StratumClient::stop() {
  if (!impl_->thread.joinable()) return;
  impl_->thread.request_stop();
  {
    std::scoped_lock lock(impl_->write_mutex);
    if (impl_->socket) { asio::error_code ignored; impl_->socket->cancel(ignored); impl_->socket->close(ignored); }
  }
  impl_->thread.join();
}

std::int64_t StratumClient::submit(const std::string& username,
                                   const std::string& job_id,
                                   const std::string& extranonce2,
                                   const std::string& ntime,
                                   const std::string& nonce) {
  const auto id = impl_->next_id.fetch_add(1, std::memory_order_relaxed);
  {
    std::scoped_lock lock(impl_->pending_mutex);
    impl_->pending_submissions.emplace(id, std::chrono::steady_clock::now());
  }
  try {
    impl_->send(make_request(id, "mining.submit", nlohmann::json::array({username, job_id, extranonce2, ntime, nonce})));
  } catch (...) {
    std::scoped_lock lock(impl_->pending_mutex);
    impl_->pending_submissions.erase(id);
    throw;
  }
  impl_->emit("[SHARE] soumise id=" + std::to_string(id));
  return id;
}

bool StratumClient::connected() const noexcept { return impl_->is_connected.load(std::memory_order_acquire); }
bool StratumClient::authorized() const noexcept { return impl_->is_authorized.load(std::memory_order_acquire); }

}  // namespace srm::stratum
