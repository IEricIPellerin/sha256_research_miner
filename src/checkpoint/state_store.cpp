//src\checkpoint\state_store.cpp
#include "checkpoint/state_store.h"

#include "platform/windows_utf8.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <limits>
#include <string>
#include <thread>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace srm::checkpoint {
namespace {

#ifdef _WIN32

[[noreturn]] void throw_win32_error(const std::string& operation, const DWORD code) {
  throw PersistenceError(
      operation + " (Win32 " + std::to_string(code) + "): " +
      platform::windows_error_message_utf8(code));
}

bool transient_lock_error(const DWORD code) {
  return code == ERROR_SHARING_VIOLATION || code == ERROR_ACCESS_DENIED;
}

constexpr std::array<unsigned, 4> retry_backoff_ms{0, 10, 25, 50};

HANDLE open_temporary_with_retry(const std::filesystem::path& temporary) {
  DWORD last_error = ERROR_SUCCESS;
  for (std::size_t attempt = 0; attempt < retry_backoff_ms.size(); ++attempt) {
    if (retry_backoff_ms[attempt] != 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms[attempt]));
    }
    const auto handle = CreateFileW(
        temporary.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle != INVALID_HANDLE_VALUE) return handle;
    last_error = GetLastError();
    if (!transient_lock_error(last_error)) break;
  }
  throw_win32_error(
      "cannot create checkpoint temporary file " + platform::path_utf8(temporary), last_error);
}

void replace_with_retry(
    const std::filesystem::path& temporary,
    const std::filesystem::path& destination) {
  DWORD last_error = ERROR_SUCCESS;
  for (std::size_t attempt = 0; attempt < retry_backoff_ms.size(); ++attempt) {
    if (retry_backoff_ms[attempt] != 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(retry_backoff_ms[attempt]));
    }
    if (MoveFileExW(
            temporary.c_str(), destination.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      return;
    }
    last_error = GetLastError();
    if (!transient_lock_error(last_error)) break;
  }
  throw_win32_error(
      "atomic checkpoint replace failed for " + platform::path_utf8(destination), last_error);
}

#endif

}  // namespace

StateStore::StateStore(std::filesystem::path path) : path_(std::move(path)) {}

nlohmann::json StateStore::load_or(const nlohmann::json& fallback) const {
  std::ifstream input(path_, std::ios::binary);
  if (!input) return fallback;
  try {
    nlohmann::json value;
    input >> value;
    return value;
  } catch (const std::exception& error) {
    throw std::runtime_error(
        "invalid checkpoint " + platform::path_utf8(path_) + ": " + error.what());
  }
}

void StateStore::save(const nlohmann::json& state) const {
  const auto payload = state.dump(2) + '\n';
  std::error_code directory_error;
  std::filesystem::create_directories(path_.parent_path(), directory_error);
  if (directory_error) {
    const auto detail = platform::error_message_utf8(directory_error);
    const auto directory = platform::path_utf8(path_.parent_path());
    throw PersistenceError(
        "cannot create checkpoint directory " + directory + ": " + detail);
  }
  auto temporary = path_;
  temporary += ".tmp";

#ifdef _WIN32
  const auto temporary_handle = open_temporary_with_retry(temporary);
  std::size_t offset = 0;
  while (offset < payload.size()) {
    const auto remaining = payload.size() - offset;
    const auto chunk = static_cast<DWORD>(std::min<std::size_t>(
        remaining, std::numeric_limits<DWORD>::max()));
    DWORD written = 0;
    const auto write_succeeded =
        WriteFile(temporary_handle, payload.data() + offset, chunk, &written, nullptr) != FALSE;
    if (!write_succeeded || written != chunk) {
      const auto write_error = write_succeeded ? ERROR_WRITE_FAULT : GetLastError();
      CloseHandle(temporary_handle);
      throw_win32_error(
          "cannot write checkpoint temporary file " + platform::path_utf8(temporary), write_error);
    }
    offset += written;
  }
  if (!FlushFileBuffers(temporary_handle)) {
    const auto flush_error = GetLastError();
    CloseHandle(temporary_handle);
    throw_win32_error(
        "checkpoint FlushFileBuffers failed for " + platform::path_utf8(temporary), flush_error);
  }
  CloseHandle(temporary_handle);
  replace_with_retry(temporary, path_);
#else
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw PersistenceError("cannot create checkpoint temporary file: " + temporary.string());
    output << payload;
    output.flush();
    if (!output) throw PersistenceError("cannot flush checkpoint temporary file: " + temporary.string());
  }
  std::error_code error;
  std::filesystem::rename(temporary, path_, error);
  if (error) {
    throw PersistenceError(
        "atomic checkpoint rename failed: " + platform::error_message_utf8(error));
  }
#endif
}

}  // namespace srm::checkpoint
