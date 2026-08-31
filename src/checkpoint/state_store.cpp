//src\checkpoint\state_store.cpp
#include "checkpoint/state_store.h"

#include <fstream>
#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace srm::checkpoint {

StateStore::StateStore(std::filesystem::path path) : path_(std::move(path)) {}

nlohmann::json StateStore::load_or(const nlohmann::json& fallback) const {
  std::ifstream input(path_, std::ios::binary);
  if (!input) return fallback;
  try {
    nlohmann::json value;
    input >> value;
    return value;
  } catch (const std::exception& error) {
    throw std::runtime_error("invalid checkpoint " + path_.string() + ": " + error.what());
  }
}

void StateStore::save(const nlohmann::json& state) const {
  std::filesystem::create_directories(path_.parent_path());
  auto temporary = path_;
  temporary += ".tmp";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("cannot create checkpoint temporary file: " + temporary.string());
    output << state.dump(2) << '\n';
    output.flush();
    if (!output) throw std::runtime_error("cannot flush checkpoint temporary file: " + temporary.string());
  }

#ifdef _WIN32
  const auto temporary_handle = CreateFileW(temporary.c_str(), GENERIC_READ | GENERIC_WRITE,
                                             FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                             FILE_ATTRIBUTE_NORMAL, nullptr);
  if (temporary_handle == INVALID_HANDLE_VALUE) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "cannot open checkpoint for FlushFileBuffers");
  }
  if (!FlushFileBuffers(temporary_handle)) {
    const auto flush_error = GetLastError();
    CloseHandle(temporary_handle);
    throw std::system_error(static_cast<int>(flush_error), std::system_category(), "checkpoint FlushFileBuffers failed");
  }
  CloseHandle(temporary_handle);
  if (!MoveFileExW(temporary.c_str(), path_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "atomic checkpoint replace failed");
  }
#else
  std::error_code error;
  std::filesystem::rename(temporary, path_, error);
  if (error) throw std::system_error(error, "atomic checkpoint rename failed");
#endif
}

}  // namespace srm::checkpoint
