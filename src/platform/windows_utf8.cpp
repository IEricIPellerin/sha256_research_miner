//src\platform\windows_utf8.cpp
#include "platform/windows_utf8.h"

#include <string_view>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace srm::platform {
namespace {

#ifdef _WIN32
std::string wide_to_utf8(const std::wstring_view text) {
  if (text.empty()) return {};
  const auto size = WideCharToMultiByte(
      CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
  if (size <= 0) return "Win32 message conversion failed";
  std::string result(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(
      CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
  return result;
}
#endif

}  // namespace

void configure_utf8_console() noexcept {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
#endif
}

std::string path_utf8(const std::filesystem::path& path) {
#ifdef _WIN32
  return wide_to_utf8(path.native());
#else
  return path.string();
#endif
}

std::string error_message_utf8(const std::error_code& error) {
#ifdef _WIN32
  return windows_error_message_utf8(static_cast<std::uint32_t>(error.value()));
#else
  return error.message();
#endif
}

std::string windows_error_message_utf8(const std::uint32_t code) {
#ifdef _WIN32
  wchar_t* buffer = nullptr;
  const auto length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, static_cast<DWORD>(code), 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
  std::wstring message;
  if (length != 0 && buffer != nullptr) {
    message.assign(buffer, length);
    LocalFree(buffer);
    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
      message.pop_back();
    }
  }
  if (!message.empty()) return wide_to_utf8(message);
#endif
  return "system error " + std::to_string(code);
}

}  // namespace srm::platform
