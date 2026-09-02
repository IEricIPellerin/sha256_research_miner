//include\platform\windows_utf8.h
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>

namespace srm::platform {

void configure_utf8_console() noexcept;
std::string path_utf8(const std::filesystem::path& path);
std::string error_message_utf8(const std::error_code& error);
std::string windows_error_message_utf8(std::uint32_t code);

}  // namespace srm::platform
