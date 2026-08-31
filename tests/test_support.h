#pragma once

#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace test_support {

struct TestCase { std::string name; std::function<void()> function; };
inline std::vector<TestCase>& registry() { static std::vector<TestCase> tests; return tests; }

struct Registrar {
  Registrar(std::string name, std::function<void()> function) { registry().push_back({std::move(name), std::move(function)}); }
};

template <typename L, typename R>
void require_equal(const L& left, const R& right, const char* left_text, const char* right_text) {
  if (!(left == right)) {
    std::ostringstream message;
    message << "REQUIRE_EQ failed: " << left_text << " != " << right_text;
    throw std::runtime_error(message.str());
  }
}

inline void require(bool value, const char* text) {
  if (!value) throw std::runtime_error(std::string("REQUIRE failed: ") + text);
}

}  // namespace test_support

#define SRM_JOIN_INNER(a,b) a##b
#define SRM_JOIN(a,b) SRM_JOIN_INNER(a,b)
#define TEST_CASE(name) \
  static void SRM_JOIN(test_, __LINE__)(); \
  static test_support::Registrar SRM_JOIN(registrar_, __LINE__)(name, SRM_JOIN(test_, __LINE__)); \
  static void SRM_JOIN(test_, __LINE__)()
#define REQUIRE(value) test_support::require((value), #value)
#define REQUIRE_EQ(left,right) test_support::require_equal((left), (right), #left, #right)

