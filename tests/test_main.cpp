//tests\test_main.cpp
#include "test_support.h"

#include <exception>
#include <iostream>

int main() {
  unsigned failures = 0;
  for (const auto& test : test_support::registry()) {
    try { test.function(); std::cout << "[PASS] " << test.name << '\n'; }
    catch (const std::exception& error) { ++failures; std::cerr << "[FAIL] " << test.name << ": " << error.what() << '\n'; }
  }
  std::cout << (test_support::registry().size() - failures) << '/' << test_support::registry().size() << " tests passed\n";
  return failures == 0 ? 0 : 1;
}
