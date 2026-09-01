//tests\test_stratum_parser.cpp
#include "stratum/stratum_job.h"
#include "stratum/stratum_message.h"
#include "test_support.h"

TEST_CASE("standard mining.notify parses all nine fields") {
  const auto message = srm::stratum::parse_message(R"({"id":null,"method":"mining.notify","params":["job1","0000000000000000000000000000000000000000000000000000000000000000","00","",[],"20000000","207fffff","65000000",true]})");
  const auto job = srm::stratum::parse_notify(message.params);
  REQUIRE_EQ(job.job_id, "job1");
  REQUIRE(job.clean_jobs);
  REQUIRE_EQ(job.merkle_branches.size(), 0U);
}

TEST_CASE("Stratum prevhash word endianness and dword fields") {
  srm::crypto::Digest merkle{};
  for (std::size_t i = 0; i < merkle.size(); ++i) merkle[i] = static_cast<std::uint8_t>(i);
  const auto header = srm::bitcoin::build_stratum_header("01020304", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", merkle, "11223344", "aabbccdd", 0x01020304);
  REQUIRE_EQ(srm::crypto::to_hex(std::span<const std::uint8_t>(header.data(), 4)), "04030201");
  REQUIRE_EQ(srm::crypto::to_hex(std::span<const std::uint8_t>(header.data() + 4, 8)), "0302010007060504");
  REQUIRE_EQ(srm::crypto::to_hex(std::span<const std::uint8_t>(header.data() + 68, 12)), "44332211ddccbbaa04030201");
}
