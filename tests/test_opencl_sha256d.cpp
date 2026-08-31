//tests\test_opencl_sha256d.cpp
#include "bitcoin/block_header.h"
#include "crypto/sha256.h"
#include "crypto/sha256d.h"
#include "test_support.h"

#ifdef SRM_HAS_OPENCL
#include <CL/cl.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

namespace {

void cl_require(const cl_int error, const char* operation) {
  if (error != CL_SUCCESS) throw std::runtime_error(std::string(operation) + " OpenCL error " + std::to_string(error));
}

}  // namespace

TEST_CASE("OpenCL SHA256d equals CPU for 4096 deterministic headers") {
  cl_uint platform_count = 0;
  cl_require(clGetPlatformIDs(0, nullptr, &platform_count), "clGetPlatformIDs count");
  REQUIRE(platform_count > 0);
  std::vector<cl_platform_id> platforms(platform_count);
  cl_require(clGetPlatformIDs(platform_count, platforms.data(), nullptr), "clGetPlatformIDs");
  cl_device_id device = nullptr;
  for (const auto platform : platforms) {
    cl_uint count = 0;
    if (clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, &count) == CL_SUCCESS && count > 0) break;
    device = nullptr;
  }
  REQUIRE(device != nullptr);

  cl_int error = CL_SUCCESS;
  const auto context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &error); cl_require(error, "clCreateContext");
  const auto queue = clCreateCommandQueue(context, device, 0, &error); cl_require(error, "clCreateCommandQueue");
  std::ifstream input(std::filesystem::path(SRM_SOURCE_DIR) / "kernels" / "sha256d.cl", std::ios::binary);
  REQUIRE(static_cast<bool>(input));
  const std::string source{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  const char* pointer = source.c_str();
  const auto length = source.size();
  const auto program = clCreateProgramWithSource(context, 1, &pointer, &length, &error); cl_require(error, "clCreateProgramWithSource");
  error = clBuildProgram(program, 1, &device, "-cl-std=CL1.2", nullptr, nullptr);
  if (error != CL_SUCCESS) {
    std::size_t size = 0;
    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &size);
    std::string log(size, '\0');
    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, size, log.data(), nullptr);
    throw std::runtime_error("kernel build failed: " + log);
  }
  const auto kernel = clCreateKernel(program, "sha256d_vectors", &error); cl_require(error, "clCreateKernel");

  const auto header_bytes = srm::crypto::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d00000000");
  srm::bitcoin::Header header{};
  std::copy(header_bytes.begin(), header_bytes.end(), header.begin());
  constexpr std::uint32_t count = 4096;
  constexpr std::uint32_t start = 0x12340000U;
  std::vector<std::uint32_t> output(static_cast<std::size_t>(count) * 8);
  const auto prefix_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 76, header.data(), &error); cl_require(error, "prefix buffer");
  const auto output_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, output.size() * sizeof(std::uint32_t), nullptr, &error); cl_require(error, "output buffer");
  cl_require(clSetKernelArg(kernel, 0, sizeof(prefix_buffer), &prefix_buffer), "arg 0");
  cl_require(clSetKernelArg(kernel, 1, sizeof(start), &start), "arg 1");
  cl_require(clSetKernelArg(kernel, 2, sizeof(count), &count), "arg 2");
  cl_require(clSetKernelArg(kernel, 3, sizeof(output_buffer), &output_buffer), "arg 3");
  const std::size_t global = count;
  const std::size_t local = 64;
  cl_require(clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, &global, &local, 0, nullptr, nullptr), "vector kernel");
  cl_require(clFinish(queue), "clFinish");
  cl_require(clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, output.size() * sizeof(std::uint32_t), output.data(), 0, nullptr, nullptr), "digest read");

  for (std::uint32_t index = 0; index < count; ++index) {
    srm::bitcoin::set_nonce(header, start + index);
    const auto cpu = srm::crypto::sha256d(header);
    srm::crypto::Digest gpu{};
    for (std::size_t word = 0; word < 8; ++word) {
      const auto value = output[static_cast<std::size_t>(index) * 8 + word];
      gpu[word * 4] = static_cast<std::uint8_t>(value >> 24U);
      gpu[word * 4 + 1] = static_cast<std::uint8_t>(value >> 16U);
      gpu[word * 4 + 2] = static_cast<std::uint8_t>(value >> 8U);
      gpu[word * 4 + 3] = static_cast<std::uint8_t>(value);
    }
    REQUIRE_EQ(gpu, cpu);
  }

  clReleaseMemObject(output_buffer); clReleaseMemObject(prefix_buffer); clReleaseKernel(kernel);
  clReleaseProgram(program); clReleaseCommandQueue(queue); clReleaseContext(context);
}

#else

TEST_CASE("OpenCL SHA256d validation is optional when SDK is absent") { REQUIRE(true); }

#endif

