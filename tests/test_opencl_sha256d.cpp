//tests\test_opencl_sha256d.cpp
#include "bitcoin/block_header.h"
#include "crypto/sha256.h"
#include "crypto/sha256d.h"
#include "test_support.h"

#ifdef SRM_HAS_OPENCL
#include <CL/cl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void cl_require(const cl_int error, const char* operation) {
  if (error != CL_SUCCESS) {
    throw std::runtime_error(
        std::string(operation) +
        " OpenCL error " +
        std::to_string(error));
  }
}

struct OpenClFixture {
  cl_context context{};
  cl_command_queue queue{};
  cl_program program{};
  cl_device_id device{};

  OpenClFixture() {
    cl_uint platform_count = 0;
    cl_require(
        clGetPlatformIDs(0, nullptr, &platform_count),
        "clGetPlatformIDs count");

    if (platform_count == 0) {
      throw std::runtime_error("Aucune plateforme OpenCL.");
    }

    std::vector<cl_platform_id> platforms(platform_count);

    cl_require(
        clGetPlatformIDs(
            platform_count,
            platforms.data(),
            nullptr),
        "clGetPlatformIDs");

    for (const auto platform : platforms) {
      cl_uint count = 0;

      if (clGetDeviceIDs(
              platform,
              CL_DEVICE_TYPE_GPU,
              1,
              &device,
              &count) == CL_SUCCESS &&
          count > 0) {
        break;
      }

      device = nullptr;
    }

    if (device == nullptr) {
      throw std::runtime_error("Aucun GPU OpenCL.");
    }

    cl_int error = CL_SUCCESS;

    context = clCreateContext(
        nullptr,
        1,
        &device,
        nullptr,
        nullptr,
        &error);

    cl_require(error, "clCreateContext");

    queue = clCreateCommandQueue(
        context,
        device,
        0,
        &error);

    cl_require(error, "clCreateCommandQueue");

    std::ifstream input(
        std::filesystem::path(SRM_SOURCE_DIR) /
            "kernels" /
            "sha256d.cl",
        std::ios::binary);

    if (!input) {
      throw std::runtime_error(
          "Impossible d'ouvrir kernels/sha256d.cl");
    }

    const std::string source{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};

    const char* pointer = source.c_str();
    const auto length = source.size();

    program = clCreateProgramWithSource(
        context,
        1,
        &pointer,
        &length,
        &error);

    cl_require(error, "clCreateProgramWithSource");

    error = clBuildProgram(
        program,
        1,
        &device,
        "-cl-std=CL1.2",
        nullptr,
        nullptr);

    if (error != CL_SUCCESS) {
      std::size_t size = 0;

      clGetProgramBuildInfo(
          program,
          device,
          CL_PROGRAM_BUILD_LOG,
          0,
          nullptr,
          &size);

      std::string log(size, '\0');

      clGetProgramBuildInfo(
          program,
          device,
          CL_PROGRAM_BUILD_LOG,
          size,
          log.data(),
          nullptr);

      throw std::runtime_error(
          "Kernel OpenCL invalide : " + log);
    }
  }

  ~OpenClFixture() {
    if (program) {
      clReleaseProgram(program);
    }

    if (queue) {
      clReleaseCommandQueue(queue);
    }

    if (context) {
      clReleaseContext(context);
    }
  }
};

srm::bitcoin::Header genesis_header() {
  const auto bytes = srm::crypto::from_hex(
      "01000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
      "29ab5f49"
      "ffff001d"
      "00000000");

  srm::bitcoin::Header header{};

  std::copy(
      bytes.begin(),
      bytes.end(),
      header.begin());

  return header;
}

}  // namespace

TEST_CASE(
    "OpenCL SHA256d equals CPU for 4096 deterministic headers") {
  OpenClFixture opencl;

  cl_int error = CL_SUCCESS;

  const auto kernel = clCreateKernel(
      opencl.program,
      "sha256d_vectors",
      &error);

  cl_require(error, "clCreateKernel sha256d_vectors");

  auto header = genesis_header();

  constexpr std::uint32_t count = 4096;
  constexpr std::uint32_t start = 0x12340000U;

  std::vector<std::uint32_t> output(
      static_cast<std::size_t>(count) * 8);

  const auto prefix_buffer = clCreateBuffer(
      opencl.context,
      CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
      76,
      header.data(),
      &error);

  cl_require(error, "prefix buffer");

  const auto output_buffer = clCreateBuffer(
      opencl.context,
      CL_MEM_WRITE_ONLY,
      output.size() * sizeof(std::uint32_t),
      nullptr,
      &error);

  cl_require(error, "output buffer");

  cl_require(
      clSetKernelArg(
          kernel,
          0,
          sizeof(prefix_buffer),
          &prefix_buffer),
      "arg 0");

  cl_require(
      clSetKernelArg(
          kernel,
          1,
          sizeof(start),
          &start),
      "arg 1");

  cl_require(
      clSetKernelArg(
          kernel,
          2,
          sizeof(count),
          &count),
      "arg 2");

  cl_require(
      clSetKernelArg(
          kernel,
          3,
          sizeof(output_buffer),
          &output_buffer),
      "arg 3");

  const std::size_t global = count;
  const std::size_t local = 64;

  cl_require(
      clEnqueueNDRangeKernel(
          opencl.queue,
          kernel,
          1,
          nullptr,
          &global,
          &local,
          0,
          nullptr,
          nullptr),
      "vector kernel");

  cl_require(
      clFinish(opencl.queue),
      "clFinish");

  cl_require(
      clEnqueueReadBuffer(
          opencl.queue,
          output_buffer,
          CL_TRUE,
          0,
          output.size() * sizeof(std::uint32_t),
          output.data(),
          0,
          nullptr,
          nullptr),
      "digest read");

  for (std::uint32_t index = 0;
       index < count;
       ++index) {
    srm::bitcoin::set_nonce(
        header,
        start + index);

    const auto cpu =
        srm::crypto::sha256d(header);

    srm::crypto::Digest gpu{};

    for (std::size_t word = 0;
         word < 8;
         ++word) {
      const auto value =
          output[
              static_cast<std::size_t>(index) * 8 +
              word];

      gpu[word * 4] =
          static_cast<std::uint8_t>(
              value >> 24U);

      gpu[word * 4 + 1] =
          static_cast<std::uint8_t>(
              value >> 16U);

      gpu[word * 4 + 2] =
          static_cast<std::uint8_t>(
              value >> 8U);

      gpu[word * 4 + 3] =
          static_cast<std::uint8_t>(
              value);
    }

    REQUIRE_EQ(gpu, cpu);
  }

  clReleaseMemObject(output_buffer);
  clReleaseMemObject(prefix_buffer);
  clReleaseKernel(kernel);
}

TEST_CASE(
    "OpenCL scan finds the winning Genesis nonce") {
  OpenClFixture opencl;

  cl_int error = CL_SUCCESS;

  const auto kernel = clCreateKernel(
      opencl.program,
      "sha256d_scan",
      &error);

  cl_require(error, "clCreateKernel sha256d_scan");

  auto header = genesis_header();

  constexpr std::uint32_t winning_nonce =
      2083236893U;

  constexpr std::uint32_t start =
      winning_nonce - 128U;

  constexpr std::uint32_t count =
      256U;

  const auto target =
      srm::crypto::from_hex(
          "00000000ffff0000000000000000000000000000000000000000000000000000");

  REQUIRE_EQ(
      target.size(),
      static_cast<std::size_t>(32));

  std::array<std::uint8_t, 32> target_bytes{};

  std::copy(
      target.begin(),
      target.end(),
      target_bytes.begin());

  std::uint32_t candidate_count = 0;

  std::array<std::uint32_t, 64>
      candidate_nonces{};

  const auto prefix_buffer = clCreateBuffer(
      opencl.context,
      CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
      76,
      header.data(),
      &error);

  cl_require(error, "Genesis prefix buffer");

  const auto target_buffer = clCreateBuffer(
      opencl.context,
      CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
      target_bytes.size(),
      target_bytes.data(),
      &error);

  cl_require(error, "Genesis target buffer");

  const auto count_buffer = clCreateBuffer(
      opencl.context,
      CL_MEM_READ_WRITE |
          CL_MEM_COPY_HOST_PTR,
      sizeof(candidate_count),
      &candidate_count,
      &error);

  cl_require(error, "Genesis count buffer");

  const auto candidates_buffer =
      clCreateBuffer(
          opencl.context,
          CL_MEM_WRITE_ONLY,
          sizeof(candidate_nonces),
          nullptr,
          &error);

  cl_require(error, "Genesis candidates buffer");

  cl_require(
      clSetKernelArg(
          kernel,
          0,
          sizeof(prefix_buffer),
          &prefix_buffer),
      "Genesis arg 0");

  cl_require(
      clSetKernelArg(
          kernel,
          1,
          sizeof(start),
          &start),
      "Genesis arg 1");

  cl_require(
      clSetKernelArg(
          kernel,
          2,
          sizeof(count),
          &count),
      "Genesis arg 2");

  cl_require(
      clSetKernelArg(
          kernel,
          3,
          sizeof(target_buffer),
          &target_buffer),
      "Genesis arg 3");

  cl_require(
      clSetKernelArg(
          kernel,
          4,
          sizeof(count_buffer),
          &count_buffer),
      "Genesis arg 4");

  cl_require(
      clSetKernelArg(
          kernel,
          5,
          sizeof(candidates_buffer),
          &candidates_buffer),
      "Genesis arg 5");

  const std::size_t global = 256;
  const std::size_t local = 64;

  cl_require(
      clEnqueueNDRangeKernel(
          opencl.queue,
          kernel,
          1,
          nullptr,
          &global,
          &local,
          0,
          nullptr,
          nullptr),
      "Genesis scan kernel");

  cl_require(
      clFinish(opencl.queue),
      "Genesis scan finish");

  cl_require(
      clEnqueueReadBuffer(
          opencl.queue,
          count_buffer,
          CL_TRUE,
          0,
          sizeof(candidate_count),
          &candidate_count,
          0,
          nullptr,
          nullptr),
      "Genesis candidate count read");

  REQUIRE(candidate_count > 0);

  cl_require(
      clEnqueueReadBuffer(
          opencl.queue,
          candidates_buffer,
          CL_TRUE,
          0,
          sizeof(candidate_nonces),
          candidate_nonces.data(),
          0,
          nullptr,
          nullptr),
      "Genesis candidates read");

  const auto bounded_count =
      std::min(
          candidate_count,
          static_cast<std::uint32_t>(
              candidate_nonces.size()));

  const auto found =
      std::find(
          candidate_nonces.begin(),
          candidate_nonces.begin() +
              bounded_count,
          winning_nonce);

  REQUIRE(
      found !=
      candidate_nonces.begin() +
          bounded_count);

  srm::bitcoin::set_nonce(
      header,
      winning_nonce);

  const auto digest =
      srm::crypto::sha256d(header);

  REQUIRE_EQ(
      srm::crypto::bitcoin_hash_hex(digest),
      std::string(
          "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));

  clReleaseMemObject(candidates_buffer);
  clReleaseMemObject(count_buffer);
  clReleaseMemObject(target_buffer);
  clReleaseMemObject(prefix_buffer);
  clReleaseKernel(kernel);
}

TEST_CASE("OpenCL observed bootstrap returns the exact non-share minimum") {
  OpenClFixture opencl;
  cl_int error = CL_SUCCESS;
  const auto kernel = clCreateKernel(opencl.program, "sha256d_scan_observed", &error);
  cl_require(error, "clCreateKernel sha256d_scan_observed");
  auto header = genesis_header();
  constexpr std::uint32_t start = 0x10203040U;
  constexpr std::uint32_t count = 4096U;
  constexpr std::size_t local = 64U;
  constexpr std::size_t groups = count / local;
  std::array<std::uint8_t, 32> impossible_target{};
  std::uint32_t candidate_count = 0;
  std::array<std::uint32_t, 64> candidates{};
  std::vector<std::uint32_t> minima(groups * 9U);
  const auto prefix = clCreateBuffer(opencl.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                     76U, header.data(), &error);
  cl_require(error, "observed prefix");
  const auto target = clCreateBuffer(opencl.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                     impossible_target.size(), impossible_target.data(), &error);
  cl_require(error, "observed target");
  const auto count_buffer = clCreateBuffer(opencl.context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                                           sizeof(candidate_count), &candidate_count, &error);
  cl_require(error, "observed count");
  const auto candidate_buffer = clCreateBuffer(opencl.context, CL_MEM_WRITE_ONLY,
                                                sizeof(candidates), nullptr, &error);
  cl_require(error, "observed candidates");
  const auto minima_buffer = clCreateBuffer(opencl.context, CL_MEM_WRITE_ONLY,
                                             minima.size() * sizeof(std::uint32_t), nullptr, &error);
  cl_require(error, "observed minima");
  cl_require(clSetKernelArg(kernel, 0, sizeof(prefix), &prefix), "observed arg0");
  cl_require(clSetKernelArg(kernel, 1, sizeof(start), &start), "observed arg1");
  cl_require(clSetKernelArg(kernel, 2, sizeof(count), &count), "observed arg2");
  cl_require(clSetKernelArg(kernel, 3, sizeof(target), &target), "observed arg3");
  cl_require(clSetKernelArg(kernel, 4, sizeof(count_buffer), &count_buffer), "observed arg4");
  cl_require(clSetKernelArg(kernel, 5, sizeof(candidate_buffer), &candidate_buffer), "observed arg5");
  cl_require(clSetKernelArg(kernel, 6, sizeof(minima_buffer), &minima_buffer), "observed arg6");
  cl_require(clSetKernelArg(kernel, 7, local * 9U * sizeof(std::uint32_t), nullptr), "observed arg7");
  const std::size_t global = count;
  cl_require(clEnqueueNDRangeKernel(opencl.queue, kernel, 1, nullptr, &global, &local,
                                    0, nullptr, nullptr), "observed launch");
  cl_require(clFinish(opencl.queue), "observed finish");
  cl_require(clEnqueueReadBuffer(opencl.queue, minima_buffer, CL_TRUE, 0,
                                 minima.size() * sizeof(std::uint32_t), minima.data(),
                                 0, nullptr, nullptr), "observed minima read");

  std::uint32_t gpu_nonce = minima[8U];
  std::array<std::uint32_t, 8> gpu_value{};
  std::copy_n(minima.begin(), 8U, gpu_value.begin());
  for (std::size_t group = 1; group < groups; ++group) {
    std::array<std::uint32_t, 8> value{};
    std::copy_n(minima.begin() + group * 9U, 8U, value.begin());
    const auto nonce = minima[group * 9U + 8U];
    if (value < gpu_value || (value == gpu_value && nonce < gpu_nonce)) {
      gpu_value = value;
      gpu_nonce = nonce;
    }
  }
  std::string cpu_best;
  std::uint32_t cpu_nonce = 0;
  for (std::uint32_t offset = 0; offset < count; ++offset) {
    srm::bitcoin::set_nonce(header, start + offset);
    const auto hash = srm::crypto::bitcoin_hash_hex(srm::crypto::sha256d(header));
    if (cpu_best.empty() || hash < cpu_best) { cpu_best = hash; cpu_nonce = start + offset; }
  }
  std::ostringstream gpu_hex;
  gpu_hex << std::hex << std::setfill('0');
  for (const auto word : gpu_value) gpu_hex << std::setw(8) << word;
  REQUIRE_EQ(gpu_hex.str(), cpu_best);
  REQUIRE_EQ(gpu_nonce, cpu_nonce);

  clReleaseMemObject(minima_buffer);
  clReleaseMemObject(candidate_buffer);
  clReleaseMemObject(count_buffer);
  clReleaseMemObject(target);
  clReleaseMemObject(prefix);
  clReleaseKernel(kernel);
}

#else

TEST_CASE(
    "OpenCL SHA256d validation is optional when SDK is absent") {
  REQUIRE(true);
}

#endif
