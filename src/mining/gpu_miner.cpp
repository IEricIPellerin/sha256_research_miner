//src\mining\gpu_miner.cpp
#include "mining/gpu_miner.h"

#include "bitcoin/block_header.h"
#include "checkpoint/state_store.h"
#include "crypto/sha256.h"
#include "crypto/sha256d.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iterator>
#include <limits>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <vector>

#ifdef SRM_HAS_OPENCL
#include <CL/cl.h>
#endif

namespace srm::mining {
namespace {

std::string normalized(std::string value) {
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](const unsigned char c) { return !std::isspace(c); }));
  value.erase(std::find_if(value.rbegin(), value.rend(), [](const unsigned char c) { return !std::isspace(c); }).base(), value.end());
  std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

bool is_auto(const std::string& selector) { return normalized(selector) == "auto"; }

bool is_amd(const GpuInfo& device) {
  const auto vendor = normalized(device.vendor);
  return vendor.find("amd") != std::string::npos || vendor.find("advanced micro devices") != std::string::npos;
}

}  // namespace

struct GpuMiner::Impl {
  WorkAllocator& allocator;
  telemetry::Telemetry& telemetry;
  std::atomic<std::uint64_t>& active_generation;
  CpuMiner::CandidateHandler handler;
  std::filesystem::path kernel_path;
  std::filesystem::path profile_path;
  std::jthread thread;
  GpuInfo info;
#ifdef SRM_HAS_OPENCL
  cl_platform_id platform_id{};
  cl_device_id device_id{};
  struct Choice {
    GpuInfo info;
    cl_platform_id platform{};
    cl_device_id device{};
  };
#endif

  Impl(WorkAllocator& work_allocator,
       telemetry::Telemetry& stats,
       std::atomic<std::uint64_t>& generation,
       CpuMiner::CandidateHandler candidate_handler,
       std::filesystem::path kernel,
       std::filesystem::path profile)
      : allocator(work_allocator), telemetry(stats), active_generation(generation),
        handler(std::move(candidate_handler)), kernel_path(std::move(kernel)), profile_path(std::move(profile)) {}

#ifdef SRM_HAS_OPENCL
  static void check(const cl_int error, const char* operation) {
    if (error != CL_SUCCESS) throw std::runtime_error(std::string(operation) + " failed with OpenCL error " + std::to_string(error));
  }

  template <typename Id>
  static std::string get_string(Id id, const cl_uint field, cl_int (*getter)(Id, cl_uint, std::size_t, void*, std::size_t*)) {
    std::size_t size = 0;
    check(getter(id, field, 0, nullptr, &size), "OpenCL info size");
    std::string value(size, '\0');
    check(getter(id, field, size, value.data(), nullptr), "OpenCL info");
    while (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
  }

  static std::string optional_device_string(const cl_device_id device, const cl_uint field) {
    std::size_t size = 0;
    if (clGetDeviceInfo(device, field, 0, nullptr, &size) != CL_SUCCESS || size == 0) return {};
    std::string value(size, '\0');
    if (clGetDeviceInfo(device, field, size, value.data(), nullptr) != CL_SUCCESS) return {};
    while (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
  }

  std::vector<Choice> enumerate_opencl() const {
    cl_uint platform_count = 0;
    if (clGetPlatformIDs(0, nullptr, &platform_count) != CL_SUCCESS || platform_count == 0) return {};
    std::vector<cl_platform_id> platforms(platform_count);
    check(clGetPlatformIDs(platform_count, platforms.data(), nullptr), "clGetPlatformIDs");

    std::vector<Choice> choices;
    for (std::size_t platform_index = 0; platform_index < platforms.size(); ++platform_index) {
      const auto platform = platforms[platform_index];
      cl_uint count = 0;
      if (clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &count) != CL_SUCCESS || count == 0) continue;
      std::vector<cl_device_id> devices(count);
      check(clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, count, devices.data(), nullptr), "clGetDeviceIDs");
      for (std::size_t device_index = 0; device_index < devices.size(); ++device_index) {
        const auto device = devices[device_index];
        GpuInfo value;
        value.available = true;
        value.index = choices.size();
        value.platform_index = platform_index;
        value.device_index = device_index;
        value.platform = get_string(platform, CL_PLATFORM_NAME, clGetPlatformInfo);
        value.name = get_string(device, CL_DEVICE_NAME, clGetDeviceInfo);
        value.board_name = optional_device_string(device, 0x4038U);  // CL_DEVICE_BOARD_NAME_AMD
        value.vendor = get_string(device, CL_DEVICE_VENDOR, clGetDeviceInfo);
        value.driver = get_string(device, CL_DRIVER_VERSION, clGetDeviceInfo);
        check(clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(value.compute_units), &value.compute_units, nullptr), "compute units");
        check(clGetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(value.global_memory), &value.global_memory, nullptr), "global memory");
        check(clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(value.max_workgroup_size), &value.max_workgroup_size, nullptr), "workgroup size");
        choices.push_back({std::move(value), platform, device});
      }
    }
    return choices;
  }

  GpuInfo detect_opencl(const std::string& platform_selector, const std::string& device_selector) {
    const auto choices = enumerate_opencl();
    if (choices.empty()) return {};
    std::vector<GpuInfo> devices;
    devices.reserve(choices.size());
    for (const auto& choice : choices) devices.push_back(choice.info);
    const auto selected = GpuMiner::select_device_index(devices, platform_selector, device_selector);
    const auto& choice = choices.at(selected);
    platform_id = choice.platform;
    device_id = choice.device;
    return choice.info;
  }

  std::string read_kernel() const {
    std::ifstream input(kernel_path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open OpenCL kernel: " + kernel_path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  }

  GpuBenchmarkResult benchmark_opencl(const bitcoin::Header& base_header,
                                      const std::string& platform_selector,
                                      const std::string& device_selector,
                                      const bool auto_tune,
                                      const unsigned warmup_ms,
                                      const unsigned measurement_ms) {
    info = detect_opencl(platform_selector, device_selector);
    if (!info.available) throw std::runtime_error("no OpenCL GPU available");

    cl_context context{};
    cl_command_queue queue{};
    cl_program program{};
    cl_kernel vector_kernel{};
    cl_kernel scan_kernel{};
    cl_mem prefix_buffer{};
    cl_mem output_buffer{};
    cl_mem target_buffer{};
    cl_mem count_buffer{};
    cl_mem candidates_buffer{};
    const auto release_all = [&] {
      if (candidates_buffer) clReleaseMemObject(candidates_buffer);
      if (count_buffer) clReleaseMemObject(count_buffer);
      if (target_buffer) clReleaseMemObject(target_buffer);
      if (output_buffer) clReleaseMemObject(output_buffer);
      if (prefix_buffer) clReleaseMemObject(prefix_buffer);
      if (scan_kernel) clReleaseKernel(scan_kernel);
      if (vector_kernel) clReleaseKernel(vector_kernel);
      if (program) clReleaseProgram(program);
      if (queue) clReleaseCommandQueue(queue);
      if (context) clReleaseContext(context);
    };

    try {
      cl_int error = CL_SUCCESS;
      context = clCreateContext(nullptr, 1, &device_id, nullptr, nullptr, &error); check(error, "clCreateContext");
      // OpenCL 1.2 is the compatibility baseline of the existing kernel and AMD runtime.
      queue = clCreateCommandQueue(context, device_id, CL_QUEUE_PROFILING_ENABLE, &error); check(error, "clCreateCommandQueue");
      const auto source = read_kernel();
      const char* source_pointer = source.c_str();
      const auto source_size = source.size();
      program = clCreateProgramWithSource(context, 1, &source_pointer, &source_size, &error); check(error, "clCreateProgramWithSource");
      error = clBuildProgram(program, 1, &device_id, "-cl-std=CL1.2", nullptr, nullptr);
      if (error != CL_SUCCESS) {
        std::size_t size = 0;
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, nullptr, &size);
        std::string log(size, '\0');
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, size, log.data(), nullptr);
        throw std::runtime_error("OpenCL kernel compilation failed: " + log);
      }
      vector_kernel = clCreateKernel(program, "sha256d_vectors", &error); check(error, "clCreateKernel sha256d_vectors");
      scan_kernel = clCreateKernel(program, "sha256d_scan", &error); check(error, "clCreateKernel sha256d_scan");
      prefix_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 76,
                                     const_cast<std::uint8_t*>(base_header.data()), &error); check(error, "benchmark prefix buffer");

      constexpr std::uint32_t validation_count = 4096;
      constexpr std::uint32_t validation_start = 0x12340000U;
      std::vector<std::uint32_t> output(static_cast<std::size_t>(validation_count) * 8U);
      output_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, output.size() * sizeof(std::uint32_t), nullptr, &error);
      check(error, "validation output buffer");
      check(clSetKernelArg(vector_kernel, 0, sizeof(prefix_buffer), &prefix_buffer), "validation prefix arg");
      check(clSetKernelArg(vector_kernel, 1, sizeof(validation_start), &validation_start), "validation start arg");
      check(clSetKernelArg(vector_kernel, 2, sizeof(validation_count), &validation_count), "validation count arg");
      check(clSetKernelArg(vector_kernel, 3, sizeof(output_buffer), &output_buffer), "validation output arg");
      const std::size_t validation_global = validation_count;
      std::size_t validation_local = 1;
      while (validation_local * 2 <= std::min<std::size_t>(64, info.max_workgroup_size)) validation_local *= 2;
      check(clEnqueueNDRangeKernel(queue, vector_kernel, 1, nullptr, &validation_global, &validation_local, 0, nullptr, nullptr),
            "validation kernel");
      check(clFinish(queue), "validation finish");
      check(clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, output.size() * sizeof(std::uint32_t),
                                output.data(), 0, nullptr, nullptr), "validation digest read");
      auto validation_header = base_header;
      for (std::uint32_t index = 0; index < validation_count; ++index) {
        bitcoin::set_nonce(validation_header, validation_start + index);
        const auto cpu = crypto::sha256d(validation_header);
        crypto::Digest gpu{};
        for (std::size_t word = 0; word < 8; ++word) {
          const auto value = output[static_cast<std::size_t>(index) * 8U + word];
          gpu[word * 4U] = static_cast<std::uint8_t>(value >> 24U);
          gpu[word * 4U + 1U] = static_cast<std::uint8_t>(value >> 16U);
          gpu[word * 4U + 2U] = static_cast<std::uint8_t>(value >> 8U);
          gpu[word * 4U + 3U] = static_cast<std::uint8_t>(value);
        }
        if (gpu != cpu) throw std::runtime_error("GPU validation differs from CPU at deterministic vector " + std::to_string(index));
      }

      const std::array<std::uint8_t, 32> impossible_target{};
      target_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, impossible_target.size(),
                                     const_cast<std::uint8_t*>(impossible_target.data()), &error); check(error, "benchmark target buffer");
      std::uint32_t zero = 0;
      count_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(zero), &zero, &error);
      check(error, "benchmark candidate count buffer");
      std::array<std::uint32_t, 64> candidate_nonces{};
      candidates_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(candidate_nonces), nullptr, &error);
      check(error, "benchmark candidate buffer");
      check(clSetKernelArg(scan_kernel, 0, sizeof(prefix_buffer), &prefix_buffer), "benchmark prefix arg");
      check(clSetKernelArg(scan_kernel, 3, sizeof(target_buffer), &target_buffer), "benchmark target arg");
      check(clSetKernelArg(scan_kernel, 4, sizeof(count_buffer), &count_buffer), "benchmark count arg");
      check(clSetKernelArg(scan_kernel, 5, sizeof(candidates_buffer), &candidates_buffer), "benchmark candidates arg");

      std::vector<std::tuple<std::size_t, std::size_t, unsigned>> configurations;
      if (auto_tune) {
        const std::array<std::size_t, 3> locals{64, 128, 256};
        const std::array<std::size_t, 3> globals{1U << 16U, 1U << 18U, 1U << 20U};
        const std::array<unsigned, 3> batch_repeats{1, 4, 16};
        for (const auto local : locals) {
          if (local > info.max_workgroup_size) continue;
          for (const auto global : globals) {
            for (const auto repeats : batch_repeats) configurations.emplace_back(local, global, repeats);
          }
        }
      } else {
        std::size_t local = std::min<std::size_t>(256, info.max_workgroup_size);
        std::size_t global = 1U << 20U;
        std::uint64_t batch = 1U << 24U;
        const auto document = checkpoint::StateStore(profile_path).load_or(nlohmann::json::object());
        const auto profile = document.contains("gpu") ? document.at("gpu") : document;
        const auto profile_name = profile.value("device_name", profile.value("name", ""));
        if (profile_name == info.name && profile.value("driver", "") == info.driver) {
          local = profile.value("local_work_size", local);
          global = profile.value("global_work_size", global);
          batch = profile.value("batch_size", batch);
        }
        if (local == 0 || local > info.max_workgroup_size) local = std::min<std::size_t>(256, info.max_workgroup_size);
        if (global == 0) global = 1U << 20U;
        const auto repeats = static_cast<unsigned>(std::max<std::uint64_t>(1, (batch + global - 1U) / global));
        configurations.emplace_back(local, global, repeats);
      }

      GpuBenchmarkResult result;
      result.device = info;
      result.validated = true;
      std::uint32_t nonce_cursor = 0;
      for (const auto& [local, global, repeats] : configurations) {
        if (local == 0 || global == 0 || global % local != 0 || global > std::numeric_limits<std::uint32_t>::max()) continue;
        const auto count = static_cast<std::uint32_t>(global);
        check(clSetKernelArg(scan_kernel, 2, sizeof(count), &count), "benchmark nonce count arg");
        check(clEnqueueWriteBuffer(queue, count_buffer, CL_TRUE, 0, sizeof(zero), &zero, 0, nullptr, nullptr),
              "benchmark candidate reset");
        const auto run_batch = [&] {
          for (unsigned repeat = 0; repeat < repeats; ++repeat) {
            const auto start = nonce_cursor;
            nonce_cursor += count;
            check(clSetKernelArg(scan_kernel, 1, sizeof(start), &start), "benchmark nonce start arg");
            check(clEnqueueNDRangeKernel(queue, scan_kernel, 1, nullptr, &global, &local, 0, nullptr, nullptr),
                  "benchmark kernel launch");
          }
          check(clFinish(queue), "benchmark batch finish");
          return static_cast<std::uint64_t>(global) * repeats;
        };

        const auto warmup_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(warmup_ms);
        do { run_batch(); } while (std::chrono::steady_clock::now() < warmup_deadline);
        const auto before = std::chrono::steady_clock::now();
        const auto measurement_deadline = before + std::chrono::milliseconds(measurement_ms);
        std::uint64_t hashes = 0;
        do { hashes += run_batch(); } while (std::chrono::steady_clock::now() < measurement_deadline);
        const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - before).count();
        GpuBenchmarkSample sample{local, global, static_cast<std::uint64_t>(global) * repeats,
                                  hashes, seconds, seconds > 0.0 ? static_cast<double>(hashes) / seconds : 0.0};
        result.samples.push_back(sample);
        if (sample.hash_rate > result.best.hash_rate) result.best = sample;
      }
      if (result.samples.empty()) throw std::runtime_error("no valid OpenCL benchmark configuration");
      release_all();
      return result;
    } catch (...) {
      release_all();
      throw;
    }
  }

  void run(std::stop_token token, LiveMiningJob job, bool auto_tune)
  {
    auto unit = allocator.acquire(WorkerKind::Gpu);
    if (!unit)
    {
      return;
    }

    cl_context context{};
    cl_command_queue queue{};
    cl_program program{};
    cl_kernel kernel{};
    cl_kernel observed_kernel{};
    cl_mem header_buffer{};
    cl_mem target_buffer{};
    cl_mem count_buffer{};
    cl_mem candidates_buffer{};
    cl_mem minima_buffer{};

    std::string current_unit_id = unit->id;

    const auto release_all = [&]
    {
      if (minima_buffer)
      {
        clReleaseMemObject(minima_buffer);
      }

      if (candidates_buffer)
      {
        clReleaseMemObject(candidates_buffer);
      }

      if (count_buffer)
      {
        clReleaseMemObject(count_buffer);
      }

      if (target_buffer)
      {
        clReleaseMemObject(target_buffer);
      }

      if (header_buffer)
      {
        clReleaseMemObject(header_buffer);
      }

      if (kernel)
      {
        clReleaseKernel(kernel);
      }

      if (observed_kernel)
      {
        clReleaseKernel(observed_kernel);
      }

      if (program)
      {
        clReleaseProgram(program);
      }

      if (queue)
      {
        clReleaseCommandQueue(queue);
      }

      if (context)
      {
        clReleaseContext(context);
      }
    };

    try
    {
      cl_int error = CL_SUCCESS;

      context =
          clCreateContext(
              nullptr,
              1,
              &device_id,
              nullptr,
              nullptr,
              &error);
      check(error, "clCreateContext");

      // OpenCL 1.2 remains the compatibility baseline
      // for the deployed AMD runtime.
      queue =
          clCreateCommandQueue(
              context,
              device_id,
              CL_QUEUE_PROFILING_ENABLE,
              &error);
      check(error, "clCreateCommandQueue");

      const auto source = read_kernel();
      const char *source_pointer = source.c_str();
      const auto source_size = source.size();

      program =
          clCreateProgramWithSource(
              context,
              1,
              &source_pointer,
              &source_size,
              &error);
      check(error, "clCreateProgramWithSource");

      error =
          clBuildProgram(
              program,
              1,
              &device_id,
              "-cl-std=CL1.2",
              nullptr,
              nullptr);

      if (error != CL_SUCCESS)
      {
        std::size_t size = 0;

        clGetProgramBuildInfo(
            program,
            device_id,
            CL_PROGRAM_BUILD_LOG,
            0,
            nullptr,
            &size);

        std::string log(size, '\0');

        clGetProgramBuildInfo(
            program,
            device_id,
            CL_PROGRAM_BUILD_LOG,
            size,
            log.data(),
            nullptr);

        throw std::runtime_error(
            "OpenCL kernel compilation failed: " + log);
      }

      kernel =
          clCreateKernel(
              program,
              "sha256d_scan",
              &error);
      check(error, "clCreateKernel");

      auto built =
          stratum::build_work(
              job.job,
              job.extranonce1,
              unit->extranonce2,
              0);

      header_buffer =
          clCreateBuffer(
              context,
              CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
              76,
              built.header.data(),
              &error);
      check(error, "header buffer");

      target_buffer =
          clCreateBuffer(
              context,
              CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
              32,
              job.share_target.big_endian.data(),
              &error);
      check(error, "target buffer");

      std::uint32_t zero = 0;

      count_buffer =
          clCreateBuffer(
              context,
              CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
              sizeof(zero),
              &zero,
              &error);
      check(error, "candidate count buffer");

      std::array<std::uint32_t, 64> candidate_nonces{};

      candidates_buffer =
          clCreateBuffer(
              context,
              CL_MEM_WRITE_ONLY,
              sizeof(candidate_nonces),
              nullptr,
              &error);
      check(error, "candidate buffer");

      check(
          clSetKernelArg(
              kernel,
              0,
              sizeof(header_buffer),
              &header_buffer),
          "kernel header arg");

      check(
          clSetKernelArg(
              kernel,
              3,
              sizeof(target_buffer),
              &target_buffer),
          "kernel target arg");

      check(
          clSetKernelArg(
              kernel,
              4,
              sizeof(count_buffer),
              &count_buffer),
          "kernel count arg");

      check(
          clSetKernelArg(
              kernel,
              5,
              sizeof(candidates_buffer),
              &candidates_buffer),
          "kernel candidates arg");

      std::size_t local_size =
          std::min<std::size_t>(
              256,
              info.max_workgroup_size);

      std::size_t global_size = 1U << 20U;
      std::uint64_t batch_size = 1U << 24U;

      bool profile_matches = false;

      const auto profile_document =
          checkpoint::StateStore(profile_path)
              .load_or(nlohmann::json::object());

      const auto profile =
          profile_document.contains("gpu")
              ? profile_document.at("gpu")
              : profile_document;

      const auto profile_name =
          profile.value(
              "device_name",
              profile.value("name", ""));

      if (profile_name == info.name &&
          profile.value("driver", "") == info.driver &&
          profile.value("tuned", false))
      {
        local_size =
            profile.value(
                "local_work_size",
                local_size);

        global_size =
            profile.value(
                "global_work_size",
                global_size);

        batch_size =
            profile.value(
                "batch_size",
                batch_size);

        profile_matches = true;
      }

      if (auto_tune && !profile_matches)
      {
        double best_rate = 0.0;

        const std::array<std::size_t, 3> locals{
            64,
            128,
            256};

        const std::array<std::size_t, 3> globals{
            1U << 16U,
            1U << 18U,
            1U << 20U};

        const std::array<unsigned, 3> batch_repeats{
            1,
            4,
            16};

        const std::array<std::uint8_t, 32>
            impossible_target{};

        check(
            clEnqueueWriteBuffer(
                queue,
                target_buffer,
                CL_TRUE,
                0,
                32,
                impossible_target.data(),
                0,
                nullptr,
                nullptr),
            "tune target write");

        for (const auto local : locals)
        {
          if (local > info.max_workgroup_size)
          {
            continue;
          }

          for (const auto global : globals)
          {
            for (const auto repeats : batch_repeats)
            {
              std::uint32_t count =
                  static_cast<std::uint32_t>(
                      global);

              check(
                  clEnqueueWriteBuffer(
                      queue,
                      count_buffer,
                      CL_TRUE,
                      0,
                      sizeof(zero),
                      &zero,
                      0,
                      nullptr,
                      nullptr),
                  "tune reset");

              check(
                  clSetKernelArg(
                      kernel,
                      2,
                      sizeof(count),
                      &count),
                  "tune count arg");

              const auto before =
                  std::chrono::steady_clock::now();

              bool launch_ok = true;

              for (unsigned repeat = 0;
                   repeat < repeats;
                   ++repeat)
              {
                const auto start =
                    static_cast<std::uint32_t>(
                        static_cast<std::uint64_t>(
                            repeat) *
                        global);

                check(
                    clSetKernelArg(
                        kernel,
                        1,
                        sizeof(start),
                        &start),
                    "tune start arg");

                if (clEnqueueNDRangeKernel(
                        queue,
                        kernel,
                        1,
                        nullptr,
                        &global,
                        &local,
                        0,
                        nullptr,
                        nullptr) != CL_SUCCESS)
                {
                  launch_ok = false;
                  break;
                }
              }

              if (!launch_ok)
              {
                continue;
              }

              check(
                  clFinish(queue),
                  "tune finish");

              const auto seconds =
                  std::chrono::duration<double>(
                      std::chrono::steady_clock::now() -
                      before)
                      .count();

              const auto tested =
                  static_cast<double>(global) *
                  repeats;

              const auto rate =
                  seconds > 0.0
                      ? tested / seconds
                      : 0.0;

              if (rate > best_rate)
              {
                best_rate = rate;
                local_size = local;
                global_size = global;

                batch_size =
                    static_cast<std::uint64_t>(
                        global) *
                    repeats;
              }
            }
          }
        }

        check(
            clEnqueueWriteBuffer(
                queue,
                target_buffer,
                CL_TRUE,
                0,
                32,
                job.share_target.big_endian.data(),
                0,
                nullptr,
                nullptr),
            "target restore");

        checkpoint::StateStore(profile_path).save({
            {"schema_version", 1},
            {"device_name", info.name},
            {"vendor", info.vendor},
            {"driver", info.driver},
            {"local_work_size", local_size},
            {"global_work_size", global_size},
            {"batch_size", batch_size},
            {"tuned", true},
        });

        telemetry.event(
            "[GPU] auto-tuning terminé: local=" +
            std::to_string(local_size) +
            " global=" +
            std::to_string(global_size));
      }

      // One observed bootstrap launch establishes an exact personal threshold.
      // Subsequent launches keep the lean kernel and use the union of the share
      // target and that threshold, so record tracking has negligible steady cost.
      observed_kernel = clCreateKernel(program, "sha256d_scan_observed", &error);
      check(error, "clCreateKernel sha256d_scan_observed");

      const auto maximum_groups = (global_size + local_size - 1U) / local_size;
      std::vector<std::uint32_t> group_minima(maximum_groups * 9U);
      minima_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
                                     group_minima.size() * sizeof(std::uint32_t),
                                     nullptr, &error);
      check(error, "personal minimum buffer");
      check(clSetKernelArg(observed_kernel, 0, sizeof(header_buffer), &header_buffer), "observed header arg");
      check(clSetKernelArg(observed_kernel, 3, sizeof(target_buffer), &target_buffer), "observed target arg");
      check(clSetKernelArg(observed_kernel, 4, sizeof(count_buffer), &count_buffer), "observed count arg");
      check(clSetKernelArg(observed_kernel, 5, sizeof(candidates_buffer), &candidates_buffer), "observed candidates arg");
      check(clSetKernelArg(observed_kernel, 6, sizeof(minima_buffer), &minima_buffer), "observed minima arg");
      const auto local_minima_bytes = local_size * 9U * sizeof(std::uint32_t);
      check(clSetKernelArg(observed_kernel, 7, local_minima_bytes, nullptr), "observed local minima arg");

      std::string unit_best_hash;
      std::optional<std::uint32_t> unit_best_nonce;
      std::optional<bitcoin::Target256> personal_target;
      bool bootstrap_complete = false;

      while (!token.stop_requested() &&
             active_generation.load(
                 std::memory_order_acquire) ==
                 job.generation)
      {
        current_unit_id = unit->id;

        telemetry.set_gpu_extranonce2(unit->extranonce2);

        built =
            stratum::build_work(
                job.job,
                job.extranonce1,
                unit->extranonce2,
                0);

        check(
            clEnqueueWriteBuffer(
                queue,
                header_buffer,
                CL_TRUE,
                0,
                76,
                built.header.data(),
                0,
                nullptr,
                nullptr),
            "header update");

        auto next = unit->nonce_next;

        while (!token.stop_requested() &&
               active_generation.load(
                   std::memory_order_acquire) ==
                   job.generation &&
               next < unit->nonce_end)
        {
          const auto batch_count =
              std::min<std::uint64_t>(
                  batch_size,
                  unit->nonce_end - next);

          std::uint64_t processed = 0;

          while (processed < batch_count &&
                 !token.stop_requested() &&
                 active_generation.load(
                     std::memory_order_relaxed) ==
                     job.generation)
          {
            const auto count64 =
                std::min<std::uint64_t>(
                    global_size,
                    batch_count - processed);

            const auto count =
                static_cast<std::uint32_t>(
                    count64);

            const auto start =
                static_cast<std::uint32_t>(
                    next + processed);

            const auto launch_global =
                ((static_cast<std::size_t>(count) +
                  local_size - 1) /
                 local_size) *
                local_size;

            zero = 0;

            check(
                clEnqueueWriteBuffer(
                    queue,
                    count_buffer,
                    CL_TRUE,
                    0,
                    sizeof(zero),
                    &zero,
                    0,
                    nullptr,
                    nullptr),
                "candidate reset");

            auto active_kernel = bootstrap_complete ? kernel : observed_kernel;

            check(
                clSetKernelArg(
                    active_kernel,
                    1,
                    sizeof(start),
                    &start),
                "start arg");

            check(
                clSetKernelArg(
                    active_kernel,
                    2,
                    sizeof(count),
                    &count),
                "count arg");

            check(
                clEnqueueNDRangeKernel(
                    queue,
                    active_kernel,
                    1,
                    nullptr,
                    &launch_global,
                    &local_size,
                    0,
                    nullptr,
                    nullptr),
                "kernel launch");

            check(
                clFinish(queue),
                "kernel finish");

            bool target_changed = false;
            if (!bootstrap_complete) {
              const auto group_count = launch_global / local_size;
              check(clEnqueueReadBuffer(queue, minima_buffer, CL_TRUE, 0,
                                        group_count * 9U * sizeof(std::uint32_t),
                                        group_minima.data(), 0, nullptr, nullptr),
                    "personal minima read");
              std::size_t best_group = 0;
              for (std::size_t group = 1; group < group_count; ++group) {
                const auto left = group * 9U;
                const auto right = best_group * 9U;
                bool precedes = false;
                bool differs = false;
                for (std::size_t word = 0; word < 8U; ++word) {
                  if (group_minima[left + word] == group_minima[right + word]) continue;
                  precedes = group_minima[left + word] < group_minima[right + word];
                  differs = true;
                  break;
                }
                if (!differs) precedes = group_minima[left + 8U] < group_minima[right + 8U];
                if (precedes) best_group = group;
              }
              const auto observed_nonce = group_minima[best_group * 9U + 8U];
              auto observed_header = built.header;
              bitcoin::set_nonce(observed_header, observed_nonce);
              const auto observed_digest = crypto::sha256d(observed_header);
              const auto observed_hash = crypto::bitcoin_hash_hex(observed_digest);
              personal_target = bitcoin::target_from_hex(observed_hash);
              unit_best_hash = observed_hash;
              unit_best_nonce = observed_nonce;
              handler(Candidate{job, unit->extranonce2, observed_header, built.merkle_root,
                                observed_digest, observed_nonce, false,
                                bitcoin::hash_meets_target(observed_digest, job.network_target), "GPU"});
              bootstrap_complete = true;
              target_changed = true;
            }

            std::uint32_t candidate_count = 0;

            check(
                clEnqueueReadBuffer(
                    queue,
                    count_buffer,
                    CL_TRUE,
                    0,
                    sizeof(candidate_count),
                    &candidate_count,
                    0,
                    nullptr,
                    nullptr),
                "candidate count read");

            if (candidate_count > 0)
            {
              check(
                  clEnqueueReadBuffer(
                      queue,
                      candidates_buffer,
                      CL_TRUE,
                      0,
                      sizeof(candidate_nonces),
                      candidate_nonces.data(),
                      0,
                      nullptr,
                      nullptr),
                  "candidate read");

              const auto bounded_candidates =
                  std::min(
                      candidate_count,
                      static_cast<std::uint32_t>(
                          candidate_nonces.size()));

              for (std::uint32_t i = 0;
                   i < bounded_candidates;
                   ++i)
              {
                auto header = built.header;

                bitcoin::set_nonce(
                    header,
                    candidate_nonces[i]);

                const auto digest =
                    crypto::sha256d(header);

                const auto share_candidate = bitcoin::hash_meets_target(digest, job.share_target);
                const auto candidate_hash = crypto::bitcoin_hash_hex(digest);
                if (!personal_target || candidate_hash < bitcoin::target_hex(*personal_target)) {
                  personal_target = bitcoin::target_from_hex(candidate_hash);
                  target_changed = true;
                  if (unit_best_hash.empty() || candidate_hash < unit_best_hash) {
                    unit_best_hash = candidate_hash;
                    unit_best_nonce = candidate_nonces[i];
                  }
                }

                handler(
                    Candidate{
                        job,
                        unit->extranonce2,
                        header,
                        built.merkle_root,
                        digest,
                        candidate_nonces[i],
                        share_candidate,
                        bitcoin::hash_meets_target(
                            digest,
                            job.network_target),
                        "GPU"});
              }
            }

            if (target_changed && personal_target) {
              auto union_target = job.share_target;
              if (union_target.big_endian < personal_target->big_endian) union_target = *personal_target;
              check(clEnqueueWriteBuffer(queue, target_buffer, CL_TRUE, 0,
                                         union_target.big_endian.size(), union_target.big_endian.data(),
                                         0, nullptr, nullptr),
                    "personal/share union target update");
            }

            processed += count64;
          }

          next += processed;

          allocator.update_progress(
              unit->id,
              next,
              processed,
              unit_best_hash,
              unit_best_nonce);

          telemetry.set_gpu_progress(
              unit->nonce_start,
              next,
              unit->nonce_end);

          telemetry.gpu_hashes.fetch_add(
              processed,
              std::memory_order_relaxed);

          if (processed == 0)
          {
            break;
          }
        }

        if (next >= unit->nonce_end)
        {
          allocator.complete(unit->id);

          telemetry.headers_complete.fetch_add(
              1,
              std::memory_order_relaxed);
        }
        else
        {
          allocator.release(unit->id);
          current_unit_id.clear();
          break;
        }

        current_unit_id.clear();

        if (token.stop_requested() ||
            active_generation.load(
                std::memory_order_acquire) !=
                job.generation)
        {
          break;
        }

        unit =
            allocator.acquire(
                WorkerKind::Gpu);

        if (!unit)
        {
          telemetry.event(
              "[GPU] aucune unité disponible après "
              "complétion");

          break;
        }
        unit_best_hash.clear();
        unit_best_nonce.reset();
      }

      release_all();
    }
    catch (const std::exception &error)
    {
      if (!current_unit_id.empty())
      {
        allocator.release(current_unit_id);
      }

      release_all();

      telemetry.event(
          std::string(
              "[GPU] erreur, CPU maintenu: ") +
          error.what());
    }
  }
#endif
};

GpuMiner::GpuMiner(WorkAllocator& allocator,
                   telemetry::Telemetry& telemetry,
                   std::atomic<std::uint64_t>& active_generation,
                   CpuMiner::CandidateHandler handler,
                   std::filesystem::path kernel_path,
                   std::filesystem::path profile_path)
    : impl_(std::make_unique<Impl>(allocator, telemetry, active_generation, std::move(handler),
                                   std::move(kernel_path), std::move(profile_path))) {}

GpuMiner::~GpuMiner() { stop(); }

std::size_t GpuMiner::select_device_index(const std::vector<GpuInfo>& devices,
                                          const std::string& platform_selector,
                                          const std::string& device_selector) {
  if (devices.empty()) throw std::runtime_error("no OpenCL GPU detected");
  std::vector<std::size_t> candidates(devices.size());
  for (std::size_t index = 0; index < devices.size(); ++index) candidates[index] = index;

  if (!is_auto(platform_selector)) {
    const auto wanted = normalized(platform_selector);
    if (wanted.starts_with("index:")) {
      const auto requested = static_cast<std::size_t>(std::stoull(wanted.substr(6)));
      candidates.erase(std::remove_if(candidates.begin(), candidates.end(), [&](const std::size_t index) {
        return devices[index].platform_index != requested;
      }), candidates.end());
      if (candidates.empty()) throw std::invalid_argument("OpenCL platform index matches no platform: " + platform_selector);
    } else {
      auto filter_platform = [&](const bool exact) {
        std::vector<std::size_t> matches;
        for (const auto index : candidates) {
          const auto platform = normalized(devices[index].platform);
          if ((exact && platform == wanted) ||
              (!exact && platform.find(wanted) != std::string::npos)) {
            matches.push_back(index);
          }
        }
        return matches;
      };
      auto matches = filter_platform(true);
      if (matches.empty()) matches = filter_platform(false);
      if (matches.empty()) {
        throw std::invalid_argument("OpenCL platform selector matches no platform: " +
                                    platform_selector);
      }
      std::set<std::size_t> platform_indices;
      for (const auto index : matches) platform_indices.insert(devices[index].platform_index);
      if (platform_indices.size() > 1) {
        throw std::invalid_argument("ambiguous OpenCL platform selector: " + platform_selector);
      }
      candidates = std::move(matches);
    }
  }

  if (!is_auto(device_selector)) {
    const auto wanted = normalized(device_selector);
    if (wanted.starts_with("index:")) {
      const auto requested = static_cast<std::size_t>(std::stoull(wanted.substr(6)));
      const auto found = std::find_if(candidates.begin(), candidates.end(), [&](const std::size_t index) {
        return devices[index].index == requested;
      });
      if (found == candidates.end()) throw std::invalid_argument("OpenCL GPU index matches no device: " + device_selector);
      return *found;
    }
    auto filter_device = [&](const bool exact) {
      std::vector<std::size_t> matches;
      for (const auto index : candidates) {
        const auto name = normalized(devices[index].name);
        const auto board = normalized(devices[index].board_name);
        if ((exact && (name == wanted || board == wanted)) ||
            (!exact && (name.find(wanted) != std::string::npos || board.find(wanted) != std::string::npos))) {
          matches.push_back(index);
        }
      }
      return matches;
    };
    auto matches = filter_device(true);
    if (matches.empty()) matches = filter_device(false);
    if (matches.empty()) throw std::invalid_argument("OpenCL device selector matches no GPU: " + device_selector);
    if (matches.size() > 1) throw std::invalid_argument("ambiguous OpenCL device selector: " + device_selector);
    return matches.front();
  }

  return *std::max_element(candidates.begin(), candidates.end(), [&](const std::size_t left, const std::size_t right) {
    const auto& a = devices[left];
    const auto& b = devices[right];
    return std::tuple{is_amd(a), a.compute_units, a.global_memory, a.max_workgroup_size} <
           std::tuple{is_amd(b), b.compute_units, b.global_memory, b.max_workgroup_size};
  });
}

std::vector<GpuInfo> GpuMiner::enumerate() const {
#ifdef SRM_HAS_OPENCL
  try {
    const auto choices = impl_->enumerate_opencl();
    std::vector<GpuInfo> devices;
    devices.reserve(choices.size());
    for (const auto& choice : choices) devices.push_back(choice.info);
    return devices;
  }
  catch (const std::exception& error) { impl_->telemetry.event(std::string("[GPU] détection OpenCL échouée: ") + error.what()); impl_->info = {}; }
#else
  impl_->telemetry.event("[GPU] OpenCL absent à la compilation; poursuite CPU");
#endif
  return {};
}

GpuInfo GpuMiner::detect(const std::string& platform_selector, const std::string& device_selector) {
#ifdef SRM_HAS_OPENCL
  try { impl_->info = impl_->detect_opencl(platform_selector, device_selector); }
  catch (const std::exception& error) { impl_->telemetry.event(std::string("[GPU] détection OpenCL échouée: ") + error.what()); impl_->info = {}; }
#else
  (void)platform_selector;
  (void)device_selector;
  impl_->telemetry.event("[GPU] OpenCL absent à la compilation; poursuite CPU");
  impl_->info = {};
#endif
  return impl_->info;
}

GpuBenchmarkResult GpuMiner::benchmark(const bitcoin::Header& header,
                                       const std::string& platform_selector,
                                       const std::string& device_selector,
                                       const bool auto_tune,
                                       const unsigned warmup_ms,
                                       const unsigned measurement_ms) {
#ifdef SRM_HAS_OPENCL
  return impl_->benchmark_opencl(header, platform_selector, device_selector, auto_tune, warmup_ms, measurement_ms);
#else
  (void)header;
  (void)platform_selector;
  (void)device_selector;
  (void)auto_tune;
  (void)warmup_ms;
  (void)measurement_ms;
  throw std::runtime_error("benchmark GPU unavailable: OpenCL support was not compiled");
#endif
}

void GpuMiner::start(const LiveMiningJob& job, const bool auto_tune) {
  stop();
#ifdef SRM_HAS_OPENCL
  if (impl_->info.available) impl_->thread = std::jthread([this, job, auto_tune](const std::stop_token token) { impl_->run(token, job, auto_tune); });
#else
  (void)job; (void)auto_tune;
#endif
}

void GpuMiner::stop() {
  if (!impl_->thread.joinable()) return;
  impl_->thread.request_stop();
  impl_->thread.join();
}

}  // namespace srm::mining
