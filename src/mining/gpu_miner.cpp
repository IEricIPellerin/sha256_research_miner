//src\mining\gpu_miner.cpp
#include "mining/gpu_miner.h"

#include "bitcoin/block_header.h"
#include "checkpoint/state_store.h"
#include "crypto/sha256.h"
#include "crypto/sha256d.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <thread>
#include <vector>

#ifdef SRM_HAS_OPENCL
#include <CL/cl.h>
#endif

namespace srm::mining {

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

  GpuInfo detect_opencl() {
    cl_uint platform_count = 0;
    if (clGetPlatformIDs(0, nullptr, &platform_count) != CL_SUCCESS || platform_count == 0) return {};
    std::vector<cl_platform_id> platforms(platform_count);
    check(clGetPlatformIDs(platform_count, platforms.data(), nullptr), "clGetPlatformIDs");

    struct Choice { cl_platform_id platform; cl_device_id device; bool amd; };
    std::vector<Choice> choices;
    for (const auto platform : platforms) {
      cl_uint count = 0;
      if (clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &count) != CL_SUCCESS || count == 0) continue;
      std::vector<cl_device_id> devices(count);
      check(clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, count, devices.data(), nullptr), "clGetDeviceIDs");
      for (const auto device : devices) {
        const auto vendor = get_string(device, CL_DEVICE_VENDOR, clGetDeviceInfo);
        choices.push_back({platform, device, vendor.find("AMD") != std::string::npos || vendor.find("Advanced Micro Devices") != std::string::npos});
      }
    }
    if (choices.empty()) return {};
    const auto selected = std::find_if(choices.begin(), choices.end(), [](const Choice& choice) { return choice.amd; });
    const auto& choice = selected == choices.end() ? choices.front() : *selected;
    platform_id = choice.platform;
    device_id = choice.device;
    GpuInfo result;
    result.available = true;
    result.platform = get_string(platform_id, CL_PLATFORM_NAME, clGetPlatformInfo);
    result.name = get_string(device_id, CL_DEVICE_NAME, clGetDeviceInfo);
    result.vendor = get_string(device_id, CL_DEVICE_VENDOR, clGetDeviceInfo);
    result.driver = get_string(device_id, CL_DRIVER_VERSION, clGetDeviceInfo);
    check(clGetDeviceInfo(device_id, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(result.compute_units), &result.compute_units, nullptr), "compute units");
    check(clGetDeviceInfo(device_id, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(result.global_memory), &result.global_memory, nullptr), "global memory");
    check(clGetDeviceInfo(device_id, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(result.max_workgroup_size), &result.max_workgroup_size, nullptr), "workgroup size");
    return result;
  }

  std::string read_kernel() const {
    std::ifstream input(kernel_path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open OpenCL kernel: " + kernel_path.string());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  }

  void run(std::stop_token token, LiveMiningJob job, bool auto_tune) {
    auto unit = allocator.acquire(WorkerKind::Gpu);
    if (!unit) return;
    try {
      cl_int error = CL_SUCCESS;
      cl_context context = clCreateContext(nullptr, 1, &device_id, nullptr, nullptr, &error); check(error, "clCreateContext");
      cl_command_queue queue = clCreateCommandQueue(context, device_id, CL_QUEUE_PROFILING_ENABLE, &error); check(error, "clCreateCommandQueue");
      const auto source = read_kernel();
      const char* source_pointer = source.c_str();
      const auto source_size = source.size();
      cl_program program = clCreateProgramWithSource(context, 1, &source_pointer, &source_size, &error); check(error, "clCreateProgramWithSource");
      error = clBuildProgram(program, 1, &device_id, "-cl-std=CL1.2", nullptr, nullptr);
      if (error != CL_SUCCESS) {
        std::size_t size = 0;
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, nullptr, &size);
        std::string log(size, '\0');
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, size, log.data(), nullptr);
        throw std::runtime_error("OpenCL kernel compilation failed: " + log);
      }
      cl_kernel kernel = clCreateKernel(program, "sha256d_scan", &error); check(error, "clCreateKernel");

      auto built = stratum::build_work(job.job, job.extranonce1, unit->extranonce2, 0);
      cl_mem header_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 76, built.header.data(), &error); check(error, "header buffer");
      cl_mem target_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 32, job.share_target.big_endian.data(), &error); check(error, "target buffer");
      std::uint32_t zero = 0;
      cl_mem count_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, sizeof(zero), &zero, &error); check(error, "candidate count buffer");
      std::array<std::uint32_t, 64> candidate_nonces{};
      cl_mem candidates_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(candidate_nonces), nullptr, &error); check(error, "candidate buffer");
      check(clSetKernelArg(kernel, 0, sizeof(header_buffer), &header_buffer), "kernel header arg");
      check(clSetKernelArg(kernel, 3, sizeof(target_buffer), &target_buffer), "kernel target arg");
      check(clSetKernelArg(kernel, 4, sizeof(count_buffer), &count_buffer), "kernel count arg");
      check(clSetKernelArg(kernel, 5, sizeof(candidates_buffer), &candidates_buffer), "kernel candidates arg");

      std::size_t local_size = std::min<std::size_t>(256, info.max_workgroup_size);
      std::size_t global_size = 1U << 20U;
      std::uint64_t batch_size = 1U << 24U;
      bool profile_matches = false;
      const auto profile = checkpoint::StateStore(profile_path).load_or(nlohmann::json::object());
      if (profile.value("device_name", "") == info.name && profile.value("driver", "") == info.driver && profile.value("tuned", false)) {
        local_size = profile.value("local_work_size", local_size);
        global_size = profile.value("global_work_size", global_size);
        batch_size = profile.value("batch_size", batch_size);
        profile_matches = true;
      }

      if (auto_tune && !profile_matches) {
        double best_rate = 0.0;
        const std::array<std::size_t, 3> locals{64, 128, 256};
        const std::array<std::size_t, 3> globals{1U << 16U, 1U << 18U, 1U << 20U};
        const std::array<unsigned, 3> batch_repeats{1, 4, 16};
        const std::array<std::uint8_t, 32> impossible_target{};
        check(clEnqueueWriteBuffer(queue, target_buffer, CL_TRUE, 0, 32, impossible_target.data(), 0, nullptr, nullptr), "tune target write");
        for (const auto local : locals) {
          if (local > info.max_workgroup_size) continue;
          for (const auto global : globals) {
            for (const auto repeats : batch_repeats) {
              std::uint32_t count = static_cast<std::uint32_t>(global);
              check(clEnqueueWriteBuffer(queue, count_buffer, CL_TRUE, 0, sizeof(zero), &zero, 0, nullptr, nullptr), "tune reset");
              check(clSetKernelArg(kernel, 2, sizeof(count), &count), "tune count arg");
              const auto before = std::chrono::steady_clock::now();
              bool launch_ok = true;
              for (unsigned repeat = 0; repeat < repeats; ++repeat) {
                const auto start = static_cast<std::uint32_t>(static_cast<std::uint64_t>(repeat) * global);
                check(clSetKernelArg(kernel, 1, sizeof(start), &start), "tune start arg");
                if (clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, &global, &local, 0, nullptr, nullptr) != CL_SUCCESS) {
                  launch_ok = false;
                  break;
                }
              }
              if (!launch_ok) continue;
              check(clFinish(queue), "tune finish");
              const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - before).count();
              const auto tested = static_cast<double>(global) * repeats;
              const auto rate = seconds > 0 ? tested / seconds : 0.0;
              if (rate > best_rate) {
                best_rate = rate;
                local_size = local;
                global_size = global;
                batch_size = static_cast<std::uint64_t>(global) * repeats;
              }
            }
          }
        }
        check(clEnqueueWriteBuffer(queue, target_buffer, CL_TRUE, 0, 32, job.share_target.big_endian.data(), 0, nullptr, nullptr), "target restore");
        checkpoint::StateStore(profile_path).save({
            {"schema_version", 1}, {"device_name", info.name}, {"vendor", info.vendor}, {"driver", info.driver},
            {"local_work_size", local_size}, {"global_work_size", global_size}, {"batch_size", batch_size}, {"tuned", true}});
        telemetry.event("[GPU] auto-tuning terminé: local=" + std::to_string(local_size) + " global=" + std::to_string(global_size));
      }

      auto next = unit->nonce_next;
      while (!token.stop_requested() && active_generation.load(std::memory_order_acquire) == job.generation && next < unit->nonce_end) {
        const auto batch_count = std::min<std::uint64_t>(batch_size, unit->nonce_end - next);
        std::uint64_t processed = 0;
        while (processed < batch_count && !token.stop_requested() &&
               active_generation.load(std::memory_order_relaxed) == job.generation) {
          const auto count64 = std::min<std::uint64_t>(global_size, batch_count - processed);
          const auto count = static_cast<std::uint32_t>(count64);
          const auto start = static_cast<std::uint32_t>(next + processed);
          const auto launch_global = ((static_cast<std::size_t>(count) + local_size - 1) / local_size) * local_size;
          zero = 0;
          check(clEnqueueWriteBuffer(queue, count_buffer, CL_TRUE, 0, sizeof(zero), &zero, 0, nullptr, nullptr), "candidate reset");
          check(clSetKernelArg(kernel, 1, sizeof(start), &start), "start arg");
          check(clSetKernelArg(kernel, 2, sizeof(count), &count), "count arg");
          check(clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, &launch_global, &local_size, 0, nullptr, nullptr), "kernel launch");
          check(clFinish(queue), "kernel finish");
          std::uint32_t candidate_count = 0;
          check(clEnqueueReadBuffer(queue, count_buffer, CL_TRUE, 0, sizeof(candidate_count), &candidate_count, 0, nullptr, nullptr), "candidate count read");
          if (candidate_count > 0) {
            check(clEnqueueReadBuffer(queue, candidates_buffer, CL_TRUE, 0, sizeof(candidate_nonces), candidate_nonces.data(), 0, nullptr, nullptr), "candidate read");
            for (std::uint32_t i = 0; i < std::min<std::uint32_t>(candidate_count, candidate_nonces.size()); ++i) {
              auto header = built.header;
              bitcoin::set_nonce(header, candidate_nonces[i]);
              const auto digest = crypto::sha256d(header);
              if (!bitcoin::hash_meets_target(digest, job.share_target)) continue;
              handler(Candidate{job, unit->extranonce2, header, built.merkle_root, digest, candidate_nonces[i],
                                bitcoin::hash_meets_target(digest, job.network_target)});
            }
          }
          processed += count64;
        }
        next += processed;
        allocator.update_progress(unit->id, next, processed);
        telemetry.set_progress(unit->nonce_start, next, unit->nonce_end);
        telemetry.gpu_hashes.fetch_add(processed, std::memory_order_relaxed);
        if (processed == 0) break;
      }
      if (next >= unit->nonce_end) { allocator.complete(unit->id); telemetry.headers_complete.fetch_add(1); }
      else allocator.release(unit->id);

      clReleaseMemObject(candidates_buffer); clReleaseMemObject(count_buffer); clReleaseMemObject(target_buffer); clReleaseMemObject(header_buffer);
      clReleaseKernel(kernel); clReleaseProgram(program); clReleaseCommandQueue(queue); clReleaseContext(context);
    } catch (const std::exception& error) {
      allocator.release(unit->id);
      telemetry.event(std::string("[GPU] erreur, CPU maintenu: ") + error.what());
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

GpuInfo GpuMiner::detect() {
#ifdef SRM_HAS_OPENCL
  try { impl_->info = impl_->detect_opencl(); }
  catch (const std::exception& error) { impl_->telemetry.event(std::string("[GPU] détection OpenCL échouée: ") + error.what()); impl_->info = {}; }
#else
  impl_->telemetry.event("[GPU] OpenCL absent à la compilation; poursuite CPU");
  impl_->info = {};
#endif
  return impl_->info;
}

void GpuMiner::start(const LiveMiningJob& job, const bool auto_tune) {
  stop();
  if (!impl_->info.available) detect();
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
