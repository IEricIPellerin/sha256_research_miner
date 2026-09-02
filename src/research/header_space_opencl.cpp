//src\research\header_space_opencl.cpp
#include "research/header_space.h"

#include <algorithm>
#include <bit>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <tuple>
#include <utility>

#ifdef SRM_HAS_OPENCL
#include <CL/cl.h>
#endif

namespace srm::research::header_space {
namespace {

std::string normalized(std::string value) {
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](const unsigned char c) {
    return !std::isspace(c);
  }));
  value.erase(std::find_if(value.rbegin(), value.rend(), [](const unsigned char c) {
    return !std::isspace(c);
  }).base(), value.end());
  std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

#ifdef SRM_HAS_OPENCL

void cl_require(const cl_int error, const char* operation) {
  if (error != CL_SUCCESS) {
    throw std::runtime_error(std::string(operation) + " failed with OpenCL error " +
                             std::to_string(error));
  }
}

template <typename Id>
std::string get_string(Id id,
                       const cl_uint field,
                       cl_int (*getter)(Id, cl_uint, std::size_t, void*, std::size_t*)) {
  std::size_t size = 0;
  cl_require(getter(id, field, 0, nullptr, &size), "OpenCL info size");
  std::string value(size, '\0');
  cl_require(getter(id, field, size, value.data(), nullptr), "OpenCL info");
  while (!value.empty() && value.back() == '\0') value.pop_back();
  return value;
}

std::string optional_device_string(const cl_device_id device, const cl_uint field) {
  std::size_t size = 0;
  if (clGetDeviceInfo(device, field, 0, nullptr, &size) != CL_SUCCESS || size == 0) return {};
  std::string value(size, '\0');
  if (clGetDeviceInfo(device, field, size, value.data(), nullptr) != CL_SUCCESS) return {};
  while (!value.empty() && value.back() == '\0') value.pop_back();
  return value;
}

struct DeviceChoice {
  GpuDeviceInfo info;
  cl_platform_id platform{};
  cl_device_id device{};
};

std::vector<DeviceChoice> enumerate_choices() {
  cl_uint platform_count = 0;
  if (clGetPlatformIDs(0, nullptr, &platform_count) != CL_SUCCESS || platform_count == 0) return {};
  std::vector<cl_platform_id> platforms(platform_count);
  cl_require(clGetPlatformIDs(platform_count, platforms.data(), nullptr), "clGetPlatformIDs");

  std::vector<DeviceChoice> choices;
  for (std::size_t platform_index = 0; platform_index < platforms.size(); ++platform_index) {
    const auto platform = platforms[platform_index];
    cl_uint device_count = 0;
    if (clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, nullptr, &device_count) != CL_SUCCESS ||
        device_count == 0) {
      continue;
    }
    std::vector<cl_device_id> devices(device_count);
    cl_require(clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, device_count, devices.data(), nullptr),
               "clGetDeviceIDs");
    for (std::size_t device_index = 0; device_index < devices.size(); ++device_index) {
      const auto device = devices[device_index];
      GpuDeviceInfo info;
      info.index = choices.size();
      info.platform_index = platform_index;
      info.device_index = device_index;
      info.platform = get_string(platform, CL_PLATFORM_NAME, clGetPlatformInfo);
      info.name = get_string(device, CL_DEVICE_NAME, clGetDeviceInfo);
      info.board_name = optional_device_string(device, 0x4038U);  // CL_DEVICE_BOARD_NAME_AMD
      info.vendor = get_string(device, CL_DEVICE_VENDOR, clGetDeviceInfo);
      info.driver = get_string(device, CL_DRIVER_VERSION, clGetDeviceInfo);
      cl_require(clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS,
                                 sizeof(info.compute_units), &info.compute_units, nullptr),
                 "CL_DEVICE_MAX_COMPUTE_UNITS");
      cl_require(clGetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE,
                                 sizeof(info.global_memory_bytes), &info.global_memory_bytes, nullptr),
                 "CL_DEVICE_GLOBAL_MEM_SIZE");
      cl_require(clGetDeviceInfo(device, CL_DEVICE_LOCAL_MEM_SIZE,
                                 sizeof(info.local_memory_bytes), &info.local_memory_bytes, nullptr),
                 "CL_DEVICE_LOCAL_MEM_SIZE");
      cl_require(clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE,
                                 sizeof(info.max_workgroup_size), &info.max_workgroup_size, nullptr),
                 "CL_DEVICE_MAX_WORK_GROUP_SIZE");
      choices.push_back({std::move(info), platform, device});
    }
  }
  return choices;
}

std::size_t parse_index_selector(const std::string& selector) {
  constexpr std::string_view prefix = "index:";
  const auto normalized_selector = normalized(selector);
  if (!normalized_selector.starts_with(prefix)) return std::numeric_limits<std::size_t>::max();
  const auto digits = normalized_selector.substr(prefix.size());
  if (digits.empty()) throw std::invalid_argument("empty OpenCL device index selector");
  std::size_t consumed = 0;
  const auto value = std::stoull(digits, &consumed, 10);
  if (consumed != digits.size() || value > std::numeric_limits<std::size_t>::max()) {
    throw std::invalid_argument("invalid OpenCL device index selector");
  }
  return static_cast<std::size_t>(value);
}

DeviceChoice select_choice(const std::string& selector) {
  auto choices = enumerate_choices();
  if (choices.empty()) throw std::runtime_error("no OpenCL GPU detected");
  const auto wanted = normalized(selector);
  if (wanted.empty() || wanted == "auto") {
    const auto score = [](const DeviceChoice& choice) {
      const auto vendor = normalized(choice.info.vendor);
      const bool amd = vendor.find("amd") != std::string::npos ||
                       vendor.find("advanced micro devices") != std::string::npos;
      return std::tuple{amd, choice.info.compute_units, choice.info.global_memory_bytes};
    };
    return *std::max_element(choices.begin(), choices.end(), [&](const auto& left, const auto& right) {
      return score(left) < score(right);
    });
  }

  const auto index = parse_index_selector(selector);
  if (index != std::numeric_limits<std::size_t>::max()) {
    const auto found = std::find_if(choices.begin(), choices.end(), [&](const auto& choice) {
      return choice.info.index == index;
    });
    if (found == choices.end()) throw std::invalid_argument("OpenCL device index is out of range");
    return *found;
  }

  std::vector<DeviceChoice> matches;
  for (const auto& choice : choices) {
    const auto name = normalized(choice.info.name);
    const auto board = normalized(choice.info.board_name);
    if (name == wanted || board == wanted) return choice;
    if (name.find(wanted) != std::string::npos || board.find(wanted) != std::string::npos) {
      matches.push_back(choice);
    }
  }
  if (matches.empty()) throw std::invalid_argument("OpenCL device selector matches no GPU: " + selector);
  if (matches.size() != 1) throw std::invalid_argument("ambiguous OpenCL device selector: " + selector);
  return matches.front();
}

std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot open OpenCL kernel: " + path.string());
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

#endif

}  // namespace

bool opencl_compiled() noexcept {
#ifdef SRM_HAS_OPENCL
  return true;
#else
  return false;
#endif
}

std::vector<GpuDeviceInfo> enumerate_gpu_devices() {
#ifdef SRM_HAS_OPENCL
  std::vector<GpuDeviceInfo> result;
  for (const auto& choice : enumerate_choices()) result.push_back(choice.info);
  return result;
#else
  return {};
#endif
}

struct GpuScanner::Impl {
  GpuDeviceInfo info;
  std::size_t requested_local_size{0};
#ifdef SRM_HAS_OPENCL
  cl_device_id device{};
  cl_context context{};
  cl_command_queue queue{};
  cl_program program{};
  cl_kernel kernel{};

  ~Impl() {
    if (kernel) clReleaseKernel(kernel);
    if (program) clReleaseProgram(program);
    if (queue) clReleaseCommandQueue(queue);
    if (context) clReleaseContext(context);
  }
#endif
};

GpuScanner::GpuScanner(std::string device_selector,
                       std::filesystem::path kernel_path,
                       const std::size_t local_size)
    : impl_(std::make_unique<Impl>()) {
#ifdef SRM_HAS_OPENCL
  if (local_size == 0 || !std::has_single_bit(local_size)) {
    throw std::invalid_argument("--local-size must be a positive power of two");
  }
  const auto choice = select_choice(device_selector);
  impl_->info = choice.info;
  impl_->device = choice.device;
  impl_->requested_local_size = local_size;
  if (local_size > impl_->info.max_workgroup_size) {
    throw std::invalid_argument("--local-size exceeds CL_DEVICE_MAX_WORK_GROUP_SIZE");
  }
  constexpr std::size_t minimum_words_per_item = 9U * sizeof(cl_uint) + 7U * sizeof(cl_ulong);
  if (local_size > impl_->info.local_memory_bytes / minimum_words_per_item) {
    throw std::invalid_argument("--local-size requires more local memory than the selected GPU provides");
  }

  cl_int error = CL_SUCCESS;
  impl_->context = clCreateContext(nullptr, 1, &impl_->device, nullptr, nullptr, &error);
  cl_require(error, "clCreateContext");
  impl_->queue = clCreateCommandQueue(impl_->context, impl_->device, CL_QUEUE_PROFILING_ENABLE, &error);
  cl_require(error, "clCreateCommandQueue");
  const auto source = read_file(kernel_path);
  const char* source_pointer = source.c_str();
  const auto source_size = source.size();
  impl_->program = clCreateProgramWithSource(impl_->context, 1, &source_pointer, &source_size, &error);
  cl_require(error, "clCreateProgramWithSource");
  error = clBuildProgram(impl_->program, 1, &impl_->device, "-cl-std=CL1.2", nullptr, nullptr);
  if (error != CL_SUCCESS) {
    std::size_t log_size = 0;
    clGetProgramBuildInfo(impl_->program, impl_->device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
    std::string log(log_size, '\0');
    clGetProgramBuildInfo(impl_->program, impl_->device, CL_PROGRAM_BUILD_LOG,
                          log.size(), log.data(), nullptr);
    throw std::runtime_error("OpenCL header-space kernel compilation failed: " + log);
  }
  impl_->kernel = clCreateKernel(impl_->program, "map_header_space_zones", &error);
  cl_require(error, "clCreateKernel map_header_space_zones");
  std::size_t kernel_max_workgroup = 0;
  cl_require(clGetKernelWorkGroupInfo(impl_->kernel, impl_->device, CL_KERNEL_WORK_GROUP_SIZE,
                                      sizeof(kernel_max_workgroup), &kernel_max_workgroup, nullptr),
             "CL_KERNEL_WORK_GROUP_SIZE");
  if (local_size > kernel_max_workgroup) {
    throw std::invalid_argument("--local-size exceeds the compiled kernel workgroup limit");
  }
#else
  (void)device_selector;
  (void)kernel_path;
  (void)local_size;
  throw std::runtime_error("header-space GPU scanner was built without OpenCL support");
#endif
}

GpuScanner::~GpuScanner() = default;
GpuScanner::GpuScanner(GpuScanner&&) noexcept = default;
GpuScanner& GpuScanner::operator=(GpuScanner&&) noexcept = default;

const GpuDeviceInfo& GpuScanner::device() const { return impl_->info; }
std::size_t GpuScanner::local_size() const noexcept { return impl_->requested_local_size; }

GpuScanResult GpuScanner::scan(const bitcoin::Header& header,
                               const std::uint64_t nonce_start,
                               const std::uint64_t nonce_count,
                               const std::uint64_t zone_size,
                               const std::size_t batch_zones) {
#ifdef SRM_HAS_OPENCL
  if (batch_zones == 0) throw std::invalid_argument("--batch-zones must be positive");
  const auto layout = make_zone_layout(nonce_start, nonce_count, zone_size);
  const auto maximum_batch = std::min(batch_zones, layout.size());
  if (maximum_batch > std::numeric_limits<std::size_t>::max() / impl_->requested_local_size) {
    throw std::overflow_error("OpenCL global size overflows size_t");
  }

  cl_int error = CL_SUCCESS;
  cl_mem prefix_buffer{};
  cl_mem starts_buffer{};
  cl_mem counts_buffer{};
  cl_mem minima_buffer{};
  cl_mem tail_counts_buffer{};
  const auto release_buffers = [&] {
    if (tail_counts_buffer) clReleaseMemObject(tail_counts_buffer);
    if (minima_buffer) clReleaseMemObject(minima_buffer);
    if (counts_buffer) clReleaseMemObject(counts_buffer);
    if (starts_buffer) clReleaseMemObject(starts_buffer);
    if (prefix_buffer) clReleaseMemObject(prefix_buffer);
  };

  try {
    prefix_buffer = clCreateBuffer(impl_->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 76,
                                   const_cast<std::uint8_t*>(header.data()), &error);
    cl_require(error, "header-space prefix buffer");
    starts_buffer = clCreateBuffer(impl_->context, CL_MEM_READ_ONLY,
                                   maximum_batch * sizeof(cl_ulong), nullptr, &error);
    cl_require(error, "header-space zone starts buffer");
    counts_buffer = clCreateBuffer(impl_->context, CL_MEM_READ_ONLY,
                                   maximum_batch * sizeof(cl_ulong), nullptr, &error);
    cl_require(error, "header-space zone counts buffer");
    minima_buffer = clCreateBuffer(impl_->context, CL_MEM_WRITE_ONLY,
                                   maximum_batch * 9U * sizeof(cl_uint), nullptr, &error);
    cl_require(error, "header-space minima buffer");
    tail_counts_buffer = clCreateBuffer(impl_->context, CL_MEM_WRITE_ONLY,
                                        maximum_batch * 7U * sizeof(cl_ulong), nullptr, &error);
    cl_require(error, "header-space tail counts buffer");

    cl_require(clSetKernelArg(impl_->kernel, 0, sizeof(prefix_buffer), &prefix_buffer), "prefix arg");
    cl_require(clSetKernelArg(impl_->kernel, 1, sizeof(starts_buffer), &starts_buffer), "starts arg");
    cl_require(clSetKernelArg(impl_->kernel, 2, sizeof(counts_buffer), &counts_buffer), "counts arg");
    cl_require(clSetKernelArg(impl_->kernel, 3, sizeof(minima_buffer), &minima_buffer), "minima arg");
    cl_require(clSetKernelArg(impl_->kernel, 4, sizeof(tail_counts_buffer), &tail_counts_buffer),
               "tail counts arg");
    const auto local_minima_bytes = impl_->requested_local_size * 9U * sizeof(cl_uint);
    const auto local_counts_bytes = impl_->requested_local_size * 7U * sizeof(cl_ulong);
    cl_require(clSetKernelArg(impl_->kernel, 5, local_minima_bytes, nullptr), "local minima arg");
    cl_require(clSetKernelArg(impl_->kernel, 6, local_counts_bytes, nullptr), "local counts arg");

    GpuScanResult result;
    result.device = impl_->info;
    result.local_size = impl_->requested_local_size;
    result.batch_zones = batch_zones;
    result.maximum_global_size = maximum_batch * impl_->requested_local_size;
    result.zones.reserve(layout.size());
    std::vector<cl_ulong> starts(maximum_batch);
    std::vector<cl_ulong> counts(maximum_batch);
    std::vector<cl_uint> minima(maximum_batch * 9U);
    std::vector<cl_ulong> tail_counts(maximum_batch * 7U);
    const auto wall_start = std::chrono::steady_clock::now();
    for (std::size_t offset = 0; offset < layout.size(); offset += maximum_batch) {
      const auto current = std::min(maximum_batch, layout.size() - offset);
      for (std::size_t i = 0; i < current; ++i) {
        starts[i] = static_cast<cl_ulong>(layout[offset + i].nonce_start);
        counts[i] = static_cast<cl_ulong>(layout[offset + i].nonce_count);
      }
      cl_require(clEnqueueWriteBuffer(impl_->queue, starts_buffer, CL_TRUE, 0,
                                      current * sizeof(cl_ulong), starts.data(), 0, nullptr, nullptr),
                 "zone starts upload");
      cl_require(clEnqueueWriteBuffer(impl_->queue, counts_buffer, CL_TRUE, 0,
                                      current * sizeof(cl_ulong), counts.data(), 0, nullptr, nullptr),
                 "zone counts upload");
      const auto global_size = current * impl_->requested_local_size;
      cl_event event{};
      cl_require(clEnqueueNDRangeKernel(impl_->queue, impl_->kernel, 1, nullptr,
                                        &global_size, &impl_->requested_local_size,
                                        0, nullptr, &event),
                 "header-space kernel launch");
      cl_require(clFinish(impl_->queue), "header-space kernel finish");
      cl_ulong event_start = 0;
      cl_ulong event_end = 0;
      if (clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START,
                                  sizeof(event_start), &event_start, nullptr) == CL_SUCCESS &&
          clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END,
                                  sizeof(event_end), &event_end, nullptr) == CL_SUCCESS &&
          event_end >= event_start) {
        result.kernel_seconds += static_cast<double>(event_end - event_start) * 1e-9;
      }
      clReleaseEvent(event);
      cl_require(clEnqueueReadBuffer(impl_->queue, minima_buffer, CL_TRUE, 0,
                                     current * 9U * sizeof(cl_uint), minima.data(), 0, nullptr, nullptr),
                 "zone minima download");
      cl_require(clEnqueueReadBuffer(impl_->queue, tail_counts_buffer, CL_TRUE, 0,
                                     current * 7U * sizeof(cl_ulong), tail_counts.data(), 0, nullptr, nullptr),
                 "zone counts download");
      for (std::size_t i = 0; i < current; ++i) {
        ZoneStats zone;
        zone.range = layout[offset + i];
        for (std::size_t word = 0; word < 8; ++word) {
          zone.minimum_pow_value[word] = minima[i * 9U + word];
        }
        zone.minimum_nonce = minima[i * 9U + 8U];
        for (std::size_t threshold = 0; threshold < 7; ++threshold) {
          zone.counts[threshold] = tail_counts[i * 7U + threshold];
        }
        result.zones.push_back(zone);
      }
      ++result.kernel_launches;
    }
    result.elapsed_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - wall_start).count();
    release_buffers();
    return result;
  } catch (...) {
    release_buffers();
    throw;
  }
#else
  (void)header;
  (void)nonce_start;
  (void)nonce_count;
  (void)zone_size;
  (void)batch_zones;
  throw std::runtime_error("header-space GPU scanner was built without OpenCL support");
#endif
}

}  // namespace srm::research::header_space
