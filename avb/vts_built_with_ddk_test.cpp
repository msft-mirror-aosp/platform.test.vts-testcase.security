/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/result.h>
#include <android-base/strings.h>

#include <gtest/gtest.h>
#include <kver/kernel_release.h>
#include <libelf64/parse.h>
#include <openssl/sha.h>
#include <tinyxml2.h>
#include <vintf/VintfObject.h>

namespace android {
namespace {

constexpr std::string_view kOptionalKernelModulesConfigPath =
    "/system/etc/kernel/kernel-modules.xml";

class ModinfoTags {
 public:
  void ParseData(const std::vector<char>& data) {
    size_t offset = 0;
    while (offset < data.size()) {
      std::string_view chunk(data.data() + offset);
      offset += chunk.size() + 1;
      // Probably just padding
      if (chunk.empty()) continue;
      const auto delimiter = chunk.find('=');
      // Malformed chunk, just ignore it.
      if (delimiter == std::string_view::npos) continue;
      tags_[std::string(chunk.substr(0, delimiter))].emplace_back(
          chunk.substr(delimiter + 1));
    }
  }

  // Returns all the values found for the given |tag| joined with a new line.
  std::string TagValue(const std::string& tag) const {
    const auto& tag_values = tags_.find(tag);
    if (tag_values == tags_.end()) {
      return "";
    }
    return android::base::Join(tag_values->second, "\n");
  }

 private:
  std::unordered_map<std::string, std::vector<std::string>> tags_;
};

android::base::Result<void> AddModulesFromPath(
    std::unordered_set<std::string>& modules,
    const std::string_view& config_path, bool optional) {
  if (!std::filesystem::exists(config_path)) {
    if (optional) {
      GTEST_LOG_(INFO) << "Config file " << config_path << " does not exist.";
      return {};
    }
    return android::base::Error()
           << "Config file " << config_path << " does not exist.";
  }
  std::string kernel_modules_content;
  if (!android::base::ReadFileToString(std::string(config_path),
                                       &kernel_modules_content)) {
    return android::base::ErrnoError()
           << "Failed to read file at " << config_path;
  }
  tinyxml2::XMLDocument kernel_modules_xml;
  const auto& xml_error =
      kernel_modules_xml.Parse(kernel_modules_content.c_str());
  if (tinyxml2::XMLError::XML_SUCCESS != xml_error) {
    return android::base::Error()
           << "Failed to parse kernel modules config: "
           << tinyxml2::XMLDocument::ErrorIDToName(xml_error);
  }
  const tinyxml2::XMLElement* const kernel_modules_element =
      kernel_modules_xml.RootElement();
  for (const tinyxml2::XMLElement* module_element =
           kernel_modules_element->FirstChildElement("module");
       module_element != nullptr;
       module_element = module_element->NextSiblingElement("module")) {
    modules.insert(std::string(module_element->Attribute("value")));
  }
  return {};
}

android::base::Result<std::unordered_set<std::string>> GetAckModules() {
  std::unordered_set<std::string> modules;
  // Load information from the test data.
  const auto& exec_dir = android::base::GetExecutableDirectory();
  const auto& kernel_modules_config = exec_dir + "/kernel-modules.xml";
  if (!AddModulesFromPath(modules, kernel_modules_config,
                          /* optional = */ false)
           .ok()) {
    return android::base::Error()
           << "Failed to read test data from " << kernel_modules_config;
  }
  // Then check if there is additional information available from the device.
  if (!AddModulesFromPath(modules, kOptionalKernelModulesConfigPath,
                          /* optional = */ true)
           .ok()) {
    return android::base::Error() << "Failed to read test data from "
                                  << kOptionalKernelModulesConfigPath;
  }
  return modules;
}

std::string sha256(const std::string& content) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  const unsigned char* data = (const unsigned char*)content.data();
  SHA256(data, content.size(), hash);
  std::ostringstream os;
  os << std::hex << std::setfill('0');
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    os << std::setw(2) << static_cast<unsigned int>(hash[i]);
  }
  return os.str();
}

class BuiltWithDdkTest : public testing::Test {
 protected:
  void SetUp() override {
    // Fetch device runtime information.
    const auto& runtime_info = android::vintf::VintfObject::GetRuntimeInfo();
    ASSERT_NE(nullptr, runtime_info);

    constexpr uint64_t kMinAndroidRelease = 16;
    const auto& kernel_version = runtime_info->kernelVersion();
    const auto& kernel_release = android::kver::KernelRelease::Parse(
        runtime_info->osRelease(), /* allow_suffix = */ true);

    if (!kernel_release.has_value() ||
        (kernel_release->android_release() < kMinAndroidRelease)) {
      GTEST_SKIP() << "The test only applies to android" << kMinAndroidRelease
                   << " or later kernels.";
    }
    if (runtime_info->kernelVersion().dropMinor() <
        android::vintf::Version{6, 12}) {
      GTEST_SKIP() << "Exempt from built with DDK test. Kernel: "
                   << kernel_version.version << " " << kernel_version.majorRev;
    }

    // Get the information of ACK modules from the test data and from the system
    // if available.
    ack_modules_ = GetAckModules();
    ASSERT_RESULT_OK(ack_modules_) << "Unable to read list of ACK modules.";
  }
  android::base::Result<std::unordered_set<std::string>> ack_modules_;
};

std::string ModuleHash(const std::string& name, const std::string& author,
                       const std::string& license) {
  return sha256(name + author + license);
}

android::base::Result<void> AddModulesFromPartition(
    std::vector<std::filesystem::path>& modules, const std::string& partition) {
  int modules_found = 0;
  if (!std::filesystem::is_directory(partition)) {
    return android::base::Error() << "Unable to analyze path " << partition;
  }
  for (const auto& path_entry :
       std::filesystem::recursive_directory_iterator(partition)) {
    if (path_entry.path().extension() == ".ko") {
      modules.push_back(path_entry);
      ++modules_found;
    }
  }
  GTEST_LOG_(INFO) << modules_found << " modules found within " << partition;
  return {};
}

android::base::Result<void> InspectModule(
    const std::unordered_set<std::string>& ack_modules,
    const std::filesystem::path& module_path) {
  android::elf64::Elf64Binary elf;
  if (!android::elf64::Elf64Parser::ParseElfFile(module_path, elf)) {
    GTEST_LOG_(WARNING) << "Unable to parse module at " << module_path;
    return {};
  }
  ModinfoTags modinfo_tags;
  for (int i = 0; i < elf.sections.size(); i++) {
    android::elf64::Elf64_Sc& section = elf.sections[i];
    // Skip irrelevant sections
    if (section.name != ".modinfo") continue;
    // Ensure the buffer is zero terminated.
    if (section.data.back() != '\0') {
      section.data.push_back('\0');
    }
    modinfo_tags.ParseData(section.data);
    break;
  }
  // GKI Module
  // TODO: b/374932907 -- Despite the fact that technically GKI modules are a
  // subset of ACK modules add a dedicated check for them in V2.

  // ACK
  const std::string module_hash =
      ModuleHash(modinfo_tags.TagValue("name"), modinfo_tags.TagValue("author"),
                 modinfo_tags.TagValue("license"));
  if (ack_modules.contains(module_hash)) {
    return {};
  }
  // DDK
  if (modinfo_tags.TagValue("built_with") == "DDK") {
    return {};
  }
  return android::base::Error()
         << "Non compliant module found: " << module_path;
}

// @VsrTest = 3.4.2
TEST_F(BuiltWithDdkTest, SystemModules) {
  std::vector<std::filesystem::path> device_module_paths;
  ASSERT_RESULT_OK(
      AddModulesFromPartition(device_module_paths, "/vendor_dlkm/"));
  ASSERT_RESULT_OK(
      AddModulesFromPartition(device_module_paths, "/system_dlkm/"));

  // Run the inspection for each module found.
  for (const auto& module_path : device_module_paths) {
    EXPECT_RESULT_OK(InspectModule(ack_modules_.value(), module_path));
  }
}

// TODO: b/374932907 -- For V2 of this test, also include ramdisk files.

}  // namespace
}  // namespace android

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  android::base::InitLogging(argv, android::base::StderrLogger);
  return RUN_ALL_TESTS();
}
