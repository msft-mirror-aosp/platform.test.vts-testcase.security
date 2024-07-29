/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <string>
#include <string_view>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/result.h>
#include <tinyxml2.h>
#include <utils/Errors.h>

#include "ogki_builds_utils.h"

using android::base::Result;
using android::base::ResultError;

namespace ogki {

const std::string approved_builds_config_path =
    "/system/etc/kernel/approved-ogki-builds.xml";

Result<std::unordered_map<std::string, BuildInfo>> GetApprovedBuilds(
    std::string_view branch_name) {
  std::string approved_builds_content;
  if (!android::base::ReadFileToString(approved_builds_config_path,
                                       &approved_builds_content)) {
    return ResultError("Failed to read approved OGKI builds config at " +
                           approved_builds_config_path,
                       -errno);
  }

  tinyxml2::XMLDocument approved_builds_xml;
  if (auto xml_error =
          approved_builds_xml.Parse(approved_builds_content.c_str());
      xml_error != tinyxml2::XMLError::XML_SUCCESS) {
    return ResultError(
        std::format("Failed to parse approved builds config: {}",
                    tinyxml2::XMLDocument::ErrorIDToName(xml_error)),
        android::UNKNOWN_ERROR);
  }

  tinyxml2::XMLElement* branch_element = nullptr;
  const auto ogki_element = approved_builds_xml.RootElement();
  for (auto branch = ogki_element->FirstChildElement("branch"); branch;
       branch = branch->NextSiblingElement("branch")) {
    if (branch->Attribute("name", branch_name.data())) {
      branch_element = branch;
      break;
    }
  }
  if (!branch_element) {
    return ResultError(
        std::format("Branch '{}' not found in approved builds config",
                    branch_name.data()),
        android::NAME_NOT_FOUND);
  }

  std::unordered_map<std::string, BuildInfo> approved_builds;
  for (auto build = branch_element->FirstChildElement("build"); build;
       build = build->NextSiblingElement("build")) {
    approved_builds.emplace(build->Attribute("id"), BuildInfo{});
  }
  return approved_builds;
}

}  // namespace ogki
