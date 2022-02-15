/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <openssl/sha.h>

#include "gsi_validation_utils.h"

uint8_t HexDigitToByte(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'Z') {
    return c - 'A' + 10;
  }
  return 0xff;
}

bool HexToBytes(const std::string &hex, std::vector<uint8_t> *bytes) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  bytes->resize(hex.size() / 2);
  for (unsigned i = 0; i < bytes->size(); i++) {
    uint8_t hi = HexDigitToByte(hex[i * 2]);
    uint8_t lo = HexDigitToByte(hex[i * 2 + 1]);
    if (lo > 0xf || hi > 0xf) {
      return false;
    }
    bytes->at(i) = (hi << 4) | lo;
  }
  return true;
}

std::unique_ptr<ShaHasher> CreateShaHasher(const std::string &algorithm) {
  if (algorithm == "sha1") {
    return std::make_unique<ShaHasherImpl<SHA_CTX>>(
        SHA1_Init, SHA1_Update, SHA1_Final, SHA_DIGEST_LENGTH);
  }
  if (algorithm == "sha256") {
    return std::make_unique<ShaHasherImpl<SHA256_CTX>>(
        SHA256_Init, SHA256_Update, SHA256_Final, SHA256_DIGEST_LENGTH);
  }
  if (algorithm == "sha512") {
    return std::make_unique<ShaHasherImpl<SHA512_CTX>>(
        SHA512_Init, SHA512_Update, SHA512_Final, SHA512_DIGEST_LENGTH);
  }
  return nullptr;
}

bool ValidatePublicKeyBlob(const std::string &key_blob_to_validate) {
  if (key_blob_to_validate.empty()) {
    GTEST_LOG_(ERROR) << "Failed to validate an empty key";
    return false;
  }

  const std::string exec_dir = android::base::GetExecutableDirectory();
  std::vector<std::string> allowed_key_names = {
      "q-gsi.avbpubkey", "r-gsi.avbpubkey",    "s-gsi.avbpubkey",
      "t-gsi.avbpubkey", "qcar-gsi.avbpubkey",
  };
  for (const auto &key_name : allowed_key_names) {
    const auto key_path = exec_dir + "/" + key_name;
    std::string allowed_key_blob;
    if (android::base::ReadFileToString(key_path, &allowed_key_blob)) {
      if (key_blob_to_validate == allowed_key_blob) {
        GTEST_LOG_(INFO) << "Found matching GSI key: " << key_path;
        return true;
      }
    }
  }
  return false;
}
