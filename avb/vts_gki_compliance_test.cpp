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

#include <vector>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <bootimg.h>
#include <fs_avb/fs_avb_util.h>
#include <gtest/gtest.h>
#include <vintf/VintfObject.h>
#include <vintf/parse_string.h>

#include "gsi_validation_utils.h"

namespace {

// Loads GKI compliance V2 images.
//
// Arguments:
//   out_boot_partition_vector: the boot.img content without boot_signature.
//       It consists of a boot header, a kernel and a ramdisk.
//   out_boot_signature_vector: the boot signature used to verify
//       out_boot_partition_vector.
//
void LoadGkiComplianceV2Images(
    std::vector<uint8_t> *out_boot_partition_vector,
    std::vector<uint8_t> *out_boot_signature_vector) {
  constexpr auto BOOT_HEADER_SIZE = 4096;
  std::string boot_path = "/dev/block/by-name/boot" + fs_mgr_get_slot_suffix();

  // Read boot header first.
  android::base::unique_fd fd(open(boot_path.c_str(), O_RDONLY));
  ASSERT_GE(fd, 0) << "Fail to open boot partition. Try 'adb root'.";

  out_boot_partition_vector->resize(BOOT_HEADER_SIZE);
  ASSERT_TRUE(android::base::ReadFully(fd, out_boot_partition_vector->data(),
                                       BOOT_HEADER_SIZE))
      << "Could not read boot partition header to vector.";

  boot_img_hdr_v4 *boot_header =
      reinterpret_cast<boot_img_hdr_v4 *>(out_boot_partition_vector->data());
  std::string boot_magic(reinterpret_cast<const char *>(boot_header->magic),
                         BOOT_MAGIC_SIZE);
  ASSERT_EQ(boot_magic, BOOT_MAGIC) << "Incorrect boot magic: " << boot_magic;

  GTEST_LOG_(INFO) << "kernel size: " << boot_header->kernel_size
                   << ", ramdisk size: " << boot_header->ramdisk_size
                   << ", signature size: " << boot_header->signature_size;

  // Now reads kernel and ramdisk.
  uint32_t kernel_pages = (boot_header->kernel_size + 4096 - 1) / 4096;
  uint32_t ramdisk_pages = (boot_header->ramdisk_size + 4096 - 1) / 4096;
  uint32_t kernel_ramdisk_size = (kernel_pages + ramdisk_pages) * 4096;

  out_boot_partition_vector->resize(BOOT_HEADER_SIZE + kernel_ramdisk_size);
  ASSERT_TRUE(android::base::ReadFully(
      fd, out_boot_partition_vector->data() + BOOT_HEADER_SIZE,
      kernel_ramdisk_size))
      << "Could not read boot partition to vector.";

  // Reads boot_signature.
  uint32_t signature_pages = (boot_header->signature_size + 4096 - 1) / 4096;
  uint32_t signature_size_aligned = signature_pages * 4096;
  out_boot_signature_vector->resize(signature_size_aligned);
  ASSERT_TRUE(android::base::ReadFully(fd, out_boot_signature_vector->data(),
                                       signature_size_aligned))
      << "Could not read boot signature to vector.";
}

// Verifies the GKI 2.0 boot.img against the boot signature.
//
// Arguments:
//   boot_partition_vector: the boot.img content without boot_signature.
//       It consists of a boot header, a kernel and a ramdisk.
//   boot_signature_vector: the boot signature used to verify
//       boot_partition_vector.
//
void VerifyGkiComplianceV2Signature(
    const std::vector<uint8_t> &boot_partition_vector,
    const std::vector<uint8_t> &boot_signature_vector) {
  size_t pk_len;
  const uint8_t *pk_data;
  ::AvbVBMetaVerifyResult vbmeta_ret;

  vbmeta_ret =
      avb_vbmeta_image_verify(boot_signature_vector.data(),
                              boot_signature_vector.size(), &pk_data, &pk_len);
  ASSERT_EQ(vbmeta_ret, AVB_VBMETA_VERIFY_RESULT_OK)
      << "Failed to verify boot_signature: " << vbmeta_ret;

  std::string out_public_key_data(reinterpret_cast<const char *>(pk_data),
                                  pk_len);
  ASSERT_FALSE(out_public_key_data.empty()) << "The GKI image is not signed.";
  EXPECT_TRUE(ValidatePublicKeyBlob(out_public_key_data))
      << "The GKI image is not signed by an official key.";

  android::fs_mgr::VBMetaData boot_signature(boot_signature_vector.data(),
                                             boot_signature_vector.size(),
                                             "boot_signature");

  std::unique_ptr<android::fs_mgr::FsAvbHashDescriptor> descriptor =
      android::fs_mgr::GetHashDescriptor("boot", std::move(boot_signature));
  ASSERT_TRUE(descriptor)
      << "Failed to load hash descriptor from the boot signature";
  ASSERT_EQ(boot_partition_vector.size(), descriptor->image_size);

  const std::string &salt_str = descriptor->salt;
  const std::string &expected_digest_str = descriptor->digest;

  const std::string hash_algorithm(
      reinterpret_cast<const char *>(descriptor->hash_algorithm));
  GTEST_LOG_(INFO) << "hash_algorithm = " << hash_algorithm;

  std::unique_ptr<ShaHasher> hasher = CreateShaHasher(hash_algorithm);
  ASSERT_TRUE(hasher);

  std::vector<uint8_t> salt, expected_digest, out_digest;

  bool ok = HexToBytes(salt_str, &salt);
  ASSERT_TRUE(ok) << "Invalid salt in descriptor: " << salt_str;
  ok = HexToBytes(expected_digest_str, &expected_digest);
  ASSERT_TRUE(ok) << "Invalid digest in descriptor: " << expected_digest_str;

  ASSERT_EQ(expected_digest.size(), hasher->GetDigestSize());
  out_digest.resize(hasher->GetDigestSize());

  ASSERT_TRUE(hasher->CalculateDigest(boot_partition_vector.data(),
                                      boot_partition_vector.size(), salt.data(),
                                      descriptor->salt_len, out_digest.data()))
      << "Unable to calculate boot image digest.";

  ASSERT_EQ(out_digest.size(), expected_digest.size())
      << "Calculated GKI boot digest size does not match expected digest size.";

  ASSERT_EQ(out_digest, expected_digest)
      << "Calculated GKI boot digest does not match expected digest.";
}

// Returns true iff the device has the specified feature.
bool DeviceSupportsFeature(const char *feature) {
  bool device_supports_feature = false;
  FILE *p = popen("pm list features", "re");
  if (p) {
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, p) > 0) {
      if (strstr(line, feature)) {
        device_supports_feature = true;
        break;
      }
    }
    pclose(p);
  }
  return device_supports_feature;
}

}  // namespace

class GkiComplianceTest : public testing::Test {
 public:
  void SetUp() override {
    auto vintf = android::vintf::VintfObject::GetInstance();
    ASSERT_NE(nullptr, vintf);
    runtime_info = vintf->getRuntimeInfo(
        android::vintf::RuntimeInfo::FetchFlag::CPU_VERSION);
    ASSERT_NE(nullptr, runtime_info);

    /* Skip for non arm64 that do not mandate GKI yet. */
    if (runtime_info->hardwareId() != "aarch64") {
      GTEST_SKIP() << "Exempt from GKI test on non-arm64 devices";
    }

    /* Skip for form factors that do not mandate GKI yet */
    const static bool tv_device =
        DeviceSupportsFeature("android.software.leanback");
    const static bool auto_device =
        DeviceSupportsFeature("android.hardware.type.automotive");
    if (tv_device || auto_device) {
      GTEST_SKIP() << "Exempt from GKI test on TV/Auto devices";
    }
  }

  std::shared_ptr<const android::vintf::RuntimeInfo> runtime_info;
};

TEST_F(GkiComplianceTest, GkiComplianceV1) {
  /* Skip for devices if the kernel version is not 5.4. */
  if (runtime_info->kernelVersion().dropMinor() !=
      android::vintf::Version{5, 4}) {
    GTEST_SKIP() << "Exempt from GKI 1.0 test on kernel version: "
                 << runtime_info->kernelVersion();
  }

  /* load vbmeta struct from boot, verify struct integrity */
  std::string out_public_key_data;
  android::fs_mgr::VBMetaVerifyResult out_verify_result;
  std::string boot_path = "/dev/block/by-name/boot" + fs_mgr_get_slot_suffix();
  std::unique_ptr<android::fs_mgr::VBMetaData> vbmeta =
      android::fs_mgr::LoadAndVerifyVbmetaByPath(
          boot_path, "boot", "" /* expected_key_blob */,
          true /* allow verification error */, false /* rollback_protection */,
          false /* is_chained_vbmeta */, &out_public_key_data,
          nullptr /* out_verification_disabled */, &out_verify_result);

  ASSERT_TRUE(vbmeta) << "Verification of GKI vbmeta fails.";
  ASSERT_FALSE(out_public_key_data.empty()) << "The GKI image is not signed.";
  EXPECT_TRUE(ValidatePublicKeyBlob(out_public_key_data))
      << "The GKI image is not signed by an official key.";
  EXPECT_EQ(out_verify_result, android::fs_mgr::VBMetaVerifyResult::kSuccess)
      << "Verification of the GKI vbmeta structure failed.";

  /* verify boot partition according to vbmeta structure */
  std::unique_ptr<android::fs_mgr::FsAvbHashDescriptor> descriptor =
      android::fs_mgr::GetHashDescriptor("boot", std::move(*vbmeta));
  ASSERT_TRUE(descriptor)
      << "Failed to load hash descriptor from boot.img vbmeta";
  const std::string &salt_str = descriptor->salt;
  const std::string &expected_digest_str = descriptor->digest;

  android::base::unique_fd fd(open(boot_path.c_str(), O_RDONLY));
  ASSERT_GE(fd, 0) << "Fail to open boot partition. Try 'adb root'.";

  const std::string hash_algorithm(
      reinterpret_cast<const char *>(descriptor->hash_algorithm));
  GTEST_LOG_(INFO) << "hash_algorithm = " << hash_algorithm;

  std::unique_ptr<ShaHasher> hasher = CreateShaHasher(hash_algorithm);
  ASSERT_TRUE(hasher);

  std::vector<uint8_t> salt, expected_digest, out_digest;
  bool ok = HexToBytes(salt_str, &salt);
  ASSERT_TRUE(ok) << "Invalid salt in descriptor: " << salt_str;
  ok = HexToBytes(expected_digest_str, &expected_digest);
  ASSERT_TRUE(ok) << "Invalid digest in descriptor: " << expected_digest_str;
  ASSERT_EQ(expected_digest.size(), hasher->GetDigestSize());

  std::vector<char> boot_partition_vector;
  boot_partition_vector.resize(descriptor->image_size);
  ASSERT_TRUE(android::base::ReadFully(fd, boot_partition_vector.data(),
                                       descriptor->image_size))
      << "Could not read boot partition to vector.";

  out_digest.resize(hasher->GetDigestSize());
  ASSERT_TRUE(hasher->CalculateDigest(boot_partition_vector.data(),
                                      descriptor->image_size, salt.data(),
                                      descriptor->salt_len, out_digest.data()))
      << "Unable to calculate boot image digest.";

  ASSERT_TRUE(out_digest.size() == expected_digest.size())
      << "Calculated GKI boot digest size does not match expected digest size.";
  ASSERT_TRUE(out_digest == expected_digest)
      << "Calculated GKI boot digest does not match expected digest.";
}

TEST_F(GkiComplianceTest, GkiComplianceV2) {
  /* Skip for devices if the kernel version is not >= 5.10. */
  if (runtime_info->kernelVersion().dropMinor() <
      android::vintf::Version{5, 10}) {
    GTEST_SKIP() << "Exempt from GKI 2.0 test on kernel version: "
                 << runtime_info->kernelVersion();
  }

  std::vector<uint8_t> boot_partition_vector;
  std::vector<uint8_t> boot_signature_vector;
  ASSERT_NO_FATAL_FAILURE(LoadGkiComplianceV2Images(&boot_partition_vector,
                                                    &boot_signature_vector));
  VerifyGkiComplianceV2Signature(boot_partition_vector, boot_signature_vector);
}
