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
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <android/api-level.h>
#include <bootimg.h>
#include <fs_avb/fs_avb_util.h>
#include <gtest/gtest.h>
#include <storage_literals/storage_literals.h>
#include <vintf/VintfObject.h>
#include <vintf/parse_string.h>

#include "gsi_validation_utils.h"

using namespace std::literals;
using namespace android::storage_literals;

namespace {

std::string GetBlockDevicePath(const std::string &name) {
  return "/dev/block/by-name/" + name + fs_mgr_get_slot_suffix();
}

uint32_t GetBootHeaderVersion(const void *data) {
  return reinterpret_cast<const boot_img_hdr_v0 *>(data)->header_version;
}

class GkiBootImage {
 public:
  GkiBootImage(const uint8_t *data, size_t size) : data_(data, data + size) {}

  const uint8_t *data() const { return data_.data(); }

  size_t size() const { return data_.size(); }

  uint32_t kernel_pages() const { return GetNumberOfPages(kernel_size()); }

  uint32_t ramdisk_pages() const { return GetNumberOfPages(ramdisk_size()); }

  uint32_t kernel_offset() const {
    // The first page must be the boot image header.
    return page_size();
  }

  uint32_t ramdisk_offset() const {
    return kernel_offset() + kernel_pages() * page_size();
  }

  virtual uint32_t page_size() const = 0;
  virtual uint32_t kernel_size() const = 0;
  virtual uint32_t ramdisk_size() const = 0;
  virtual uint32_t signature_size() const = 0;
  virtual uint32_t signature_offset() const = 0;

  std::vector<uint8_t> Slice(size_t offset, size_t length) const {
    const auto begin_offset = std::clamp<size_t>(offset, 0, size());
    const auto end_offset =
        std::clamp<size_t>(begin_offset + length, begin_offset, size());
    const auto begin = data() + begin_offset;
    const auto end = data() + end_offset;
    return {begin, end};
  }

  uint32_t GetNumberOfPages(uint32_t value) const {
    return (value - 1 + page_size()) / page_size();
  }

  std::vector<uint8_t> GetKernel() const {
    return Slice(kernel_offset(), kernel_size());
  }

  std::vector<uint8_t> GetRamdisk() const {
    return Slice(ramdisk_offset(), ramdisk_size());
  }

  // Parse a vector of vbmeta image from the boot signature section.
  std::vector<android::fs_mgr::VBMetaData> GetBootSignatures() const {
    const auto begin_offset = std::clamp<size_t>(signature_offset(), 0, size());
    const uint8_t *buffer = data() + begin_offset;
    // begin_offset + remaining_bytes <= size() because boot_signature must be
    // the last section.
    size_t remaining_bytes =
        std::clamp<size_t>(signature_size(), 0, size() - begin_offset);
    // In case boot_signature is misaligned, shift to the first AVB magic, and
    // treat it as the actual beginning of boot signature.
    while (remaining_bytes >= AVB_MAGIC_LEN) {
      if (!memcmp(buffer, AVB_MAGIC, AVB_MAGIC_LEN)) {
        break;
      }
      ++buffer;
      --remaining_bytes;
    }
    std::vector<android::fs_mgr::VBMetaData> vbmeta_images;
    while (remaining_bytes >= sizeof(AvbVBMetaImageHeader)) {
      if (memcmp(buffer, AVB_MAGIC, AVB_MAGIC_LEN) != 0) {
        break;
      }
      // Extract only the header to calculate the vbmeta image size.
      android::fs_mgr::VBMetaData vbmeta_header(
          buffer, sizeof(AvbVBMetaImageHeader), "boot_signature");
      if (!vbmeta_header.GetVBMetaHeader(/* update_vbmeta_size */ true)) {
        GTEST_LOG_(ERROR) << __FUNCTION__
                          << "(): VBMetaData::GetVBMetaHeader() failed.";
        return {};
      }
      const auto vbmeta_image_size = vbmeta_header.size();
      GTEST_LOG_(INFO) << __FUNCTION__ << "(): Found vbmeta image with size "
                       << vbmeta_image_size;
      if (vbmeta_image_size < sizeof(AvbVBMetaImageHeader)) {
        GTEST_LOG_(ERROR) << __FUNCTION__
                          << "(): Impossible-sized vbmeta image: "
                          << vbmeta_image_size;
        return {};
      }

      if (vbmeta_image_size > remaining_bytes) {
        GTEST_LOG_(ERROR)
            << __FUNCTION__
            << "(): Premature EOF when parsing GKI boot signature.";
        return {};
      }

      vbmeta_images.emplace_back(buffer, vbmeta_image_size, "boot_signature");
      buffer += vbmeta_image_size;
      remaining_bytes -= vbmeta_image_size;
    }
    return vbmeta_images;
  }

  virtual ~GkiBootImage() = default;

 private:
  std::vector<uint8_t> data_;
};

class GkiBootImageV2 : public GkiBootImage {
 public:
  GkiBootImageV2(const uint8_t *data, size_t size) : GkiBootImage(data, size) {}

  const boot_img_hdr_v2 *boot_header() const {
    return reinterpret_cast<const boot_img_hdr_v2 *>(data());
  }

  uint32_t page_size() const override { return boot_header()->page_size; }

  uint32_t kernel_size() const override { return boot_header()->kernel_size; }

  uint32_t ramdisk_size() const override { return boot_header()->ramdisk_size; }

  uint32_t signature_size() const override {
    // Boot v2 header doesn't tell us the size of boot signature, so we just
    // let GkiBootImage::GetBootSignatures() method heuristically carve out any
    // boot signature blobs if it can find any. The size we return here is only
    // a heuristic so we don't look too far.
    return 16_KiB;
  }

  uint32_t signature_offset() const override {
    const uint32_t second_pages = GetNumberOfPages(boot_header()->second_size);
    const uint32_t recovery_dtbo_pages =
        GetNumberOfPages(boot_header()->recovery_dtbo_size);
    const uint32_t dtb_pages = GetNumberOfPages(boot_header()->dtb_size);
    return ramdisk_offset() +
           (ramdisk_pages() + second_pages + recovery_dtbo_pages + dtb_pages) *
               page_size();
  }
};

class GkiBootImageV4 : public GkiBootImage {
 public:
  static constexpr uint32_t kPageSize = 4096;

  GkiBootImageV4(const uint8_t *data, size_t size) : GkiBootImage(data, size) {}

  const boot_img_hdr_v4 *boot_header() const {
    return reinterpret_cast<const boot_img_hdr_v4 *>(data());
  }

  uint32_t page_size() const override { return kPageSize; }

  uint32_t kernel_size() const override { return boot_header()->kernel_size; }

  uint32_t ramdisk_size() const override { return boot_header()->ramdisk_size; }

  uint32_t signature_size() const override {
    return boot_header()->signature_size;
  }

  uint32_t signature_offset() const override {
    return ramdisk_offset() + ramdisk_pages() * page_size();
  }
};

// As strange as it sounds we let V3 inherit V4 as they share mostly the same
// header format and image layout. The only difference is that V3 doesn't have
// the |signature_size| field, so we would have to improvise.
class GkiBootImageV3 : public GkiBootImageV4 {
 public:
  GkiBootImageV3(const uint8_t *data, size_t size)
      : GkiBootImageV4(data, size) {}

  uint32_t signature_size() const override {
    // boot_header() here is actually a |boot_img_hdr_v4*|.
    // If |signature_size| is non-zero then this is actually a boot v4 image
    // wearing a boot v3 camouflage, else use the same heuristic as boot v2.
    const uint32_t value = GkiBootImageV4::boot_header()->signature_size;
    return value ? value : 16_KiB;
  }
};

std::string GetAvbProperty(
    const std::string &name,
    const std::vector<android::fs_mgr::VBMetaData> &vbmeta_images) {
  const std::string prop_name = "com.android.build." + name;
  return android::fs_mgr::GetAvbPropertyDescriptor(prop_name, vbmeta_images);
}

std::unique_ptr<GkiBootImage> LoadAndVerifyGkiBootImage(
    const std::string &name,
    std::vector<android::fs_mgr::VBMetaData> *boot_signature_images) {
  const std::string block_device_path = GetBlockDevicePath(name);
  const std::string TAG = __FUNCTION__ + "("s + block_device_path + ")";
  SCOPED_TRACE(TAG);

  std::string block_device_data;
  if (!android::base::ReadFileToString(block_device_path, &block_device_data,
                                       /* follow_symlinks */ true)) {
    ADD_FAILURE() << "Failed to read '" << block_device_path
                  << "': " << strerror(errno);
    return nullptr;
  }
  if (block_device_data.size() <= 4096) {
    ADD_FAILURE() << "Size of '" << block_device_path
                  << "' is impossibly small: " << block_device_data.size();
    return nullptr;
  }

  if (block_device_data.substr(0, BOOT_MAGIC_SIZE) != BOOT_MAGIC) {
    ADD_FAILURE() << "Device has invalid boot magic: " << block_device_path;
    return nullptr;
  }

  std::unique_ptr<GkiBootImage> boot_image;
  const auto boot_header_version =
      GetBootHeaderVersion(block_device_data.data());
  if (boot_header_version == 4) {
    boot_image = std::make_unique<GkiBootImageV4>(
        reinterpret_cast<const uint8_t *>(block_device_data.data()),
        block_device_data.size());
  } else if (boot_header_version == 3) {
    boot_image = std::make_unique<GkiBootImageV3>(
        reinterpret_cast<const uint8_t *>(block_device_data.data()),
        block_device_data.size());
  } else if (boot_header_version == 2) {
    boot_image = std::make_unique<GkiBootImageV2>(
        reinterpret_cast<const uint8_t *>(block_device_data.data()),
        block_device_data.size());
  } else {
    ADD_FAILURE() << "Unexpected boot header version: " << boot_header_version;
    return nullptr;
  }

  *boot_signature_images = boot_image->GetBootSignatures();
  if (boot_signature_images->empty()) {
    ADD_FAILURE() << "Failed to load the boot signature.";
    return nullptr;
  }

  // Verify that the vbmeta images in boot_signature are certified.
  for (const auto &vbmeta_image : *boot_signature_images) {
    size_t pk_len;
    const uint8_t *pk_data;
    const auto vbmeta_verify_result = avb_vbmeta_image_verify(
        vbmeta_image.data(), vbmeta_image.size(), &pk_data, &pk_len);
    if (vbmeta_verify_result != AVB_VBMETA_VERIFY_RESULT_OK) {
      ADD_FAILURE() << "Failed to verify boot_signature: "
                    << avb_vbmeta_verify_result_to_string(vbmeta_verify_result);
      return nullptr;
    }
    const std::string out_public_key_data(
        reinterpret_cast<const char *>(pk_data), pk_len);
    if (out_public_key_data.empty()) {
      ADD_FAILURE() << "The GKI image descriptor is not signed.";
      continue;
    }
    if (!ValidatePublicKeyBlob(out_public_key_data)) {
      ADD_FAILURE()
          << "The GKI image descriptor is not signed by an official key.";
      continue;
    }
  }

  // Verify the AVB property descriptors in boot_signature matches property
  // descriptors in vbmeta footer.
  std::unique_ptr<android::fs_mgr::VBMetaData> vbmeta_footer =
      android::fs_mgr::LoadAndVerifyVbmetaByPath(
          block_device_path, name, /* expected_key_blob */ "",
          /* allow verification error */ true, /* rollback_protection */ false,
          /* is_chained_vbmeta */ false, /* out_public_key_data */ nullptr,
          /* out_verification_disabled */ nullptr,
          /* out_verify_result */ nullptr);
  if (!vbmeta_footer) {
    ADD_FAILURE() << "Failed to load vbmeta of: " << block_device_path;
  } else {
    std::vector<android::fs_mgr::VBMetaData> footer_image;
    footer_image.push_back(std::move(*vbmeta_footer));
    vbmeta_footer.reset();

    for (const auto &prop :
         {"boot.security_patch"s, "init_boot.security_patch"s}) {
      const auto expected_value = GetAvbProperty(prop, *boot_signature_images);
      if (!expected_value.empty()) {
        const auto value = GetAvbProperty(prop, footer_image);
        if (value != expected_value) {
          ADD_FAILURE()
              << "Boot signature and vbmeta footer property mismatch '" << prop
              << "': expect '" << expected_value << "', actual '" << value
              << "'.";
        }
      }
    }
  }

  GTEST_LOG_(INFO) << TAG << ": " + name + ".fingerprint: "
                   << GetAvbProperty(name + ".fingerprint",
                                     *boot_signature_images);
  GTEST_LOG_(INFO) << TAG << ": kernel size: " << boot_image->kernel_size()
                   << ", ramdisk size: " << boot_image->ramdisk_size()
                   << ", signature size: " << boot_image->signature_size();

  return boot_image;
}

// Verify image data integrity with an AVB hash descriptor.
void VerifyImageDescriptor(
    const std::vector<uint8_t> &image,
    const android::fs_mgr::FsAvbHashDescriptor &descriptor) {
  const std::string TAG = __FUNCTION__ + "("s + descriptor.partition_name + ")";
  SCOPED_TRACE(TAG);

  ASSERT_EQ(image.size(), descriptor.image_size);

  const std::string &salt_str = descriptor.salt;
  const std::string &expected_digest_str = descriptor.digest;

  const std::string hash_algorithm(
      reinterpret_cast<const char *>(descriptor.hash_algorithm));
  GTEST_LOG_(INFO) << TAG << ": hash_algorithm = " << hash_algorithm;

  std::unique_ptr<ShaHasher> hasher = CreateShaHasher(hash_algorithm);
  ASSERT_NE(nullptr, hasher);

  std::vector<uint8_t> salt, expected_digest, out_digest;

  ASSERT_TRUE(HexToBytes(salt_str, &salt))
      << "Invalid salt in descriptor: " << salt_str;
  ASSERT_TRUE(HexToBytes(expected_digest_str, &expected_digest))
      << "Invalid digest in descriptor: " << expected_digest_str;

  ASSERT_EQ(expected_digest.size(), hasher->GetDigestSize());
  out_digest.resize(hasher->GetDigestSize());

  ASSERT_TRUE(hasher->CalculateDigest(image.data(), image.size(), salt.data(),
                                      descriptor.salt_len, out_digest.data()))
      << "Unable to calculate image digest.";

  ASSERT_EQ(out_digest.size(), expected_digest.size())
      << "Calculated digest size does not match expected digest size.";

  ASSERT_EQ(out_digest, expected_digest)
      << "Calculated digest does not match expected digest.";
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
 protected:
  void SetUp() override {
    // Fetch device runtime information.
    runtime_info = android::vintf::VintfObject::GetRuntimeInfo();
    ASSERT_NE(nullptr, runtime_info);

    std::string error_msg;
    kernel_level =
        android::vintf::VintfObject::GetInstance()->getKernelLevel(&error_msg);
    ASSERT_NE(android::vintf::Level::UNSPECIFIED, kernel_level) << error_msg;

    product_first_api_level =
        android::base::GetIntProperty("ro.product.first_api_level", 0);
    ASSERT_NE(0, product_first_api_level)
        << "ro.product.first_api_level is undefined.";

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
  android::vintf::Level kernel_level;
  int product_first_api_level;
};

TEST_F(GkiComplianceTest, GkiComplianceV1) {
  if (product_first_api_level < __ANDROID_API_R__) {
    GTEST_SKIP() << "Exempt from GKI 1.0 test: ro.product.first_api_level ("
                 << product_first_api_level << ") < " << __ANDROID_API_R__;
  }
  /* Skip for devices if the kernel version is not 5.4. */
  if (runtime_info->kernelVersion().dropMinor() !=
      android::vintf::Version{5, 4}) {
    GTEST_SKIP() << "Exempt from GKI 1.0 test on kernel version: "
                 << runtime_info->kernelVersion();
  }

  /* load vbmeta struct from boot, verify struct integrity */
  std::string out_public_key_data;
  android::fs_mgr::VBMetaVerifyResult out_verify_result;
  const std::string boot_path = GetBlockDevicePath("boot");
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

  std::vector<android::fs_mgr::VBMetaData> boot_signature_images;
  std::unique_ptr<GkiBootImage> boot_image =
      LoadAndVerifyGkiBootImage("boot", &boot_signature_images);
  ASSERT_NE(nullptr, boot_image);
  ASSERT_EQ(4, GetBootHeaderVersion(boot_image->data()));
  ASSERT_EQ(1, boot_signature_images.size());

  std::unique_ptr<android::fs_mgr::FsAvbHashDescriptor> descriptor =
      android::fs_mgr::GetHashDescriptor("boot", boot_signature_images);
  ASSERT_NE(nullptr, descriptor)
      << "Failed to load hash descriptor from the boot signature";
  ASSERT_NO_FATAL_FAILURE(VerifyImageDescriptor(
      boot_image->Slice(0, boot_image->signature_offset()), *descriptor));
}

int main(int argc, char *argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  android::base::InitLogging(argv, android::base::StderrLogger);
  return RUN_ALL_TESTS();
}
