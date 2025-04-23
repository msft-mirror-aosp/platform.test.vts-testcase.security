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

package com.android.test.gbl;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeThat;

import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import com.android.tradefed.util.FileUtil;
import com.android.tradefed.util.RunUtil;
import java.io.File;
import java.io.IOException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class VtsGblHostTest extends BaseHostJUnit4Test {
    private File mTempDir;

    @Before
    public final void setUp() throws DeviceNotAvailableException, IOException {
        ITestDevice device = getDevice();
        final long gblVersion = device.getIntProperty("ro.boot.gbl.version", -1L);
        assumeThat("GBL version prop", gblVersion, not(-1L));

        mTempDir = FileUtil.createTempDir("VtsGblHostTest");
    }

    @After
    public final void tearDown() {
        FileUtil.recursiveDelete(mTempDir);
    }

    @Test
    public void testSystemProperties() throws DeviceNotAvailableException, NumberFormatException {
        ITestDevice device = getDevice();
        final long gblVersion = device.getIntProperty("ro.boot.gbl.version", -1);
        final String gblBuildNumber = device.getProperty("ro.boot.gbl.build_number");

        CLog.i("GBL version: " + gblVersion);
        CLog.i("GBL build_number: " + gblBuildNumber);

        assertNotNull(gblBuildNumber);

        if (gblBuildNumber.startsWith("eng.")) {
            CLog.w("GBL is a local eng build");
        }

        assertThat("Invalid build ID", gblBuildNumber, matchesPattern("P?[0-9]+"));

        if (gblBuildNumber.startsWith("P")) {
            CLog.i("Skipping rest of test because GBL is presubmit build");
            return;
        }
        final long gblBuildIncremental = Long.parseLong(gblBuildNumber);
    }

    @Test
    public void testCertificate() throws DeviceNotAvailableException, IOException {
        ITestDevice device = getDevice();
        File android_esp = new File(mTempDir, "android_esp");
        assertTrue("Fetch android_esp partition",
                device.pullFile("/dev/block/by-name/android_esp", android_esp));

        CompatibilityBuildHelper buildHelper = new CompatibilityBuildHelper(getBuild());
        File mtools = buildHelper.getTestFile("mtools");
        File boot_efi = new File(mTempDir, "boot.efi");
        boolean found_efi = false;
        for (String efi_name : new String[] {"::/EFI/BOOT/BOOTAA64.EFI", "::/EFI/BOOT/BOOTX64.EFI",
                     "::/EFI/BOOT/BOOTIA32.EFI"}) {
            boot_efi.delete();
            CommandResult result = new RunUtil().runTimedCmd(3000, mtools.getAbsolutePath(), "-c",
                    "mcopy", "-i", android_esp.getAbsolutePath(),
                    "-n", // Don't complain about overwrite
                    efi_name, boot_efi.getAbsolutePath());
            if (CommandStatus.SUCCESS.equals(result.getStatus())) {
                CLog.i("Found EFI application: " + efi_name);
                found_efi = true;
                break;
            }
        }
        assertTrue("Found EFI application", found_efi);

        // FIXME(b/387241522): Check public key hash.
        File gblsigntool = buildHelper.getTestFile("gblsigntool");
        CommandResult result = new RunUtil().runTimedCmd(
                5000, gblsigntool.getAbsolutePath(), "verify", boot_efi.getAbsolutePath());
        CLog.i("gblsigntool stdout: " + result.getStdout());
        assertEquals("gblsigntool stderr: " + result.getStderr(), CommandStatus.SUCCESS,
                result.getStatus());
    }
}
