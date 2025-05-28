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
    private CompatibilityBuildHelper mBuildHelper;

    @Before
    public final void setUp() throws DeviceNotAvailableException, IOException {
        ITestDevice device = getDevice();
        final long gblVersion = device.getIntProperty("ro.boot.gbl.version", -1L);
        assumeThat("GBL version prop", gblVersion, not(-1L));

        mTempDir = FileUtil.createTempDir("VtsGblHostTest");
        mBuildHelper = new CompatibilityBuildHelper(getBuild());
    }

    @After
    public final void tearDown() {
        FileUtil.recursiveDelete(mTempDir);
    }

    private CommandResult logCommandResult(final String name, final CommandResult result) {
        CLog.i("Result of command: %s", name);
        CLog.i("Status: %s", result.getStatus());
        CLog.i("Exit code: %s", result.getExitCode());
        CLog.i("Stdout: %s", result.getStdout());
        CLog.i("Stderr: %s", result.getStderr());
        return result;
    }

    @Test
    public void testSystemProperties() throws DeviceNotAvailableException, NumberFormatException {
        ITestDevice device = getDevice();
        final long gblVersion = device.getIntProperty("ro.boot.gbl.version", -1);
        final String gblBuildNumber = device.getProperty("ro.boot.gbl.build_number");

        CLog.i("GBL version: %s", gblVersion);
        CLog.i("GBL build_number: %s", gblBuildNumber);

        assertNotNull(gblBuildNumber);

        if (gblBuildNumber.startsWith("eng.")) {
            CLog.w("GBL is a local eng build");
        }

        assertThat("Invalid build ID", gblBuildNumber, matchesPattern("P?[0-9]+"));

        if (gblBuildNumber.startsWith("P")) {
            CLog.i("Skipping rest of test because GBL is presubmit build");
            return;
        }
    }

    @Test
    public void testCertificate() throws DeviceNotAvailableException, IOException {
        ITestDevice device = getDevice();
        File bootEfi = new File(mTempDir, "boot.efi");
        assertTrue("Pull efisp partition", device.pullFile("/dev/block/by-name/efisp", bootEfi));

        File gblsigntool = mBuildHelper.getTestFile("gblsigntool");
        File gblPublicKey = new File(mBuildHelper.getTestFile("gbl"), "202504/gbl_key_pub.pem");

        CommandResult result = logCommandResult("gblsigntool info",
                new RunUtil().runTimedCmd(
                        5000, gblsigntool.getAbsolutePath(), "info", bootEfi.getAbsolutePath()));
        assertEquals("gblsigntool info command", CommandStatus.SUCCESS, result.getStatus());

        result = logCommandResult("gblsigntool verify",
                new RunUtil().runTimedCmd(5000, gblsigntool.getAbsolutePath(), "verify",
                        bootEfi.getAbsolutePath(), "--key", gblPublicKey.getAbsolutePath()));
        assertEquals("gblsigntool verify command", CommandStatus.SUCCESS, result.getStatus());
    }
}
