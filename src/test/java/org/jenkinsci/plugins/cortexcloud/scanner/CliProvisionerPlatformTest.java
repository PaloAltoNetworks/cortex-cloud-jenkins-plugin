package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for CliProvisioner.normalizeOs / normalizeArch.
 *
 * Regression guard for the ordering bug where the substring "win" inside
 * "darwin" caused macOS agents to be classified as Windows (and then handed a
 * .exe binary name). macOS must be resolved before Windows.
 * Also verifies fail-fast behaviour on unsupported platforms.
 */
class CliProvisionerPlatformTest {

    @Test
    void macOsNameMapsToDarwin() throws Exception {
        assertEquals(CortexConstants.OS_DARWIN, CliProvisioner.normalizeOs("Mac OS X"));
    }

    @Test
    void darwinNameMapsToDarwinNotWindows() throws Exception {
        assertEquals(CortexConstants.OS_DARWIN, CliProvisioner.normalizeOs("darwin"));
    }

    @Test
    void windowsNameMapsToWindows() throws Exception {
        assertEquals(CortexConstants.OS_WINDOWS, CliProvisioner.normalizeOs("Windows Server 2019"));
    }

    @Test
    void linuxNameMapsToLinux() throws Exception {
        assertEquals(CortexConstants.OS_LINUX, CliProvisioner.normalizeOs("Linux"));
    }

    @Test
    void unsupportedOsThrows() {
        IOException ex = assertThrows(IOException.class, () -> CliProvisioner.normalizeOs("SunOS"));
        assertTrue(ex.getMessage().contains("SunOS"));
        assertTrue(ex.getMessage().contains("linux, darwin and windows"));
    }

    @Test
    void blankOrNullNameThrows() {
        assertThrows(IOException.class, () -> CliProvisioner.normalizeOs(""));
        assertThrows(IOException.class, () -> CliProvisioner.normalizeOs(null));
    }

    @Test
    void aarch64AndArm64MapToArm64() throws Exception {
        assertEquals(CortexConstants.ARCH_ARM64, CliProvisioner.normalizeArch("aarch64"));
        assertEquals(CortexConstants.ARCH_ARM64, CliProvisioner.normalizeArch("arm64"));
    }

    @Test
    void x86_64AndAmd64MapToAmd64() throws Exception {
        assertEquals(CortexConstants.ARCH_AMD64, CliProvisioner.normalizeArch("x86_64"));
        assertEquals(CortexConstants.ARCH_AMD64, CliProvisioner.normalizeArch("amd64"));
    }

    @Test
    void unsupportedArchThrows() {
        IOException ex1 = assertThrows(IOException.class, () -> CliProvisioner.normalizeArch("ppc64le"));
        assertTrue(ex1.getMessage().contains("ppc64le"));
        assertTrue(ex1.getMessage().contains("amd64 and arm64"));

        IOException ex2 = assertThrows(IOException.class, () -> CliProvisioner.normalizeArch("s390x"));
        assertTrue(ex2.getMessage().contains("s390x"));
        assertTrue(ex2.getMessage().contains("amd64 and arm64"));
    }

    @Test
    void blankOrNullArchThrows() {
        assertThrows(IOException.class, () -> CliProvisioner.normalizeArch(""));
        assertThrows(IOException.class, () -> CliProvisioner.normalizeArch(null));
    }
}
