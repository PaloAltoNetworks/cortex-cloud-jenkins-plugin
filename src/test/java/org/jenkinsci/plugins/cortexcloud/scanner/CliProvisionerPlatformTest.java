package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for CliProvisioner.normalizeOs / normalizeArch.
 *
 * Regression guard for the ordering bug where the substring "win" inside
 * "darwin" caused macOS agents to be classified as Windows (and then handed a
 * .exe binary name). macOS must be resolved before Windows.
 */
class CliProvisionerPlatformTest {

    @Test
    void macOsNameMapsToDarwin() {
        assertEquals(CortexConstants.OS_DARWIN, CliProvisioner.normalizeOs("Mac OS X"));
    }

    @Test
    void darwinNameMapsToDarwinNotWindows() {
        assertEquals(CortexConstants.OS_DARWIN, CliProvisioner.normalizeOs("darwin"));
    }

    @Test
    void windowsNameMapsToWindows() {
        assertEquals(CortexConstants.OS_WINDOWS, CliProvisioner.normalizeOs("Windows Server 2019"));
    }

    @Test
    void otherNamesMapToLinux() {
        assertEquals(CortexConstants.OS_LINUX, CliProvisioner.normalizeOs("Linux"));
    }

    @Test
    void blankOrNullNameMapsToLinux() {
        assertEquals(CortexConstants.OS_LINUX, CliProvisioner.normalizeOs(""));
        assertEquals(CortexConstants.OS_LINUX, CliProvisioner.normalizeOs(null));
    }

    @Test
    void aarch64AndArm64MapToArm64() {
        assertEquals(CortexConstants.ARCH_ARM64, CliProvisioner.normalizeArch("aarch64"));
        assertEquals(CortexConstants.ARCH_ARM64, CliProvisioner.normalizeArch("arm64"));
    }

    @Test
    void otherArchMapsToAmd64() {
        assertEquals(CortexConstants.ARCH_AMD64, CliProvisioner.normalizeArch("x86_64"));
        assertEquals(CortexConstants.ARCH_AMD64, CliProvisioner.normalizeArch("amd64"));
    }

    @Test
    void blankOrNullArchMapsToAmd64() {
        assertEquals(CortexConstants.ARCH_AMD64, CliProvisioner.normalizeArch(""));
        assertEquals(CortexConstants.ARCH_AMD64, CliProvisioner.normalizeArch(null));
    }
}
