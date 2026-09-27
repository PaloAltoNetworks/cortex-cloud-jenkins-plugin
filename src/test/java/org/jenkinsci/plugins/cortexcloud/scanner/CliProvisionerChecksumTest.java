package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CliProvisioner#algorithmForHexLength(String)}.
 *
 * <p>Regression guard for the real-tenant bug where the download-link
 * {@code checksum} is an MD5 (32 hex chars) but the verifier assumed SHA-256
 * (64 hex chars), causing every CLI download to fail integrity verification.</p>
 */
class CliProvisionerChecksumTest {

    @Test
    void md5LengthMapsToMd5() {
        // 32 hex chars — the value the live tenant actually returns.
        assertEquals("MD5", CliProvisioner.algorithmForHexLength("e747cc5c94973f1288c7cf4c7b84a384"));
    }

    @Test
    void sha1LengthMapsToSha1() {
        // 40 hex chars.
        assertEquals("SHA-1", CliProvisioner.algorithmForHexLength("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    @Test
    void sha256LengthMapsToSha256() {
        // 64 hex chars.
        assertEquals(
                "SHA-256",
                CliProvisioner.algorithmForHexLength(
                        "fc366dba3dbe21a345f5f7e9454c9a4417ba551ea148c767c30be971df8a4f2c"));
    }

    @Test
    void whitespaceIsTrimmedBeforeLengthCheck() {
        assertEquals("MD5", CliProvisioner.algorithmForHexLength("  e747cc5c94973f1288c7cf4c7b84a384\n"));
    }

    @Test
    void unrecognizedLengthReturnsNull() {
        assertNull(CliProvisioner.algorithmForHexLength("deadbeef"));
    }

    @Test
    void nullReturnsNull() {
        assertNull(CliProvisioner.algorithmForHexLength(null));
    }
}
