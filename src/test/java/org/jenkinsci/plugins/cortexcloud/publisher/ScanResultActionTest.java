package org.jenkinsci.plugins.cortexcloud.publisher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ScanResultAction}: the human-readable status label must
 * distinguish a pass, a plugin-side severity failure (CLI exit 0 but threshold
 * breached), a tenant-policy failure (exit 1), and any other error.
 */
class ScanResultActionTest {

    private static ScanResultAction action(int exitCode, boolean passed) {
        return new ScanResultAction("myrepo/app:1.0", exitCode, passed, null, "");
    }

    @Test
    void passedLabel() {
        ScanResultAction a = action(0, true);
        assertTrue(a.isPassed());
        assertEquals("PASSED", a.getStatusLabel());
    }

    @Test
    void severityFailureLabelWhenExitZeroButNotPassed() {
        // CLI passed (exit 0) but the plugin failed the build on a severity threshold.
        ScanResultAction a = action(0, false);
        assertFalse(a.isPassed());
        assertEquals("FAILED (severity)", a.getStatusLabel());
    }

    @Test
    void policyFailureLabelForExitOne() {
        ScanResultAction a = action(1, false);
        assertEquals("FAILED (policy)", a.getStatusLabel());
    }

    @Test
    void errorLabelForOtherExitCodes() {
        assertEquals("ERROR", action(2, false).getStatusLabel());
        assertEquals("ERROR", action(137, false).getStatusLabel());
    }

    @Test
    void safeDefaultsWhenNoParsedResult() {
        ScanResultAction a = action(0, true);
        assertFalse(a.hasResult());
        assertEquals(0, a.getVulnerabilityCount());
        assertEquals(0, a.getComplianceIssueCount());
        assertEquals("", a.getConsoleUrl());
    }
}
