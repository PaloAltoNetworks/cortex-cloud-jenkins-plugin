package org.jenkinsci.plugins.cortexcloud.shared;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CortexScanResult}: severity counting and the
 * threshold-breach counting that drives plugin-side gating.
 *
 * <p>The build step ({@code ImageBuildScanner.evaluateThresholdBreach}) fails a
 * build when at least one parsed finding {@link Severity#meetsOrExceeds} the
 * configured threshold. That method is private; this test exercises the same
 * counting over the public {@link CortexScanResult} view model so the gating
 * arithmetic is covered directly.</p>
 */
class CortexScanResultTest {

    private static Vulnerability vuln(String cve, String severity) {
        return Vulnerability.create().cve(cve).severity(severity);
    }

    private static CortexScanResult sampleResult() {
        List<Vulnerability> vulns = Arrays.asList(
                vuln("CVE-1", "critical"),
                vuln("CVE-2", "high"),
                vuln("CVE-3", "high"),
                vuln("CVE-4", "medium"),
                vuln("CVE-5", "low"));
        return CortexScanResult.fromFindings("myrepo/app:1.0", "sha256:abc", vulns, Collections.emptyList(), "", true);
    }

    @Test
    void countsBySeverityCaseInsensitively() {
        CortexScanResult r = sampleResult();
        assertEquals(1, r.countBySeverity("critical"));
        assertEquals(2, r.countBySeverity("HIGH"));
        assertEquals(1, r.countBySeverity("Medium"));
        assertEquals(1, r.countBySeverity("low"));
        assertEquals(5, r.getVulnerabilityCount());
    }

    @Test
    void countBySeverityIsNullSafe() {
        assertEquals(0, sampleResult().countBySeverity(null));
    }

    @Test
    void highThresholdCountsCriticalAndHighFindings() {
        // Mirrors the gating in ImageBuildScanner.evaluateThresholdBreach:
        // count findings whose severity meets or exceeds the threshold.
        CortexScanResult r = sampleResult();
        int offending = 0;
        for (CortexScanResult.Result res : r.getResults()) {
            if (res.getEntityInfo() == null) {
                continue;
            }
            for (Vulnerability v : res.getEntityInfo().getVulnerabilities()) {
                if (Severity.fromString(v.getSeverity()).meetsOrExceeds(Severity.HIGH)) {
                    offending++;
                }
            }
        }
        // 1 critical + 2 high = 3; medium/low excluded.
        assertEquals(3, offending);
    }

    @Test
    void emptyResultHasNoFindingsAndPasses() {
        CortexScanResult r = CortexScanResult.fromFindings(
                "hello-world:latest", "sha256:x", Collections.emptyList(), Collections.emptyList(), "", true);
        assertEquals(0, r.getVulnerabilityCount());
        assertTrue(r.isPass());
    }
}
