package org.jenkinsci.plugins.cortexcloud.builder;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.TaskListener;
import java.util.Collections;
import java.util.List;
import org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult;
import org.jenkinsci.plugins.cortexcloud.shared.Severity;
import org.jenkinsci.plugins.cortexcloud.shared.Vulnerability;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for the plugin's core decision: whether a severity threshold
 * breach should fail the build ({@link ImageBuildScanner#evaluateThresholdBreach}).
 *
 * <p>These are deliberately harness-free — {@code evaluateThresholdBreach} is
 * package-private and takes only a {@link CortexScanResult}, a {@link Severity}
 * and a {@link TaskListener} — so the highest-value gating scenarios (findings
 * 01 and 02) are covered without a JenkinsRule.
 */
class ImageBuildScannerGatingTest {

    private static final String IMG = "myrepo/app:1.2.3";

    /** A scanner instance carrying the given failOnUnparseableResults setting. */
    private static ImageBuildScanner scanner(boolean failOnUnparseable) {
        ImageBuildScanner s = new ImageBuildScanner(IMG);
        s.setFailOnUnparseableResults(failOnUnparseable);
        return s;
    }

    private static Vulnerability vuln(String severity) {
        return Vulnerability.create().cve("CVE-0000-0001").severity(severity).type("Vulnerability");
    }

    private static Vulnerability compliance(String severity) {
        return Vulnerability.create().severity(severity).type("Compliance").title("Malware");
    }

    private static CortexScanResult resultWith(List<Vulnerability> vulns, List<Vulnerability> compliance) {
        return CortexScanResult.fromFindings(IMG, "sha256:abc", vulns, compliance, "", true);
    }

    // ---- Finding 01: fail closed when results can't be parsed -----------

    @Test
    void failsClosedWhenResultIsNullAndThresholdSet() {
        String breach = scanner(true).evaluateThresholdBreach(null, Severity.CRITICAL, IMG, TaskListener.NULL);
        assertNotNull(breach, "A configured threshold with no parseable findings must fail closed");
        assertTrue(breach.toLowerCase().contains("failing closed"));
    }

    @Test
    void fallsBackToExitCodeWhenFailOnUnparseableDisabled() {
        String breach = scanner(false).evaluateThresholdBreach(null, Severity.CRITICAL, IMG, TaskListener.NULL);
        assertNull(breach, "With failOnUnparseableResults=false, null results fall back to exit-code gating");
    }

    @Test
    void nullResultWithThresholdNoneNeverBreaches() {
        String breach = scanner(true).evaluateThresholdBreach(null, Severity.NONE, IMG, TaskListener.NULL);
        assertNull(breach, "Threshold NONE disables gating even when results are null");
    }

    // ---- Finding 02: compliance findings (malware / secrets) are gated ---

    @Test
    void malwareIsGatedAtThreshold() {
        CortexScanResult r = resultWith(Collections.emptyList(), Collections.singletonList(compliance("critical")));
        String breach = scanner(true).evaluateThresholdBreach(r, Severity.CRITICAL, IMG, TaskListener.NULL);
        assertNotNull(breach, "A critical compliance finding must breach a CRITICAL threshold");
    }

    @Test
    void secretBelowThresholdDoesNotBreach() {
        CortexScanResult r = resultWith(Collections.emptyList(), Collections.singletonList(compliance("low")));
        String breach = scanner(true).evaluateThresholdBreach(r, Severity.HIGH, IMG, TaskListener.NULL);
        assertNull(breach, "A low compliance finding must not breach a HIGH threshold");
    }

    // ---- Vulnerability threshold behaviour ------------------------------

    @Test
    void vulnerabilityAtThresholdBreaches() {
        CortexScanResult r = resultWith(Collections.singletonList(vuln("high")), Collections.emptyList());
        String breach = scanner(true).evaluateThresholdBreach(r, Severity.HIGH, IMG, TaskListener.NULL);
        assertNotNull(breach, "A HIGH vulnerability must breach a HIGH threshold");
    }

    @Test
    void vulnerabilityBelowThresholdPasses() {
        CortexScanResult r = resultWith(Collections.singletonList(vuln("low")), Collections.emptyList());
        String breach = scanner(true).evaluateThresholdBreach(r, Severity.HIGH, IMG, TaskListener.NULL);
        assertNull(breach, "A LOW vulnerability must not breach a HIGH threshold");
    }

    @Test
    void thresholdNoneDisablesGatingEvenWithCriticalFindings() {
        CortexScanResult r = resultWith(
                Collections.singletonList(vuln("critical")), Collections.singletonList(compliance("critical")));
        String breach = scanner(true).evaluateThresholdBreach(r, Severity.NONE, IMG, TaskListener.NULL);
        assertNull(breach, "Threshold NONE means the plugin performs no severity gating");
    }
}
