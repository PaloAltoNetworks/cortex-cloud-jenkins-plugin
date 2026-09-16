package org.jenkinsci.plugins.cortexcloud.publisher;

import hudson.model.Run;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import jenkins.model.RunAction2;
import org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult;
import org.jenkinsci.plugins.cortexcloud.shared.Vulnerability;

/**
 * Per-build action that surfaces a Cortex image-scan result.
 *
 * This is the Cortex equivalent of the legacy plugin's results action: it is
 * attached to the Run, contributes a left-nav link and a build-summary box
 * (rendered by summary.jelly / index.jelly), and exposes the parsed findings to
 * those views.
 *
 * Gating already happened during the build step (driven by the CLI exit code);
 * this action is purely for reporting. When the CLI produced no JSON, the
 * findings tables are empty but the pass/fail badge and exit code are still shown.
 */
public class ScanResultAction implements RunAction2, Serializable {

    private static final long serialVersionUID = 1L;

    private static final String DISPLAY_NAME = "Cortex Cloud Scan";

    private transient Run<?, ?> run;

    private final String scanTarget;
    private final int exitCode;
    private final boolean passed;
    private final CortexScanResult result;
    private final String rawOutput;

    public ScanResultAction(
            String scanTarget, int exitCode, boolean passed, CortexScanResult result, String rawOutput) {
        this.scanTarget = scanTarget;
        this.exitCode = exitCode;
        this.passed = passed;
        this.result = result;
        this.rawOutput = rawOutput == null ? "" : rawOutput;
    }

    // ---- RunAction2 contract ----

    @Override
    public void onAttached(Run<?, ?> r) {
        this.run = r;
    }

    @Override
    public void onLoad(Run<?, ?> r) {
        this.run = r;
    }

    /** @return the build this action belongs to (used by the result view). */
    public Run<?, ?> getRun() {
        return run;
    }

    // ---- Action contract ----

    @Override
    public String getIconFileName() {
        // Core-provided icon path (served by Jenkins on all baselines); avoids a
        // hard dependency on the ionicons-api plugin or a custom icon asset.
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return DISPLAY_NAME;
    }

    @Override
    public String getUrlName() {
        return "cortexCloudScan";
    }

    // ---- View accessors ----

    public String getScanTarget() {
        return scanTarget == null ? "" : scanTarget;
    }

    public int getExitCode() {
        return exitCode;
    }

    public boolean isPassed() {
        return passed;
    }

    public String getStatusLabel() {
        if (passed) {
            return "PASSED";
        }
        if (exitCode == 0) {
            // CLI passed but the plugin failed the build on a severity threshold.
            return "FAILED (severity)";
        }
        return exitCode == 1 ? "FAILED (policy)" : "ERROR";
    }

    public boolean hasResult() {
        return result != null && result.getResults().length > 0;
    }

    public String getConsoleUrl() {
        return result == null ? "" : result.getConsoleUrl();
    }

    /** Flattened list of vulnerability findings across all scanned entities. */
    public List<Vulnerability> getVulnerabilities() {
        List<Vulnerability> all = new ArrayList<>();
        if (result != null) {
            for (CortexScanResult.Result r : result.getResults()) {
                if (r.getEntityInfo() != null) {
                    all.addAll(r.getEntityInfo().getVulnerabilities());
                }
            }
        }
        return all;
    }

    /** Flattened list of compliance findings across all scanned entities. */
    public List<Vulnerability> getComplianceIssues() {
        List<Vulnerability> all = new ArrayList<>();
        if (result != null) {
            for (CortexScanResult.Result r : result.getResults()) {
                if (r.getEntityInfo() != null) {
                    all.addAll(r.getEntityInfo().getComplianceIssues());
                }
            }
        }
        return all;
    }

    public int getVulnerabilityCount() {
        return getVulnerabilities().size();
    }

    private int countBySeverity(String severity) {
        return result == null ? 0 : result.countBySeverity(severity);
    }

    public int getCriticalCount() {
        return countBySeverity("critical");
    }

    public int getHighCount() {
        return countBySeverity("high");
    }

    public int getMediumCount() {
        return countBySeverity("medium");
    }

    public int getLowCount() {
        return countBySeverity("low");
    }

    public int getComplianceIssueCount() {
        return getComplianceIssues().size();
    }

    public String getRawOutput() {
        return rawOutput;
    }
}
