package org.jenkinsci.plugins.cortexcloud.scanner;

import java.io.Serializable;
import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;
import org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult;

/**
 * Result of running the Cortex CLI: the process exit code, the (best-effort)
 * parsed JSON result, and the captured raw output.
 *
 * Gating is driven by getExitCode() - 0 = pass, 1 = policy fail, anything else =
 * error - matching the legacy plugin's "pass/fail from the CLI" model.
 * getResult() may be null when the CLI does not emit JSON (e.g. CLI v0.31.0), in
 * which case the findings table is empty but gating still works.
 */
public class ScanOutcome implements Serializable {
    private static final long serialVersionUID = 1L;

    private final int exitCode;
    private final CortexScanResult result;
    private final String rawOutput;

    public ScanOutcome(int exitCode, CortexScanResult result, String rawOutput) {
        this.exitCode = exitCode;
        this.result = result;
        this.rawOutput = rawOutput == null ? "" : rawOutput;
    }

    public int getExitCode() {
        return exitCode;
    }

    /** @return the parsed result, or null if the CLI produced no parseable JSON. */
    public CortexScanResult getResult() {
        return result;
    }

    public String getRawOutput() {
        return rawOutput;
    }

    /** @return true when the scan passed policy (exit code 0). */
    public boolean isPass() {
        return exitCode == CortexConstants.EXIT_PASS;
    }

    /** @return true when the scan ran and explicitly failed policy (exit code 1). */
    public boolean isPolicyFailure() {
        return exitCode == CortexConstants.EXIT_FAIL;
    }

    /** @return true when the CLI errored out (bad args, license/service issue, etc.). */
    public boolean isError() {
        return exitCode != CortexConstants.EXIT_PASS && exitCode != CortexConstants.EXIT_FAIL;
    }
}
