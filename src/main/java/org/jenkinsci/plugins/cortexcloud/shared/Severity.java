package org.jenkinsci.plugins.cortexcloud.shared;

import java.util.Locale;

/**
 * Ordered vulnerability severity levels, used for plugin-side gating.
 *
 * Rationale: the Cortex CLI (v0.31.0, verified on a live tenant) returns exit
 * code 0 even for images with Critical CVEs - pass/fail at the exit-code level is
 * a tenant-policy decision that this CLI version does not enforce. To let a
 * pipeline block on findings regardless of tenant policy, the plugin can apply a
 * severity threshold to the parsed findings.
 *
 * Ordinal order is significant: higher ordinal == more severe. NONE disables
 * threshold gating.
 */
public enum Severity {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /**
     * Parses a CLI severity string (e.g. "high", "CRITICAL") into a Severity.
     * Unknown or blank values map to NONE.
     */
    public static Severity fromString(String value) {
        if (value == null) {
            return NONE;
        }
        switch (value.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL":
                return CRITICAL;
            case "HIGH":
                return HIGH;
            case "MEDIUM":
            case "MODERATE":
                return MEDIUM;
            case "LOW":
                return LOW;
            default:
                return NONE;
        }
    }

    /** @return true when this severity is at least as severe as threshold. */
    public boolean meetsOrExceeds(Severity threshold) {
        if (threshold == null || threshold == NONE) {
            return false;
        }
        return this.ordinal() >= threshold.ordinal();
    }
}
