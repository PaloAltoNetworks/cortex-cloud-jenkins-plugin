package org.jenkinsci.plugins.cortexcloud.shared;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link Severity}: string parsing (including the
 * {@code "MODERATE"} alias and unknown/blank handling) and the ordering used by
 * plugin-side threshold gating.
 */
class SeverityTest {

    @Test
    void fromStringParsesKnownLevelsCaseInsensitively() {
        assertEquals(Severity.CRITICAL, Severity.fromString("critical"));
        assertEquals(Severity.CRITICAL, Severity.fromString("CRITICAL"));
        assertEquals(Severity.HIGH, Severity.fromString("High"));
        assertEquals(Severity.MEDIUM, Severity.fromString("medium"));
        assertEquals(Severity.LOW, Severity.fromString("  low  "));
    }

    @Test
    void moderateIsTreatedAsMedium() {
        assertEquals(Severity.MEDIUM, Severity.fromString("moderate"));
        assertEquals(Severity.MEDIUM, Severity.fromString("MODERATE"));
    }

    @Test
    void unknownBlankAndNullMapToNone() {
        assertEquals(Severity.NONE, Severity.fromString("informational"));
        assertEquals(Severity.NONE, Severity.fromString(""));
        assertEquals(Severity.NONE, Severity.fromString("   "));
        assertEquals(Severity.NONE, Severity.fromString(null));
    }

    @Test
    void meetsOrExceedsRespectsOrdering() {
        assertTrue(Severity.CRITICAL.meetsOrExceeds(Severity.HIGH));
        assertTrue(Severity.HIGH.meetsOrExceeds(Severity.HIGH));
        assertFalse(Severity.MEDIUM.meetsOrExceeds(Severity.HIGH));
        assertFalse(Severity.LOW.meetsOrExceeds(Severity.HIGH));
    }

    @Test
    void noneThresholdNeverBreaches() {
        assertFalse(Severity.CRITICAL.meetsOrExceeds(Severity.NONE));
        assertFalse(Severity.LOW.meetsOrExceeds(Severity.NONE));
        // A null threshold is also treated as "no gating".
        assertFalse(Severity.CRITICAL.meetsOrExceeds(null));
    }
}
