package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult;
import org.jenkinsci.plugins.cortexcloud.shared.Severity;
import org.jenkinsci.plugins.cortexcloud.shared.Vulnerability;
import org.junit.jupiter.api.Test;

/**
 * Tests {@link ScanOutputParser} against the real Cortex CLI v0.31.0 XDM JSON
 * schema captured from a live tenant scan of {@code alpine:3.2}.
 */
class ScanOutputParserXdmTest {

    /**
     * Trimmed but structurally faithful sample of the CLI's {@code --output-format
     * json} output: an intro block, then the main object with malware/secrets
     * (empty) and vulnerability findings at four severities. Note that
     * {@code distribution.total} is intentionally 0 to mirror the CLI's unreliable
     * counts — the parser must count findings, not trust distribution.
     */
    private static final String XDM_OUTPUT =
            "<SCAN_INTRO_START>{\"imageName\":\"alpine:3.2\",\"scanners\":[]}<SCAN_INTRO_END>\n"
                    + "{\"asset_name\":\"alpine:3.2\",\"image_id\":\"sha256:98f5\",\"analysis\":["
                    + "{\"type\":\"Malware\",\"distribution\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"total\":0},\"findings\":[]},"
                    + "{\"type\":\"Secrets\",\"distribution\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"total\":0},\"findings\":[]},"
                    + "{\"type\":\"Vulnerability\",\"distribution\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"total\":0},\"findings\":["
                    + finding("CVE-2022-48174", "critical", 9.8, "busybox", "1.23.2-r3", "fixed in 1.37.0")
                    + "," + finding("CVE-2021-42381", "high", 7.2, "busybox", "1.23.2-r3", "fixed in 1.33.2")
                    + "," + finding("CVE-2021-42376", "medium", 5.5, "busybox", "1.23.2-r3", "fixed in 1.34.0")
                    + "," + finding("CVE-2025-46394", "low", 3.3, "busybox", "1.23.2-r3", "")
                    + "]}"
                    + "]}";

    private static String finding(String cve, String severity, double cvss, String pkg, String version, String status) {
        return "{"
                + "\"xdm.finding.description\":\"CVE " + cve + " found in package " + pkg + "\","
                + "\"xdm.finding.normalized_fields\":{"
                + "\"xdm.software_package.id\":\"" + pkg + "\","
                + "\"xdm.software_package.version\":\"" + version + "\","
                + "\"xdm.vulnerability.cve_id\":\"" + cve + "\","
                + "\"xdm.vulnerability.cve_vendor_link\":\"https://nvd.nist.gov/vuln/detail/" + cve + "\","
                + "\"xdm.vulnerability.cvss_score\":" + cvss + ","
                + "\"xdm.vulnerability.fix_date\":1637010907,"
                + "\"xdm.vulnerability.severity\":\"" + severity + "\","
                + "\"xdm.vulnerability.status\":\"" + status + "\""
                + "}}";
    }

    @Test
    void parsesAllVulnerabilityFindings() {
        CortexScanResult r = ScanOutputParser.parse(XDM_OUTPUT);
        assertNotNull(r, "XDM output should parse");
        assertEquals(4, r.getVulnerabilityCount());
    }

    @Test
    void countsBySeverityFromFindingsNotDistribution() {
        CortexScanResult r = ScanOutputParser.parse(XDM_OUTPUT);
        assertEquals(1, r.countBySeverity("critical"));
        assertEquals(1, r.countBySeverity("high"));
        assertEquals(1, r.countBySeverity("medium"));
        assertEquals(1, r.countBySeverity("low"));
    }

    @Test
    void mapsFindingFieldsOntoVulnerability() {
        CortexScanResult r = ScanOutputParser.parse(XDM_OUTPUT);
        List<Vulnerability> vulns = r.getResults()[0].getEntityInfo().getVulnerabilities();
        Vulnerability critical = null;
        for (Vulnerability v : vulns) {
            if ("CVE-2022-48174".equals(v.getCve())) {
                critical = v;
                break;
            }
        }
        assertNotNull(critical);
        assertEquals("critical", critical.getSeverity());
        assertEquals(9.8, critical.getCvss(), 0.001);
        assertEquals("busybox", critical.getPackageName());
        assertEquals("1.23.2-r3", critical.getPackageVersion());
        assertEquals("1.37.0", critical.getFixVersions());
        assertTrue(critical.getIsFixed());
        assertTrue(critical.getValidCve());
    }

    @Test
    void returnsResultEvenWithZeroFindings() {
        String clean = "<SCAN_INTRO_START>{}<SCAN_INTRO_END>\n"
                + "{\"asset_name\":\"hello-world:latest\",\"image_id\":\"sha256:abc\",\"analysis\":["
                + "{\"type\":\"Vulnerability\",\"findings\":[]}]}";
        CortexScanResult r = ScanOutputParser.parse(clean);
        assertNotNull(r);
        assertEquals(0, r.getVulnerabilityCount());
    }

    @Test
    void returnsNullForNonJsonOutput() {
        assertNull(ScanOutputParser.parse("Scanning...\nno JSON here"));
        assertNull(ScanOutputParser.parse(""));
        assertNull(ScanOutputParser.parse(null));
    }

    @Test
    void returnsNullForJsonWithoutAnalysisBlock() {
        // Valid JSON, but not the XDM shape the parser understands.
        assertNull(ScanOutputParser.parse("{\"asset_name\":\"x\",\"unexpected\":true}"));
    }

    @Test
    void toleratesMalformedJsonAfterIntroBlock() {
        // The intro is stripped, then the remaining text is not parseable JSON.
        String output = "<SCAN_INTRO_START>{}<SCAN_INTRO_END>\n{ this is not valid json";
        assertNull(ScanOutputParser.parse(output));
    }

    @Test
    void skipsAnalysisEntryWhoseFindingsAreNotAnArray() {
        // "findings" is an object, not an array → that analysis entry is skipped
        // rather than throwing; the overall parse still succeeds with 0 findings.
        String output = "{\"asset_name\":\"x\",\"analysis\":["
                + "{\"type\":\"Vulnerability\",\"findings\":{\"not\":\"an array\"}}]}";
        CortexScanResult r = ScanOutputParser.parse(output);
        assertNotNull(r);
        assertEquals(0, r.getVulnerabilityCount());
    }

    @Test
    void mapsFindingMissingNormalizedFieldsWithoutThrowing() {
        // A finding object with no xdm.finding.normalized_fields still maps to a
        // (mostly empty) Vulnerability rather than crashing the parser.
        String output = "{\"asset_name\":\"x\",\"analysis\":["
                + "{\"type\":\"Vulnerability\",\"findings\":[{\"xdm.finding.description\":\"d\"}]}]}";
        CortexScanResult r = ScanOutputParser.parse(output);
        assertNotNull(r);
        assertEquals(1, r.getVulnerabilityCount());
        Vulnerability v = r.getResults()[0].getEntityInfo().getVulnerabilities().get(0);
        assertEquals("", v.getCve());
        assertEquals("d", v.getDescription());
    }

    @Test
    void parsesLegacyDataPrefixedLine() {
        // The legacy "=====DATA" prefixed line path is still tolerated.
        String output = "some preamble\n"
                + ScanOutputParser.DATA_PREFIX
                + " {\"asset_name\":\"x\",\"analysis\":["
                + "{\"type\":\"Vulnerability\",\"findings\":[]}]}\n";
        CortexScanResult r = ScanOutputParser.parse(output);
        assertNotNull(r);
        assertEquals(0, r.getVulnerabilityCount());
    }

    @Test
    void complianceFindingsAreParsedAndCounted() {
        // Malware + Secrets findings must land in the compliance list and be
        // included in the severity counts (finding 02), not silently dropped.
        String output = "{\"asset_name\":\"x\",\"image_id\":\"sha256:abc\",\"analysis\":["
                + "{\"type\":\"Malware\",\"findings\":["
                + finding("", "critical", 0.0, "layer", "1", "")
                + "]},"
                + "{\"type\":\"Secrets\",\"findings\":["
                + finding("", "high", 0.0, "config", "1", "")
                + "]},"
                + "{\"type\":\"Vulnerability\",\"findings\":["
                + finding("CVE-2022-48174", "critical", 9.8, "busybox", "1.23.2-r3", "")
                + "]}"
                + "]}";
        CortexScanResult r = ScanOutputParser.parse(output);
        assertNotNull(r);
        List<Vulnerability> compliance = r.getResults()[0].getEntityInfo().getComplianceIssues();
        assertEquals(2, compliance.size(), "malware + secrets findings should be in the compliance list");
        // getVulnerabilityCount + countBySeverity include compliance findings.
        assertEquals(3, r.getVulnerabilityCount(), "count should include vulnerabilities + compliance");
        assertEquals(2, r.countBySeverity("critical"), "critical vuln + critical malware");
        assertEquals(1, r.countBySeverity("high"), "high secret");
    }

    @Test
    void severityThresholdGating() {
        // High threshold: critical + high both breach (2), medium/low do not.
        assertTrue(Severity.fromString("critical").meetsOrExceeds(Severity.HIGH));
        assertTrue(Severity.fromString("high").meetsOrExceeds(Severity.HIGH));
        assertFalse(Severity.fromString("medium").meetsOrExceeds(Severity.HIGH));
        assertFalse(Severity.fromString("low").meetsOrExceeds(Severity.HIGH));
        // NONE threshold never breaches.
        assertFalse(Severity.fromString("critical").meetsOrExceeds(Severity.NONE));
    }
}
