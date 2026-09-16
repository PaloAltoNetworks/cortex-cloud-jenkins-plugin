package org.jenkinsci.plugins.cortexcloud.shared;

import com.google.gson.annotations.SerializedName;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Parsed result of a Cortex CLI "image scan --output-format json" invocation.
 *
 * Structure mirrors the legacy plugin's CLIScanResult so the result UI ports
 * cleanly. Gson SerializedName aliases keep deserialization tolerant of the exact
 * CLI JSON key names; the precise mapping is finalized once a real payload is
 * captured from a newer CLI release. Until then, gating relies on the CLI exit
 * code and this model populates whatever fields are present.
 */
public class CortexScanResult implements Serializable {
    private static final long serialVersionUID = 1L;

    @SerializedName(
            value = "results",
            alternate = {"Results", "scanResults"})
    private Result[] results;

    @SerializedName(
            value = "consoleURL",
            alternate = {"consoleUrl", "platformURL", "platformUrl", "link"})
    private String consoleUrl;

    public CortexScanResult() {
        // for Gson
    }

    public CortexScanResult(Result[] results, String consoleUrl) {
        this.results = results;
        this.consoleUrl = consoleUrl;
    }

    /**
     * Builds a result from findings already mapped out of the Cortex CLI's XDM
     * JSON (see ScanOutputParser). Wraps them in a single Result / EntityInfo so
     * the existing result views render unchanged.
     *
     * @param imageName    scanned image reference (from asset_name)
     * @param imageId      image config digest (from image_id)
     * @param vulns        vulnerability findings
     * @param compliance   compliance findings (malware / secrets / config)
     * @param consoleUrl   optional deep link into the Cortex console
     * @param pass         whether the scan is considered passing
     */
    public static CortexScanResult fromFindings(
            String imageName,
            String imageId,
            List<Vulnerability> vulns,
            List<Vulnerability> compliance,
            String consoleUrl,
            boolean pass) {
        Result.EntityInfo info = new Result.EntityInfo();
        info.id = imageId;
        info.vulnerabilities = vulns == null ? new ArrayList<Vulnerability>() : new ArrayList<>(vulns);
        info.complianceIssues = compliance == null ? new ArrayList<Vulnerability>() : new ArrayList<>(compliance);
        info.repoTag = imageName == null ? null : new RepoTag("", imageName, "");
        Result result = new Result(info, pass, "");
        return new CortexScanResult(new Result[] {result}, consoleUrl);
    }

    public Result[] getResults() {
        return results == null ? new Result[0] : results;
    }

    /**
     * @return total number of findings across all entities, counting both
     * vulnerabilities and compliance findings (malware / secrets). Compliance
     * findings are included so the reported count matches what is actually gated.
     */
    public int getVulnerabilityCount() {
        int n = 0;
        for (Result r : getResults()) {
            if (r.getEntityInfo() != null) {
                n += r.getEntityInfo().getVulnerabilities().size();
                n += r.getEntityInfo().getComplianceIssues().size();
            }
        }
        return n;
    }

    /**
     * @return count of findings whose severity matches {@code severity}
     * (case-insensitive), counting both vulnerabilities and compliance findings
     * (malware / secrets) so the printed summary matches the gating decision.
     */
    public int countBySeverity(String severity) {
        int n = 0;
        if (severity == null) {
            return 0;
        }
        for (Result r : getResults()) {
            if (r.getEntityInfo() == null) {
                continue;
            }
            for (Vulnerability v : r.getEntityInfo().getVulnerabilities()) {
                if (severity.equalsIgnoreCase(v.getSeverity())) {
                    n++;
                }
            }
            for (Vulnerability v : r.getEntityInfo().getComplianceIssues()) {
                if (severity.equalsIgnoreCase(v.getSeverity())) {
                    n++;
                }
            }
        }
        return n;
    }

    public String getConsoleUrl() {
        return consoleUrl == null ? "" : consoleUrl;
    }

    /** @return true when every result entity passed policy (used as a parser-side cross-check of the exit code). */
    public boolean isPass() {
        for (Result r : getResults()) {
            if (!r.getPass()) {
                return false;
            }
        }
        return true;
    }

    public static class Result implements Serializable {
        private static final long serialVersionUID = 11L;

        @SerializedName(
                value = "entityInfo",
                alternate = {"entity", "EntityInfo"})
        private EntityInfo entityInfo;

        @SerializedName(
                value = "pass",
                alternate = {"passed", "Pass"})
        private boolean pass;

        @SerializedName(
                value = "err",
                alternate = {"error", "Err"})
        private String err;

        public Result() {
            // for Gson
        }

        public Result(EntityInfo entityInfo, boolean pass, String err) {
            this.entityInfo = entityInfo;
            this.pass = pass;
            this.err = err;
        }

        public EntityInfo getEntityInfo() {
            return entityInfo;
        }

        public String getErr() {
            return err == null ? "" : err;
        }

        public boolean getPass() {
            return pass;
        }

        public static class EntityInfo implements Serializable {
            private static final long serialVersionUID = 1L;

            private String id;

            @SuppressFBWarnings(
                    value = "UWF_UNWRITTEN_FIELD",
                    justification = "Populated by Gson via reflection during JSON deserialization "
                            + "of the CLI's image-scan output")
            private Date scanTime;

            @SuppressFBWarnings(
                    value = "UWF_UNWRITTEN_FIELD",
                    justification = "Populated by Gson via reflection during JSON deserialization "
                            + "of the CLI's image-scan output")
            private String hostname;

            private RepoTag repoTag;

            @SerializedName(
                    value = "vulnerabilities",
                    alternate = {"vulns", "Vulnerabilities"})
            private ArrayList<Vulnerability> vulnerabilities;

            @SerializedName(
                    value = "complianceIssues",
                    alternate = {"compliance", "complianceVulnerabilities"})
            private ArrayList<Vulnerability> complianceIssues;

            @SuppressFBWarnings(
                    value = "UWF_UNWRITTEN_FIELD",
                    justification = "Populated by Gson via reflection during JSON deserialization "
                            + "of the CLI's image-scan output")
            private Date creationTime;

            @SuppressFBWarnings(
                    value = "UWF_UNWRITTEN_FIELD",
                    justification = "Populated by Gson via reflection during JSON deserialization "
                            + "of the CLI's image-scan output")
            private ScanType type;

            public String getId() {
                return id == null ? "" : id;
            }

            public Date getScanTime() {
                return scanTime;
            }

            public String getHostname() {
                return hostname == null ? "" : hostname;
            }

            public RepoTag getRepoTag() {
                return repoTag;
            }

            public List<Vulnerability> getVulnerabilities() {
                return vulnerabilities == null ? new ArrayList<Vulnerability>() : vulnerabilities;
            }

            public List<Vulnerability> getComplianceIssues() {
                return complianceIssues == null ? new ArrayList<Vulnerability>() : complianceIssues;
            }

            public Date getCreationTime() {
                return creationTime;
            }

            public ScanType getType() {
                return type;
            }

            public enum ScanType implements Serializable {
                ciImage("image"),
                ciServerless("function");

                private final String display;

                ScanType(String display) {
                    this.display = display;
                }

                public String display() {
                    return this.display;
                }
            }
        }
    }
}
