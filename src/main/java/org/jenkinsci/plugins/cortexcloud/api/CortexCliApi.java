package org.jenkinsci.plugins.cortexcloud.api;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;

/**
 * Thin REST client for the Cortex tenant API.
 *
 * It is responsible for the one platform endpoint the plugin needs at build
 * time: the unified-CLI download-link lookup (CortexConstants.DOWNLOAD_LINK_PATH).
 * That endpoint both (a) proves the base URL and credentials are valid (used by
 * the global config's Test Connection) and (b) yields the signed URL + checksum
 * used to provision the cortexcli binary onto an agent.
 *
 * Authentication uses the same credentials the CLI consumes, sent as HTTP headers:
 * - Authorization: <api key>
 * - x-xdr-auth-id: <api key id>
 *
 * Implemented with HttpURLConnection to avoid pulling in an HTTP client
 * dependency; this keeps the plugin classpath minimal and proxy-friendly (it
 * honours the JVM's standard proxy system properties).
 */
public class CortexCliApi {

    private static final Gson GSON = new Gson();
    private static final int CONNECT_TIMEOUT_MS = 15_000;
    private static final int READ_TIMEOUT_MS = 30_000;

    /**
     * Upper bound on the response body we will read into memory. The expected
     * download-link JSON is a few hundred bytes; capping the read defends against
     * a misbehaving or hostile endpoint returning an unbounded body.
     */
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    private final String baseUrl;
    private final String apiKey;
    private final String apiKeyId;

    /**
     * @param baseUrl  tenant API base URL (trailing slash optional)
     * @param apiKey   API key (secret)
     * @param apiKeyId API key ID (maps to the x-xdr-auth-id header)
     */
    public CortexCliApi(String baseUrl, String apiKey, String apiKeyId) {
        this.baseUrl = stripTrailingSlash(baseUrl);
        this.apiKey = apiKey;
        this.apiKeyId = apiKeyId;
    }

    /**
     * Verifies connectivity and credentials by requesting a download link for
     * the current platform. A 2xx response with a usable signed URL means the
     * tenant is reachable and the credentials are accepted.
     *
     * @throws IOException if the request fails or the tenant rejects the credentials
     */
    public void testConnection() throws IOException {
        DownloadLink link = getDownloadLink(currentOs(), currentArch());
        if (link == null || isBlank(link.signedUrl)) {
            throw new IOException("tenant did not return a download link (unexpected response)");
        }
    }

    /**
     * Requests a signed download link + checksum for the cortexcli binary
     * matching the given OS and architecture.
     *
     * @param os   one of CortexConstants.OS_LINUX, OS_DARWIN, OS_WINDOWS
     * @param arch one of CortexConstants.ARCH_AMD64, ARCH_ARM64
     * @return the parsed download link metadata
     * @throws IOException on transport error or non-2xx response
     */
    public DownloadLink getDownloadLink(String os, String arch) throws IOException {
        String url = baseUrl + CortexConstants.DOWNLOAD_LINK_PATH
                + "?" + CortexConstants.DOWNLOAD_PARAM_OS + "=" + enc(os)
                + "&" + CortexConstants.DOWNLOAD_PARAM_ARCH + "=" + enc(arch);

        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty(CortexConstants.HEADER_AUTHORIZATION, apiKey);
            conn.setRequestProperty(CortexConstants.HEADER_AUTH_ID, apiKeyId);
            conn.setRequestProperty("Accept", "application/json");

            int status = conn.getResponseCode();
            if (status < 200 || status >= 300) {
                String body = readStream(conn.getErrorStream());
                throw new IOException("HTTP " + status + " from " + CortexConstants.DOWNLOAD_LINK_PATH
                        + (isBlank(body) ? "" : (": " + truncate(body))));
            }

            String body = readStream(conn.getInputStream());
            DownloadLink link = GSON.fromJson(body, DownloadLink.class);
            if (link == null) {
                throw new IOException("empty/invalid JSON from " + CortexConstants.DOWNLOAD_LINK_PATH);
            }
            return link;
        } finally {
            conn.disconnect();
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** @return the os value for the JVM currently running this code. */
    public static String currentOs() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            return CortexConstants.OS_WINDOWS;
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return CortexConstants.OS_DARWIN;
        }
        return CortexConstants.OS_LINUX;
    }

    /** @return the architecture value for the JVM currently running this code. */
    public static String currentArch() {
        String arch = System.getProperty("os.arch", "").toLowerCase();
        if (arch.contains("aarch64") || arch.contains("arm64")) {
            return CortexConstants.ARCH_ARM64;
        }
        return CortexConstants.ARCH_AMD64;
    }

    private static String stripTrailingSlash(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    /**
     * Reads a response body into a string, reading at most MAX_RESPONSE_BYTES so a
     * hostile or misbehaving endpoint cannot exhaust memory. Any bytes beyond
     * the cap are discarded.
     */
    private static String readStream(InputStream in) throws IOException {
        if (in == null) {
            return "";
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int total = 0;
        int n;
        while (total < MAX_RESPONSE_BYTES && (n = in.read(chunk)) != -1) {
            int remaining = MAX_RESPONSE_BYTES - total;
            int toWrite = Math.min(n, remaining);
            buffer.write(chunk, 0, toWrite);
            total += toWrite;
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String truncate(String s) {
        return s.length() > 500 ? s.substring(0, 500) + "..." : s;
    }

    /**
     * Response body of CortexConstants.DOWNLOAD_LINK_PATH.
     * Shape (verified against a live tenant):
     * { "signed_url": "...", "checksum": "...", "file_name": "...", "expiration": ... }.
     *
     * Note: the tenant returns the checksum as an MD5 hex digest in practice (32
     * chars), not SHA-256. The verifier in CliProvisioner infers the algorithm
     * from the hex length, so it handles MD5, SHA-1, or SHA-256 transparently.
     */
    public static class DownloadLink implements Serializable {
        private static final long serialVersionUID = 1L;

        @SerializedName(
                value = "signed_url",
                alternate = {"signedUrl", "url"})
        public String signedUrl;

        @SerializedName(
                value = "checksum",
                alternate = {"md5", "md5Checksum", "sha256", "sha256Checksum"})
        public String checksum;

        @SerializedName(
                value = "file_name",
                alternate = {"fileName", "filename"})
        public String fileName;

        @SerializedName(
                value = "expiration",
                alternate = {"expires", "expiresAt"})
        public Long expiration;

        public String getSignedUrl() {
            return signedUrl;
        }

        public String getChecksum() {
            return checksum;
        }

        public String getFileName() {
            return fileName;
        }

        public Long getExpiration() {
            return expiration;
        }
    }
}
