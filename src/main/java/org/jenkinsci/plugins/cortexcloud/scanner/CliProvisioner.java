package org.jenkinsci.plugins.cortexcloud.scanner;

import hudson.FilePath;
import hudson.model.TaskListener;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.jenkinsci.plugins.cortexcloud.api.CortexCliApi;
import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;

/**
 * Resolves an executable cortexcli binary onto the build node.
 *
 * Resolution order (the CLI is distributed as a single static Go binary, so no
 * JRE is required on the agent):
 *
 * 1. Override path - if the global config specifies a pre-installed CLI path, and
 *    it exists on the agent, use it as-is.
 * 2. Per-agent cache - if a previously downloaded binary (matching the expected
 *    checksum) is already cached on this node, reuse it.
 * 3. Download - otherwise request a signed URL + checksum from the tenant API,
 *    download the binary, verify its checksum, mark it executable, and cache it.
 *    The checksum algorithm is inferred from the hex length the tenant returns
 *    (32=MD5, 40=SHA-1, 64=SHA-256), because the tenant returns an MD5 digest in
 *    practice.
 *
 * All filesystem work goes through FilePath so it executes correctly on remote
 * agents, not just the controller.
 */
public class CliProvisioner {

    /** Cache directory under the agent's root, e.g. <agent-root>/caches/cortexcli. */
    static final String CACHE_DIR = "caches/cortexcli";

    /** Connection timeout for the binary download, in milliseconds. */
    private static final int DOWNLOAD_CONNECT_TIMEOUT_MS = 15_000;

    /** Read timeout for the binary download, in milliseconds (the CLI is ~14 MB). */
    private static final int DOWNLOAD_READ_TIMEOUT_MS = 120_000;

    /** Buffer size for streaming the download and computing digests. */
    private static final int STREAM_BUFFER_BYTES = 8192;

    /** Suffix for the per-node provisioning lock directory (created inside the cache dir). */
    private static final String LOCK_DIR_SUFFIX = ".lock";

    /** Suffix for in-progress download temp files. */
    private static final String PART_SUFFIX = ".part";

    /** Maximum time to wait to acquire the provisioning lock, in milliseconds. */
    private static final long LOCK_TIMEOUT_MS = 180_000;

    /** Poll interval while waiting for the provisioning lock, in milliseconds. */
    private static final long LOCK_POLL_INTERVAL_MS = 500;

    /** Age after which a leftover lock is considered stale and forcibly reclaimed, in milliseconds. */
    private static final long LOCK_STALE_AFTER_MS = 300_000;

    private final CortexCliApi api;
    private final TaskListener listener;
    private final boolean debug;

    public CliProvisioner(CortexCliApi api, TaskListener listener, boolean debug) {
        this.api = api;
        this.listener = listener;
        this.debug = debug;
    }

    /**
     * Resolves the CLI binary and returns its remote path on the agent.
     *
     * @param nodeRoot   the agent's root FilePath (for the cache); may be null
     * @param workspace  the build workspace (fallback cache location)
     * @param overridePath optional pre-installed CLI path from global config (may be null/blank)
     * @return the executable CLI path on the agent
     */
    public String resolve(FilePath nodeRoot, FilePath workspace, String overridePath)
            throws IOException, InterruptedException {

        // 1) Explicit override wins.
        if (overridePath != null && !overridePath.trim().isEmpty()) {
            FilePath candidate = new FilePath(workspace.getChannel(), overridePath.trim());
            if (candidate.exists()) {
                log("Using pre-installed Cortex CLI: " + candidate.getRemote());
                return candidate.getRemote();
            }
            log("Configured CLI path does not exist on the agent, falling back to download: " + overridePath);
        }

        // Determine the agent's OS/arch in a single remote round-trip.
        ProbedPlatform platform = probePlatform(workspace);
        String os = platform.os;
        String arch = platform.arch;

        CortexCliApi.DownloadLink link = api.getDownloadLink(os, arch);
        if (link == null || isBlank(link.getSignedUrl())) {
            throw new IOException("tenant did not return a download link for " + os + "/" + arch);
        }

        FilePath cacheDir = resolveCacheDir(nodeRoot, workspace);
        cacheDir.mkdirs();

        FilePath cached = cacheDir.child(binaryNameFor(os));

        // 2) Reuse a valid cached binary (no lock needed for a read-only check).
        if (cached.exists() && !isBlank(link.getChecksum()) && digestMatches(cached, link.getChecksum())) {
            log("Reusing cached Cortex CLI: " + cached.getRemote());
            setUnixExecutableBit(cached, os);
            return cached.getRemote();
        }

        // Provision under a per-node lock so concurrent builds on the same
        // agent don't race on the shared cache path. Only one
        // build downloads; the rest wait and then hit the warm, valid cache.
        FilePath lock = cacheDir.child(binaryNameFor(os) + LOCK_DIR_SUFFIX);
        acquireLock(lock);
        try {
            // Re-check inside the lock: another build may have provisioned it
            // while we were waiting.
            if (cached.exists() && !isBlank(link.getChecksum()) && digestMatches(cached, link.getChecksum())) {
                log("Reusing cached Cortex CLI (provisioned by a concurrent build): " + cached.getRemote());
                setUnixExecutableBit(cached, os);
                return cached.getRemote();
            }

            //    Integrity verification is mandatory and fails closed: the plugin
            //    downloads and executes a binary on the build node, so an unverified
            //    binary must never run. A missing or unrecognized checksum is treated
            //    as a hard error, not a warning.
            String expected = link.getChecksum();
            if (isBlank(expected)) {
                throw new IOException("Refusing to run the Cortex CLI: the tenant did not provide a checksum, "
                        + "so the downloaded binary cannot be integrity-verified.");
            }
            String algo = algorithmForHexLength(expected);
            if (algo == null) {
                throw new IOException("Refusing to run the Cortex CLI: the tenant checksum has an unrecognized "
                        + "length (" + expected.trim().length() + " hex chars), so it cannot be verified.");
            }

            // Clean up any debris left by an aborted build before we start.
            cleanStalePartFiles(cacheDir);

            // Download to a unique temp file, verify it there, then atomically
            // rename into place. A rename on the same filesystem is atomic, so a
            // concurrent reader always sees either the old binary or the fully
            // written new one, never a half-written file.
            FilePath tmp = cacheDir.child(binaryNameFor(os) + "." + UUID.randomUUID() + PART_SUFFIX);
            try {
                log("Downloading Cortex CLI (" + os + "/" + arch + ")");
                download(link.getSignedUrl(), tmp);

                String actual = digest(tmp, algo);
                if (!expected.trim().equalsIgnoreCase(actual)) {
                    throw new IOException("Cortex CLI checksum verification failed (expected " + expected + ", got "
                            + actual + " [" + algo + "]); the download was discarded.");
                }
                log("Checksum verified (" + algo + ")");

                setUnixExecutableBit(tmp, os);
                // Replace atomically. renameTo on POSIX overwrites the destination.
                cached.delete();
                tmp.renameTo(cached);
            } finally {
                if (tmp.exists()) {
                    tmp.delete();
                }
            }

            log("Cortex CLI ready: " + cached.getRemote());
            return cached.getRemote();
        } finally {
            releaseLock(lock);
        }
    }


    /**
     * Acquires an exclusive provisioning lock by creating a lock directory. A
     * directory create is atomic on both POSIX and Windows filesystems, so it
     * doubles as a mutex across concurrent builds on the same node. A lock older
     * than {@link #LOCK_STALE_AFTER_MS} is treated as abandoned (the owning build
     * died without cleaning up) and reclaimed.
     */
    private void acquireLock(FilePath lock) throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + LOCK_TIMEOUT_MS;
        boolean warned = false;
        while (true) {
            if (mkdirIfAbsent(lock)) {
                return;
            }
            // Reclaim a stale lock left behind by a crashed build.
            long age = System.currentTimeMillis() - lock.lastModified();
            if (lock.lastModified() > 0 && age > LOCK_STALE_AFTER_MS) {
                log("Reclaiming stale Cortex CLI provisioning lock (age " + (age / 1000) + "s)");
                lock.deleteRecursive();
                if (mkdirIfAbsent(lock)) {
                    return;
                }
            }
            if (System.currentTimeMillis() >= deadline) {
                throw new IOException("Timed out after " + (LOCK_TIMEOUT_MS / 1000)
                        + "s waiting to provision the Cortex CLI (another build on this node holds the lock).");
            }
            if (!warned) {
                log("Waiting for a concurrent build to finish provisioning the Cortex CLI...");
                warned = true;
            }
            TimeUnit.MILLISECONDS.sleep(LOCK_POLL_INTERVAL_MS);
        }
    }

    /** @return true if the lock directory was created by this call (i.e. we now own it). */
    private static boolean mkdirIfAbsent(FilePath lock) throws IOException, InterruptedException {
        if (lock.exists()) {
            return false;
        }
        lock.mkdirs();
        return lock.exists();
    }

    private void releaseLock(FilePath lock) {
        try {
            if (lock.exists()) {
                lock.deleteRecursive();
            }
        } catch (IOException | InterruptedException e) {
            log("Warning: failed to release Cortex CLI provisioning lock: " + e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Removes leftover *.part temp files from aborted downloads in the cache dir. */
    private void cleanStalePartFiles(FilePath cacheDir) throws IOException, InterruptedException {
        FilePath[] stale = cacheDir.list("*" + PART_SUFFIX);
        for (FilePath f : stale) {
            try {
                f.delete();
            } catch (IOException e) {
                log("Warning: could not delete stale download file " + f.getName() + ": " + e.getMessage());
            }
        }
    }

    /** @return the cached binary file name for the given OS (adds .exe on Windows). */
    private static String binaryNameFor(String os) {
        boolean windows = CortexConstants.OS_WINDOWS.equals(os);
        return windows ? CortexConstants.CLI_BINARY_NAME + ".exe" : CortexConstants.CLI_BINARY_NAME;
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    private FilePath resolveCacheDir(FilePath nodeRoot, FilePath workspace) {
        FilePath base = (nodeRoot != null) ? nodeRoot : workspace;
        return base.child(CACHE_DIR);
    }

    /**
     * Streams a URL to a FilePath on the agent. The URL must use HTTPS so the CLI
     * binary is fetched over an authenticated, encrypted channel; a non-HTTPS
     * download link is rejected (fail closed).
     */
    private void download(String signedUrl, FilePath dest) throws IOException, InterruptedException {
        URL url = new URL(signedUrl);
        String protocol = url.getProtocol();
        if (protocol == null || !"https".equalsIgnoreCase(protocol)) {
            throw new IOException("Refusing to download the Cortex CLI over a non-HTTPS URL (scheme: " + protocol
                    + "); the download link must use HTTPS.");
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setConnectTimeout(DOWNLOAD_CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(DOWNLOAD_READ_TIMEOUT_MS);
            int status = conn.getResponseCode();
            if (status < 200 || status >= 300) {
                throw new IOException("HTTP " + status + " downloading Cortex CLI");
            }
            try (InputStream in = conn.getInputStream();
                    OutputStream out = dest.write()) {
                byte[] buf = new byte[STREAM_BUFFER_BYTES];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            }
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Maps a hex checksum string to the JCA digest algorithm that produces it,
     * inferred from its length. Returns null for unrecognized lengths.
     *
     * - 32 hex chars -> MD5
     * - 40 hex chars -> SHA-1
     * - 64 hex chars -> SHA-256
     */
    static String algorithmForHexLength(String checksum) {
        if (checksum == null) {
            return null;
        }
        switch (checksum.trim().length()) {
            case 32:
                return "MD5";
            case 40:
                return "SHA-1";
            case 64:
                return "SHA-256";
            default:
                return null;
        }
    }

    /**
     * Verifies the file against the expected checksum, auto-selecting the digest
     * algorithm from the expected value's hex length. Returns false if the length
     * is unrecognized (treated as a non-match, forcing a re-download).
     */
    private static boolean digestMatches(FilePath file, String expected) throws IOException, InterruptedException {
        String algo = algorithmForHexLength(expected);
        if (algo == null) {
            return false;
        }
        return expected.trim().equalsIgnoreCase(digest(file, algo));
    }

    private static String digest(FilePath file, String algorithm) throws IOException, InterruptedException {
        try (InputStream in = file.read()) {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] buf = new byte[STREAM_BUFFER_BYTES];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
            return toHex(md.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException(algorithm + " not available", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** Sets the unix executable bit (rwxr-xr-x) on non-Windows agents; a no-op on Windows. */
    private static void setUnixExecutableBit(FilePath file, String os) throws IOException, InterruptedException {
        if (!CortexConstants.OS_WINDOWS.equals(os)) {
            file.chmod(0755);
        }
    }

    /**
     * Probes the agent once and returns its normalized OS and architecture. A
     * single remote round-trip covers both values.
     */
    private static ProbedPlatform probePlatform(FilePath workspace) throws IOException, InterruptedException {
        OsArchProbe.Result raw = workspace.act(new OsArchProbe());
        return new ProbedPlatform(normalizeOs(raw.os), normalizeArch(raw.arch));
    }

    /**
     * Normalizes a raw os.name value to a Cortex OS constant. macOS is checked
     * before Windows because the string "darwin" contains the substring "win".
     */
    static String normalizeOs(String rawOsName) {
        String name = rawOsName == null ? "" : rawOsName.toLowerCase(Locale.ROOT);
        if (name.contains("mac") || name.contains("darwin")) {
            return CortexConstants.OS_DARWIN;
        }
        if (name.contains("windows")) {
            return CortexConstants.OS_WINDOWS;
        }
        return CortexConstants.OS_LINUX;
    }

    /** Normalizes a raw os.arch value to a Cortex architecture constant. */
    static String normalizeArch(String rawArch) {
        String arch = rawArch == null ? "" : rawArch.toLowerCase(Locale.ROOT);
        if (arch.contains("aarch64") || arch.contains("arm64")) {
            return CortexConstants.ARCH_ARM64;
        }
        return CortexConstants.ARCH_AMD64;
    }

    private void log(String msg) {
        if (listener != null) {
            listener.getLogger().println("[Cortex] " + msg);
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** The agent's normalized OS and architecture, resolved in a single probe. */
    static final class ProbedPlatform {
        final String os;
        final String arch;

        ProbedPlatform(String os, String arch) {
            this.os = os;
            this.arch = arch;
        }
    }

    /**
     * A FilePath.FileCallable that reports the agent JVM's OS/arch. Runs on the
     * node where the workspace lives (controller or remote agent).
     */
    static class OsArchProbe extends jenkins.MasterToSlaveFileCallable<OsArchProbe.Result> {
        private static final long serialVersionUID = 1L;

        Result invokeResult() {
            Result r = new Result();
            r.os = System.getProperty("os.name", "");
            r.arch = System.getProperty("os.arch", "");
            return r;
        }

        @Override
        public Result invoke(java.io.File f, hudson.remoting.VirtualChannel channel) {
            return invokeResult();
        }

        static class Result implements java.io.Serializable {
            private static final long serialVersionUID = 1L;
            String os = "";
            String arch = "";
        }
    }
}
