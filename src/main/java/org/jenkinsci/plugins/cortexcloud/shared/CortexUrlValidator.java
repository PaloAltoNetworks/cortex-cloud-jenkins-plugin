package org.jenkinsci.plugins.cortexcloud.shared;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Validates a user-supplied Cortex API base URL before it is used for outbound
 * requests.
 *
 * The base URL is operator-configurable, so it is validated to reduce the risk of
 * server-side request forgery (SSRF): only well-formed absolute HTTPS URLs are
 * accepted, and hosts that resolve to loopback, link-local, or private ranges (or
 * obvious internal-only names) are rejected. This keeps the configured endpoint
 * pointed at a public Cortex tenant rather than an internal service.
 *
 * This class performs syntactic and host-shape checks only; it does not perform
 * DNS resolution, so it is safe to call from form validation without making
 * network calls.
 */
public final class CortexUrlValidator {

    /** Outcome of validating a base URL. */
    public enum Result {
        OK,
        BLANK,
        MALFORMED,
        NOT_HTTPS,
        INTERNAL_HOST
    }

    private CortexUrlValidator() {
        // utility class
    }

    /**
     * Validates the given base URL.
     *
     * @param value the candidate URL (may be null/blank)
     * @return the Result describing why the URL is or is not acceptable
     */
    public static Result validate(String value) {
        if (value == null || value.trim().isEmpty()) {
            return Result.BLANK;
        }
        String trimmed = value.trim();

        final URI uri;
        try {
            uri = new URI(trimmed);
        } catch (URISyntaxException e) {
            return Result.MALFORMED;
        }

        String scheme = uri.getScheme();
        if (scheme == null || !"https".equals(scheme.toLowerCase(Locale.ROOT))) {
            return Result.NOT_HTTPS;
        }

        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            return Result.MALFORMED;
        }

        if (isInternalHost(host)) {
            return Result.INTERNAL_HOST;
        }
        return Result.OK;
    }

    /**
     * @param host the URL host (already lower-cased by callers is not required)
     * @return true when the host is loopback, link-local, or a private /
     *     internal-only address or name that a public tenant URL should never use
     */
    static boolean isInternalHost(String host) {
        String h = host.toLowerCase(Locale.ROOT);

        // Strip IPv6 brackets, e.g. "[::1]" -> "::1".
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }

        // Obvious loopback / internal names.
        if (h.equals("localhost")
                || h.endsWith(".localhost")
                || h.endsWith(".local")
                || h.endsWith(".internal")
                || h.endsWith(".intranet")
                || h.equals("::1")
                || h.equals("0.0.0.0")) {
            return true;
        }

        // IPv4 literals in loopback / private / link-local ranges.
        if (isIpv4(h)) {
            return isPrivateOrLoopbackIpv4(h);
        }

        // IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
        if (h.startsWith("fc")
                || h.startsWith("fd")
                || h.startsWith("fe8")
                || h.startsWith("fe9")
                || h.startsWith("fea")
                || h.startsWith("feb")) {
            return true;
        }

        return false;
    }

    private static boolean isIpv4(String h) {
        String[] parts = h.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(p) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPrivateOrLoopbackIpv4(String h) {
        String[] parts = h.split("\\.");
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);

        // 127.0.0.0/8 loopback
        if (a == 127) {
            return true;
        }
        // 10.0.0.0/8 private
        if (a == 10) {
            return true;
        }
        // 172.16.0.0/12 private
        if (a == 172 && b >= 16 && b <= 31) {
            return true;
        }
        // 192.168.0.0/16 private
        if (a == 192 && b == 168) {
            return true;
        }
        // 169.254.0.0/16 link-local
        if (a == 169 && b == 254) {
            return true;
        }
        return false;
    }
}
