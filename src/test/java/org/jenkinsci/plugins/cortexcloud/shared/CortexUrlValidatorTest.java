package org.jenkinsci.plugins.cortexcloud.shared;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CortexUrlValidator}: the base URL must be a well-formed
 * absolute HTTPS URL pointing at a public host (SSRF guard).
 */
class CortexUrlValidatorTest {

    @Test
    void acceptsValidPublicHttpsUrl() {
        assertEquals(
                CortexUrlValidator.Result.OK,
                CortexUrlValidator.validate("https://api-tenant.xdr.us.paloaltonetworks.com"));
    }

    @Test
    void rejectsBlank() {
        assertEquals(CortexUrlValidator.Result.BLANK, CortexUrlValidator.validate(""));
        assertEquals(CortexUrlValidator.Result.BLANK, CortexUrlValidator.validate("   "));
        assertEquals(CortexUrlValidator.Result.BLANK, CortexUrlValidator.validate(null));
    }

    @Test
    void rejectsNonHttps() {
        assertEquals(CortexUrlValidator.Result.NOT_HTTPS, CortexUrlValidator.validate("http://example.com"));
        assertEquals(CortexUrlValidator.Result.NOT_HTTPS, CortexUrlValidator.validate("ftp://example.com"));
        assertEquals(CortexUrlValidator.Result.NOT_HTTPS, CortexUrlValidator.validate("file:///etc/passwd"));
    }

    @Test
    void rejectsMalformed() {
        assertEquals(CortexUrlValidator.Result.MALFORMED, CortexUrlValidator.validate("not a url"));
        assertEquals(CortexUrlValidator.Result.MALFORMED, CortexUrlValidator.validate("https://"));
    }

    @Test
    void rejectsLoopbackAndInternalNames() {
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://localhost"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://localhost:8080/x"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://foo.local"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://svc.internal"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://[::1]/path"));
    }

    @Test
    void rejectsLoopbackAndPrivateIpv4() {
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://127.0.0.1"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://10.0.0.5"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://172.16.0.1"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://192.168.1.1"));
        assertEquals(
                CortexUrlValidator.Result.INTERNAL_HOST,
                CortexUrlValidator.validate("https://169.254.169.254/latest/meta-data"));
    }

    @Test
    void acceptsPublicIpv4() {
        assertEquals(CortexUrlValidator.Result.OK, CortexUrlValidator.validate("https://8.8.8.8"));
        // 172.15 and 172.32 are outside the 172.16/12 private block.
        assertEquals(CortexUrlValidator.Result.OK, CortexUrlValidator.validate("https://172.15.0.1"));
        assertEquals(CortexUrlValidator.Result.OK, CortexUrlValidator.validate("https://172.32.0.1"));
    }

    @Test
    void rejectsUnspecifiedAddressAndIpv6UniqueLocal() {
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://0.0.0.0"));
        // IPv6 unique-local (fc00::/7): fc.. and fd.. prefixes.
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://[fd00::1]"));
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://[fc00::1]/path"));
        // IPv6 link-local (fe80::/10).
        assertEquals(CortexUrlValidator.Result.INTERNAL_HOST, CortexUrlValidator.validate("https://[fe80::1]"));
    }
}
