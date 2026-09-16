package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SecretMasker}: the API key must never survive in text
 * that is written to the build log.
 */
class SecretMaskerTest {

    @Test
    void redactsTheSecretFromOutput() {
        SecretMasker masker = SecretMasker.forSecrets("super-secret-key");
        String line = "connecting with key super-secret-key to tenant";
        String masked = masker.mask(line);
        assertFalse(masked.contains("super-secret-key"), "secret must not remain in output");
        assertTrue(masked.contains(SecretMasker.REDACTED));
    }

    @Test
    void redactsMultipleOccurrences() {
        SecretMasker masker = SecretMasker.forSecrets("abc123");
        String masked = masker.mask("abc123 ... abc123");
        assertEquals(SecretMasker.REDACTED + " ... " + SecretMasker.REDACTED, masked);
    }

    @Test
    void ignoresBlankSecrets() {
        SecretMasker masker = SecretMasker.forSecrets("", null);
        assertFalse(masker.hasSecrets());
        // A blank secret must not turn ordinary text into the redaction token.
        assertEquals("nothing to hide", masker.mask("nothing to hide"));
    }

    @Test
    void handlesNullAndEmptyInput() {
        SecretMasker masker = SecretMasker.forSecrets("k");
        assertNull(masker.mask(null));
        assertEquals("", masker.mask(""));
    }

    @Test
    void redactsOverlappingSubstringSecretsRegardlessOfOrder() {
        // One secret is a substring of the other; both must be redacted whichever
        // order they are supplied in, so no fragment of either survives.
        String text = "token=supersecret and short=secret";
        String maskedLongFirst =
                SecretMasker.forSecrets("supersecret", "secret").mask(text);
        String maskedShortFirst =
                SecretMasker.forSecrets("secret", "supersecret").mask(text);

        assertFalse(maskedLongFirst.contains("supersecret"), "long secret must not remain");
        assertFalse(maskedLongFirst.contains("secret"), "short secret must not remain");
        assertFalse(maskedShortFirst.contains("supersecret"), "long secret must not remain");
        assertFalse(maskedShortFirst.contains("secret"), "short secret must not remain");
    }
}
