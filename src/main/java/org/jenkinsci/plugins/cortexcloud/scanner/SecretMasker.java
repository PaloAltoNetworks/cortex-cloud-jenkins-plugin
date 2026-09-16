package org.jenkinsci.plugins.cortexcloud.scanner;

import java.util.ArrayList;
import java.util.List;

/**
 * Redacts sensitive values (e.g. the Cortex API key) from text before it is
 * written to the build log.
 *
 * The Cortex CLI receives its credentials via environment variables and does not
 * normally echo them, but this masker is applied defensively to every line of
 * captured CLI output so that a secret can never leak into the console log even
 * if a future CLI version, error path, or verbose mode prints it.
 *
 * Only non-blank secrets are masked; blank values are ignored so the masker never
 * turns empty strings into the replacement token.
 */
final class SecretMasker {

    /** Replacement token shown in place of a redacted secret. */
    static final String REDACTED = "****";

    private final List<String> secrets;

    private SecretMasker(List<String> secrets) {
        this.secrets = secrets;
    }

    /**
     * Builds a masker for the given secret values. Null/blank values are skipped.
     *
     * @param values candidate secrets to redact
     * @return a masker that redacts every non-blank value
     */
    static SecretMasker forSecrets(String... values) {
        List<String> nonBlank = new ArrayList<>();
        if (values != null) {
            for (String v : values) {
                if (v != null && !v.isEmpty()) {
                    nonBlank.add(v);
                }
            }
        }
        return new SecretMasker(nonBlank);
    }

    /** @return true when there is at least one secret to redact. */
    boolean hasSecrets() {
        return !secrets.isEmpty();
    }

    /**
     * Returns input with every known secret replaced by REDACTED.
     *
     * @param input text that may contain a secret; may be null
     * @return the masked text, or null if input was null
     */
    String mask(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        String out = input;
        for (String secret : secrets) {
            out = out.replace(secret, REDACTED);
        }
        return out;
    }
}
