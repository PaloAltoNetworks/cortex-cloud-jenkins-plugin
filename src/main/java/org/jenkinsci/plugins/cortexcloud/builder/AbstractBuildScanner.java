package org.jenkinsci.plugins.cortexcloud.builder;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Common base for Cortex Cloud build steps.
 *
 * Mirrors the legacy plugin's AbstractBuildScanner: it is a Builder implementing
 * SimpleBuildStep so the same step works in both freestyle jobs and Pipeline.
 * Shared, optional settings live here; concrete subclasses (e.g.
 * ImageBuildScanner) add target-specific fields and implement perform.
 */
public abstract class AbstractBuildScanner extends Builder implements SimpleBuildStep {

    /** When true (default), a policy violation (CLI exit 1) fails the build. */
    private boolean failBuildOnPolicyViolation = true;

    /**
     * When true (default), the build fails closed if a severity threshold is
     * configured but the plugin cannot produce machine-readable findings to
     * evaluate it against. Set to false only to restore the old fail-open behaviour.
     */
    private boolean failOnUnparseableResults = true;

    /** Optional scan timeout in seconds; non-positive means use the CLI default. */
    private int timeout;

    protected AbstractBuildScanner() {
        // no-arg base; concrete steps use @DataBoundConstructor
    }

    public boolean isFailBuildOnPolicyViolation() {
        return failBuildOnPolicyViolation;
    }

    @DataBoundSetter
    public void setFailBuildOnPolicyViolation(boolean failBuildOnPolicyViolation) {
        this.failBuildOnPolicyViolation = failBuildOnPolicyViolation;
    }

    public boolean isFailOnUnparseableResults() {
        return failOnUnparseableResults;
    }

    @DataBoundSetter
    public void setFailOnUnparseableResults(boolean failOnUnparseableResults) {
        this.failOnUnparseableResults = failOnUnparseableResults;
    }

    public int getTimeout() {
        return timeout;
    }

    @DataBoundSetter
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    /** @return the configured timeout as a positive Integer, or null for "use CLI default". */
    protected Integer timeoutSecondsOrNull() {
        return timeout > 0 ? timeout : null;
    }

    /**
     * Expands $VAR / ${VAR} references in a step parameter using the build
     * environment, matching the legacy plugin's resolveEnvs behaviour.
     */
    protected String resolveEnvs(String value, Run<?, ?> run, TaskListener listener)
            throws IOException, InterruptedException {
        if (value == null) {
            return null;
        }
        EnvVars env = run.getEnvironment(listener);
        return env.expand(value);
    }

    /** Aborts the build with a clear message (turns the build red). */
    protected static void abort(String message) throws AbortException {
        throw new AbortException(message);
    }
}
