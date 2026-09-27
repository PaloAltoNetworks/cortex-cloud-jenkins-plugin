package org.jenkinsci.plugins.cortexcloud.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import hudson.model.FreeStyleProject;
import hudson.util.FormValidation;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * JenkinsRule tests for the {@link ImageBuildScanner} build step: descriptor
 * registration, configuration round-trip through the UI/XML layer, and form
 * validation.
 */
@WithJenkins
class ImageBuildScannerTest {

    @Test
    void descriptorIsRegistered(JenkinsRule j) {
        ImageBuildScanner.DescriptorImpl d = j.jenkins.getDescriptorByType(ImageBuildScanner.DescriptorImpl.class);
        assertNotNull(d, "Build step descriptor should be registered");
        assertEquals("Scan container image with Cortex Cloud", d.getDisplayName());
    }

    @Test
    void configRoundTrip(JenkinsRule j) throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();

        ImageBuildScanner step = new ImageBuildScanner("myrepo/app:1.2.3");
        step.setDockerHost("unix:///var/run/docker.sock");
        step.setScanName("my-scan");
        step.setTimeout(120);
        step.setFailBuildOnPolicyViolation(false);
        step.setFailOnUnparseableResults(false);
        step.setSeverityThreshold("HIGH");
        step.setSource("jenkins");
        step.setUploadMode("all");
        p.getBuildersList().add(step);

        // Round-trip through the config form (serializes to XML and back).
        j.configRoundtrip(p);

        ImageBuildScanner reloaded = p.getBuildersList().get(ImageBuildScanner.class);
        assertNotNull(reloaded);
        assertEquals("myrepo/app:1.2.3", reloaded.getImage());
        assertEquals("unix:///var/run/docker.sock", reloaded.getDockerHost());
        assertEquals("my-scan", reloaded.getScanName());
        assertEquals(120, reloaded.getTimeout());
        assertFalse(reloaded.isFailBuildOnPolicyViolation());
        assertFalse(reloaded.isFailOnUnparseableResults());
        assertEquals("HIGH", reloaded.getSeverityThreshold());
        assertEquals("jenkins", reloaded.getSource());
        assertEquals("all", reloaded.getUploadMode());
    }

    @Test
    void severityThresholdItemsAreOffered(JenkinsRule j) {
        ImageBuildScanner.DescriptorImpl d = j.jenkins.getDescriptorByType(ImageBuildScanner.DescriptorImpl.class);
        // None, Low, Medium, High, Critical
        assertEquals(5, d.doFillSeverityThresholdItems(null).size());
    }

    @Test
    void imageValidation(JenkinsRule j) {
        ImageBuildScanner.DescriptorImpl d = j.jenkins.getDescriptorByType(ImageBuildScanner.DescriptorImpl.class);

        assertEquals(FormValidation.Kind.ERROR, d.doCheckImage(null, "").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckImage(null, "myrepo/app:1.0").kind);
    }

    @Test
    void dockerHostValidation(JenkinsRule j) {
        ImageBuildScanner.DescriptorImpl d = j.jenkins.getDescriptorByType(ImageBuildScanner.DescriptorImpl.class);

        assertEquals(FormValidation.Kind.OK, d.doCheckDockerHost(null, "").kind);
        assertEquals(FormValidation.Kind.OK, d.doCheckDockerHost(null, "unix:///var/run/docker.sock").kind);
        assertEquals(FormValidation.Kind.WARNING, d.doCheckDockerHost(null, "not-a-socket").kind);
    }
}
