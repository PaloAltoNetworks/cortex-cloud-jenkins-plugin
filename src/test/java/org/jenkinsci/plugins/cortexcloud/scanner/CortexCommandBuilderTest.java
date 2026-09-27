package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CortexCommandBuilderTest {

    @Test
    void buildsVerifiedArchiveScanCommand() {
        List<String> cmd = new CortexCommandBuilder("/opt/cortexcli")
                .name("alpine:latest")
                .target("/tmp/alpine.tar")
                .build();

        // cortexcli image scan --archive --archive-format docker-archive --name alpine:latest --output-format json
        // /tmp/alpine.tar
        assertEquals("/opt/cortexcli", cmd.get(0));
        assertEquals("image", cmd.get(1));
        assertEquals("scan", cmd.get(2));
        assertTrue(cmd.contains("--archive"));
        assertEquals("docker-archive", valueAfter(cmd, "--archive-format"));
        assertEquals("alpine:latest", valueAfter(cmd, "--name"));
        assertEquals("json", valueAfter(cmd, "--output-format"));
        // target is the last positional argument
        assertEquals("/tmp/alpine.tar", cmd.get(cmd.size() - 1));
    }

    @Test
    void targetIsAlwaysLastEvenWithExtraFlags() {
        List<String> cmd = new CortexCommandBuilder("cortexcli")
                .name("img")
                .target("/tmp/img.tar")
                .dockerHost("unix:///var/run/docker.sock")
                .ciPipelineId("pipe-1")
                .ciBuildId("42")
                .timeoutSeconds(120)
                .build();

        assertEquals("/tmp/img.tar", cmd.get(cmd.size() - 1));
        assertEquals("unix:///var/run/docker.sock", valueAfter(cmd, "--docker-host"));
        assertEquals("pipe-1", valueAfter(cmd, "--ci-pipeline-id"));
        assertEquals("42", valueAfter(cmd, "--ci-build-id"));
        assertEquals("120", valueAfter(cmd, "--timeout"));
    }

    @Test
    void omitsArchiveFlagsWhenScanningImageReference() {
        List<String> cmd = new CortexCommandBuilder("cortexcli")
                .archive(false)
                .target("alpine:latest")
                .build();

        assertFalse(cmd.contains("--archive"));
        assertFalse(cmd.contains("--archive-format"));
        assertEquals("alpine:latest", cmd.get(cmd.size() - 1));
    }

    @Test
    void includesSourceAndUploadModeWhenSet() {
        List<String> cmd = new CortexCommandBuilder("cortexcli")
                .archive(false)
                .source("jenkins")
                .uploadMode("all")
                .target("alpine:latest")
                .build();

        assertEquals("jenkins", valueAfter(cmd, "--source"));
        assertEquals("all", valueAfter(cmd, "--upload-mode"));
        assertEquals("alpine:latest", cmd.get(cmd.size() - 1), "target stays last after the new flags");
    }

    @Test
    void omitsSourceAndUploadModeWhenBlank() {
        List<String> cmd = new CortexCommandBuilder("cortexcli")
                .archive(false)
                .source("")
                .uploadMode(null)
                .target("alpine:latest")
                .build();

        assertFalse(cmd.contains("--source"));
        assertFalse(cmd.contains("--upload-mode"));
    }

    @Test
    void requiresTarget() {
        assertThrows(
                IllegalStateException.class,
                () -> new CortexCommandBuilder("cortexcli").name("x").build());
    }

    private static String valueAfter(List<String> cmd, String flag) {
        int i = cmd.indexOf(flag);
        return i >= 0 && i + 1 < cmd.size() ? cmd.get(i + 1) : null;
    }
}
