package org.jenkinsci.plugins.cortexcloud.scanner;

import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import java.util.List;
import org.jenkinsci.plugins.cortexcloud.global.Config;

/**
 * Scans a container image with "cortexcli image scan".
 *
 * The image is identified by its reference (e.g. myrepo/app:1.2.3). The CLI talks
 * to the local Docker daemon to read the image, optionally via a caller-supplied
 * --docker-host. CI metadata (pipeline/build IDs) is forwarded so results are
 * correlated in the Cortex console.
 */
public class ImageScanner extends Scanner {

    private final String image;
    private final String dockerHost;
    private final String scanName;
    private final String ciPipelineId;
    private final String ciBuildId;
    private final Integer timeoutSeconds;
    private final String source;
    private final String uploadMode;

    public ImageScanner(
            Run<?, ?> run,
            FilePath workspace,
            Launcher launcher,
            TaskListener listener,
            Config config,
            String image,
            String dockerHost,
            String scanName,
            String ciPipelineId,
            String ciBuildId,
            Integer timeoutSeconds,
            String source,
            String uploadMode) {
        super(run, workspace, launcher, listener, config);
        this.image = image;
        this.dockerHost = dockerHost;
        this.scanName = scanName;
        this.ciPipelineId = ciPipelineId;
        this.ciBuildId = ciBuildId;
        this.timeoutSeconds = timeoutSeconds;
        this.source = source;
        this.uploadMode = uploadMode;
    }

    @Override
    protected List<String> buildCommand(String cliPath) throws IOException, InterruptedException {
        if (image == null || image.trim().isEmpty()) {
            throw new IOException("image reference is required");
        }
        return new CortexCommandBuilder(cliPath)
                // Scanning an image reference (not a tar archive).
                .archive(false)
                .name(scanName != null && !scanName.trim().isEmpty() ? scanName : image)
                .dockerHost(dockerHost)
                .ciPipelineId(ciPipelineId)
                .ciBuildId(ciBuildId)
                .timeoutSeconds(timeoutSeconds)
                .source(source)
                .uploadMode(uploadMode)
                .target(image.trim())
                .build();
    }

    @Override
    protected String describeTarget() {
        return "image " + image;
    }

    @Override
    protected Integer getTimeoutSeconds() {
        return timeoutSeconds;
    }
}
