package org.jenkinsci.plugins.cortexcloud.shared;

import java.io.Serializable;

/**
 * Repository and tag identifying a scanned image, as reported by the Cortex CLI.
 * Mirrors the structure used by the legacy plugin so the result UI ports cleanly.
 */
public class RepoTag implements Serializable {
    private static final long serialVersionUID = 1L;

    private String registry;
    private String repo;
    private String tag;

    public RepoTag(String registry, String repo, String tag) {
        this.registry = registry;
        this.repo = repo;
        this.tag = tag;
    }

    public String getRegistry() {
        return registry;
    }

    public String getRepo() {
        return repo;
    }

    public String getTag() {
        return tag;
    }

    /**
     * @return a human-readable [registry/]repo:tag string
     */
    public String getFullName() {
        StringBuilder sb = new StringBuilder();
        if (registry != null && !registry.isEmpty()) {
            sb.append(registry);
            if (!registry.endsWith("/")) {
                sb.append('/');
            }
        }
        if (repo != null) {
            sb.append(repo);
        }
        if (tag != null && !tag.isEmpty()) {
            sb.append(':').append(tag);
        }
        return sb.toString();
    }
}
