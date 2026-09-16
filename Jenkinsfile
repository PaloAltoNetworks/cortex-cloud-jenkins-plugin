/*
 * Standard ci.jenkins.io build for a jenkinsci-hosted plugin.
 *
 * buildPlugin(...) is a shared pipeline step provided by ci.jenkins.io.
 * It builds and tests the plugin across the configured platform/JDK matrix.
 *
 * PLACEHOLDER: this assumes the repo is hosted under the jenkinsci org and
 * built by ci.jenkins.io. Confirm before publishing.
 */
buildPlugin(
  // Use the recommended container agents on ci.jenkins.io.
  useContainerAgent: true,

  // Build across the supported JDK / platform combinations.
  // Build JDK is 21; the plugin compiles to Java 17 (see pom.xml).
  configurations: [
    [platform: 'linux',   jdk: 21],
    [platform: 'windows', jdk: 17],
  ]
)
