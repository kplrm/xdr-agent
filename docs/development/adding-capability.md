# Changing the runtime

Keep changes within process/file/network collection or release-bundled YARA protection. Ransomware, memory, and behavioral features need a separate scope decision before implementation; do not add placeholders for them.

Use the shared event envelope and lifecycle in `internal/service/run.go`. Keep dependencies explicit in constructors and comments concise. Coordinator policies group agents; they do not distribute protection content.

For an HTTP change, update `docs/api-endpoints.md`, its contract/test case, and the receiving Coordinator route together. New endpoints must pass the build's API regression check. Protection changes need positive/negative matching tests and failure-path tests; Linux enforcement needs disposable privileged host validation.

Run `make test` and `make build`. Update architecture and roadmap claims to match the implemented behavior and known limits.
