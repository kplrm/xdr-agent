// Package cloud provides cloud environment awareness and container security.
package cloud

// Metadata collects cloud provider metadata (AWS, GCP, Azure) to enrich events
// with cloud context: instance ID, region, account, tags, IAM role.

// TODO: Implement cloud metadata collection
// - AWS: IMDSv2 (http://169.254.169.254/latest/meta-data/ with token)
// - GCP: Metadata server (http://metadata.google.internal/computeMetadata/v1/)
// - Azure: IMDS (http://169.254.169.254/metadata/instance?api-version=2021-02-01)
// - Auto-detect cloud provider
// - Cache metadata (refresh periodically)
// - Enrich all events with cloud context fields
