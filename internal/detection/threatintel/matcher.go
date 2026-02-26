// Package threatintel provides threat intelligence matching capabilities.
// It compares observed indicators (file hashes, IPs, domains, URLs) against
// known threat indicators from various intelligence sources.
package threatintel

// Matcher compares events against loaded Indicators of Compromise (IoCs).

// TODO: Implement IoC matcher
// - Support indicator types: sha256, md5, sha1, ipv4, ipv6, domain, url, email
// - Load IoCs from:
//   * Local files (rules/threatintel/)
//   * Control plane pushed lists
//   * STIX/TAXII feeds
// - Use bloom filters for fast negative lookups
// - Match against every relevant event field
// - Emit "threatintel.match" alert with indicator details and source
