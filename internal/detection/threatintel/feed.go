package threatintel

// Feed handles ingestion of threat intelligence from external sources.
//
// Supported feed formats:
//  - STIX 2.1 (Structured Threat Information eXpression)
//  - TAXII 2.1 (Trusted Automated eXchange of Intelligence Information)
//  - MISP (Malware Information Sharing Platform) JSON format
//  - CSV (simple hash/IP/domain lists)
//  - OpenCTI export format

// TODO: Implement feed ingestion
// - Schedule periodic feed pulls (configurable interval)
// - Parse STIX bundles → extract indicators
// - Support authentication for TAXII servers
// - Deduplicate indicators across sources
// - Expire indicators based on valid_until field
// - Store in local database for fast lookup
