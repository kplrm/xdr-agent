package threatintel

// Reputation provides file, IP, and domain reputation lookups.

// TODO: Implement reputation service
// - Query external reputation services (configurable endpoints)
// - Cache results with TTL to reduce API calls
// - Support multiple providers with priority/fallback
// - Score: 0 (clean) to 100 (definitely malicious)
// - Enrich events with reputation score before shipping
