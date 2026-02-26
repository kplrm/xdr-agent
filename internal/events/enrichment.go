package events

// Enrichment adds contextual data to events before they are shipped.
// Examples: GeoIP for network events, MITRE ATT&CK tags for behavior events,
// threat intel reputation scores for IoC matches.

// Enricher is a function that adds context to an event in-place.
type Enricher func(event *Event)

// EnrichmentChain applies multiple enrichers in sequence.
type EnrichmentChain struct {
	enrichers []Enricher
}

// NewEnrichmentChain creates a new enrichment chain.
func NewEnrichmentChain(enrichers ...Enricher) *EnrichmentChain {
	return &EnrichmentChain{enrichers: enrichers}
}

// Enrich applies all enrichers to the event.
func (ec *EnrichmentChain) Enrich(event *Event) {
	for _, enricher := range ec.enrichers {
		enricher(event)
	}
}
