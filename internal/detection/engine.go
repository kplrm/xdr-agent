// Package detection provides the detection engine layer for the XDR agent.
// Detection engines consume telemetry events and produce security alerts when
// threats or suspicious activity are identified.
//
// Sub-packages:
//   - malware/     — Static malware detection (hashes, YARA, file analysis)
//   - behavioral/  — Behavioral rule-based detection (process chains, scripts, LOLBins)
//   - memory/      — Memory and exploit detection (injection, hollowing, fileless)
//   - threatintel/ — Threat intelligence IoC matching
package detection

// Engine orchestrates all detection sub-engines. It subscribes to telemetry
// events from the pipeline and routes them to the appropriate detection module.

// TODO: Implement detection engine
// - Subscribe to event pipeline for telemetry events
// - Route events to registered detection modules
// - Collect alerts from detection modules → emit to pipeline as "alert" events
// - Support detection mode: "detect" (alert only) vs "prevent" (block + alert)
