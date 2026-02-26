# Threat Intelligence Feed Integration
#
# The XDR agent supports consuming threat intelligence from multiple sources
# to match observed indicators (file hashes, IPs, domains) against known threats.
#
# Supported feed formats:
#   - STIX 2.x (JSON bundles)
#   - TAXII 2.x (automated feed retrieval)
#   - MISP (event export format)
#   - CSV (simple hash/IP/domain lists)
#   - OpenCTI (via API)
#
# Configuration:
#   Feeds are configured in the agent's config.json under "threat_intel.feeds":
#
#   "threat_intel": {
#     "enabled": true,
#     "feeds": [
#       {
#         "name": "abuse-ch-malware-bazaar",
#         "type": "csv",
#         "url": "https://bazaar.abuse.ch/export/csv/recent/",
#         "interval_hours": 1,
#         "indicator_types": ["sha256"]
#       },
#       {
#         "name": "custom-stix-feed",
#         "type": "taxii",
#         "url": "https://threatintel.example.com/taxii2/",
#         "api_key": "${TAXII_API_KEY}",
#         "interval_hours": 6,
#         "indicator_types": ["sha256", "ipv4", "domain"]
#       }
#     ]
#   }
#
# Free threat intel sources:
#   - abuse.ch (Malware Bazaar, URLhaus, ThreatFox)
#   - AlienVault OTX
#   - CIRCL (Luxembourg CERT)
#   - Emerging Threats (Proofpoint open rules)
#   - VirusTotal (with API key)
