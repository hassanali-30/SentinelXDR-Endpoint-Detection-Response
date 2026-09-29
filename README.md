# SentinelXDR

A defensive endpoint detection, response, and forensics platform for an isolated security lab. SentinelXDR connects endpoint telemetry, file integrity monitoring, Sigma detections, malware and phishing triage, safe response queueing, and incident timelines in one simple Python foundation.

## Modules

1. **EDR-lite and FIM** — hash approved files, compare snapshots, and represent endpoint events.
2. **Sigma and ATT&CK** — match normalized events to JSON Sigma-like rules and map alerts to technique IDs.
3. **Malware analysis** — calculate hashes, entropy, strings, PE signatures, and a non-executing sandbox status.
4. **Phishing triage** — inspect email headers, URLs, and attachment names for a transparent risk score.
5. **SOAR queue** — simulate or queue allowlisted response intents such as isolation, blocking, quarantine, evidence collection, and notification.
6. **Case manager** — group events and actions into cases with an ordered forensic timeline.

## Quick start

\`\`\`bash
python -m venv .venv
# Windows
.venv\\\\Scripts\\\\activate
# Linux/macOS
source .venv/bin/activate

python -m pip install -r requirements.txt
python sentinelxdr.py demo
\`\`\`

Run the detection engine against sample telemetry:

\`\`\`bash
python sentinelxdr.py detect --events sample_events.json --rules rules/sigma_rules.json
\`\`\`

Analyze a file without executing it:

\`\`\`bash
python sentinelxdr.py malware path/to/approved/sample.bin
\`\`\`

Triage an authorized email export:

\`\`\`bash
python sentinelxdr.py phishing path/to/message.eml
\`\`\`

Create a file-integrity snapshot:

\`\`\`bash
python sentinelxdr.py fim path/to/approved/lab-directory
\`\`\`

## Architecture

\`\`\`text
Endpoint/FIM + Honeypot feeds
            |
      Normalized events
            |
   Sigma + ATT&CK mapping
       /          \
Malware triage   Phishing triage
       \          /
       IOC/SIEM integrations
            |
    SOAR simulation/queue
            |
    Case + forensic timeline
\`\`\`

## Integration boundaries

The project accepts normalized event dictionaries, so it can connect to your Mini-SIEM, IOC platform, and honeypot repositories through reviewed adapters. Adapters are intentionally not included as network-active integrations in this starter foundation.

## Safety

This is defensive software for authorized lab environments. Malware samples are analyzed statically and never executed. SOAR actions are simulated by default and only represented as queued intents after approval. No arbitrary shell execution or destructive endpoint action is implemented.

Do not upload real malware, credentials, private email, or sensitive telemetry to a public repository.

## Testing

\`\`\`bash
pytest -q
\`\`\`

## Roadmap

- FastAPI ingestion API with authentication and rate limits.
- Optional psutil/watchdog endpoint collectors.
- Full Sigma YAML compatibility.
- Organization-approved YARA rule loading.
- PostgreSQL persistence and React dashboard.
- Signed adapter packages for Mini-SIEM, IOC, and honeypot integrations.

## License

MIT. See [LICENSE](LICENSE).
