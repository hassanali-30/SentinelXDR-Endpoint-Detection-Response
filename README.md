# SentinelXDR — Endpoint Detection, Response and Forensics

[![CI](https://github.com/hassanali-30/SentinelXDR-Endpoint-Detection-Response/actions/workflows/ci.yml/badge.svg)](https://github.com/hassanali-30/SentinelXDR-Endpoint-Detection-Response/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

SentinelXDR is a defensive Python prototype for correlating endpoint, file-integrity, malware, phishing, and threat-intelligence signals in an isolated security lab.

It provides a single workflow for normalizing security events, applying detection rules, mapping findings to MITRE ATT&CK techniques, triaging suspicious files and emails, queuing response intents, and preserving an auditable case timeline.

The project is designed for learning, portfolio demonstration, and controlled lab testing. It is not presented as a production XDR replacement.

## Core capabilities

- **Endpoint and file-integrity monitoring**  
  Create file hashes, compare approved directory snapshots, and represent endpoint telemetry as normalized events.

- **Detection and ATT&CK mapping**  
  Match normalized events against JSON detection rules and attach relevant MITRE ATT&CK technique identifiers.

- **Static malware triage**  
  Calculate hashes, inspect entropy and printable strings, identify basic PE characteristics, and record a non-executing analysis result.

- **Phishing triage**  
  Review authorized email exports, URLs, headers, and attachment names using transparent risk indicators.

- **Safe response orchestration**  
  Match alerts to allowlisted response intents such as host isolation, indicator blocking, quarantine, evidence collection, and notification. Actions are simulated or queued and require approval.

- **Case and forensic timeline**  
  Group related events and response decisions into cases with an ordered evidence trail.

## Architecture

```text
Endpoint/FIM and approved feeds
              |
       Event normalization
              |
      Detection rules + ATT&CK
          /              \
  Malware triage     Phishing triage
          \              /
       IOC and SIEM adapters
              |
      Approval-gated SOAR queue
              |
       Case and evidence timeline
```

The command-line application uses local files and JSON rules. It does not require an external SIEM, endpoint agent, database server, or cloud service for the demonstration workflow.

## Requirements

- Python 3.10 or newer
- A local virtual environment
- An isolated and authorized lab for any security testing

## Installation

```bash
git clone https://github.com/hassanali-30/SentinelXDR-Endpoint-Detection-Response.git
cd SentinelXDR-Endpoint-Detection-Response

python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```powershell
.venv\\Scripts\\Activate.ps1
```

**Linux/macOS**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Run the built-in demonstration:

```bash
python sentinelxdr.py demo
```

Run detections against the supplied sample telemetry:

```bash
python sentinelxdr.py detect \
  --events sample_events.json \
  --rules rules/sigma_rules.json
```

Perform static analysis on an approved sample file. The tool does not execute the file:

```bash
python sentinelxdr.py malware path/to/approved/sample.bin
```

Triage an authorized email export:

```bash
python sentinelxdr.py phishing path/to/message.eml
```

Create a file-integrity snapshot for an approved lab directory:

```bash
python sentinelxdr.py fim path/to/approved/lab-directory
```

## Project structure

```text
sentinelxdr.py          # CLI, event processing, detections, triage, and cases
sample_events.json      # Safe demonstration telemetry
rules/                  # Detection rules
tests/                  # Automated tests
SECURITY.md             # Defensive-use and reporting policy
```

The normalized event boundary allows future adapters for the Mini-SIEM, IOC platform, and honeypot projects in this portfolio. Network-active integrations are intentionally excluded from this reference implementation.

## Safety and privacy

Use SentinelXDR only with systems, files, messages, and telemetry that you own or are explicitly authorized to analyze.

- Malware analysis is static; samples are never executed.
- Response actions are simulated or queued by default.
- The project does not run arbitrary shell commands or perform destructive endpoint changes.
- Do not commit real malware, credentials, private email, or sensitive telemetry to a public repository.
- Replace demonstration data with synthetic or sanitized data before sharing results.

## Limitations

SentinelXDR is a learning and defensive prototype. Its detections and risk scores depend on the quality of supplied telemetry, rules, and analyst context. Validate rules against representative data before using them in an operational environment.

It currently does not provide live endpoint collection, full Sigma YAML compatibility, a production authentication layer, multi-user case management, or a real containment integration.

## Testing

Run the test suite with:

```bash
python -m pytest -q
```

## Roadmap

- FastAPI ingestion API with authentication and rate limiting
- Optional `psutil` and `watchdog` endpoint collectors
- Full Sigma YAML rule support
- Organization-approved YARA rule loading
- PostgreSQL persistence and a web dashboard
- Reviewed adapters for approved Mini-SIEM, IOC, and honeypot integrations
- Signed, narrowly scoped response adapters with rollback controls

## License

Released under the MIT License. See [LICENSE](LICENSE).
