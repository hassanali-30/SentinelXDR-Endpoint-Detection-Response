# Security Policy

SentinelXDR is for authorized defensive lab use only.

Safety boundaries:
- Malware analysis is static-only; samples are never executed.
- SOAR actions are simulated by default and only queued after explicit approval.
- No arbitrary shell execution is implemented.
- Endpoint collection should be scoped to approved hosts and paths.
- Do not commit malware, credentials, private logs, or sensitive email contents.

Production adapters must add least-privilege credentials, authentication, authorization, rate limiting, rollback, secure secret storage, and independent approval.
