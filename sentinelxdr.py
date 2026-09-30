#!/usr/bin/env python3
"""SentinelXDR: defensive endpoint telemetry, detection, triage, response and cases."""
from __future__ import annotations
import argparse, hashlib, json, math, os, re, sqlite3, sys
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

URL_RE = re.compile(r"https?://[^\s<>()\"']+", re.I)
SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".ps1", ".hta", ".iso", ".lnk", ".docm", ".xlsm"}

def now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = [data.count(bytes([i])) for i in range(256)]
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts if n)

@dataclass
class Event:
    event_type: str
    severity: str
    source: str
    entity: str
    fields: dict[str, Any]
    timestamp: str = ""
    event_id: str = ""

    def __post_init__(self):
        self.timestamp = self.timestamp or now()
        self.event_id = self.event_id or sha256_bytes(f"{self.timestamp}:{self.event_type}:{self.entity}".encode())[:16]

    def to_dict(self): return asdict(self)

class FileIntegrityMonitor:
    def snapshot(self, root: str | Path, max_files: int = 500) -> dict[str, str]:
        root = Path(root)
        result = {}
        for path in sorted(root.rglob("*")):
            if len(result) >= max_files: break
            if path.is_file() and not any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
                try: result[str(path.relative_to(root))] = sha256_bytes(path.read_bytes())
                except OSError: continue
        return result

    def diff(self, before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
        return {"added": sorted(set(after) - set(before)),
                "removed": sorted(set(before) - set(after)),
                "modified": sorted(k for k in set(before) & set(after) if before[k] != after[k])}

class SigmaEngine:
    def __init__(self, rules: list[dict[str, Any]]): self.rules = rules

    def match(self, event: Event) -> list[dict[str, Any]]:
        alerts = []
        for rule in self.rules:
            detection = rule.get("detection", {})
            ok = True
            for field, expected in detection.items():
                actual = getattr(event, field, event.fields.get(field))
                if isinstance(expected, list): ok = actual in expected
                elif isinstance(expected, str) and expected.startswith("*") and expected.endswith("*"): ok = expected.strip("*").lower() in str(actual).lower()
                else: ok = actual == expected
                if not ok: break
            if ok:
                alerts.append({"rule_id": rule["id"], "title": rule["title"], "level": rule.get("level", "medium"),
                                "techniques": rule.get("tags", []), "event_id": event.event_id})
        return alerts

class MalwareAnalyzer:
    def analyze(self, path: str | Path) -> dict[str, Any]:
        path = Path(path)
        data = path.read_bytes()
        ascii_strings = re.findall(rb"[ -~]{6,}", data)
        strings = [s.decode("ascii", "replace")[:200] for s in ascii_strings[:100]]
        findings = []
        if path.suffix.lower() in SUSPICIOUS_EXTENSIONS: findings.append("suspicious_extension")
        if data[:2] == b"MZ": findings.append("pe_signature")
        if entropy(data) >= 7.2: findings.append("high_entropy")
        if any(x in " ".join(strings).lower() for x in ("powershell", "wscript", "cmd.exe", "http://", "https://")): findings.append("suspicious_string")
        return {"path": str(path), "sha256": sha256_bytes(data), "size": len(data), "entropy": round(entropy(data), 3),
                "is_pe": data[:2] == b"MZ", "strings": strings, "findings": sorted(set(findings)),
                "verdict": "suspicious" if findings else "no_static_indicators", "sandbox": {"executed": False, "reason": "static-only safe mode"}}

class PhishingTriage:
    def analyze(self, path: str | Path) -> dict[str, Any]:
        raw = Path(path).read_bytes()
        message = BytesParser(policy=policy.default).parsebytes(raw)
        urls = URL_RE.findall(message.get_body(preferencelist=("plain", "html")).get_content() if message.get_body() else raw.decode("utf-8", "replace"))
        attachments = []
        for part in message.iter_attachments():
            filename = part.get_filename() or "unnamed"
            attachments.append({"filename": filename, "size": len(part.get_payload(decode=True) or b""), "extension": Path(filename).suffix.lower()})
        risk, reasons = 0, []
        sender = str(message.get("From", ""))
        reply_to = str(message.get("Reply-To", ""))
        if reply_to and reply_to.lower() not in sender.lower(): risk += 25; reasons.append("reply_to_mismatch")
        if len(urls) >= 3: risk += 15; reasons.append("many_links")
        if any(Path(a["filename"]).suffix in SUSPICIOUS_EXTENSIONS for a in attachments): risk += 45; reasons.append("risky_attachment")
        if any(re.search(r"(login|verify|urgent|password|invoice)", u, re.I) for u in urls): risk += 20; reasons.append("credential_or_urgency_link")
        return {"subject": str(message.get("Subject", "")), "from": sender, "urls": urls, "attachments": attachments,
                "risk_score": min(risk, 100), "reasons": reasons, "verdict": "high_risk" if risk >= 50 else ("review" if risk >= 20 else "low_risk")}

class SOARQueue:
    ALLOWED = {"notify", "collect_evidence", "isolate_host", "block_ip", "quarantine_file"}
    def __init__(self, db: str | Path):
        self.db = sqlite3.connect(db)
        self.db.execute("create table if not exists actions (id integer primary key, event_id text, action text, target text, status text, created_at text)")
        self.db.commit()
    def queue(self, event: Event, action: str, target: str, approved: bool = False) -> dict[str, Any]:
        if action not in self.ALLOWED: raise ValueError("action is not allowlisted")
        status = "simulated" if not approved else "queued"
        self.db.execute("insert into actions(event_id,action,target,status,created_at) values(?,?,?,?,?)", (event.event_id, action, target, status, now()))
        self.db.commit()
        return {"event_id": event.event_id, "action": action, "target": target, "status": status}
    def close(self): self.db.close()

class CaseManager:
    def __init__(self, db: str | Path):
        self.db = sqlite3.connect(db)
        self.db.execute("create table if not exists cases (case_id text primary key, title text, status text, created_at text)")
        self.db.execute("create table if not exists timeline (case_id text, timestamp text, kind text, summary text, data_json text)")
        self.db.commit()
    def create(self, case_id: str, title: str) -> None:
        self.db.execute("insert or ignore into cases values(?,?,?,?)", (case_id, title, "open", now())); self.db.commit()
    def add(self, case_id: str, event: Event, summary: str) -> None:
        self.db.execute("insert into timeline values(?,?,?,?,?)", (case_id, event.timestamp, event.event_type, summary, json.dumps(event.to_dict(), sort_keys=True))); self.db.commit()
    def timeline(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.db.execute("select timestamp,kind,summary,data_json from timeline where case_id=? order by timestamp", (case_id,)).fetchall()
        return [{"timestamp": r[0], "kind": r[1], "summary": r[2], "data": json.loads(r[3])} for r in rows]
    def close(self): self.db.close()

def load_events(path: str) -> list[Event]:
    return [Event(**item) for item in json.loads(Path(path).read_text(encoding="utf-8"))]

def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelXDR defensive lab platform")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("detect"); p.add_argument("--events", required=True); p.add_argument("--rules", default="rules/sigma_rules.json")
    p = sub.add_parser("malware"); p.add_argument("path")
    p = sub.add_parser("phishing"); p.add_argument("path")
    p = sub.add_parser("fim"); p.add_argument("root")
    p = sub.add_parser("demo"); p.add_argument("--output", default="sentinelxdr-demo.json")
    args = parser.parse_args()
    if args.command == "detect":
        engine = SigmaEngine(json.loads(Path(args.rules).read_text()))
        print(json.dumps([{"event": e.to_dict(), "alerts": engine.match(e)} for e in load_events(args.events)], indent=2))
    elif args.command == "malware": print(json.dumps(MalwareAnalyzer().analyze(args.path), indent=2))
    elif args.command == "phishing": print(json.dumps(PhishingTriage().analyze(args.path), indent=2))
    elif args.command == "fim": print(json.dumps(FileIntegrityMonitor().snapshot(args.root), indent=2))
    else:
        event = Event("malware_alert", "high", "edr", "lab-host", {"path": "sample.bin"})
        soar = SOARQueue("sentinelxdr.db"); case = CaseManager("sentinelxdr.db")
        try:
            case.create("CASE-DEMO", "SentinelXDR demonstration incident")
            case.add("CASE-DEMO", event, "Simulated malware alert received from EDR")
            result = {"event": event.to_dict(), "response": soar.queue(event, "isolate_host", "lab-host"), "timeline": case.timeline("CASE-DEMO")}
            Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8"); print(json.dumps(result, indent=2))
        finally: soar.close(); case.close()
    return 0

if __name__ == "__main__": raise SystemExit(main())

