from sentinelxdr import Event, FileIntegrityMonitor, MalwareAnalyzer, PhishingTriage, SigmaEngine, SOARQueue, CaseManager

def test_sigma_maps_attack_technique():
    event = Event("process_start", "high", "edr", "host", {"process_name": "powershell.exe"})
    alerts = SigmaEngine([{"id":"r1","title":"PowerShell","tags":["T1059.001"],"detection":{"process_name":"powershell.exe"}}]).match(event)
    assert alerts[0]["techniques"] == ["T1059.001"]

def test_malware_analysis_is_static(tmp_path):
    path = tmp_path / "sample.exe"; path.write_bytes(b"MZ" + b"A" * 100)
    result = MalwareAnalyzer().analyze(path)
    assert result["is_pe"] is True
    assert result["sandbox"]["executed"] is False
    assert "pe_signature" in result["findings"]

def test_phishing_triage_flags_link(tmp_path):
    path = tmp_path / "mail.eml"
    path.write_text("From: sender@example.test\nSubject: Invoice\nMIME-Version: 1.0\nContent-Type: text/plain\n\nPlease review https://example.test/login\n", encoding="utf-8")
    result = PhishingTriage().analyze(path)
    assert result["urls"]

def test_fim_diff():
    diff = FileIntegrityMonitor().diff({"a":"1","b":"2"}, {"a":"9","c":"3"})
    assert diff == {"added":["c"],"removed":["b"],"modified":["a"]}

def test_soar_is_safe_by_default(tmp_path):
    q = SOARQueue(tmp_path / "actions.db")
    event = Event("malware_alert", "high", "edr", "host", {})
    try:
        assert q.queue(event, "isolate_host", "host")["status"] == "simulated"
    finally: q.close()

def test_case_timeline_is_ordered(tmp_path):
    c = CaseManager(tmp_path / "case.db")
    try:
        c.create("C1", "Demo")
        c.add("C1", Event("late", "low", "test", "x", {}, "2026-01-02T00:00:00Z"), "late")
        c.add("C1", Event("early", "low", "test", "x", {}, "2026-01-01T00:00:00Z"), "early")
        assert [x["summary"] for x in c.timeline("C1")] == ["early", "late"]
    finally: c.close()
