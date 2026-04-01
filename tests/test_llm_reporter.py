import json
import pytest

from app.models.report import Report, ReportMetadata, TargetInfo
from app.reporters.llm_reporter import to_llm_json
from app.reporters.json_reporter import to_json


@pytest.fixture
def sample_report():
    return Report(
        metadata=ReportMetadata(
            scan_type="deep",
            target=TargetInfo(host="10.0.0.1", port=22, user="ubuntu"),
            timestamp="2026-04-01T10:00:00Z",
        ),
        sections={
            "processes": [
                {"user": "root", "pid": "1", "cpu": "0.0", "mem": "0.1", "command": "/sbin/init"},
                {"user": "www-data", "pid": "999", "cpu": "0.1", "mem": "0.5", "command": "/usr/sbin/nginx"},
            ],
            "network": {
                "ports": [{"proto": "tcp", "state": "LISTEN", "local_address": "0.0.0.0:22", "process": "sshd"}],
                "connections": [],
            },
            "ssh_keys": [
                {"path": "/root/.ssh/authorized_keys", "key_type": "ssh-ed25519", "key": "AAAAC3...", "comment": "user@host"},
            ],
        },
    )


class TestLLMReporter:
    def test_output_is_valid_json(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        assert isinstance(data, dict)

    def test_has_required_top_level_keys(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        assert "metadata" in data
        assert "sections" in data

    def test_no_score_or_findings(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        assert "summary" not in data
        assert "findings" not in data
        assert "recommended_actions" not in data
        assert "risk_score" not in str(data)

    def test_metadata_fields(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        meta = data["metadata"]
        assert meta["tool"] == "sec-check"
        assert meta["scan_type"] == "deep"
        assert meta["target"]["host"] == "10.0.0.1"
        assert meta["target"]["port"] == 22
        assert meta["target"]["user"] == "ubuntu"

    def test_sections_contain_raw_data(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        assert "processes" in data["sections"]
        assert len(data["sections"]["processes"]) == 2
        assert "network" in data["sections"]
        assert "ssh_keys" in data["sections"]

    def test_save_llm_to_file(self, sample_report, tmp_path):
        from app.reporters.llm_reporter import save_llm_json
        path = str(tmp_path / "report.json")
        save_llm_json(sample_report, path)
        with open(path) as f:
            data = json.load(f)
        assert "sections" in data


class TestJSONReporter:
    def test_valid_json(self, sample_report):
        data = json.loads(to_json(sample_report))
        assert "metadata" in data
        assert "sections" in data

    def test_no_score(self, sample_report):
        data = json.loads(to_json(sample_report))
        assert "summary" not in data

    def test_save_to_file(self, sample_report, tmp_path):
        from app.reporters.json_reporter import save_json
        path = str(tmp_path / "report.json")
        save_json(sample_report, path)
        with open(path) as f:
            data = json.load(f)
        assert data["metadata"]["target"]["host"] == "10.0.0.1"
