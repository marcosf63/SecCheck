import json
import pytest

from app.models.report import Report, ReportMetadata, RiskSummary, TargetInfo
from app.models.finding import Finding, Evidence
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
        summary=RiskSummary(risk_score=78, status="COMPROMISED", confidence="high"),
        findings=[
            Finding(
                id="proc_tmp_exec",
                severity="high",
                category="process",
                title="Processo executando em diretório suspeito",
                evidence=Evidence(command="ps aux", match="/tmp/.x123/agent"),
                reasoning="Processos em /tmp são suspeitos.",
                score_contribution=20,
            ),
            Finding(
                id="ssh_unknown_key",
                severity="high",
                category="ssh",
                title="Chave SSH desconhecida",
                evidence=Evidence(file="/root/.ssh/authorized_keys", match="ssh-ed25519 AAAAC3..."),
                reasoning="Chave não reconhecida.",
                score_contribution=30,
            ),
        ],
        recommended_actions=["Isolar a máquina", "Revisar chaves SSH"],
        raw_sections={"processes": [], "network": []},
    )


class TestLLMReporter:
    def test_output_is_valid_json(self, sample_report):
        output = to_llm_json(sample_report)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_has_required_top_level_keys(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        assert "metadata" in data
        assert "summary" in data
        assert "findings" in data
        assert "recommended_actions" in data
        assert "raw_sections" in data

    def test_metadata_fields(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        meta = data["metadata"]
        assert meta["tool"] == "sec-check"
        assert meta["scan_type"] == "deep"
        assert meta["target"]["host"] == "10.0.0.1"
        assert meta["target"]["port"] == 22
        assert meta["target"]["user"] == "ubuntu"

    def test_summary_fields(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        summary = data["summary"]
        assert summary["risk_score"] == 78
        assert summary["status"] == "COMPROMISED"
        assert summary["confidence"] == "high"

    def test_findings_structure(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        assert len(data["findings"]) == 2
        f = data["findings"][0]
        assert "id" in f
        assert "severity" in f
        assert "category" in f
        assert "title" in f
        assert "evidence" in f
        assert "reasoning" in f
        # score_contribution não deve aparecer no LLM reporter
        assert "score_contribution" not in f

    def test_evidence_has_no_null_values(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        for finding in data["findings"]:
            for v in finding["evidence"].values():
                assert v is not None

    def test_recommended_actions(self, sample_report):
        data = json.loads(to_llm_json(sample_report))
        assert "Isolar a máquina" in data["recommended_actions"]

    def test_json_reporter_includes_score_contribution(self, sample_report):
        data = json.loads(to_json(sample_report))
        assert data["findings"][0]["score_contribution"] == 20


class TestJSONReporter:
    def test_valid_json(self, sample_report):
        output = to_json(sample_report)
        data = json.loads(output)
        assert data["summary"]["risk_score"] == 78

    def test_save_to_file(self, sample_report, tmp_path):
        from app.reporters.json_reporter import save_json
        path = str(tmp_path / "report.json")
        save_json(sample_report, path)
        with open(path) as f:
            data = json.load(f)
        assert data["summary"]["status"] == "COMPROMISED"

    def test_save_llm_to_file(self, sample_report, tmp_path):
        from app.reporters.llm_reporter import save_llm_json
        path = str(tmp_path / "llm_report.json")
        save_llm_json(sample_report, path)
        with open(path) as f:
            data = json.load(f)
        assert "findings" in data
