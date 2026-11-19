# Tests for DemoController patch state persistence, routes, and multi-module assessments.

from raven.server.routes import DemoController


def test_vulnerable_execution() -> None:
    c = DemoController()
    res = c.run_full()
    assert res["result"]["success"] is True
    assert res["result"]["status"] == "VULNERABILITY_CONFIRMED"
    assert len(res["result"]["findings"]) == 1
    assert res["result"]["evidence"][1]["response_status"] == 200


def test_patched_execution() -> None:
    c = DemoController()
    c.toggle_patch(False)
    res = c.run_full()
    assert res["result"]["success"] is False
    assert res["result"]["status"] == "VULNERABILITY_NOT_DETECTED"
    assert len(res["result"]["findings"]) == 0
    assert res["result"]["evidence"][1]["response_status"] == 403


def test_step_by_step_patched_execution() -> None:
    c = DemoController()
    c.toggle_patch(False)
    s1 = c.run_step(1)
    assert s1["step"] == 1
    s2 = c.run_step(2)
    assert s2["step"] == 2
    s3 = c.run_step(3)
    assert s3["step"] == 3
    assert s3["confirmed"] is False
    assert s3["response"]["status"] == 403
    assert s3["finding"] is None


def test_run_all_modules_vulnerable_and_remediated() -> None:
    c = DemoController()
    # 1. Vulnerable state: detects multiple findings across the 6 modules
    res_vuln = c.run_module("all")
    assert res_vuln["total_findings"] >= 5
    assert res_vuln["integrity_verified"] is True
    assert any(f["vulnerability_type"] == "Insecure Direct Object Reference (IDOR)" for f in res_vuln["findings"])
    assert any("Content Security Policy" in f["vulnerability_type"] or "Clickjacking" in f["vulnerability_type"] for f in res_vuln["findings"])

    # 2. Remediated state: target patched, all vulnerabilities eliminated
    c.toggle_patch(False)
    res_patch = c.run_module("all")
    assert res_patch["target"]["is_vulnerable"] is False
    assert res_patch["integrity_verified"] is True


def test_run_individual_module() -> None:
    c = DemoController()
    res_headers = c.run_module("headers")
    assert res_headers["module_requested"] == "headers"
    assert res_headers["total_evidence"] >= 1


def test_report_generation_json_and_markdown() -> None:
    c = DemoController()
    c.run_module("all")

    # JSON report
    rep_json = c.generate_report("json")
    assert isinstance(rep_json, dict)
    assert rep_json["title"] == "RAVEN Security Assessment & Vulnerability Report"
    assert rep_json["integrity_chain_valid"] is True
    assert rep_json["total_findings"] >= 1

    # Markdown report
    rep_md = c.generate_report("markdown")
    assert isinstance(rep_md, str)
    assert "# RAVEN Security Assessment & Vulnerability Report" in rep_md
    assert "HMAC Evidence Chain Integrity" in rep_md


def test_set_mode_student_and_professional() -> None:
    c = DemoController()
    assert c.mode == "student"
    res1 = c.set_mode("professional")
    assert res1["mode"] == "professional"
    assert c.mode == "professional"
    res2 = c.set_mode("student")
    assert res2["mode"] == "student"
