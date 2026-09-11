# Tests for DemoController patch state persistence and routes.

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
