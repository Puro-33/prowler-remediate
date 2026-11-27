import json

from remediate.ci import gate, plan_comment


def ev(check, status, uid="r1"):
    return {
        "status_code": status,
        "metadata": {"event_code": check},
        "resources": [{"uid": uid}],
        "status_detail": "x",
    }


def dump(tmp_path, events, name="a.ocsf.json"):
    p = tmp_path / name
    p.write_text(json.dumps(events))
    return str(p)


def test_gate_passes_without_fail(tmp_path):
    f = dump(tmp_path, [ev("c1", "PASS"), ev("c2", "MANUAL")])
    assert gate.main([f]) == 0


def test_gate_fails_when_fail_remains(tmp_path, capsys):
    f = dump(tmp_path, [ev("c1", "PASS"), ev("c2", "FAIL", "bucket-x")])
    assert gate.main([f]) == 1
    out = capsys.readouterr().out
    assert "FAIL remaining: 1" in out and "bucket-x" in out


def test_gate_checks_filter_ignores_other_checks(tmp_path):
    f = dump(tmp_path, [ev("other", "FAIL"), ev("c1", "PASS")])
    assert gate.main([f, "--checks", "c1"]) == 0
    assert gate.main([f, "--checks", "other"]) == 1


def test_gate_glob_and_summary(tmp_path):
    dump(tmp_path, [ev("c1", "PASS")], "a.ocsf.json")
    dump(tmp_path, [ev("c2", "FAIL")], "b.ocsf.json")
    s = tmp_path / "sum.md"
    assert gate.main([str(tmp_path / "*.ocsf.json"), "--summary", str(s)]) == 1
    assert "Remediation gate" in s.read_text()


def test_plan_comment_renders_table_and_marker():
    r = {
        "check_id": "c1",
        "resource_id": "b1",
        "outcome": "dry-run",
        "plan": {
            "commands": ["aws x"],
            "diff": {"k": {"before": 1, "after": 2}},
            "blast_radius": {"risk": "low", "summary": "ok"},
            "advice": "go",
        },
    }
    text = plan_comment.render([r])
    assert text.startswith(plan_comment.MARKER)
    assert "| `c1` | `b1` | low | dry-run |" in text
    assert "aws x" in text and "Blast radius: ok" in text


def test_plan_comment_empty():
    assert "No fixable findings" in plan_comment.render([])
