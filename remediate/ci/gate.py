"""Fail (exit 1) when a re-scan (prowler -M json-ocsf) still contains FAIL findings."""

import argparse
import glob
import json
import sys


def load_events(path):
    files = sorted(glob.glob(path)) if any(c in path for c in "*?[") else [path]
    if not files:
        raise FileNotFoundError(path)
    events = []
    for f in files:
        with open(f, encoding="utf8") as fh:
            data = json.load(fh)
        events.extend(data if isinstance(data, list) else [data])
    return events


def failing(events, checks=None):
    out = []
    for e in events:
        if e.get("status_code") != "FAIL":
            continue
        check = (e.get("metadata") or {}).get("event_code", "")
        if checks and check not in checks:
            continue
        resources = e.get("resources") or [{}]
        out.append(
            {
                "check_id": check,
                "resource": resources[0].get("uid") or resources[0].get("name", ""),
                "message": e.get("status_detail", ""),
            }
        )
    return out


def main(argv=None):
    p = argparse.ArgumentParser(prog="remediate-gate")
    p.add_argument("ocsf", help="json-ocsf output file or glob")
    p.add_argument("--checks", nargs="*", help="only gate on these check ids")
    p.add_argument("--summary", help="append a markdown summary to this file")
    a = p.parse_args(argv)
    events = load_events(a.ocsf)
    bad = failing(events, set(a.checks) if a.checks else None)
    lines = [f"scanned findings: {len(events)}, FAIL remaining: {len(bad)}"]
    lines += [f"- {b['check_id']} {b['resource']}: {b['message']}" for b in bad]
    text = "\n".join(lines)
    print(text)
    if a.summary:
        with open(a.summary, "a", encoding="utf8") as fh:
            fh.write("### Remediation gate\n" + text + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
