"""Render remediate plan result JSON files as a markdown PR comment."""

import argparse
import glob
import json
import sys

MARKER = "<!-- remediate-plan-comment -->"


def render(results):
    out = [MARKER, "## Remediation plan (dry-run)", ""]
    if not results:
        out.append("No fixable findings.")
        return "\n".join(out) + "\n"
    out += ["| check | resource | risk | outcome |", "|---|---|---|---|"]
    for r in results:
        plan = r.get("plan") or {}
        risk = (plan.get("blast_radius") or {}).get("risk", "?")
        out.append(f"| `{r['check_id']}` | `{r['resource_id']}` | {risk} | {r['outcome']} |")
    for r in results:
        plan = r.get("plan") or {}
        out += ["", f"<details><summary>{r['check_id']} / {r['resource_id']}</summary>", ""]
        out.append("Commands:")
        out += [f"- `{c}`" for c in plan.get("commands", [])]
        out += ["", "Diff:", "```json", json.dumps(plan.get("diff", {}), indent=2, default=str), "```"]
        summary = (plan.get("blast_radius") or {}).get("summary")
        if summary:
            out += ["", f"Blast radius: {summary}"]
        if plan.get("advice"):
            out += ["", f"Advice: {plan['advice']}"]
        out += ["", "</details>"]
    return "\n".join(out) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(prog="remediate-plan-comment")
    p.add_argument("results", help="result JSON file or glob")
    p.add_argument("--out", default="-")
    a = p.parse_args(argv)
    results = []
    for f in sorted(glob.glob(a.results)):
        with open(f, encoding="utf8") as fh:
            results.append(json.load(fh))
    text = render(results)
    if a.out == "-":
        sys.stdout.write(text)
    else:
        with open(a.out, "w", encoding="utf8") as fh:
            fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
