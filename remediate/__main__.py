import argparse
import json
import sys

from remediate.cli import demo

p = argparse.ArgumentParser(prog="remediate")
p.add_argument("--demo", choices=["s3", "s3-write", "s3-list", "ssh", "rdp", "ebs", "iam-length"], required=True)
p.add_argument("--approve", action="store_true")
p.add_argument("--advisor", choices=["rules", "llm"], default="rules")
p.add_argument("--out", default="remediate_result.json")
a = p.parse_args()
res = demo(a.demo, approve=a.approve, advisor_kind=a.advisor, out=a.out)
print(
    json.dumps(
        {"outcome": res.outcome, "timings": res.timings, "total_seconds": res.total_seconds},
        indent=2,
    )
)
sys.exit(0 if res.outcome in ("fixed", "dry-run") else 1)
