# prowler-remediate

Closed-loop fixes for [Prowler](https://github.com/prowler-cloud/prowler) AWS findings:
**plan, snapshot, apply, verify, roll back**. Prowler's own `--fixer` applies a change and
returns a bool. This adds the parts around it: a reviewable plan, a saved copy of the
original state, a re-scan of the same check to confirm the finding is really gone, and an
automatic restore when it is not.

Status: proof of concept. It only runs against [moto](https://github.com/getmoto/moto)
(a fake in-memory AWS). There is no CLI path to a real account.

## Why

- `--fixer` has no fixer for the SG port 22 / 3389 checks, gives no plan, and cannot undo.
- Fixers use global singleton clients created at start-up, so a re-scan after the fix can
  read stale state. This tool re-scans in the same process with fresh clients.
- A successful API call is not proof the finding is gone. Verify re-runs the check.

## Flow

```
finding (FAIL) -> plan (diff + blast radius + advice)
               -> [stop here unless --approve]
               -> snapshot -> apply -> verify (same check, this resource)
                                          PASS -> fixed
                                          FAIL / exception -> restore snapshot -> rolled_back
```

Each step is timed; the result JSON has `timings` and `total_seconds`.

## Covered checks (7)

| Check id | Fix |
|---|---|
| `s3_bucket_public_access` | bucket PublicAccessBlock on |
| `s3_bucket_public_write_acl` | drop AllUsers/AuthenticatedUsers write grants |
| `s3_bucket_public_list_acl` | drop AllUsers/AuthenticatedUsers read grants |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | remove 0.0.0.0/0 rule |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389` | remove 0.0.0.0/0 rule |
| `ec2_ebs_default_encryption` | enable EBS default encryption |
| `iam_password_policy_minimum_length_14` | minimum length 14 |

## Install

Python 3.10 to 3.13. Installing pulls in `prowler==5.52.0` (large).

```
python -m venv .venv
.venv/bin/pip install -e ".[test]"        # Windows: .venv\Scripts\pip
```

## Use

```
python -m remediate --demo s3                      # dry-run: prints the plan only
python -m remediate --demo s3 --approve            # apply + verify, writes remediate_result.json
python -m remediate --demo ssh --approve
# kinds: s3 s3-write s3-list ssh rdp ebs iam-length
```

`--demo` seeds a vulnerable resource in moto, scans it with the real Prowler check, then runs
the loop. The advisor is rule-based by default. To plug an LLM in for the "what could break"
note, set `REMEDIATE_LLM_FUNC=pkg.module:function` (a `str -> str` callable). The fix commands
themselves are fixed templates, never LLM output, and no key is read by this code.

## CI

- `.github/workflows/remediate-plan-comment.yml`: on a pull request, runs all seven demos
  as dry-runs against moto and posts (or updates) one comment with the plans.
- `.github/workflows/remediate-gate.yml`: manual or reusable. Fails if a Prowler `json-ocsf`
  re-scan file still contains FAIL findings (`python -m remediate.ci.gate "<glob>"`).
- `.github/workflows/tests.yml`: pytest.
- `samples/ocsf-pass.json` / `samples/ocsf-fail.json`: hand-written minimal OCSF inputs for the gate (pass exits 0, fail exits 1).

## Tests

```
python -m pytest remediate/tests -q
```

## Limits

- moto only. Nothing here was run against a real AWS account, and timings measured on moto
  say nothing about real API latency.
- The plan/gate workflows were exercised on GitHub-hosted runners with sample input only;
  not validated inside a real remediation pipeline.
- The apply logic duplicates what Prowler fixers do for the S3 checks (two copies to keep in sync).
- It depends on Prowler internals (service class names), pinned to `prowler==5.52.0`.
- Verify re-runs only the one check; it does not detect other checks newly failing.
- Snapshot covers only what is changed (for example SG: the removed rule, not tags or description).
- S3 blast radius looks at ACLs, website config and object count; for bucket-policy exposure
  it does not say which policy statement is responsible.
- moto does not implement a few EC2 APIs Prowler calls; those errors appear in the log and do
  not change the result.

## License

Apache-2.0, see `LICENSE` and `NOTICE`. Built on Prowler
(https://github.com/prowler-cloud/prowler, Apache-2.0); not affiliated with Prowler.
