import json
import time

from remediate.advisor import RuleAdvisor
from remediate.models import Result
from remediate.remediators import REGISTRY
from remediate.scanner import failing


class Timer:
    def __init__(self):
        self.t0 = time.perf_counter()
        self.marks = {}

    def stage(self, name):
        return _Stage(self, name)

    def total(self):
        return round(time.perf_counter() - self.t0, 4)


class _Stage:
    def __init__(self, timer, name):
        self.timer, self.name = timer, name

    def __enter__(self):
        self.s = time.perf_counter()

    def __exit__(self, *exc):
        self.timer.marks[self.name] = round(time.perf_counter() - self.s, 4)


def still_failing(finding, regions):
    return any(
        f.resource_id == finding.resource_id for f in failing(finding.check_id, regions)
    )


def remediate(finding, client, regions, approve=False, advisor=None, remediator=None):
    advisor = advisor or RuleAdvisor()
    rem = remediator or REGISTRY[finding.check_id](client)
    timer = Timer()
    result = Result(
        check_id=finding.check_id,
        resource_id=finding.resource_id,
        mode="approve" if approve else "dry-run",
        outcome="",
    )
    try:
        with timer.stage("plan"):
            plan = rem.plan(finding)
            plan.advice = advisor.advise(plan.to_dict())
            result.plan = plan.to_dict()
        if not approve:
            result.outcome = "dry-run"
            return _finish(result, timer)
        with timer.stage("snapshot"):
            result.snapshot = rem.snapshot(finding)
        try:
            with timer.stage("apply"):
                rem.apply(finding, result.snapshot)
            with timer.stage("verify"):
                ok = not still_failing(finding, regions)
        except Exception as e:
            ok = False
            result.error = f"{e.__class__.__name__}: {e}"
        if ok:
            result.outcome = "fixed"
        else:
            with timer.stage("rollback"):
                rem.restore(finding, result.snapshot)
            result.outcome = "rolled_back"
    except Exception as e:
        result.outcome = "error"
        result.error = f"{e.__class__.__name__}: {e}"
    return _finish(result, timer)


def _finish(result, timer):
    result.timings = timer.marks
    result.total_seconds = timer.total()
    return result


def write_json(result, path):
    with open(path, "w", encoding="utf8") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
