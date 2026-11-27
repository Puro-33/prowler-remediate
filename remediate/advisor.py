import importlib
import os
from typing import Callable, Optional


class Advisor:
    def advise(self, plan_dict: dict) -> str:
        raise NotImplementedError


class RuleAdvisor(Advisor):
    def advise(self, plan_dict):
        br = plan_dict["blast_radius"]
        risk = br.get("risk", "unknown")
        return f"rule-based: risk={risk}; {br.get('summary', '')}"


class LLMAdvisor(Advisor):
    def __init__(self, complete: Callable[[str], str]):
        self.complete = complete

    def advise(self, plan_dict):
        prompt = (
            "Review this cloud remediation plan. Reply in 3 short lines: "
            "what may break, what to check before approving, rollback ok?\n"
            f"{plan_dict}"
        )
        return "llm: " + self.complete(prompt)


def load_advisor(kind: str = "rules") -> Advisor:
    if kind != "llm":
        return RuleAdvisor()
    target = os.environ.get("REMEDIATE_LLM_FUNC")
    if not target:
        return RuleAdvisor()
    mod, _, func = target.partition(":")
    return LLMAdvisor(getattr(importlib.import_module(mod), func))
