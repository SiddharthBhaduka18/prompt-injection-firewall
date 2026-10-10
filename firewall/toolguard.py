"""Layer 7 - Tool-call guard (action-time defence against tool abuse).

Even if an injection slips past content scanning, the agent's *actions* are checked
before execution. Each proposed tool call is evaluated against:
  1. a per-tool policy (risk tier, allowed destinations, needs human approval)
  2. provenance / taint - does the call use data or destinations that only appeared
     in untrusted content (e.g. an email address found inside a web page)?
  3. intent alignment - does the user's own request justify this action?
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
URL_RE = re.compile(r"https?://[^\s\"')<>]+")

POLICY = {
    "search_web":      {"tier": "low"},
    "read_file":       {"tier": "low"},
    "summarize":       {"tier": "low"},
    "send_email":      {"tier": "high", "allowed_domains": ["company.com"], "intent": r"\b(send|email|mail|forward|reply)\b"},
    "http_post":       {"tier": "high", "allowed_domains": ["api.company.com"], "intent": r"\b(post|upload|submit|send)\b"},
    "delete_files":    {"tier": "critical", "intent": r"\b(delete|remove|clean ?up|erase)\b"},
    "transfer_funds":  {"tier": "critical", "intent": r"\b(pay|transfer|wire|send money)\b"},
    "run_shell":       {"tier": "critical", "intent": r"\b(run|execute|shell|command)\b"},
}


@dataclass
class ToolDecision:
    tool: str
    allowed: bool
    needs_approval: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class TaintStore:
    """Indicators (emails, URLs) seen only in untrusted/flagged content."""
    indicators: set = field(default_factory=set)

    def add_from(self, text: str):
        self.indicators |= {e.lower() for e in EMAIL_RE.findall(text)}
        self.indicators |= {u.lower().rstrip(".,") for u in URL_RE.findall(text)}


def _domain(target: str) -> str:
    if target.startswith("http"):
        return target.split("/")[2].split(":")[0]
    return target.split("@")[-1]


def check(tool: str, args: dict, user_request: str, taint: TaintStore) -> ToolDecision:
    pol = POLICY.get(tool, {"tier": "critical"})
    reasons: list[str] = []
    blob = " ".join(str(v) for v in args.values())
    allowed, approval = True, False

    if tool not in POLICY:
        allowed = False
        reasons.append(f"Unknown tool '{tool}' is denied by default")

    targets = {e.lower() for e in EMAIL_RE.findall(blob)} | {u.lower().rstrip(".,") for u in URL_RE.findall(blob)}
    tainted = sorted(t for t in targets if t in taint.indicators and t not in user_request.lower())
    if tainted:
        allowed = False
        reasons.append(f"Destination {', '.join(tainted)} came from untrusted content, not from the user")

    if "allowed_domains" in pol:
        bad = [t for t in targets if not any(_domain(t).endswith(d) for d in pol["allowed_domains"])]
        bad = [b for b in bad if b not in user_request.lower()]
        if bad:
            allowed = False
            reasons.append(f"Destination {', '.join(bad)} is outside the allow-list {pol['allowed_domains']}")

    if pol["tier"] in {"high", "critical"} and "intent" in pol and not re.search(pol["intent"], user_request, re.I):
        allowed = False
        reasons.append("The user's request does not ask for this kind of action (intent mismatch)")

    if pol["tier"] == "critical" and allowed:
        approval = True
        reasons.append("Critical tool - requires human approval before execution")

    if not reasons:
        reasons.append("Low-risk tool, consistent with the user's request")
    return ToolDecision(tool, allowed, approval, reasons)
