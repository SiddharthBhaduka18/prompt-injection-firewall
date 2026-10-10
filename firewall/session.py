"""Layer 5 - Conversation (session) analyser for multi-step jailbreaks.

Single-message detectors miss attacks that are spread over several turns. For each
session we keep a sliding window of turns and look for:
  * escalation   - risk rising over consecutive turns (crescendo attacks)
  * trigger set-up followed by the trigger ("when I say X..." ... "X")
  * payload splitting - fragments that are harmless alone but malicious when joined
  * repeated probing - many low/medium-risk turns in a short window
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

from . import rules
from .taxonomy import Attack

TRIGGER_SETUP = re.compile(r"when i (?:say|type|write)\s+[\"']?([\w-]{3,20})[\"']?", re.I)
VAR_ASSIGN = re.compile(r"\b(?:let|set|remember|define)?\s*([a-z]\w{0,10})\s*=\s*[\"']([^\"']{2,80})[\"']", re.I)


@dataclass
class Turn:
    text: str
    risk: float


@dataclass
class SessionState:
    turns: deque = field(default_factory=lambda: deque(maxlen=8))
    triggers: set = field(default_factory=set)
    variables: dict = field(default_factory=dict)


class SessionTracker:
    def __init__(self):
        self.sessions: dict[str, SessionState] = defaultdict(SessionState)

    def reset(self, sid: str):
        self.sessions.pop(sid, None)

    def analyse(self, sid: str, text: str, risk: float) -> list[rules.Hit]:
        st = self.sessions[sid]
        hits: list[rules.Hit] = []
        A = Attack.MULTI_STEP_JAILBREAK

        # trigger words
        for t in st.triggers:
            if re.search(rf"\b{re.escape(t)}\b", text, re.I):
                hits.append(rules.Hit("SS-TRIG", A, 0.9, 0, 0, t, "session",
                                      f"Uses trigger word '{t}' set up in an earlier turn"))
        for m in TRIGGER_SETUP.finditer(text):
            st.triggers.add(m.group(1).lower())

        # payload splitting via variables, e.g. a='ignore all' b='previous instructions' then a+b
        for m in VAR_ASSIGN.finditer(text):
            st.variables[m.group(1).lower()] = m.group(2)
        if len(st.variables) >= 2:
            joined = " ".join(st.variables.values())
            sub = [h for h in rules.scan(joined, "session-joined") if h.attack != A]
            if sub and not rules.scan(text):
                hits.append(rules.Hit("SS-SPLIT", A, 0.9, 0, 0, joined[:160], "session",
                                      "Fragments from several turns combine into an injection"))

        # cross-turn concatenation (sentence split over messages)
        if st.turns:
            window = " ".join(t.text for t in list(st.turns)[-3:]) + " " + text
            prev_hits = {h.rule_id for t in list(st.turns)[-3:] for h in rules.scan(t.text)}
            new = [h for h in rules.scan(window, "session-window")
                   if h.rule_id not in prev_hits and h.attack != A and not rules.scan(text)]
            if new:
                hits.append(rules.Hit("SS-CONCAT", A, 0.85, 0, 0, new[0].text, "session",
                                      f"Injection spread across turns ({new[0].desc.lower()})"))

        # escalation: 3 rising turns ending above 0.4
        risks = [t.risk for t in st.turns] + [risk]
        if len(risks) >= 3 and risks[-1] > 0.4 and risks[-3] < risks[-2] < risks[-1]:
            hits.append(rules.Hit("SS-ESC", A, 0.7, 0, 0, "", "session",
                                  "Risk escalating over consecutive turns (crescendo pattern)"))
        # probing: >=3 of last 5 turns flagged
        if sum(r >= 0.45 for r in risks[-5:]) >= 3:
            hits.append(rules.Hit("SS-PROBE", A, 0.75, 0, 0, "", "session",
                                  "Repeated injection attempts in this session"))

        st.turns.append(Turn(text, risk))
        return hits

    def history(self, sid: str):
        return [(t.text, t.risk) for t in self.sessions[sid].turns]
