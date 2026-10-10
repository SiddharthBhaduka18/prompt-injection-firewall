"""Firewall orchestrator - runs the layered pipeline and returns an explainable Verdict.

    content --> [0] extract segments (visible + hidden channels)
            --> [1] normalise / decode every segment (views)
            --> [2] signature rules on every view
            --> [3] ML classifier
            --> [5] session analyser (multi-turn)
            --> risk fusion (+ source trust + hidden-channel boost)
            --> [4] LLM judge only in the grey zone (free-tier friendly)
            --> policy decision: ALLOW / SANITIZE / BLOCK
            --> [6] neutraliser + spotlighting
            --> audit log (observability)
Layer [7] (tool-call guard) runs later, when the agent proposes an action.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from . import extractors, llm_judge, rules, sanitizer
from .ml import Classifier
from .normalize import normalize
from .session import SessionTracker
from .taxonomy import LABELS, SEVERITY, USER_SOURCES, Attack

USER_ACTION_RULES = {"TA-02", "TA-03", "TA-05"}
LOG_DIR =os.path.join(os.path.dirname(__file__), "..", "logs")
DEFAULT_CONFIG = {
    "allow_below": 0.45,        # risk < this -> ALLOW
    "block_at": 0.75,           # risk >= this -> BLOCK user messages; documents get SANITIZED
    "grey_zone": (0.35, 0.75),  # LLM judge consulted only here
    "use_llm": True,
    "hidden_channel_boost": 0.15,
    "untrusted_source_boost": 0.05,
}


@dataclass
class Finding:
    attack: str
    label: str
    confidence: float
    evidence: list[dict] = field(default_factory=list)


@dataclass
class Verdict:
    id: str
    source_type: str
    action: str                 # ALLOW | SANITIZE | BLOCK
    risk: float
    findings: list[Finding]
    obfuscation: list[str]
    segments: list[dict]
    layers: dict
    sanitized: str
    safe_prompt: str
    latency_ms: float

    @property
    def attacks(self) -> list[str]:
        return [f.attack for f in self.findings]

    def to_dict(self):
        d = asdict(self)
        d["attacks"] = self.attacks
        return d


def _noisy_or(ws):
    p = 1.0
    for w in ws:
        p *= (1 - w)
    return 1 - p


class Firewall:
    def __init__(self, config: dict | None = None, log: bool = True):
        self.cfg = {**DEFAULT_CONFIG, **(config or {})}
        self.clf = Classifier()
        self.sessions = SessionTracker()
        self.log = log
        if log:
            os.makedirs(LOG_DIR, exist_ok=True)

    # ------------------------------------------------------------------ public
    def scan_text(self, text: str, source_type: str = "user_message", session_id: str | None = None) -> Verdict:
        return self.scan(text, source_type, session_id=session_id)

    def scan_file(self, data: bytes, filename: str, session_id: str | None = None) -> Verdict:
        return self.scan(data, extractors.detect_type(filename, data), filename, session_id)

    def scan(self, content, source_type="user_message", filename="", session_id=None) -> Verdict:
        t0 = time.perf_counter()
        segments = extractors.extract(content, source_type, filename)
        untrusted = source_type not in USER_SOURCES

        per_attack: dict[Attack, list[tuple[float, dict]]] = defaultdict(list)
        obf_all: set[str] = set()
        spans_by_seg: dict[int, list] = defaultdict(list)
        drop_seg: set[int] = set()
        ml_scores, seg_report = [], []
        n_soft_only = 0

        for i, seg in enumerate(segments):
            norm = normalize(seg.text)
            obf_all |= set(norm.obfuscation)
            seg_hits: list[rules.Hit] = []
            for view, vt in norm.all_views():
                seg_hits += rules.scan(vt, view)
            decoded_hits = [h for h in seg_hits if h.view != "clean"]
            clean_ids = {h.rule_id for h in seg_hits if h.view == "clean"}
            # encoded instructions: an injection that only appears after decoding
            if any(h.rule_id not in clean_ids for h in decoded_hits):
                h0 = next(h for h in decoded_hits if h.rule_id not in clean_ids)
                seg_hits.append(rules.Hit("EN-01", Attack.ENCODED_INSTRUCTIONS, 0.9, 0, len(norm.clean),
                                          h0.text, h0.view, f"Injection hidden with {h0.view} encoding"))
                spans_by_seg[i].append((0, len(norm.clean), "encoded_instructions"))
            if norm.obfuscation and seg_hits and not decoded_hits and \
                    {"zero-width characters", "homoglyphs", "unicode tag smuggling"} & set(norm.obfuscation):
                seg_hits.append(rules.Hit("EN-02", Attack.ENCODED_INSTRUCTIONS, 0.85, 0, 0, "", "clean",
                                          "Injection disguised with " + ", ".join(norm.obfuscation)))
            # ML score on clean + decoded views
            ml = max([self.clf.score(norm.clean)] + [self.clf.score(v) for _, v in norm.views[:5]])
            ml_scores.append(ml)

            boost = self.cfg["hidden_channel_boost"] if seg.hidden else 0.0
            mention = {id(h) for h in seg_hits
                       if h.view == "clean" and h.end > h.start and _is_mention(norm.clean, h.start, h.end)}
            strong = [h for h in seg_hits if h.rule_id not in rules.SOFT_IDS and id(h) not in mention]
            for h in seg_hits:
                w = h.weight
                if h.rule_id in rules.SOFT_IDS and not strong and ml < 0.5:
                    w *= 0.45  # weak signal alone (e.g. "hypothetically") - needs corroboration
                if not untrusted and h.rule_id in USER_ACTION_RULES and len(strong) == 1 and ml < 0.75:
                    w *= 0.5   # a user asking for an action is legitimate; the tool guard polices it
                if id(h) in mention:
                    w *= 0.4   # quoted example / security education ("mention, not use")
                w = min(0.99, w + (boost if h in strong else 0.0))
                per_attack[h.attack].append((w, {"rule": h.rule_id, "text": h.text, "view": h.view,
                                                 "channel": seg.channel, "why": h.desc}))
            # indirect: injection found inside retrieved / third-party content
            if untrusted and (strong or (ml >= 0.7)):
                w = 0.9 if strong else 0.6 + 0.3 * ml
                why = ("Instructions found in a hidden channel of third-party content" if seg.hidden
                       else f"Instructions embedded in untrusted {source_type.replace('_', ' ')} content")
                per_attack[Attack.INDIRECT_INJECTION].append(
                    (min(0.99, w + boost), {"rule": "II-SRC", "text": (strong[0].text if strong else seg.text[:120]),
                                            "view": "clean", "channel": seg.channel, "why": why}))
            # remember what to neutralise
            seg_flag = bool(strong) or ml >= 0.75
            if seg_flag:
                if seg.hidden or (untrusted and len(norm.clean) < 500 and source_type != "source_code"):
                    drop_seg.add(i)  # hidden channel, or a short field (review, JSON value) that is itself the attack
                else:
                    for h in seg_hits:
                        if h.view == "clean" and h.end > h.start and (h.rule_id not in rules.SOFT_IDS or strong):
                            spans_by_seg[i].append((h.start, h.end, h.attack.value))
                    if not spans_by_seg[i] and ml >= 0.75:
                        # ML-only: remove the highest scoring sentence window
                        spans_by_seg[i].append(_ml_span(self.clf, norm.clean))
            seg_report.append({"channel": seg.channel, "hidden": seg.hidden, "chars": len(seg.text),
                               "preview": seg.text[:300], "rule_hits": len(seg_hits), "ml": round(ml, 3),
                               "flagged": seg_flag, "_clean": norm.clean})

        # ---- session layer (multi-turn)
        session_hits = []
        if session_id:
            prelim = max([_noisy_or([w for w, _ in v]) for v in per_attack.values()] + [max(ml_scores or [0]) * 0.8])
            full_text = "\n".join(s.text for s in segments)
            session_hits = self.sessions.analyse(session_id, full_text, prelim)
            for h in session_hits:
                per_attack[h.attack].append((h.weight, {"rule": h.rule_id, "text": h.text, "view": "session",
                                                        "channel": "conversation", "why": h.desc}))

        # ---- fusion
        findings = []
        for atk, items in per_attack.items():
            conf = _noisy_or([w for w, _ in items])
            ev = sorted((e for _, e in items), key=lambda e: e["rule"])
            seen, dedup = set(), []
            for e in ev:
                k = (e["rule"], e["channel"])
                if k not in seen:
                    seen.add(k)
                    dedup.append(e)
            findings.append(Finding(atk.value, LABELS[atk], round(conf, 3), dedup[:6]))
        findings.sort(key=lambda f: -f.confidence)
        rule_risk = max([f.confidence * (0.6 + 0.4 * SEVERITY[Attack(f.attack)]) / 1.0 for f in findings] + [0])
        ml_max = max(ml_scores or [0])
        if findings:
            risk = 1 - (1 - rule_risk) * (1 - 0.5 * ml_max ** 2)
        else:
            risk = 0.9 * ml_max ** 2  # ML alone is a weaker signal than an explainable rule
        if untrusted and any(f.confidence >= 0.6 for f in findings):
            risk = min(1.0, risk + self.cfg["untrusted_source_boost"])

        # ---- LLM judge in the grey zone
        lo, hi = self.cfg["grey_zone"]
        judge = {"status": "not needed"}
        if self.cfg["use_llm"] and lo <= risk < hi:
            judge = llm_judge.judge("\n".join(s.text for s in segments)[:6000])
            if judge.get("status") == "ok":
                if judge["malicious"]:
                    risk = max(risk, 0.5 + 0.45 * judge["confidence"])
                    for t in judge["attack_types"]:
                        if t not in {f.attack for f in findings}:
                            findings.append(Finding(t, LABELS[Attack(t)], round(judge["confidence"] * 0.8, 3),
                                                    [{"rule": "LLM", "text": "", "view": "clean", "channel": "llm-judge",
                                                      "why": judge["rationale"]}]))
                else:
                    risk *= (1 - 0.5 * judge["confidence"])
        risk = round(min(max(risk, 0.0), 1.0), 3)

        # ---- decision
        if risk < self.cfg["allow_below"]:
            action = "ALLOW"
        elif risk >= self.cfg["block_at"] and not untrusted:
            action = "BLOCK"
        else:
            action = "SANITIZE"

        # ---- neutralise
        kept, removed_chars, total_chars = [], 0, 0
        for i, seg in enumerate(segments):
            clean = seg_report[i]["_clean"]
            total_chars += len(clean)
            if action == "ALLOW":
                if not seg.hidden or seg.channel.startswith("ocr"):
                    kept.append(clean)
                continue
            if i in drop_seg or (seg.hidden and seg_report[i]["flagged"]):
                removed_chars += len(clean)
                continue
            if seg.hidden:
                continue  # hidden channels are never forwarded once content is suspicious
            spans = spans_by_seg.get(i, [])
            if source_type == "source_code" and seg.channel == "code":
                txt, rem = sanitizer.sanitize_code(seg.text, [e["text"] for f in per_attack.values() for _, e in f])
            else:
                if spans:  # sweep neighbouring sentences the ML layer considers instructions
                    spans = spans + [(a, b, "ml-flagged instruction") for a, b in _ml_sentences(self.clf, clean)]
                txt, rem = sanitizer.remove_spans(clean, spans)
            removed_chars += rem
            kept.append(txt)
        sanitized = "\n\n".join(k for k in kept if k.strip())
        if action == "SANITIZE" and total_chars and removed_chars / total_chars > 0.8:
            action = "BLOCK"  # nothing meaningful left - safer to block entirely
        if action == "SANITIZE" and not untrusted and risk >= self.cfg["block_at"]:
            action = "BLOCK"
        if action == "BLOCK":
            sanitized = ""
        safe_prompt = "" if action == "BLOCK" else (
            sanitized if (action == "ALLOW" and not untrusted) else sanitizer.spotlight(sanitized, source_type))

        for s in seg_report:
            s.pop("_clean", None)
        layers = {
            "extraction": {"segments": len(segments), "hidden_channels": sum(s.hidden for s in segments)},
            "normalisation": {"obfuscation": sorted(obf_all)},
            "rules": {"hits": sum(len(v) for v in per_attack.values()) - len(session_hits)},
            "ml": {"max_score": round(ml_max, 3)},
            "session": {"hits": [h.desc for h in session_hits]},
            "llm_judge": judge,
        }
        v = Verdict(uuid.uuid4().hex[:10], source_type, action, risk, findings, sorted(obf_all),
                    seg_report, layers, sanitized, safe_prompt, round((time.perf_counter() - t0) * 1000, 1))
        self._audit(v, filename)
        return v

    # ------------------------------------------------------------------ learning loop
    def feedback(self, text: str, is_attack: bool, note: str = ""):
        """Record an analyst correction; used on the next `retrain()`."""
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "feedback.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "text": text[:4000],
                                "label": int(is_attack), "note": note}) + "\n")

    def retrain(self):
        from . import ml
        ml.build()
        self.clf = Classifier()

    # ------------------------------------------------------------------ audit
    def _audit(self, v: Verdict, filename: str):
        if not self.log:
            return
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "id": v.id, "source": v.source_type, "file": filename,
               "action": v.action, "risk": v.risk, "attacks": v.attacks, "obfuscation": v.obfuscation,
               "latency_ms": v.latency_ms, "llm": v.layers["llm_judge"].get("status")}
        with open(os.path.join(LOG_DIR, "audit.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def _is_mention(text: str, start: int, end: int) -> bool:
    a = max(text.rfind(c, 0, start) for c in ".!?\n") + 1
    rs = [i for i in (text.find(c, end) for c in ".!?\n") if i != -1]
    sent = text[a:(min(rs) + 1 if rs else len(text))]
    quoted = text[max(0, start - 1):start] in "'\"\u201c\u2018" and start > 0
    return bool(rules.META_DISCUSSION.search(sent)) or quoted


def _ml_sentences(clf: Classifier, text: str, thr: float = 0.75):
    import re
    return [(m.start(), m.end()) for m in re.finditer(r"[^.!?\n]+[.!?]?", text)
            if len(m.group().split()) >= 4 and clf.score(m.group()) >= thr]


def _ml_span(clf: Classifier, text: str):
    import re
    best, bs = (0, len(text)), -1
    for m in re.finditer(r"[^.!?\n]+[.!?]?", text):
        s = clf.score(m.group())
        if s > bs:
            bs, best = s, (m.start(), m.end())
    return (*best, "ml-flagged instruction")
