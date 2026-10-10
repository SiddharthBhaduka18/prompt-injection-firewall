"""Layer 2 - Signature / heuristic detector.

Fast, explainable, deterministic. Each rule maps to an attack type, carries a
confidence weight, and reports the matching span so the sanitizer can neutralise
exactly that span and the dashboard can highlight it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .taxonomy import Attack

A = Attack
I = re.I | re.S

# Re-usable vocabulary
PREV = r"(?:previous|prior|above|earlier|preceding|all|any|every|your|the|existing|original|initial|system|developer)"
INSTR = r"(?:instructions?|directives?|rules?|guidelines?|prompts?|commands?|context|guardrails?|restrictions?|programming|policies|constraints)"
DISREGARD = r"(?:ignore|disregard|forget|override|bypass|skip|abandon|drop|discard|neglect|cancel|nullify|erase)"
AI = r"(?:ai|assistant|chatbot|bot|llm|language model|model|agent|copilot|gpt|claude|gemini)"


@dataclass
class Rule:
    id: str
    attack: Attack
    weight: float
    pattern: re.Pattern
    desc: str


def R(id, attack, weight, pat, desc):
    return Rule(id, attack, weight, re.compile(pat, I), desc)


RULES: list[Rule] = [
    # ---------------- Instruction override ----------------
    R("IO-01", A.INSTRUCTION_OVERRIDE, 0.95,
      rf"\b{DISREGARD}\b[\w\s,'-]{{0,25}}\b{PREV}\b[\w\s,'-]{{0,20}}\b{INSTR}\b",
      "Asks the model to ignore/override its prior instructions"),
    R("IO-08", A.INSTRUCTION_OVERRIDE, 0.9,
      rf"\b{DISREGARD}\s+(?:whatever|anything|everything|what|all)\s+(?:that\s+)?(?:the\s+)?(?:developer|system|admin|operator|they|you were|you've been|you have been|you've|you were)\s*(?:told|said|instructed|given|taught)",
      "Asks the model to disregard what it was told"),
    R("IO-02", A.INSTRUCTION_OVERRIDE, 0.85,
      rf"\b(?:new|updated|revised|real|actual|true)\s+(?:system\s+)?{INSTR}\s*(?::|follow|are|is)",
      "Declares replacement instructions"),
    R("IO-03", A.INSTRUCTION_OVERRIDE, 0.8,
      r"\b(?:from now on|henceforth|going forward|for the rest of (?:this|the) conversation)\b[^.\n]{0,60}\b(?:you (?:will|must|shall|are)|only|always|never|respond)",
      "Persistently changes model behaviour"),
    R("IO-04", A.INSTRUCTION_OVERRIDE, 0.8,
      r"\b(?:instead|rather),?\s+(?:you\s+(?:must|should|will)|do the following|your (?:new|real) task)",
      "Redirects the task"),
    R("IO-05", A.INSTRUCTION_OVERRIDE, 0.75,
      r"\b(?:stop|end|terminate)\s+(?:the\s+|your\s+)?(?:current|previous)\s+task\b",
      "Terminates the current task"),
    R("IO-06", A.INSTRUCTION_OVERRIDE, 0.8,
      rf"\b(?:do not|don't|never)\s+(?:follow|obey|listen to)\s+(?:the\s+|your\s+)?{PREV}?\s*{INSTR}",
      "Tells the model not to follow its instructions"),
    R("IO-07", A.INSTRUCTION_OVERRIDE, 0.7,
      r"\b(?:priority|important|urgent|critical)\s*(?:override|instruction|update|notice)\b\s*[:!-]",
      "Priority-override framing"),

    # ---------------- Role change ----------------
    R("RC-01", A.ROLE_CHANGE, 0.85,
      r"\byou\s+are\s+(?:now|no longer)\b(?!\s+(?:registered|subscribed|connected|logged|signed|enrolled|ready|able|eligible|on the|in the|part of|a member|booked|confirmed|following))",
      "Reassigns the model's identity"),
    R("RC-02", A.ROLE_CHANGE, 0.85,
      r"\b(?:act|behave|respond|roleplay|role-play)\s+as\s+(?:if you (?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|evil|rogue|jailbroken|developer|admin|root|different|dan\b|hacker|malicious)",
      "Asks the model to act as an unrestricted persona"),
    R("RC-03", A.ROLE_CHANGE, 0.9,
      r"\b(?:do anything now|god mode|jailbr(?:oken|eak) mode|unrestricted mode|dan mode|dan prompt|evil confidant|no-limits mode)\b"
      r"|\b(?:in|enable|activate)\s+(?:developer|sudo|admin)\s+mode\b[^.\n]{0,40}\b(?:you|ignore|no (?:rules|filters|restrictions)|policy|censor)",
      "Known jailbreak persona"),
    R("RC-04", A.ROLE_CHANGE, 0.75,
      r"\bpretend\s+(?:to be|you are|that you)\b",
      "Pretend-to-be framing"),
    R("RC-07", A.ROLE_CHANGE, 0.85,
      r"\b(?:pretend|imagine|assume|act as if)\s+(?:that\s+)?you\s+(?:are|were|have)\b[^.\n]{0,40}\b(?:administrator|admin|root|superuser|owner|developer|privileges?|unrestricted|no rules|no limits)\b",
      "Claims an elevated or unrestricted identity"),
    R("RC-05", A.ROLE_CHANGE, 0.8,
      r"\b(?:enter|enable|activate|switch to)\s+(?:\w+\s+){0,2}mode\b",
      "Mode switch"),
    R("RC-06", A.ROLE_CHANGE, 0.75,
      r"\bwithout\s+(?:any\s+)?(?:restrictions|filters|limitations|censorship|ethical|safety|guidelines)\b",
      "Removes safety constraints"),

    # ---------------- Secret / system prompt extraction ----------------
    R("SE-01", A.SECRET_EXTRACTION, 0.9,
      r"\b(?:reveal|print|show|display|output|repeat|tell me|share|leak|dump|expose|disclose|give me|write out|spell out|list)\b[\w\s,'-]{0,30}\b(?:system|initial|original|hidden|secret|internal|developer|confidential)\s+(?:prompt|instructions?|message|rules|configuration|config)",
      "Requests the system prompt"),
    R("SE-02", A.SECRET_EXTRACTION, 0.85,
      r"\b(?:repeat|print|output|write out|copy|reproduce)\b[\w\s]{0,20}\b(?:everything|all (?:the )?text|words?|text|content)\s+(?:that\s+)?(?:came\s+|comes\s+|appears?\s+|is\s+|was\s+)?(?:above|before|preceding|prior to)",
      "Repeat-the-text-above leak"),
    R("SE-03", A.SECRET_EXTRACTION, 0.85,
      r"\b(?:what|which)\s+(?:are|were|is)\s+your\s+(?:system\s+)?(?:instructions|prompt|rules|initial prompt|hidden rules)",
      "Asks what the system instructions are"),
    R("SE-04", A.SECRET_EXTRACTION, 0.8,
      r"\b(?:reveal|show|print|share|leak|dump|expose|disclose|tell)\b[\w\s,'-]{0,30}\b(?:secrets?|internal data|confidential (?:data|information)|private data|customer data|pii|database contents|environment variables|env vars|\.env|config files?)\b",
      "Requests confidential data"),
    R("SE-05", A.SECRET_EXTRACTION, 0.75,
      r"\bstart (?:your|the) (?:response|reply|answer) with\s+[\"']?(?:sure|my instructions|the system prompt)",
      "Prefix-forcing leak"),

    # ---------------- Credential theft ----------------
    R("CT-01", A.CREDENTIAL_THEFT, 0.95,
      r"\b(?:send|give|provide|share|reveal|print|show|tell|enter|type|confirm|verify|submit|post|email|forward|paste)\b(?:(?!rotat|reset|chang|revok|protect|secur|stor|never|manag)[\w\s,'-]){0,35}\b(?:passwords?|passcodes?|api[\s_-]?keys?|access[\s_-]?tokens?|auth(?:entication)?[\s_-]?tokens?|bearer tokens?|session (?:cookies?|tokens?)|credentials?|private keys?|ssh keys?|otp|2fa codes?|one[- ]time (?:password|code)|pin(?: number)?|secret keys?|aws (?:secret|access) key|credit card(?: number)?s?|cvv|seed phrase|recovery phrase)\b",
      "Requests credentials or secrets"),
    R("CT-02", A.CREDENTIAL_THEFT, 0.9,
      r"\b(?:verify|confirm|re-?enter|validate|update)\s+your\s+(?:account|identity|login|credentials|password|payment)",
      "Phishing-style verification lure"),
    R("CT-03", A.CREDENTIAL_THEFT, 0.85,
      r"\b(?:sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}|xox[bp]-[A-Za-z0-9-]{10,})",
      "Contains or solicits a key-shaped token"),
    R("CT-04", A.CREDENTIAL_THEFT, 0.8,
      r"\b(?:include|append|attach|embed)\b[\w\s]{0,25}\b(?:cookies?|tokens?|api keys?|credentials|passwords?|session id)\b[\w\s]{0,25}\b(?:url|link|request|query|image|response)",
      "Asks to exfiltrate credentials via a URL/request"),

    # ---------------- Tool abuse ----------------
    R("TA-01", A.TOOL_ABUSE, 0.9,
      r"\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?(?:`?[\w.]+`?\s+)?(?:tool|function|api|plugin|command|endpoint)\b[^.\n]{0,80}\b(?:send|delete|transfer|email|post|upload|wire|pay|drop|rm|grant|share|forward|exfiltrat)",
      "Directs the agent to invoke a sensitive tool"),
    R("TA-02", A.TOOL_ABUSE, 0.9,
      r"\b(?:send|forward|email|upload|post|exfiltrate|transmit|copy)\b[\w\s,'-]{0,40}\b(?:to|at)\s+(?:[\w.+-]+@[\w-]+\.[\w.]+|https?://\S+|this (?:address|url|email|webhook)|the following (?:address|url|email))",
      "Instructs sending data to an external destination"),
    R("TA-03", A.TOOL_ABUSE, 0.95,
      r"\b(?:delete|remove|wipe|erase|drop|truncate|destroy)\s+(?:all\s+|every\s+|the\s+)?(?:files?|emails?|records?|database|tables?|repos?(?:itory)?|backups?|users?|accounts?|data|inbox|logs?)\b",
      "Instructs destructive actions"),
    R("TA-04", A.TOOL_ABUSE, 0.95,
      r"(?:\brm\s+-rf\b|\bdrop\s+table\b|\bcurl\s+[^\n|]*\|\s*(?:ba)?sh\b|\bwget\s+[^\n|]*\|\s*(?:ba)?sh\b|\bchmod\s+777\b|\bnc\s+-e\b|/etc/passwd|\bos\.system\(|\bsubprocess\.|\beval\(|\bexec\()",
      "Contains a dangerous shell/code payload"),
    R("TA-05", A.TOOL_ABUSE, 0.9,
      r"\b(?:transfer|wire|send|pay)\s+(?:\$|usd|inr|eur|rs\.?|₹)?\s?\d[\d,.]*\s*(?:\$|usd|inr|eur|dollars|rupees)?\b[\w\s]{0,30}\b(?:to|into)\b",
      "Instructs a payment/transfer"),
    R("TA-06", A.TOOL_ABUSE, 0.85,
      r"\b(?:grant|give|add|elevate)\s+(?:admin|root|owner|full|write)\s+(?:access|permissions?|privileges?|rights)\b|\badd\s+(?:my|this|the|our)\s+(?:ssh\s+|public\s+)?key\s+to\b|authorized_keys",
      "Privilege escalation"),
    R("TA-07", A.TOOL_ABUSE, 0.8,
      r"!\[[^\]]*\]\(https?://[^)]*\?(?:[^)]*=)\{?[^)]*\)",
      "Markdown image beacon used for data exfiltration"),

    # ---------------- Context poisoning ----------------
    R("CP-01", A.CONTEXT_POISONING, 0.9,
      r"(?:<\|(?:im_start|im_end|system|endoftext|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<<SYS>>|<</SYS>>|<\s*/?\s*system\s*>|\[\s*system\s*(?:message|prompt|note)?\s*\]|^#{1,4}\s*(?:system|assistant)\s*(?:message|prompt)?\s*:?\s*$)",
      "Fake chat-template / system delimiters"),
    R("CP-02", A.CONTEXT_POISONING, 0.85,
      r"(?:^|\n)\s*(?:system|assistant|admin|developer|operator)\s*(?:message|note|override)?\s*:\s*\S",
      "Fake role-prefixed turn injected into content"),
    R("CP-03", A.CONTEXT_POISONING, 0.8,
      r"\b(?:remember|memorize|store|save)\s+(?:this|that|the following)\b[^.\n]{0,40}\b(?:for (?:all )?future|permanently|from now on|in (?:your )?memory|for later)",
      "Attempts to persist instructions in memory"),
    R("CP-04", A.CONTEXT_POISONING, 0.8,
      r"\b(?:the (?:user|admin|developer|owner|ceo|security team) (?:has )?(?:authori[sz]ed|approved|confirmed|requested|instructed)|you (?:have been|are) (?:authori[sz]ed|permitted|allowed) to)\b",
      "Fabricated authorisation"),
    R("CP-05", A.CONTEXT_POISONING, 0.75,
      r"\b(?:end of (?:document|context|user input|data)|---\s*end\s*---|</(?:document|context|data|user)>)\b[\s\S]{0,40}\b(?:now|next|new|instructions?|system)",
      "Fake end-of-data boundary followed by instructions"),
    R("CP-06", A.CONTEXT_POISONING, 0.7,
      r"\b(?:official|updated|new)\s+(?:company\s+)?policy\s*(?:states|says|is|:)[^.\n]{0,80}\b(?:always|never|must)\b",
      "Injected false policy/fact"),
    R("CP-07", A.CONTEXT_POISONING, 0.7,
      r"\bwhen (?:summari[sz]ing|asked about|answering|the user asks)\b[^.\n]{0,80}\b(?:say|respond|state|claim|tell|recommend|mention)\b",
      "Conditional answer-steering planted in content"),

    # ---------------- Multi-step jailbreak (single-message signals) ----------------
    R("MS-01", A.MULTI_STEP_JAILBREAK, 0.75,
      r"\b(?:hypothetically|in a fictional (?:world|story|scenario)|for a (?:novel|story|movie|screenplay)|imagine (?:a world|that you)|purely (?:hypothetical|academic)|for educational purposes only)\b",
      "Fictional/hypothetical framing"),
    R("MS-02", A.MULTI_STEP_JAILBREAK, 0.8,
      r"\b(?:step|part|stage|phase)\s*(?:1|one|2|two|3|three)\b[^.\n]{0,60}\b(?:ignore|reveal|bypass|unlock|disable|forget|secret|password)",
      "Staged instructions"),
    R("MS-03", A.MULTI_STEP_JAILBREAK, 0.8,
      r"\b(?:when i say\s+[\"']?\w+|once you(?:'ve| have) (?:agreed|confirmed)|after you (?:confirm|agree)|reply (?:only )?with [\"']?(?:ok|yes|understood|confirmed)[\"']? (?:if|and|to))\b",
      "Sets up a trigger for a later turn"),
    R("MS-06", A.MULTI_STEP_JAILBREAK, 0.6,
      r"\bin (?:my|the) (?:next|following) message\b[^.\n]{0,40}\b(?:real|actual|true)\s+(?:task|request|question|instructions?)",
      "Defers the 'real' task to a later turn"),
    R("MS-04", A.MULTI_STEP_JAILBREAK, 0.75,
      r"\b(?:as we (?:discussed|agreed)|you (?:already|previously) (?:agreed|said|confirmed)|continuing (?:from|our) (?:earlier|previous)|you promised)\b",
      "Claims prior agreement"),
    R("MS-05", A.MULTI_STEP_JAILBREAK, 0.7,
      r"\b(?:let'?s play a game|game rules?:|you will answer (?:twice|in two ways)|opposite day|answer as both)\b",
      "Game-based jailbreak setup"),

    # ---------------- Indirect injection markers ----------------
    R("II-01", A.INDIRECT_INJECTION, 0.9,
      rf"\b(?:note|message|instructions?|attention|important)\s+(?:to|for)\s+(?:the\s+|any\s+)?{AI}s?\b",
      "Content addressed to an AI reader"),
    R("II-02", A.INDIRECT_INJECTION, 0.9,
      rf"\b(?:if you are an?|any|dear|hey)\s+{AI}s?\b[\w\s,]{{0,30}}(?:reading|processing|summari[sz]ing|parsing|seeing|analy[sz]ing|if you (?:read|process|see|parse|summari[sz]e))",
      "Targets AI systems that read this content"),
    R("II-03", A.INDIRECT_INJECTION, 0.85,
      rf"\b{AI}s?\s+(?:reading|processing|summari[sz]ing|parsing)\s+(?:this|the following)\b",
      "Targets AI systems processing this content"),
    R("II-04", A.INDIRECT_INJECTION, 0.85,
      r"\b(?:when|while|if) (?:you |the assistant )?(?:summari[sz]e|read|process|parse|translate|review)s?\s+(?:this|the following)\s+(?:page|document|email|file|text|website|content|code)\b[^.\n]{0,60}\b(?:you must|also|instead|first|do not|don't|ignore)",
      "Hidden instruction triggered on processing"),
]

# Patterns where benign uses are common: require an imperative context.
SOFT_IDS = {"MS-01", "RC-04", "RC-05", "MS-04", "MS-05", "MS-06"}

# "Mention, not use": security education / quoted examples talk ABOUT attacks.
META_DISCUSSION = re.compile(r"\b(?:phishing|scam(?:mer)?s?|attackers?|attacks?|tutorial|for example|e\.g\.|such as|beware|be careful|warn(?:s|ing)?|never (?:share|ask|give)|report (?:them|it|this)|defen[cs]es?|blocks?)\b", re.I)


@dataclass
class Hit:
    rule_id: str
    attack: Attack
    weight: float
    start: int
    end: int
    text: str
    view: str
    desc: str


def scan(text: str, view: str = "clean") -> list[Hit]:
    hits: list[Hit] = []
    for r in RULES:
        for m in r.pattern.finditer(text):
            hits.append(Hit(r.id, r.attack, r.weight, m.start(), m.end(), m.group()[:160], view, r.desc))
            break  # one hit per rule per view is enough
    return hits
