"""Attack taxonomy - the 9 attack types named in the problem statement."""
from enum import Enum


class Attack(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTIONS = "encoded_instructions"
    INDIRECT_INJECTION = "indirect_injection"


LABELS = {
    Attack.INSTRUCTION_OVERRIDE: "Instruction Override",
    Attack.ROLE_CHANGE: "Role Change",
    Attack.SECRET_EXTRACTION: "Secret Extraction",
    Attack.TOOL_ABUSE: "Tool Abuse",
    Attack.CREDENTIAL_THEFT: "Credential Theft",
    Attack.CONTEXT_POISONING: "Context Poisoning",
    Attack.MULTI_STEP_JAILBREAK: "Multi-Step Jailbreak",
    Attack.ENCODED_INSTRUCTIONS: "Encoded Instructions",
    Attack.INDIRECT_INJECTION: "Indirect Prompt Injection",
}

# Severity weights used by the risk scorer (0-1).
SEVERITY = {
    Attack.INSTRUCTION_OVERRIDE: 0.8,
    Attack.ROLE_CHANGE: 0.7,
    Attack.SECRET_EXTRACTION: 0.9,
    Attack.TOOL_ABUSE: 0.95,
    Attack.CREDENTIAL_THEFT: 0.95,
    Attack.CONTEXT_POISONING: 0.75,
    Attack.MULTI_STEP_JAILBREAK: 0.8,
    Attack.ENCODED_INSTRUCTIONS: 0.85,
    Attack.INDIRECT_INJECTION: 0.9,
}

USER_SOURCES = {"user_message"}
