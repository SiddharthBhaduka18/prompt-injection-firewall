"""Prompt Injection Firewall (PIFW).

Layered, multimodal firewall that sits between untrusted content and an LLM agent.
"""
from .core import Firewall, Verdict  # noqa: F401
