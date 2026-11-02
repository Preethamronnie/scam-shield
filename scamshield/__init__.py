"""Jagratha: check whether a message is likely a scam, in plain language.

(The Python package keeps its original name, scamshield, so imports and
settings like SCAMSHIELD_LOG don't break.)"""
from .analyzer import analyze, Result

__all__ = ["analyze", "Result"]
