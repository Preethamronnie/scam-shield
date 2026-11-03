"""Jagratha: check whether a message is likely a scam, in plain language.

(The Python package keeps its original name, scamshield, so imports and
settings like SCAMSHIELD_LOG don't break.)

`analyze` and `Result` are loaded lazily, so that light modules (such as the
file inspectors, which run in a separate sandbox process) can be imported
without loading the ML model and scikit-learn.
"""
__all__ = ["analyze", "Result"]


def __getattr__(name):
    if name in __all__:
        from . import analyzer
        return getattr(analyzer, name)
    raise AttributeError(f"module 'scamshield' has no attribute {name!r}")
