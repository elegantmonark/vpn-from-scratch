"""VPN Client UI package."""

from importlib import import_module

__all__ = ["VPNApp", "run_app"]


def __getattr__(name):
    """Lazily expose UI entrypoints without importing ui.main on package import."""
    if name in __all__:
        mod = import_module(".main", __name__)
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
