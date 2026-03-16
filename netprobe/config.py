"""Global runtime config and logging."""

import logging

_LOGGER = logging.getLogger("netprobe")
if not _LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(_handler)
_LOGGER.propagate = False
_LOGGER.setLevel(logging.INFO)


def get_logger() -> logging.Logger:
    return _LOGGER


def set_verbose(enabled: bool) -> None:
    _LOGGER.setLevel(logging.DEBUG if enabled else logging.INFO)


def vprint(*args, **kwargs):
    """Debug-print helper routed through logger."""
    msg = " ".join(str(a) for a in args)
    _LOGGER.debug(msg, **kwargs)
