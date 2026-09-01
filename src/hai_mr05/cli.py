"""Future explicit CLI boundary; execution is intentionally unavailable."""

from .failures import phase_not_implemented


def main(*args: object, **kwargs: object) -> None:
    del args, kwargs
    phase_not_implemented('cli')
