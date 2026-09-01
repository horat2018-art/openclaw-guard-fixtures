"""classification/disclosure boundary; production implementation is deferred."""

from .failures import phase_not_implemented


def not_implemented(*args: object, **kwargs: object) -> None:
    del args, kwargs
    phase_not_implemented('disclosure')
