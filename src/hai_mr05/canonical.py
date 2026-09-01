"""Deterministic, side-effect-free MR-05 canonical byte primitives."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from typing import Any

from .failures import phase_not_implemented


class CanonicalizationError(ValueError):
    """Input cannot be represented by the frozen canonical JSON policy."""


class DuplicateJSONKeyError(CanonicalizationError):
    """A JSON object contains a duplicate key."""


class UnsupportedIdentityValueError(CanonicalizationError):
    """A value is not safe for an identity-bearing canonical document."""


def _validate_string(value: object, *, context: str) -> str:
    if not isinstance(value, str):
        raise CanonicalizationError(f"{context} must be a string")
    if "\x00" in value:
        raise CanonicalizationError(f"{context} must not contain NUL")
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CanonicalizationError(f"{context} contains an unpaired surrogate")
    return value


def _validate_value(value: object, *, identity_critical: bool, context: str = "value") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"{context} contains a non-finite float")
        if identity_critical:
            raise UnsupportedIdentityValueError(
                f"{context} contains a float; use an integer or canonical decimal string"
            )
        return
    if isinstance(value, str):
        _validate_string(value, context=context)
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            _validate_string(key, context=f"{context} object key")
            _validate_value(
                child,
                identity_critical=identity_critical,
                context=f"{context}.{key}",
            )
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_value(
                child,
                identity_critical=identity_critical,
                context=f"{context}[{index}]",
            )
        return
    raise CanonicalizationError(f"{context} has unsupported type {type(value).__name__}")


def _materialize_value(value: object) -> object:
    """Convert accepted mapping/sequence views to ordinary JSON containers."""

    if isinstance(value, Mapping):
        return {key: _materialize_value(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_materialize_value(child) for child in value]
    return value


def canonical_json_bytes(value: object, *, identity_critical: bool = True) -> bytes:
    """Return compact, recursively key-sorted UTF-8 JSON with one terminal LF.

    Identity-critical values reject floats, non-JSON types, NULs, and
    unpaired surrogates. No semantic string normalization is performed.
    """

    _validate_value(value, identity_critical=identity_critical)
    serializable = _materialize_value(value)
    try:
        encoded = json.dumps(
            serializable,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            check_circular=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalizationError("value cannot be canonically serialized") from exc
    return encoded + b"\n"


def canonical_json_text(value: object, *, identity_critical: bool = True) -> str:
    """Return the canonical JSON representation as text."""

    return canonical_json_bytes(value, identity_critical=identity_critical).decode("utf-8")


def canonical_identity_bytes(value: object) -> bytes:
    """Return canonical bytes for an identity-bearing value."""

    return canonical_json_bytes(value, identity_critical=True)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise CanonicalizationError(f"non-standard JSON constant: {value}")


def parse_json_no_duplicates(
    data: str | bytes,
    *,
    identity_critical: bool = True,
) -> object:
    """Parse JSON while rejecting duplicate keys and unsupported constants."""

    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalizationError("JSON input is not valid UTF-8") from exc
    elif isinstance(data, str):
        text = data
    else:
        raise CanonicalizationError("JSON input must be text or UTF-8 bytes")
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except DuplicateJSONKeyError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CanonicalizationError("invalid JSON input") from exc
    _validate_value(parsed, identity_critical=identity_critical)
    return parsed


def canonical_pathset_bytes(paths: Iterable[str]) -> bytes:
    """Return the frozen repository-relative pathset byte representation."""

    values = list(paths)
    if not values:
        raise CanonicalizationError("pathset must not be empty")
    validated: list[str] = []
    for path in values:
        path = _validate_string(path, context="path")
        if not path or path.startswith("/"):
            raise CanonicalizationError("path must be a non-empty relative path")
        if "\n" in path or "\r" in path:
            raise CanonicalizationError("path must not contain a line separator")
        parts = path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise CanonicalizationError("path contains an invalid relative component")
        validated.append(path)
    if len(set(validated)) != len(validated):
        raise CanonicalizationError("pathset contains duplicate paths")
    return ("\n".join(sorted(validated)) + "\n").encode("utf-8")


def canonical_pathset_text(paths: Iterable[str]) -> str:
    """Return the frozen pathset representation as text."""

    return canonical_pathset_bytes(paths).decode("utf-8")


def not_implemented(*args: object, **kwargs: object) -> None:
    """Retain the non-operational module boundary for future phases."""

    del args, kwargs
    phase_not_implemented("canonical")
