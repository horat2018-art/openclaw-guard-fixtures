"""Deterministic MR-05 controller transition-policy primitives.

This module classifies controller transition intent only.  It does not execute
workflow transitions, Human Gate decisions, dependency calls, filesystem or
network operations, model routing, retries, fallback, stage, commit, or push.
Operational orchestration remains fail-closed and deferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from .failures import phase_not_implemented


FAIL_CLOSED_OVERRIDE = "ENABLED"
HUMAN_GATE_REQUIRED_TO_LEAVE_SEMANTICS = "PROGRESS_TRANSITIONS_ONLY"
HOLD_TRANSITION_SEMANTICS = "QUALIFIED / PASS"
READY_FOR_HUMAN_REVIEW_GATE_SEMANTICS = "QUALIFIED / PASS"
PASS_FOR_REVIEW_IS_IMPLEMENTATION_AUTHORITY = "NO"

TRANSITION_FAIL_CLOSED = "FAIL_CLOSED"
TRANSITION_PROGRESS = "PROGRESS"
TRANSITION_HOLD = "HOLD"
TRANSITION_READY_FOR_HUMAN_REVIEW_GATE = "READY_FOR_HUMAN_REVIEW_GATE"
TRANSITION_KINDS = (
    TRANSITION_FAIL_CLOSED,
    TRANSITION_PROGRESS,
    TRANSITION_HOLD,
    TRANSITION_READY_FOR_HUMAN_REVIEW_GATE,
)

QUALIFIED_PASS = "QUALIFIED / PASS"
HUMAN_GATE_REQUIRED = "HUMAN_GATE_REQUIRED"
NO_IMPLEMENTATION_AUTHORITY = "NONE"

# Materialization marker only.  All operational execution surfaces stay zero.
CONTROLLER_IMPLEMENTATION_COUNT = 1
OPERATIONAL_ORCHESTRATION_IMPLEMENTATION_COUNT = 0
STATE_TRANSITION_EXECUTION_COUNT = 0
HUMAN_APPROVAL_EXECUTION_COUNT = 0
MR03_EXECUTION_IMPLEMENTATION_COUNT = 0
MR04_EXECUTION_IMPLEMENTATION_COUNT = 0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0


class ControllerPolicyError(ValueError):
    """A transition request is outside the frozen controller semantics."""


@dataclass(frozen=True)
class TransitionQualification:
    """Immutable, non-executing qualification of one transition class."""

    transition_kind: str
    semantic_status: str
    human_gate_required: bool
    fail_closed_override_applied: bool
    implementation_authority: str = NO_IMPLEMENTATION_AUTHORITY


_TRANSITION_POLICY = MappingProxyType(
    {
        TRANSITION_FAIL_CLOSED: TransitionQualification(
            transition_kind=TRANSITION_FAIL_CLOSED,
            semantic_status=QUALIFIED_PASS,
            human_gate_required=False,
            fail_closed_override_applied=True,
        ),
        TRANSITION_PROGRESS: TransitionQualification(
            transition_kind=TRANSITION_PROGRESS,
            semantic_status=HUMAN_GATE_REQUIRED,
            human_gate_required=True,
            fail_closed_override_applied=False,
        ),
        TRANSITION_HOLD: TransitionQualification(
            transition_kind=TRANSITION_HOLD,
            semantic_status=HOLD_TRANSITION_SEMANTICS,
            human_gate_required=False,
            fail_closed_override_applied=False,
        ),
        TRANSITION_READY_FOR_HUMAN_REVIEW_GATE: TransitionQualification(
            transition_kind=TRANSITION_READY_FOR_HUMAN_REVIEW_GATE,
            semantic_status=READY_FOR_HUMAN_REVIEW_GATE_SEMANTICS,
            human_gate_required=False,
            fail_closed_override_applied=False,
        ),
    }
)


def qualify_transition(transition_kind: object) -> TransitionQualification:
    """Return frozen semantics for a transition class without executing it.

    Unknown, malformed, or verifier-decision strings have no permissive
    fallback.  Callers must handle ControllerPolicyError fail-closed.
    """

    if type(transition_kind) is not str:
        raise ControllerPolicyError("transition_kind must be an exact string")
    try:
        return _TRANSITION_POLICY[transition_kind]
    except KeyError as exc:
        raise ControllerPolicyError(
            f"unknown controller transition kind: {transition_kind!r}"
        ) from exc


def human_gate_required_for_transition(transition_kind: object) -> bool:
    """Report the frozen Human Gate requirement; never execute the gate."""

    return qualify_transition(transition_kind).human_gate_required


def not_implemented(*args: object, **kwargs: object) -> None:
    """Fail closed for operational controller orchestration."""

    del args, kwargs
    phase_not_implemented('controller')
