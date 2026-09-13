"""Deterministic Trust-Level-0 operational controller result contracts.

This module qualifies observations produced by the external Inwjud controller.
It performs no routing, subprocess execution, filesystem access, network I/O,
model calls, Git operations, or state transitions.
"""
from __future__ import annotations

from dataclasses import dataclass

from .identity import identity_from_fields
from .multi_agent import CONTROL_PLANE, LANE_CODEX, LANE_HERMES, LANE_OPENCLAW, TRUST_LEVEL

OPERATIONAL_CONTROLLER_CONTRACT_IMPLEMENTATION_COUNT = 1
OPERATIONAL_RESULT_BUILD_COUNT = 1
FILESYSTEM_SOURCE_READ_COUNT = 0
FILESYSTEM_WRITE_IMPLEMENTATION_COUNT = 0
SUBPROCESS_EXECUTION_COUNT = 0
NETWORK_IMPLEMENTATION_COUNT = 0
PROVIDER_CLIENT_IMPLEMENTATION_COUNT = 0
MODEL_CALL_IMPLEMENTATION_COUNT = 0
MODEL_ROUTING_IMPLEMENTATION_COUNT = 0
AUTH_IMPLEMENTATION_COUNT = 0
AUTO_RETRY_IMPLEMENTATION_COUNT = 0
AUTO_FALLBACK_IMPLEMENTATION_COUNT = 0
HUMAN_APPROVAL_EXECUTION_COUNT = 0
HUMAN_DECISION_SIDE_EFFECT_COUNT = 0
STATE_TRANSITION_EXECUTION_COUNT = 0
GIT_OPERATION_COUNT = 0
LIVE_CLOUD_EXECUTION_COUNT = 0

DISPOSITION_EXECUTED = "EXECUTED"
DISPOSITION_BLOCKED_BY_LIVE_POLICY = "BLOCKED_BY_LIVE_POLICY"
DISPOSITION_NOT_OPERATIONALLY_BOUND = "NOT_OPERATIONALLY_BOUND"
DISPOSITION_FAILED = "FAILED"
DISPOSITIONS = (
    DISPOSITION_EXECUTED,
    DISPOSITION_BLOCKED_BY_LIVE_POLICY,
    DISPOSITION_NOT_OPERATIONALLY_BOUND,
    DISPOSITION_FAILED,
)
ROUTE_MODES = {
    LANE_HERMES: "LOCAL_BOUNDED_WORKER",
    LANE_CODEX: "INDEPENDENT_READ_ONLY_REVIEW",
    LANE_OPENCLAW: "CONTROLLED_DELEGATION",
}


class OperationalControllerContractError(ValueError):
    pass


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise OperationalControllerContractError(f"{field} must be non-empty safe text")
    return value


def _sha(value: object, field: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    text = _text(value, field)
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise OperationalControllerContractError(f"{field} must be lowercase sha256")
    return text


@dataclass(frozen=True)
class OperationalRunResult:
    run_id: str
    task_identity: str
    lane_id: str
    route_mode: str
    disposition: str
    wrapper_exit_code: int | None
    input_identity: str
    output_identity: str | None
    route_identity: str
    ledger_record_hashes: tuple[str, ...]
    diagnostic: str
    control_plane: str = CONTROL_PLANE
    trust_level: str = TRUST_LEVEL
    mr05_gate: str = "REQUIRED"
    human_final_authority: bool = True
    execution_authority: str = "NONE"
    live_send_authority: str = "NONE"
    state_transition_authority: str = "NONE"
    memory_promotion_authority: str = "NONE"

    def __post_init__(self) -> None:
        _text(self.run_id, "run_id")
        _sha(self.task_identity, "task_identity")
        if self.lane_id not in ROUTE_MODES:
            raise OperationalControllerContractError("unsupported lane")
        if self.route_mode != ROUTE_MODES[self.lane_id]:
            raise OperationalControllerContractError("route mode does not match lane")
        if self.disposition not in DISPOSITIONS:
            raise OperationalControllerContractError("unsupported disposition")
        if self.wrapper_exit_code is not None and (
            not isinstance(self.wrapper_exit_code, int) or isinstance(self.wrapper_exit_code, bool)
        ):
            raise OperationalControllerContractError("wrapper_exit_code must be int or null")
        _sha(self.input_identity, "input_identity")
        _sha(self.output_identity, "output_identity", allow_none=True)
        _sha(self.route_identity, "route_identity")
        if not isinstance(self.ledger_record_hashes, tuple):
            raise OperationalControllerContractError("ledger_record_hashes must be tuple")
        if not self.ledger_record_hashes:
            raise OperationalControllerContractError("at least one ledger record is required")
        for i, value in enumerate(self.ledger_record_hashes):
            _sha(value, f"ledger_record_hashes[{i}]")
        _text(self.diagnostic, "diagnostic")
        if self.control_plane != CONTROL_PLANE or self.trust_level != TRUST_LEVEL:
            raise OperationalControllerContractError("control-plane or trust-level drift")
        if self.mr05_gate != "REQUIRED" or not self.human_final_authority:
            raise OperationalControllerContractError("MR05/Human governance must remain required")
        if any(
            value != "NONE"
            for value in (
                self.execution_authority,
                self.live_send_authority,
                self.state_transition_authority,
                self.memory_promotion_authority,
            )
        ):
            raise OperationalControllerContractError("operational result cannot grant authority")

        if self.lane_id == LANE_HERMES:
            if self.disposition == DISPOSITION_EXECUTED:
                if self.wrapper_exit_code != 0 or self.output_identity is None:
                    raise OperationalControllerContractError("successful Hermes execution requires exit 0 and output identity")
            elif self.disposition == DISPOSITION_BLOCKED_BY_LIVE_POLICY:
                raise OperationalControllerContractError("Hermes local lane is not a cloud-live-policy lane")
        elif self.lane_id == LANE_CODEX:
            if self.disposition == DISPOSITION_BLOCKED_BY_LIVE_POLICY:
                if self.wrapper_exit_code != 69 or self.output_identity is not None:
                    raise OperationalControllerContractError("Codex live-policy block must be exit 69 with no output")
            elif self.disposition == DISPOSITION_EXECUTED:
                raise OperationalControllerContractError("Codex execution is not qualified while LIVE_SEND_AUTHORITY=NONE")
        elif self.lane_id == LANE_OPENCLAW:
            if self.disposition != DISPOSITION_NOT_OPERATIONALLY_BOUND:
                raise OperationalControllerContractError("OpenClaw must remain unbound until HAI-OPS-02")
            if self.wrapper_exit_code is not None or self.output_identity is not None:
                raise OperationalControllerContractError("unbound OpenClaw lane cannot expose wrapper execution")

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "task_identity": self.task_identity,
            "lane_id": self.lane_id,
            "route_mode": self.route_mode,
            "disposition": self.disposition,
            "wrapper_exit_code": self.wrapper_exit_code,
            "input_identity": self.input_identity,
            "output_identity": self.output_identity,
            "route_identity": self.route_identity,
            "ledger_record_hashes": list(self.ledger_record_hashes),
            "diagnostic": self.diagnostic,
            "control_plane": self.control_plane,
            "trust_level": self.trust_level,
            "mr05_gate": self.mr05_gate,
            "human_final_authority": self.human_final_authority,
            "execution_authority": self.execution_authority,
            "live_send_authority": self.live_send_authority,
            "state_transition_authority": self.state_transition_authority,
            "memory_promotion_authority": self.memory_promotion_authority,
        }

    @property
    def result_identity(self) -> str:
        return identity_from_fields(self.to_dict())


def qualify_operational_result(**kwargs: object) -> OperationalRunResult:
    if "ledger_record_hashes" in kwargs:
        kwargs["ledger_record_hashes"] = tuple(kwargs["ledger_record_hashes"])
    return OperationalRunResult(**kwargs)
