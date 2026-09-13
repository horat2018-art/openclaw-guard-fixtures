import unittest

from hai_mr05 import operational_controller


class OperationalControllerRuntimeTests(unittest.TestCase):
    def _base(self, **overrides):
        data = dict(
            run_id="run-abc",
            task_identity="1" * 64,
            lane_id="HERMES",
            route_mode="LOCAL_BOUNDED_WORKER",
            disposition="EXECUTED",
            wrapper_exit_code=0,
            input_identity="2" * 64,
            output_identity="3" * 64,
            route_identity="4" * 64,
            ledger_record_hashes=("5" * 64, "6" * 64),
            diagnostic="bounded result",
        )
        data.update(overrides)
        return data

    def test_hermes_executed_result_is_deterministic_and_zero_authority(self):
        a = operational_controller.qualify_operational_result(**self._base())
        b = operational_controller.qualify_operational_result(**self._base())
        self.assertEqual(a.result_identity, b.result_identity)
        self.assertEqual(a.execution_authority, "NONE")
        self.assertEqual(a.live_send_authority, "NONE")
        self.assertEqual(a.state_transition_authority, "NONE")
        self.assertEqual(a.memory_promotion_authority, "NONE")

    def test_codex_live_policy_block_is_qualified_without_execution(self):
        result = operational_controller.qualify_operational_result(
            **self._base(
                lane_id="CODEX",
                route_mode="INDEPENDENT_READ_ONLY_REVIEW",
                disposition="BLOCKED_BY_LIVE_POLICY",
                wrapper_exit_code=69,
                output_identity=None,
            )
        )
        self.assertEqual(result.disposition, "BLOCKED_BY_LIVE_POLICY")
        self.assertIsNone(result.output_identity)

    def test_codex_executed_result_fails_closed_while_live_send_is_none(self):
        with self.assertRaises(operational_controller.OperationalControllerContractError):
            operational_controller.qualify_operational_result(
                **self._base(
                    lane_id="CODEX",
                    route_mode="INDEPENDENT_READ_ONLY_REVIEW",
                    disposition="EXECUTED",
                    wrapper_exit_code=0,
                )
            )

    def test_openclaw_remains_unbound_until_ops02(self):
        result = operational_controller.qualify_operational_result(
            **self._base(
                lane_id="OPENCLAW",
                route_mode="CONTROLLED_DELEGATION",
                disposition="NOT_OPERATIONALLY_BOUND",
                wrapper_exit_code=None,
                output_identity=None,
            )
        )
        self.assertEqual(result.disposition, "NOT_OPERATIONALLY_BOUND")
        with self.assertRaises(operational_controller.OperationalControllerContractError):
            operational_controller.qualify_operational_result(
                **self._base(
                    lane_id="OPENCLAW",
                    route_mode="CONTROLLED_DELEGATION",
                    disposition="EXECUTED",
                    wrapper_exit_code=0,
                )
            )

    def test_bad_hash_and_missing_ledger_fail_closed(self):
        with self.assertRaises(operational_controller.OperationalControllerContractError):
            operational_controller.qualify_operational_result(**self._base(task_identity="bad"))
        with self.assertRaises(operational_controller.OperationalControllerContractError):
            operational_controller.qualify_operational_result(**self._base(ledger_record_hashes=()))

    def test_all_external_authorities_remain_zero(self):
        names = (
            "FILESYSTEM_SOURCE_READ_COUNT",
            "FILESYSTEM_WRITE_IMPLEMENTATION_COUNT",
            "SUBPROCESS_EXECUTION_COUNT",
            "NETWORK_IMPLEMENTATION_COUNT",
            "PROVIDER_CLIENT_IMPLEMENTATION_COUNT",
            "MODEL_CALL_IMPLEMENTATION_COUNT",
            "MODEL_ROUTING_IMPLEMENTATION_COUNT",
            "AUTH_IMPLEMENTATION_COUNT",
            "AUTO_RETRY_IMPLEMENTATION_COUNT",
            "AUTO_FALLBACK_IMPLEMENTATION_COUNT",
            "HUMAN_APPROVAL_EXECUTION_COUNT",
            "HUMAN_DECISION_SIDE_EFFECT_COUNT",
            "STATE_TRANSITION_EXECUTION_COUNT",
            "GIT_OPERATION_COUNT",
            "LIVE_CLOUD_EXECUTION_COUNT",
        )
        for name in names:
            self.assertEqual(getattr(operational_controller, name), 0, name)


if __name__ == "__main__":
    unittest.main()
