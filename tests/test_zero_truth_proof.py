import sys
import os
import unittest
from unittest.mock import MagicMock

class MockAddress(str): pass
class MockBigInt(int): pass
class MockUserError(Exception): pass

class MockReturn:
    def __init__(self, calldata):
        self.calldata = calldata

class MockContractStub:
    def __init__(self, address, tracker):
        self.address = address
        self.tracker = tracker

    def emit_transfer(self, value):
        self.tracker.append({"to": self.address, "value": value})

class MockGL:
    class Contract:
        def __init__(self):
            self.tasks = {}
            self.task_ids = []
            self.platform_admin = "0xadmin"

    class public:
        @staticmethod
        def view(fn): return fn
        @staticmethod
        def write(fn): return fn

    class message:
        value = MockBigInt(0)
        sender_address = MockAddress("0xProjectOwner")

    class nondet:
        class web:
            @staticmethod
            def render(url, mode="text"): pass
        @staticmethod
        def exec_prompt(prompt, response_format="json"): pass

    class vm:
        Return = MockReturn
        @staticmethod
        def run_nondet(leader_fn, validator_fn):
            res = leader_fn()
            ret = MockReturn(calldata=res)
            if not validator_fn(ret):
                raise MockUserError("Consensus Disagreement")
            return res

    def __init__(self):
        self.transfers = []
        self.message_raw = {"datetime": "2026-08-24T00:00:00+00:00"}

    def get_contract_at(self, address):
        return MockContractStub(address, self.transfers)

MockGL.public.write.payable = lambda fn: fn

mock_mod = MagicMock()
mock_mod.gl = MockGL()
mock_mod.allow_storage = lambda cls: cls
mock_mod.Address = MockAddress
mock_mod.bigint = MockBigInt
mock_mod.u256 = MockBigInt
mock_mod.UserError = MockUserError
mock_mod.TreeMap = dict
mock_mod.DynArray = list

sys.modules["genlayer"] = mock_mod
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "contracts")))
import ZeroTruthProof as contract_module

class TestZeroTruthProofExecutionSuite(unittest.TestCase):
    def setUp(self):
        self.gl = mock_mod.gl
        self.gl.transfers = []
        self.gl.message_raw = {"datetime": "2026-08-24T00:00:00+00:00"}
        self.admin = MockAddress("0xadmin")
        self.owner = MockAddress("0xzk_rollup_owner")
        self.auditor = MockAddress("0xzk_security_researcher")

        self.gl.message.sender_address = self.admin
        self.contract = contract_module.Contract()
        self.contract.tasks = {}
        self.contract.task_ids = []
        self.contract.platform_admin = self.admin.lower()

        # Project owner locks 3000 GEN bounty
        self.tid = "zk_merkle_tree_circuit_01"
        self.gl.message.sender_address = self.owner
        self.gl.message.value = MockBigInt(3000)
        self.contract.create_audit_bounty(
            self.tid,
            "https://github.com/zk-protocol/circuits/merkle.circom",
            "Circom 2.1.6 / Groth16",
            "Under-constrained intermediate path signals allowing root forging"
        )

    def test_01_under_staking_reverts(self):
        """Auditor attempts to deposit < 20% stake (599 < 600) -> MUST REVERT"""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(599)
        with self.assertRaises(MockUserError):
            self.contract.accept_audit_task(self.tid)

    def test_02_valid_counterexample_approved_and_cooling_off(self):
        """Valid counterexample approved -> 24h delay enforced before 3600 GEN payout."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": "Circom circuit and PoC witness proof code"
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {
            "verdict": "APPROVED", "confidence": 99, "reason": "Signal path_index[i] unconstrained allowing fake root proof"
        }

        self.contract.submit_counterexample(self.tid, "https://gist.github.com/zk-exploit/fake_witness.js")
        self.assertEqual(self.contract.tasks[self.tid].status, "AWAITING_PAYOUT")

        # Early finalization attempt -> REVERT
        self.gl.message_raw = {"datetime": "2026-08-24T12:00:00+00:00"}
        with self.assertRaises(MockUserError):
            self.contract.finalize_payout(self.tid)

        # Finalization at T+24h01m -> SUCCEEDS
        self.gl.message_raw = {"datetime": "2026-08-25T00:01:00+00:00"}
        self.contract.finalize_payout(self.tid)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(self.gl.transfers[0]["to"], self.auditor)
        self.assertEqual(self.gl.transfers[0]["value"], 3600)

    def test_03_dispute_flow_and_arbitration(self):
        """Project owner disputes proof -> transitions to DISPUTED and blocks payout."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": "Circuit code"
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"verdict": "APPROVED", "confidence": 92, "reason": "Proof valid"}
        self.contract.submit_counterexample(self.tid, "https://gist.github.com/proof.js")

        # Owner raises dispute at T+8h
        self.gl.message_raw = {"datetime": "2026-08-24T08:00:00+00:00"}
        self.gl.message.sender_address = self.owner
        self.contract.raise_dispute(self.tid, "PoC uses an out-of-scope compiler version")
        self.assertEqual(self.contract.tasks[self.tid].status, "DISPUTED")

        # Payout blocked
        self.gl.message_raw = {"datetime": "2026-08-25T02:00:00+00:00"}
        self.gl.message.sender_address = self.auditor
        with self.assertRaises(MockUserError):
            self.contract.finalize_payout(self.tid)

        # Admin resolves with SPLIT
        self.gl.message.sender_address = self.admin
        self.contract.resolve_escalation(self.tid, "SPLIT")
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(len(self.gl.transfers), 2)
        self.assertEqual(self.gl.transfers[0]["to"], self.auditor)
        self.assertEqual(self.gl.transfers[0]["value"], 2100) # 1500 half + 600 stake
        self.assertEqual(self.gl.transfers[1]["to"], self.owner)
        self.assertEqual(self.gl.transfers[1]["value"], 1500)

if __name__ == "__main__":
    unittest.main(verbosity=2)
