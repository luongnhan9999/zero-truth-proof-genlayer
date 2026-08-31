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
        self.circuit_code = "pragma circom 2.1.6;\ntemplate MerkleProof() {\n    signal input path_index;\n    signal output root;\n    path_index === 1;\n}"
        self.exploit_code = '{"path_index": 1, "root": 999}'
        import hashlib
        self.circuit_hash = hashlib.sha256(self.circuit_code.encode("utf-8")).hexdigest()
        self.exploit_hash = hashlib.sha256(self.exploit_code.encode("utf-8")).hexdigest()

        self.gl.message.sender_address = self.owner
        self.gl.message.value = MockBigInt(3000)
        self.contract.create_audit_bounty(
            self.tid,
            "https://github.com/zk-protocol/circuits/merkle.circom",
            self.circuit_hash,
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

        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else self.exploit_code
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {
            "verdict": "APPROVED", "confidence": 99, "reason": "Signal path_index[i] unconstrained allowing fake root proof"
        }

        self.contract.submit_counterexample(self.tid, "https://gist.github.com/zk-exploit/fake_witness.js", self.exploit_hash)
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

        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else self.exploit_code
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"verdict": "APPROVED", "confidence": 92, "reason": "Proof valid"}
        self.contract.submit_counterexample(self.tid, "https://gist.github.com/proof.js", self.exploit_hash)

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

    def test_04_deterministic_compiler_verification(self):
        """Test on-chain Circom AST parsing, R1CS constraint extraction, and witness evaluation."""
        circuit = """pragma circom 2.1.6;
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
    a === b;
}"""
        witness_valid = '{"a": 5, "b": 5, "c": 25}'
        res = contract_module.R1CSEvaluator.compile_and_verify(circuit, witness_valid)
        self.assertTrue(res["verified"])
        self.assertTrue(any("PASSED" in line for line in res["trace"]))

        # Missing input signal in witness -> MUST FAIL DETERMINISTICALLY
        witness_invalid = '{"a": 5}'
        res_fail = contract_module.R1CSEvaluator.compile_and_verify(circuit, witness_invalid)
        self.assertFalse(res_fail["verified"])
        self.assertIn("Missing input signals in witness", res_fail["reason"])

    def test_05_untruncated_prompt_evidence(self):
        """Verify prompt generated for LLM validator contains full untruncated source code without slicing."""
        captured_prompt = []
        def mock_exec_prompt(p, response_format="json"):
            captured_prompt.append(p)
            return {"verdict": "APPROVED", "confidence": 95, "reason": "Verified"}

        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        long_circuit = self.circuit_code + "\n" + "// padding " * 500
        long_exploit = self.exploit_code + "\n" + "// exploit padding " * 500
        import hashlib
        long_c_hash = hashlib.sha256(long_circuit.encode("utf-8")).hexdigest()
        long_e_hash = hashlib.sha256(long_exploit.encode("utf-8")).hexdigest()

        tid_long = "long_code_task"
        self.gl.message.sender_address = self.owner
        self.gl.message.value = MockBigInt(3000)
        self.contract.create_audit_bounty(
            tid_long, "https://github.com/long.circom", long_c_hash, "Circom 2.1.6", "Focus"
        )
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(tid_long)

        self.gl.nondet.web.render = lambda url, mode="text": long_circuit if "long.circom" in url else long_exploit
        self.gl.nondet.exec_prompt = mock_exec_prompt

        self.contract.submit_counterexample(tid_long, "https://gist.github.com/long_exploit.js", long_e_hash)
        self.assertTrue(len(captured_prompt) >= 1)
        prompt_text = captured_prompt[0]
        self.assertIn("DETERMINISTIC COMPILER & WITNESS EVALUATION TRACE:", prompt_text)
        self.assertIn(long_circuit, prompt_text)
        self.assertIn(long_exploit, prompt_text)

    def test_06_adversarial_invalid_witnesses_rejected(self):
        """Adversarial tests: verify that invalid format, invalid math values, and arbitrary text witnesses are rejected."""
        circuit = """pragma circom 2.1.6;
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}"""
        # 1. Arbitrary non-JSON witness text (Steward: 'arbitrary witness text') -> MUST REJECT
        res_text = contract_module.R1CSEvaluator.compile_and_verify(circuit, "arbitrary non-JSON text witness exploit")
        self.assertFalse(res_text["verified"])
        self.assertIn("Witness verification failed", res_text["reason"])

        # 2. Correct input names but mathematically incorrect constraint values -> MUST REJECT
        res_math = contract_module.R1CSEvaluator.compile_and_verify(circuit, '{"a": 5, "b": 5, "c": 999}')
        self.assertFalse(res_math["verified"])
        self.assertIn("R1CS constraint violation", res_math["reason"])

        # 3. Correct names but non-integer values -> MUST REJECT
        res_str = contract_module.R1CSEvaluator.compile_and_verify(circuit, '{"a": "hello", "b": 5, "c": 25}')
        self.assertFalse(res_str["verified"])
        self.assertIn("Witness verification failed", res_str["reason"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
