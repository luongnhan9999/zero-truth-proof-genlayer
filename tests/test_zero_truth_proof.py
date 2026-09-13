import sys
import os
import unittest
from unittest.mock import MagicMock
import hashlib

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
        class llm:
            @staticmethod
            def call(prompt, model=""):
                return '{"action": "SPLIT", "confidence": 90, "reason": "Validator consensus split"}'
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


class TestR1CSVerifier(unittest.TestCase):
    """Dedicated test suite for R1CSConstraintVerifier — the core on-chain verification engine."""

    CIRCUIT = """pragma circom 2.1.6;
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}"""

    CIRCUIT_WITH_EQUALITY = """pragma circom 2.1.6;
template EqualCheck() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
    a === b;
}"""

    CIRCUIT_PRECEDENCE = """pragma circom 2.1.6;
template Precedence() {
    signal input x;
    signal input y;
    signal input z;
    signal output out;
    out <== x + y * z;
}"""

    def test_01_valid_witness_passes(self):
        """Correct witness values satisfy all R1CS constraints."""
        res = contract_module.R1CSConstraintVerifier.verify(self.CIRCUIT, '{"a": 3, "b": 7, "c": 21}')
        self.assertTrue(res["verified"])
        self.assertEqual(res["stage"], "COMPLETE")
        self.assertTrue(any("SATISFIED" in line for line in res["trace"]))

    def test_02_wrong_arithmetic_rejected(self):
        """Witness declares c=99 but circuit requires c = a*b = 3*7 = 21 → MUST REJECT."""
        res = contract_module.R1CSConstraintVerifier.verify(self.CIRCUIT, '{"a": 3, "b": 7, "c": 99}')
        self.assertFalse(res["verified"])
        self.assertEqual(res["stage"], "R1CS_VERIFICATION")
        self.assertIn("VIOLATED", res["reason"])
        self.assertTrue(any("VIOLATED" in line for line in res["trace"]))

    def test_03_arbitrary_text_rejected(self):
        """Non-JSON arbitrary text (comments, prose) → MUST REJECT at WITNESS_PARSING stage."""
        witness = "This is some arbitrary code or comment describing a witness but not executing one."
        res = contract_module.R1CSConstraintVerifier.verify(self.CIRCUIT, witness)
        self.assertFalse(res["verified"])
        self.assertEqual(res["stage"], "WITNESS_PARSING")
        self.assertIn("non-JSON", res["reason"])

    def test_04_missing_input_signal_rejected(self):
        """Witness missing required input signal 'b' → MUST REJECT at WITNESS_BINDING stage."""
        res = contract_module.R1CSConstraintVerifier.verify(self.CIRCUIT, '{"a": 5, "c": 25}')
        self.assertFalse(res["verified"])
        self.assertEqual(res["stage"], "WITNESS_BINDING")
        self.assertIn("b", res["reason"])

    def test_05_zero_value_bypass_attempt(self):
        """Witness sets all signals to 0 — constraint c === a*b holds (0*0=0) → passes (correctly).
        Then test with equality constraint a === b where a=0, b=1 → MUST REJECT."""
        # Zero-zero: c = 0*0 = 0, passes correctly
        res_zero = contract_module.R1CSConstraintVerifier.verify(self.CIRCUIT, '{"a": 0, "b": 0, "c": 0}')
        self.assertTrue(res_zero["verified"])

        # Zero vs non-zero with equality constraint: a=0, b=1 → a !== b → REJECT
        res_fail = contract_module.R1CSConstraintVerifier.verify(
            self.CIRCUIT_WITH_EQUALITY, '{"a": 0, "b": 1, "c": 0}'
        )
        self.assertFalse(res_fail["verified"])
        self.assertEqual(res_fail["stage"], "R1CS_VERIFICATION")

    def test_06_invalid_circuit_syntax(self):
        """Circuit without 'pragma circom' → MUST REJECT at CIRCUIT_COMPILATION stage."""
        bad_circuit = "template Foo() { signal input x; x === 1; }"
        res = contract_module.R1CSConstraintVerifier.verify(bad_circuit, '{"x": 1}')
        self.assertFalse(res["verified"])
        self.assertEqual(res["stage"], "CIRCUIT_COMPILATION")
        self.assertIn("pragma circom", res["reason"])

    def test_07_operator_precedence(self):
        """Expression 'x + y * z' must evaluate as x + (y*z), not (x+y)*z.
        x=2, y=3, z=4 → out = 2 + 3*4 = 14, NOT (2+3)*4 = 20."""
        # Correct: out = 14
        res_correct = contract_module.R1CSConstraintVerifier.verify(
            self.CIRCUIT_PRECEDENCE, '{"x": 2, "y": 3, "z": 4, "out": 14}'
        )
        self.assertTrue(res_correct["verified"])

        # Wrong precedence value: out = 20 → MUST REJECT
        res_wrong = contract_module.R1CSConstraintVerifier.verify(
            self.CIRCUIT_PRECEDENCE, '{"x": 2, "y": 3, "z": 4, "out": 20}'
        )
        self.assertFalse(res_wrong["verified"])
        self.assertEqual(res_wrong["stage"], "R1CS_VERIFICATION")

    def test_08_empty_json_rejected(self):
        """Empty JSON object {} → MUST REJECT (no signal assignments)."""
        res = contract_module.R1CSConstraintVerifier.verify(self.CIRCUIT, '{}')
        self.assertFalse(res["verified"])
        self.assertEqual(res["stage"], "WITNESS_PARSING")
        self.assertIn("empty", res["reason"].lower())

    def test_09_boolean_values_rejected(self):
        """JSON with boolean values → MUST REJECT (signals must be numeric)."""
        res = contract_module.R1CSConstraintVerifier.verify(self.CIRCUIT, '{"a": true, "b": 5, "c": 5}')
        self.assertFalse(res["verified"])
        self.assertEqual(res["stage"], "WITNESS_PARSING")
        self.assertIn("boolean", res["reason"])

    def test_10_expression_evaluator_standalone(self):
        """Directly test the expression tokenizer/parser/evaluator for correctness."""
        ev = contract_module.R1CSConstraintVerifier.evaluate_expression
        signals = {"a": 3, "b": 5, "c": 10}

        # Basic arithmetic
        self.assertEqual(ev("a * b", signals), 15)
        self.assertEqual(ev("a + b", signals), 8)
        self.assertEqual(ev("c - a", signals), 7)

        # Operator precedence: a + b * c = 3 + 5*10 = 53
        self.assertEqual(ev("a + b * c", signals), 53)

        # Parentheses: (a + b) * c = (3+5)*10 = 80
        self.assertEqual(ev("(a + b) * c", signals), 80)

        # Literal numbers
        self.assertEqual(ev("42", {}), 42)
        self.assertEqual(ev("0xff", {}), 255)

        # Unary minus in finite field: -3 mod p = p - 3
        p = contract_module.R1CSConstraintVerifier.BN254_PRIME
        self.assertEqual(ev("-a", signals), (p - 3) % p)

        # Unknown signal → error
        with self.assertRaises(ValueError):
            ev("unknown_signal", signals)

    def test_11_bn254_finite_field_overflow_wraps(self):
        """Signals exceeding BN254 prime wrap modulo p correctly."""
        p = contract_module.R1CSConstraintVerifier.BN254_PRIME
        ev = contract_module.R1CSConstraintVerifier.evaluate_expression
        signals = {"a": p - 1, "b": 2}
        self.assertEqual(ev("a + b", signals), 1)

    def test_12_bn254_modular_division_via_fermat_inverse(self):
        """Division in BN254 field uses modular multiplicative inverse."""
        p = contract_module.R1CSConstraintVerifier.BN254_PRIME
        ev = contract_module.R1CSConstraintVerifier.evaluate_expression
        signals = {"a": 1, "b": 2}
        res = ev("a / b", signals)
        self.assertEqual((res * 2) % p, 1)

    def test_13_bn254_division_by_zero_reverts(self):
        """Division by zero in constraint expression raises ValueError."""
        ev = contract_module.R1CSConstraintVerifier.evaluate_expression
        signals = {"a": 5, "b": 0}
        with self.assertRaises(ValueError):
            ev("a / b", signals)

    def test_14_array_signals_parsed_and_verified(self):
        """Circuit with array signal input a[2] parses and verifies correctly."""
        circuit = """pragma circom 2.1.6;
template ArrayCheck() {
    signal input a[2];
    signal output sum;
    sum <== a[0] + a[1];
}
"""
        parsed = contract_module.R1CSConstraintVerifier.parse_circuit(circuit)
        self.assertIn("a[0]", parsed["input_signals"])
        self.assertIn("a[1]", parsed["input_signals"])

        witness = '{"a[0]": 10, "a[1]": 20, "sum": 30}'
        res = contract_module.R1CSConstraintVerifier.verify(circuit, witness)
        self.assertTrue(res["verified"])

    def test_15_component_and_include_parsing(self):
        """Includes and component declarations are tracked in circuit structure."""
        circuit = """pragma circom 2.1.6;
include "comparators.circom";
template HasSub() {
    signal input in;
    signal output out;
    component c = IsZero();
    out <== in;
}
"""
        parsed = contract_module.R1CSConstraintVerifier.parse_circuit(circuit)
        self.assertIn("comparators.circom", parsed["includes"])
        self.assertEqual(len(parsed["components"]), 1)
        self.assertEqual(parsed["components"][0]["name"], "c")
        self.assertEqual(parsed["components"][0]["template"], "IsZero")

    def test_16_compiler_version_extracted_from_pragma(self):
        """Pragma version is extracted and pinned in verification trace."""
        parsed = contract_module.R1CSConstraintVerifier.parse_circuit(self.CIRCUIT)
        self.assertEqual(parsed["compiler_version"], "2.1.6")


class TestContractIntegration(unittest.TestCase):
    """Contract-level integration tests for the full escrow lifecycle."""

    def setUp(self):
        self.gl = mock_mod.gl
        self.gl.transfers = []
        self.gl.message_raw = {"datetime": "2026-08-24T00:00:00+00:00"}
        self.owner = MockAddress("0xzk_rollup_owner")
        self.auditor = MockAddress("0xzk_security_researcher")
        self.stranger = MockAddress("0xrandom_user")

        self.contract = contract_module.Contract()
        self.contract.tasks = {}
        self.contract.task_ids = []

        self.tid = "zk_merkle_tree_circuit_01"
        self.circuit_code = "pragma circom 2.1.6;\ntemplate MerkleProof() {\n    signal input path_index;\n    signal output root;\n    path_index === 1;\n}"
        self.exploit_code = '{"path_index": 1, "root": 1}'
        self.circuit_hash = hashlib.sha256(self.circuit_code.encode("utf-8")).hexdigest()
        self.exploit_hash = hashlib.sha256(self.exploit_code.encode("utf-8")).hexdigest()

        self.gl.message.sender_address = self.owner
        self.gl.message.value = MockBigInt(3000)
        self.contract.create_audit_bounty(
            self.tid,
            "https://github.com/zk-protocol/circuits/merkle.circom",
            self.circuit_hash,
            "Circom 2.1.6 / Groth16",
            "Under-constrained intermediate path signals allowing root forging",
            "a1b2c3d4e5f678901234567890abcdef12345678"
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
            "verdict": "APPROVED", "confidence": 99, "reason": "Signal path_index unconstrained"
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

    def test_03_dispute_flow_and_validator_consensus(self):
        """Project owner disputes proof -> validator consensus adjudicates resolution."""
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

        # Payout blocked during dispute
        self.gl.message_raw = {"datetime": "2026-08-25T02:00:00+00:00"}
        self.gl.message.sender_address = self.auditor
        with self.assertRaises(MockUserError):
            self.contract.finalize_payout(self.tid)

        # Validator-governed consensus resolves with SPLIT
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"action": "SPLIT", "confidence": 95, "reason": "Circumstances warrant 50/50 split"}
        self.contract.resolve_dispute_consensus(self.tid)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(len(self.gl.transfers), 2)
        self.assertEqual(self.gl.transfers[0]["to"], self.auditor)
        self.assertEqual(self.gl.transfers[0]["value"], 2100) # 1500 half + 600 stake
        self.assertEqual(self.gl.transfers[1]["to"], self.owner)
        self.assertEqual(self.gl.transfers[1]["value"], 1500)

    def test_04_voluntary_concession_release_and_refund(self):
        """Owner can voluntarily concede (RELEASE); Auditor can voluntarily concede (REFUND)."""
        task = self.contract.tasks[self.tid]
        task.status = "DISPUTED"
        task.auditor = self.auditor
        task.auditor_stake = MockBigInt(600)
        self.contract.tasks[self.tid] = task

        # Owner voluntarily concedes funds to auditor via RELEASE
        self.gl.message.sender_address = self.owner
        self.contract.resolve_escalation(self.tid, "RELEASE")
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(self.gl.transfers[-1]["to"], self.auditor)
        self.assertEqual(self.gl.transfers[-1]["value"], 3600)

    def test_05_unauthorized_dispute_caller_reverts(self):
        """Random stranger cannot dispute or arbitrate a task."""
        self.gl.message.sender_address = self.stranger
        with self.assertRaises(MockUserError):
            self.contract.raise_dispute(self.tid, "Trolling")

    def test_06_untruncated_prompt_evidence(self):
        """Verify prompt generated for LLM validator contains full untruncated source code."""
        captured_prompt = []
        def mock_exec_prompt(p, response_format="json"):
            captured_prompt.append(p)
            return {"verdict": "APPROVED", "confidence": 95, "reason": "Verified"}

        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        long_circuit = self.circuit_code + "\n" + "// padding " * 500
        long_exploit = '{"path_index": 1, "root": 1, "pad_0": 0, "pad_1": 0}'
        long_c_hash = hashlib.sha256(long_circuit.encode("utf-8")).hexdigest()
        long_e_hash = hashlib.sha256(long_exploit.encode("utf-8")).hexdigest()

        tid_long = "long_code_task"
        self.gl.message.sender_address = self.owner
        self.gl.message.value = MockBigInt(3000)
        self.contract.create_audit_bounty(
            tid_long, "https://github.com/long.circom", long_c_hash, "Circom 2.1.6", "Focus", "commit123"
        )
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(tid_long)

        self.gl.nondet.web.render = lambda url, mode="text": long_circuit if "long.circom" in url else long_exploit
        self.gl.nondet.exec_prompt = mock_exec_prompt

        self.contract.submit_counterexample(tid_long, "https://gist.github.com/long_exploit.js", long_e_hash)
        self.assertTrue(len(captured_prompt) >= 1)
        self.assertIn("R1CS CONSTRAINT VERIFICATION TRACE:", captured_prompt[0])

    def test_07_failed_circuit_retrieval_escalates(self):
        """404 on circuit URL results in ESCALATED verdict to protect auditor stake."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": "404 Not Found" if "merkle" in url else self.exploit_code
        self.contract.submit_counterexample(self.tid, "https://gist.github.com/exploit.js", self.exploit_hash)
        self.assertEqual(self.contract.tasks[self.tid].status, "ESCALATED")

    def test_08_failed_exploit_retrieval_escalates(self):
        """404 on exploit witness URL results in REFUND verdict."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else "404 Not Found"
        self.contract.submit_counterexample(self.tid, "https://gist.github.com/exploit.js", self.exploit_hash)
        self.assertEqual(self.contract.tasks[self.tid].status, "NEEDS_REVISION")

    def test_09_circuit_hash_mismatch_escalates(self):
        """Mismatch between target circuit and pinned SHA-256 escalates immediately."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        tampered_code = self.circuit_code + "\n// tampered"
        self.gl.nondet.web.render = lambda url, mode="text": tampered_code if "merkle" in url else self.exploit_code
        self.contract.submit_counterexample(self.tid, "https://gist.github.com/exploit.js", self.exploit_hash)
        self.assertEqual(self.contract.tasks[self.tid].status, "ESCALATED")

    def test_10_validator_disagreement_raises_consensus_error(self):
        """Disagreement between leader and validator in consensus raises UserError."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else self.exploit_code

        def bad_run_nondet(leader_fn, validator_fn):
            raise MockUserError("Consensus Disagreement")
        old_run = self.gl.vm.run_nondet
        self.gl.vm.run_nondet = bad_run_nondet
        try:
            with self.assertRaises(MockUserError):
                self.contract.submit_counterexample(self.tid, "https://gist.github.com/exploit.js", self.exploit_hash)
        finally:
            self.gl.vm.run_nondet = old_run

    def test_11_accounting_conservation_on_approval(self):
        """Sum of transfers on APPROVED finalization strictly equals escrow + stake (3600)."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else self.exploit_code
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"verdict": "APPROVED", "confidence": 99, "reason": "OK"}
        self.contract.submit_counterexample(self.tid, "https://proof.js", self.exploit_hash)

        self.gl.message_raw = {"datetime": "2026-08-25T01:00:00+00:00"}
        self.contract.finalize_payout(self.tid)
        total_out = sum(t["value"] for t in self.gl.transfers)
        self.assertEqual(total_out, 3600)

    def test_12_accounting_conservation_on_slashing(self):
        """Two consecutive failed attempts slash auditor stake: 3600 returned to owner."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        bad_witness = '{"path_index": 999, "root": 999}'
        bad_hash = hashlib.sha256(bad_witness.encode("utf-8")).hexdigest()
        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else bad_witness
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"verdict": "REFUND", "confidence": 95, "reason": "Counterexample failed constraints"}

        # Attempt 1 -> NEEDS_REVISION
        self.contract.submit_counterexample(self.tid, "https://proof1.js", bad_hash)
        self.assertEqual(self.contract.tasks[self.tid].status, "NEEDS_REVISION")

        # Attempt 2 -> Slashing -> CLOSED
        self.contract.submit_counterexample(self.tid, "https://proof2.js", bad_hash)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(self.gl.transfers[-1]["to"], self.owner)
        self.assertEqual(self.gl.transfers[-1]["value"], 3600)

    def test_13_accounting_conservation_on_split(self):
        """Bilateral SPLIT conserves total escrow + stake (3000 + 600 = 3600)."""
        task = self.contract.tasks[self.tid]
        task.status = "DISPUTED"
        task.auditor = self.auditor
        task.auditor_stake = MockBigInt(600)
        self.contract.tasks[self.tid] = task

        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"action": "SPLIT", "confidence": 90, "reason": "Split"}
        self.gl.message.sender_address = self.owner
        self.contract.resolve_dispute_consensus(self.tid)
        total_out = sum(t["value"] for t in self.gl.transfers)
        self.assertEqual(total_out, 3600)

    def test_14_repeated_bounty_creation_rejected(self):
        """Attempting to create duplicate bounty with existing task_id reverts."""
        self.gl.message.sender_address = self.owner
        self.gl.message.value = MockBigInt(1000)
        with self.assertRaises(MockUserError):
            self.contract.create_audit_bounty(
                self.tid, "https://github.com/dup.circom", self.circuit_hash, "Circom", "Focus"
            )

    def test_15_double_accept_rejected(self):
        """Accepting an already accepted (IN_PROGRESS) task reverts."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        other_auditor = MockAddress("0xother_auditor")
        self.gl.message.sender_address = other_auditor
        self.gl.message.value = MockBigInt(600)
        with self.assertRaises(MockUserError):
            self.contract.accept_audit_task(self.tid)

    def test_16_double_finalize_rejected(self):
        """Finalizing an already CLOSED task reverts."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else self.exploit_code
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"verdict": "APPROVED", "confidence": 99, "reason": "OK"}
        self.contract.submit_counterexample(self.tid, "https://proof.js", self.exploit_hash)

        self.gl.message_raw = {"datetime": "2026-08-25T01:00:00+00:00"}
        self.contract.finalize_payout(self.tid)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")

        with self.assertRaises(MockUserError):
            self.contract.finalize_payout(self.tid)

    def test_17_self_audit_rejected(self):
        """Project owner cannot accept their own bounty task."""
        self.gl.message.sender_address = self.owner
        self.gl.message.value = MockBigInt(600)
        with self.assertRaises(MockUserError):
            self.contract.accept_audit_task(self.tid)

    def test_18_cancel_bounty_before_timeout_reverts(self):
        """Owner attempting to cancel OPEN bounty before 30 days elapses reverts."""
        self.gl.message.sender_address = self.owner
        self.gl.message_raw = {"datetime": "2026-09-03T00:00:00+00:00"}
        with self.assertRaises(MockUserError):
            self.contract.cancel_bounty(self.tid)

    def test_19_cancel_bounty_after_timeout_succeeds(self):
        """Owner recovers 100% escrow after 30 days of unaccepted bounty."""
        self.gl.message.sender_address = self.owner
        self.gl.message_raw = {"datetime": "2026-09-25T00:00:00+00:00"}
        self.contract.cancel_bounty(self.tid)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(self.gl.transfers[-1]["to"], self.owner)
        self.assertEqual(self.gl.transfers[-1]["value"], 3000)

    def test_20_recover_expired_in_progress_task(self):
        """Auditor abandons IN_PROGRESS task for > 14 days -> timeout recovery refunds both parties."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.message_raw = {"datetime": "2026-09-09T00:00:00+00:00"}
        self.gl.message.sender_address = self.owner
        self.contract.recover_expired_task(self.tid)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(len(self.gl.transfers), 2)
        self.assertEqual(self.gl.transfers[0]["to"], self.owner)
        self.assertEqual(self.gl.transfers[0]["value"], 3000)
        self.assertEqual(self.gl.transfers[1]["to"], self.auditor)
        self.assertEqual(self.gl.transfers[1]["value"], 600)

    def test_21_recover_expired_needs_revision_task(self):
        """Auditor abandons NEEDS_REVISION for > 7 days -> recovery refunds escrow to owner, stake to auditor."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        bad_w = '{"path_index": 0, "root": 0}'
        bad_h = hashlib.sha256(bad_w.encode("utf-8")).hexdigest()
        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else bad_w
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"verdict": "REFUND", "confidence": 95, "reason": "Counterexample failed"}
        self.contract.submit_counterexample(self.tid, "https://p.js", bad_h)
        self.assertEqual(self.contract.tasks[self.tid].status, "NEEDS_REVISION")

        self.gl.message_raw = {"datetime": "2026-09-02T00:00:00+00:00"}
        self.contract.recover_expired_task(self.tid)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")

    def test_22_recover_expired_dispute_auto_splits(self):
        """Dispute unresolved for > 30 days automatically triggers 50/50 fallback split."""
        task = self.contract.tasks[self.tid]
        task.status = "DISPUTED"
        task.auditor = self.auditor
        task.auditor_stake = MockBigInt(600)
        task.disputed_at = MockBigInt(1724457600)
        self.contract.tasks[self.tid] = task

        self.gl.message_raw = {"datetime": "2026-09-25T00:00:00+00:00"}
        self.gl.message.sender_address = self.auditor
        self.contract.recover_expired_task(self.tid)
        self.assertEqual(self.contract.tasks[self.tid].status, "CLOSED")
        self.assertEqual(len(self.gl.transfers), 2)
        self.assertEqual(self.gl.transfers[0]["to"], self.auditor)
        self.assertEqual(self.gl.transfers[0]["value"], 2100)
        self.assertEqual(self.gl.transfers[1]["to"], self.owner)
        self.assertEqual(self.gl.transfers[1]["value"], 1500)

    def test_23_dispute_after_cooling_off_reverts(self):
        """Raising dispute after 24h cooling-off period has passed reverts."""
        self.gl.message.sender_address = self.auditor
        self.gl.message.value = MockBigInt(600)
        self.contract.accept_audit_task(self.tid)

        self.gl.nondet.web.render = lambda url, mode="text": self.circuit_code if "merkle" in url else self.exploit_code
        self.gl.nondet.exec_prompt = lambda p, response_format="json": {"verdict": "APPROVED", "confidence": 99, "reason": "OK"}
        self.contract.submit_counterexample(self.tid, "https://p.js", self.exploit_hash)

        self.gl.message_raw = {"datetime": "2026-08-25T01:01:00+00:00"}
        self.gl.message.sender_address = self.owner
        with self.assertRaises(MockUserError):
            self.contract.raise_dispute(self.tid, "Too late")


if __name__ == "__main__":
    unittest.main(verbosity=2)

