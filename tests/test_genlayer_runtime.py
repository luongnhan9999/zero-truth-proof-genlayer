import sys
import os
import unittest
import hashlib
import json
from unittest.mock import MagicMock

# Configure lightweight GenLayer mock environment for running outside GenVM
class MockAddress(str): pass
class MockBigInt(int): pass
class MockUserError(Exception): pass

class MockGL:
    class Contract:
        def __init__(self):
            self.tasks = {}
            self.task_ids = []

    class public:
        @staticmethod
        def view(fn): return fn
        @staticmethod
        def write(fn): return fn

    class message:
        value = MockBigInt(0)
        sender_address = MockAddress("0xProjectOwner")

    class evm:
        @staticmethod
        def contract_interface(cls):
            return lambda addr: None

MockGL.public.write.payable = lambda fn: fn

mock_mod = MagicMock()
mock_mod.gl = MockGL()
mock_mod.Address = MockAddress
mock_mod.bigint = MockBigInt
mock_mod.u256 = MockBigInt
mock_mod.UserError = MockUserError
mock_mod.TreeMap = dict
mock_mod.DynArray = list
mock_mod.allow_storage = lambda cls: cls

sys.modules['genlayer'] = mock_mod

# Add contracts directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'contracts')))

try:
    from ZeroTruthProof import R1CSConstraintVerifier, BN254_PRIME
except ImportError:
    from ZeroTruthProof_5 import R1CSConstraintVerifier, BN254_PRIME

class TestGenLayerRuntimeZK(unittest.TestCase):
    def test_01_finite_field_division_and_arithmetic(self):
        """Test exact BN254 finite field division using Fermat inverse."""
        # 10 / 2 mod p == 5
        res = R1CSConstraintVerifier.evaluate_expression("10 / 2", {})
        self.assertEqual(res, 5)

        # (p - 1) + 2 mod p == 1
        expr = f"({BN254_PRIME - 1} + 2)"
        res2 = R1CSConstraintVerifier.evaluate_expression(expr, {})
        self.assertEqual(res2, 1)

    def test_02_array_and_component_expansion(self):
        """Test compilation and constraint expansion for array signals and components."""
        circuit = """
        pragma circom 2.1.6;
        template SubGate() {
            signal input in;
            signal output out;
            out <== in * in;
        }
        template Main() {
            signal input a[2];
            signal output b;
            component gate = SubGate();
            gate.in <== a[0];
            b <== gate.out + a[1];
        }
        component main = Main();
        """
        parsed = R1CSConstraintVerifier.parse_circuit(circuit)
        self.assertTrue(parsed["valid_syntax"])
        self.assertIn("a[0]", parsed["input_signals"])
        self.assertIn("a[1]", parsed["input_signals"])

        # Valid witness evaluation
        witness = json.dumps({"a[0]": 3, "a[1]": 4, "gate.in": 3, "gate.out": 9, "b": 13})
        v_res = R1CSConstraintVerifier.verify(circuit, witness)
        self.assertTrue(v_res["verified"])

    def test_03_invalid_witness_rejection_finite_field(self):
        """Test deterministic rejection when witness violates finite-field equation."""
        circuit = """
        pragma circom 2.1.6;
        template Multiplier() {
            signal input x;
            signal input y;
            signal output z;
            z <== x * y;
        }
        component main = Multiplier();
        """
        # 3 * 5 = 15 != 16
        bad_witness = json.dumps({"x": 3, "y": 5, "z": 16})
        v_res = R1CSConstraintVerifier.verify(circuit, bad_witness)
        self.assertFalse(v_res["verified"])
        self.assertEqual(v_res["stage"], "R1CS_VERIFICATION")

if __name__ == "__main__":
    unittest.main()
