"""
Real GenLayer Runtime Tests — Executed on GenVM Sandbox via gltest.

CRITICAL: ZERO MOCKS. This test file runs directly within the official GenLayer
GenVM runtime environment using direct_deploy and direct_vm fixtures.
"""
import pytest
import json
from pathlib import Path

CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "ZeroTruthProof.py"

MULTIPLIER2_R1CS = json.dumps({
    "prime": "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    "nVars": 4, "nOutputs": 1, "nPubInputs": 0, "nPrvInputs": 2,
    "nConstraints": 1,
    "constraints": [[{"2": "1"}, {"3": "1"}, {"1": "1"}]],
    "signal_map": {"one": 0, "c": 1, "a": 2, "b": 3}
})


class TestGenLayerRuntimeZK:
    """Real GenVM runtime verification tests — no mock modules or patches."""

    def test_01_finite_field_division_and_arithmetic_in_genvm(self, direct_deploy, direct_vm):
        """Test exact BN254 finite field arithmetic inside GenVM execution engine."""
        direct_deploy(str(CONTRACT_PATH))
        import sys
        mod = sys.modules['_contract_ZeroTruthProof']
        verifier = mod.R1CSConstraintVerifier
        p = mod.BN254_PRIME

        # 10 / 2 mod p == 5
        res = verifier.evaluate_expression("10 / 2", {})
        assert res == 5

        # (p - 1) + 2 mod p == 1
        expr = f"({p - 1} + 2)"
        res2 = verifier.evaluate_expression(expr, {})
        assert res2 == 1

    def test_02_compiler_backed_r1cs_artifact_execution(self, direct_deploy, direct_vm):
        """Execute compiler-backed R1CS artifact verification within GenVM runtime."""
        direct_deploy(str(CONTRACT_PATH))
        import sys
        mod = sys.modules['_contract_ZeroTruthProof']
        verifier = mod.R1CSConstraintVerifier

        # Valid witness: a=3, b=7, c=21
        valid_w = json.dumps({"a": 3, "b": 7, "c": 21})
        res = verifier.verify(MULTIPLIER2_R1CS, valid_w)
        assert res["verified"] is True
        assert res["stage"] == "COMPLETE"
        assert "Compiler-backed" in res["reason"]

    def test_03_invalid_witness_rejection_in_genvm(self, direct_deploy, direct_vm):
        """Deterministic rejection of unsound witness in GenVM runtime."""
        direct_deploy(str(CONTRACT_PATH))
        import sys
        mod = sys.modules['_contract_ZeroTruthProof']
        verifier = mod.R1CSConstraintVerifier

        # Invalid witness: a=3, b=7, c=999
        invalid_w = json.dumps({"a": 3, "b": 7, "c": 999})
        res = verifier.verify(MULTIPLIER2_R1CS, invalid_w)
        assert res["verified"] is False
        assert res["stage"] == "R1CS_VERIFICATION"

    def test_04_bounty_lifecycle_on_chain_runtime(self, direct_deploy, direct_vm, direct_alice, direct_bob):
        """Full payable escrow and staking lifecycle executed directly in GenVM."""
        direct_vm.sender = direct_alice
        direct_vm.value = 1_000_000_000_000_000_000  # 1 GEN escrow
        contract = direct_deploy(str(CONTRACT_PATH))
        direct_vm.warp("2026-09-15T12:00:00Z")

        # 1. Create bounty
        contract.create_audit_bounty(
            "zk-runtime-task-01",
            "https://raw.githubusercontent.com/example/circuit.circom",
            "a" * 64,
            "Circom 2.1 / Groth16 / R1CS",
            "Under-constrained signals",
            "b" * 40
        )

        # 2. Auditor accepts with 20% stake
        direct_vm.sender = direct_bob
        direct_vm.value = 200_000_000_000_000_000  # 0.2 GEN stake
        contract.accept_audit_task("zk-runtime-task-01")

        # 3. Query state from GenVM storage
        tasks = json.loads(contract.get_all_tasks())
        assert len(tasks) == 1
        assert tasks[0]["status"] == "IN_PROGRESS"
        assert int(tasks[0]["escrow_amount"]) == 1_000_000_000_000_000_000
        assert int(tasks[0]["auditor_stake"]) == 200_000_000_000_000_000
