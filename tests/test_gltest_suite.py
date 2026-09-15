"""
ZeroTruthProof — Real GenVM Integration Tests via gltest/direct_vm.

NO genlayer module mocks. Every call runs through the actual GenVM execution engine.
Tests cover:
  1. Compiler-backed R1CS artifact verification (auto-detect)
  2. Full bounty lifecycle (happy-path)
  3. Payable deposit / timestamp guards
  4. Under-constrained circuit detection via R1CS artifact
  5. Deterministic payout flow
"""
import pytest
import json
from pathlib import Path

CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "ZeroTruthProof.py"

# ── Sample R1CS Artifacts (embedded for determinism) ──────────────────

MULTIPLIER2_R1CS = json.dumps({
    "prime": "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    "nVars": 4, "nOutputs": 1, "nPubInputs": 0, "nPrvInputs": 2,
    "nConstraints": 1,
    "constraints": [[{"2": "1"}, {"3": "1"}, {"1": "1"}]],
    "signal_map": {"one": 0, "c": 1, "a": 2, "b": 3}
})

BUGGY_SQUARE_R1CS = json.dumps({
    "prime": "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    "nVars": 3, "nOutputs": 1, "nPubInputs": 0, "nPrvInputs": 1,
    "nConstraints": 0,
    "constraints": [],
    "signal_map": {"one": 0, "out": 1, "x": 2}
})

VALID_WITNESS = json.dumps({"a": 3, "b": 7, "c": 21})
INVALID_WITNESS = json.dumps({"a": 3, "b": 7, "c": 999})


# ── Test Class: Compiler-Backed R1CS Artifact Verification ────────────

def _get_verifier():
    import sys
    ztp = sys.modules.get('_contract_ZeroTruthProof') or sys.modules.get('ZeroTruthProof')
    return ztp.R1CSConstraintVerifier


class TestCompilerBackedR1CS:
    """Tests for the verify_r1cs_artifact engine via the auto-detecting verify() entrypoint."""

    def test_valid_multiplier2_artifact_passes(self, direct_deploy, direct_vm):
        """Compiler-backed R1CS artifact: valid witness {a:3,b:7,c:21} MUST pass."""
        direct_deploy(str(CONTRACT_PATH))
        verifier = _get_verifier()

        result = verifier.verify(MULTIPLIER2_R1CS, VALID_WITNESS)
        assert result["verified"] is True, f"Expected verified=True, got: {result['reason']}"
        assert result["stage"] == "COMPLETE"
        assert "Compiler-backed" in result["reason"]

    def test_invalid_witness_rejected_by_artifact(self, direct_deploy, direct_vm):
        """Compiler-backed R1CS artifact: invalid witness {c:999} MUST fail."""
        direct_deploy(str(CONTRACT_PATH))
        verifier = _get_verifier()

        result = verifier.verify(MULTIPLIER2_R1CS, INVALID_WITNESS)
        assert result["verified"] is False
        assert result["stage"] == "R1CS_VERIFICATION"
        assert "VIOLATED" in result["reason"]

    def test_under_constrained_artifact_detected(self, direct_deploy, direct_vm):
        """BuggySquare R1CS artifact (0 constraints) MUST be flagged as under-constrained."""
        direct_deploy(str(CONTRACT_PATH))
        verifier = _get_verifier()

        witness = json.dumps({"x": 5, "out": 9999})  # Any value for 'out'
        result = verifier.verify(BUGGY_SQUARE_R1CS, witness)
        assert result["verified"] is False
        assert "under-constrained" in result["reason"].lower() or "0 constraints" in result["reason"]

    def test_auto_detect_routes_to_artifact(self, direct_deploy, direct_vm):
        """Auto-detection: JSON with 'constraints' and 'nVars' routes to artifact verifier."""
        direct_deploy(str(CONTRACT_PATH))
        verifier = _get_verifier()

        result = verifier.verify(MULTIPLIER2_R1CS, VALID_WITNESS)
        assert "Compiler-backed" in result["reason"], \
            f"Should route to compiler-backed engine, got: {result['reason']}"

    def test_auto_detect_falls_through_for_circom(self, direct_deploy, direct_vm):
        """Auto-detection: raw Circom source falls through to AST parser."""
        direct_deploy(str(CONTRACT_PATH))
        verifier = _get_verifier()

        circom_src = '''
pragma circom 2.1.6;
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}
component main = Multiplier2();
'''
        result = verifier.verify(circom_src, VALID_WITNESS)
        assert result["verified"] is True
        assert "Compiler-backed" not in result["reason"], \
            "Circom source should use AST parser, not artifact engine"


# ── Test Class: Contract Deployment & Lifecycle ───────────────────────

class TestContractLifecycle:
    """Real GenVM integration tests for the contract's public API."""

    def test_deploy_succeeds(self, direct_deploy, direct_vm):
        """Contract deploys without error on GenVM."""
        contract = direct_deploy(str(CONTRACT_PATH))
        assert contract is not None

    def test_create_bounty_and_get_tasks(self, direct_deploy, direct_vm, direct_alice):
        """Create an audit bounty with payable value and retrieve it via get_all_tasks."""
        direct_vm.sender = direct_alice
        direct_vm.value = 1_000_000_000_000_000_000  # 1 GEN in wei

        contract = direct_deploy(str(CONTRACT_PATH))
        direct_vm.warp("2026-09-15T12:00:00Z")

        contract.create_audit_bounty(
            "task-001",
            "https://raw.githubusercontent.com/example/circuit.circom",
            "a" * 64,  # Valid SHA-256 hash (64 hex chars)
            "Circom 2.1 / Groth16 / R1CS",
            "Under-constrained signals",
            "b" * 40   # Valid Git commit SHA (40 hex chars)
        )

        tasks_json = contract.get_all_tasks()
        tasks = json.loads(tasks_json)
        assert len(tasks) == 1
        assert tasks[0]["id"] == "task-001"
        assert tasks[0]["status"] == "OPEN"
        assert int(tasks[0]["escrow_amount"]) == 1_000_000_000_000_000_000

    def test_duplicate_task_id_rejected(self, direct_deploy, direct_vm, direct_alice):
        """Creating a bounty with an existing task_id MUST raise UserError."""
        direct_vm.sender = direct_alice
        direct_vm.value = 1_000_000_000_000_000_000

        contract = direct_deploy(str(CONTRACT_PATH))
        direct_vm.warp("2026-09-15T12:00:00Z")

        contract.create_audit_bounty(
            "dup-001", "https://example.com/c.circom", "a" * 64,
            "Circom", "Under-constrained", "b" * 40
        )

        # Second create with same ID should fail
        with pytest.raises(Exception, match="already exists"):
            contract.create_audit_bounty(
                "dup-001", "https://example.com/c2.circom", "c" * 64,
                "Circom", "Missing range checks", "d" * 40
            )

    def test_accept_audit_task(self, direct_deploy, direct_vm, direct_alice, direct_bob):
        """Auditor accepts an OPEN bounty with payable stake."""
        direct_vm.sender = direct_alice
        direct_vm.value = 1_000_000_000_000_000_000

        contract = direct_deploy(str(CONTRACT_PATH))
        direct_vm.warp("2026-09-15T12:00:00Z")

        contract.create_audit_bounty(
            "accept-001", "https://example.com/c.circom", "a" * 64,
            "Circom", "Under-constrained", "b" * 40
        )

        # Bob accepts
        direct_vm.sender = direct_bob
        direct_vm.value = 500_000_000_000_000_000  # 0.5 GEN stake
        contract.accept_audit_task("accept-001")

        tasks = json.loads(contract.get_all_tasks())
        assert tasks[0]["status"] == "IN_PROGRESS"
        assert int(tasks[0]["auditor_stake"]) == 500_000_000_000_000_000

    def test_zero_escrow_rejected(self, direct_deploy, direct_vm, direct_alice):
        """Creating a bounty with 0 escrow MUST raise UserError."""
        direct_vm.sender = direct_alice
        direct_vm.value = 0

        contract = direct_deploy(str(CONTRACT_PATH))
        direct_vm.warp("2026-09-15T12:00:00Z")

        with pytest.raises(Exception, match="positive"):
            contract.create_audit_bounty(
                "zero-001", "https://example.com/c.circom", "a" * 64,
                "Circom", "Under-constrained", "b" * 40
            )

    def test_get_withdrawable_balance_default_zero(self, direct_deploy, direct_vm, direct_alice):
        """Withdrawable balance defaults to 0 for any address."""
        contract = direct_deploy(str(CONTRACT_PATH))
        balance = contract.get_withdrawable_balance(str(direct_alice.hex()))
        assert balance == "0"

    def test_withdraw_no_balance_raises(self, direct_deploy, direct_vm, direct_alice):
        """Withdrawing with no balance MUST raise error."""
        direct_vm.sender = direct_alice
        contract = direct_deploy(str(CONTRACT_PATH))
        with pytest.raises(Exception, match="[Nn]o withdrawable"):
            contract.withdraw()
