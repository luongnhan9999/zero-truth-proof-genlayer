import pytest
from pathlib import Path

CONTRACT_PATH = Path(__file__).parent.parent / "contracts" / "ZeroTruthProof.py"

def test_smoke_deploy(direct_vm, direct_deploy, direct_alice):
    direct_vm.sender = direct_alice
    direct_vm.value = 1000000000000000000
    contract = direct_deploy(str(CONTRACT_PATH))
    assert contract is not None
    
    contract.create_audit_bounty(
        "task_1",
        "https://raw.githubusercontent.com/luongnhan9999/zero-truth-proof-genlayer/main/circuits/Multiplier2.circom",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Circom 2.1.6 / Groth16",
        "Multiplication constraint soundness",
        "ae84e88383c38b259163eb1d368e7ec8ff1e792c"
    )
    tasks = contract.get_all_tasks()
    print("Tasks:", tasks)

