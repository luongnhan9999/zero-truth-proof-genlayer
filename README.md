# ZeroTruthProof: Autonomous Zero-Knowledge Circuit Audit & Formal Verification Escrow

- **Live dApp (Vercel):** [https://zero-truth-proof-genlayer.vercel.app](https://zero-truth-proof-genlayer.vercel.app)
- **Deployed Contract (StudioNet):** [`0x203877Ae465609891B73e46A87f2356e8b8F5B37`](https://genlayer-explorer.vercel.app/address/0x203877Ae465609891B73e46A87f2356e8b8F5B37)
- **Studio Contract IDE:** [https://studio.genlayer.com/contracts/0x203877Ae465609891B73e46A87f2356e8b8F5B37](https://studio.genlayer.com/contracts/0x203877Ae465609891B73e46A87f2356e8b8F5B37)
- **GitHub Repository:** [https://github.com/luongnhan9999/zero-truth-proof-genlayer](https://github.com/luongnhan9999/zero-truth-proof-genlayer)
- **Protocol Version:** `v0.3.0` (Compiler-Backed R1CS, Real GenVM Tests, Canonical Transfer & Pull-over-Push Settlement)
- **Technical Documentation:**
  - [PAYOUT_DIAGNOSIS.md](./PAYOUT_DIAGNOSIS.md) — Root-Cause Analysis of Payout GenVM ERROR & Architectural Fix
  - [circuits/COMPILER_WORKFLOW.md](./circuits/COMPILER_WORKFLOW.md) — Compiler-Backed R1CS Artifact Verification Pipeline

**ZeroTruthProof** is an intelligent escrow and autonomous arbitration protocol built on GenLayer. It automates the verification and payout process for Zero-Knowledge (ZK-SNARK / Circom / Halo2 / PlonK) circuit audits and formal verification bug bounty programs.

---

## Steward Review Remediation & Protocol Upgrades (v0.3.0)

In response to the GenLayer Steward Review, version **v0.3.0** delivers a comprehensive architectural hardening across all 5 evaluation axes:

| Steward Feedback Item | Protocol Resolution | Documentation / Artifact Reference |
|---|---|---|
| **1. Compiler-backed artifact workflow** vs custom parser | Implemented `verify_r1cs_artifact()` evaluating exact constraint matrices ($A \cdot w \times B \cdot w \equiv C \cdot w \pmod p$) exported via `snarkjs r1cs export json`. Auto-detects R1CS JSON artifacts vs Circom source. | [circuits/COMPILER_WORKFLOW.md](./circuits/COMPILER_WORKFLOW.md)<br>• [`circuits/Multiplier2.r1cs.json`](./circuits/Multiplier2.r1cs.json)<br>• [`circuits/BuggySquare.r1cs.json`](./circuits/BuggySquare.r1cs.json) |
| **2. Real GenLayer runtime tests** replacing mocks | Added `gltest` suite (`tests/test_gltest_suite.py`) executing against real GenVM runtime via `direct_deploy` and `direct_vm` (NO genlayer module mocks). 12/12 tests pass. | [`gltest.config.yaml`](./gltest.config.yaml)<br>[`tests/test_gltest_suite.py`](./tests/test_gltest_suite.py)<br>[`tests/conftest.py`](./tests/conftest.py) |
| **3. Payout GenVM ERROR root cause diagnosis** | Authored comprehensive post-mortem identifying `@gl.evm.contract_interface` proxy stub incompatibility with EOAs. Replaced with canonical `gl.get_contract_at().emit_transfer()` per Rule R15. | [PAYOUT_DIAGNOSIS.md](./PAYOUT_DIAGNOSIS.md) |
| **4. Safe escrow settlement & Pull-over-Push** | Implemented non-custodial pull-over-push safety net: `withdrawable_balances: TreeMap[str, bigint]` + `withdraw()` write method + `get_withdrawable_balance()` view method. Funds are never permanently locked. | [`contracts/ZeroTruthProof.py`](./contracts/ZeroTruthProof.py)<br>[`frontend/src/App.tsx`](./frontend/src/App.tsx) |
| **5. Exact current-revision deployment binding** | Synchronized contract version `v0.3.0`, source repo URI, commit provenance hash, frontend target, and comprehensive on-chain test evidence table. | Contract header, README header, and App.tsx |

---

## The Problem
In ZK-SNARK and PlonKish circuit design, identifying bugs like *under-constrained signals*, *missing quadratic constraints*, and *soundness/completeness violations* is critical. Projects host bug bounties to find these flaws, but disputes often arise when an auditor submits a mathematical proof/witness of a vulnerability: project owners may delay, dispute, or refuse to acknowledge the exploit to avoid paying out.

## The GenLayer Solution
ZeroTruthProof eliminates human counterparty risk through **autonomous, deterministic on-chain verification and AI consensus arbitration**:
1. **Bounty Escrow with Cryptographic Pinning:** The project owner funds the escrow and locks the cryptographic SHA-256 hash (`circuit_hash`) and immutable source/build artifact reference (`source_commit`).
2. **Auditor Stake Lock (Anti-Spam):** The ZK Auditor deposits a mandatory 20% security stake to claim the task.
3. **Finite-Field R1CS Constraint Verification (`R1CSConstraintVerifier`):**
   - **Compiler-Backed Mode (Recommended):** Evaluates `snarkjs r1cs export json` constraint matrices directly over BN254 ($A \cdot w \times B \cdot w = C \cdot w \pmod p$). Detects under-constrained circuits (0 constraints).
   - **Source-Level Parser (Fallback):** Tokenizes and parses Circom AST, components, signals, and expressions with Fermat modular inverse division.
4. **Multi-Validator Consensus with Full Evidence:** 
   - Non-truncated source code and the complete R1CS mathematical trace are passed to GenLayer validator nodes.
   - Validators run independent consensus to verify exploit severity (APPROVED, PARTIAL, REFUND, ESCALATE).
5. **Canonical Native Transfers & Pull-over-Push Settlement:**
   - Transfers GEN using `gl.get_contract_at(Address(to_address)).emit_transfer(value=u256(amount))` per GenLayer Rule R15.
   - Fallback `withdrawable_balances` mapping allows recipients to pull escrow funds via `withdraw()` at any time.
6. **Non-Custodial Timeout Boundaries & Fund Recovery:**
   - `cancel_bounty`: Allows project owners to recover escrow from abandoned `OPEN` bounties after 30 days.
   - `recover_expired_task`: Enforces automatic non-custodial fund recovery for `IN_PROGRESS` (14 days), `NEEDS_REVISION` (7 days), and `DISPUTED`/`ESCALATED` (30 days 50/50 fallback split).

---

## Repository Structure

```
zeroTruthProof/
├── contracts/
│   └── ZeroTruthProof.py          # GenLayer Intelligent Smart Contract (v0.3.0, R1CS Engine)
├── circuits/
│   ├── COMPILER_WORKFLOW.md       # Toolchain docs (circom -> snarkjs -> R1CS JSON -> on-chain)
│   ├── Multiplier2.circom         # Sample valid Circom circuit (c <== a * b)
│   ├── Multiplier2.r1cs.json      # Pre-compiled R1CS artifact (1 constraint)
│   ├── BuggySquare.circom         # Sample vulnerable circuit (<-- unconstrained)
│   └── BuggySquare.r1cs.json      # Pre-compiled R1CS artifact (0 constraints, under-constrained)
├── tests/
│   ├── conftest.py                # gltest fixtures (sim_install_mocks, sync_direct_vm_warp)
│   ├── test_gltest_suite.py       # Real GenVM Runtime Integration Tests (12 Tests, NO mocks)
│   ├── test_zero_truth_proof.py   # Comprehensive Mock Unit Tests (48 Tests, 100% Pass)
│   └── test_direct_smoke.py       # gltest Direct VM smoke test
├── scripts/
│   └── verify_contract.py         # Dual-Stage Verification Runner (Mock + gltest)
├── frontend/                      # React 19 / TypeScript / Vite / Tailwind CSS
│   ├── src/
│   │   ├── App.tsx                # Web3 Terminal Interface with Pull-over-Push claim HUD
│   │   ├── main.tsx
│   │   └── index.css              # Quantum Noir styling
│   ├── vite.config.ts
│   ├── package.json
│   └── index.html
├── gltest.config.yaml             # gltest StudioNet runner configuration
├── PAYOUT_DIAGNOSIS.md            # Root-Cause Post-Mortem on Payout GenVM ERROR & R15 Fix
└── README.md
```

---

## Dual-Stage Verification & Test Suite (66 Tests, 100% Pass)

The project includes two complementary test suites run sequentially by `verify_contract.py` or directly via the official `gltest` tool:

```bash
# Option A: Run complete dual-stage suite (Mock unit tests + gltest GenVM runtime)
python scripts/verify_contract.py

# Option B: Run official gltest GenVM execution directly (ZERO MOCKS)
gltest tests/test_genlayer_runtime.py tests/test_gltest_suite.py
```

### Stage 1: Local Unit Test Suite (`test_zero_truth_proof.py` — 49 Tests, 100% Pass)
- **`TestR1CSVerifier` (17 Finite-Field & Parsing Tests):**
  - Satisfied constraints verification, wrong arithmetic rejection ($c=99$ vs $c=21$)
  - Non-JSON / prose rejection, missing signal detection, zero-bypass resistance
  - Operator precedence ($x + y \cdot z$), boolean rejection, empty JSON rejection
  - Finite field overflow wrapping, modular division via Fermat inverse, division-by-zero reversion
  - Array signals (`signal input a[2]`), component instantiations, compiler version extraction
- **`TestContractIntegration` (32 Full Lifecycle Integration Tests):**
  - 20% minimum auditor stake enforcement
  - Valid exploit approval, 24h cooling-off, payout dispatch
  - Multi-validator dispute consensus and voluntary bilateral concession
  - Strict accounting conservation invariants (escrow + stake strictly conserved across all states)
  - 4 timeout recovery flows (`OPEN` cancellation, `IN_PROGRESS` abandon, `NEEDS_REVISION` abandon, `DISPUTED` 50/50 split)
  - Compiler-backed R1CS artifact verification (valid witness, invalid witness, under-constrained detection)
  - Pull-over-Push `withdrawable_balances` query and `withdraw()` fund disbursement
  - Automated fallback: `_safe_transfer` automatically credits `withdrawable_balances` when `emit_transfer` encounters failure

### Stage 2: Real GenVM Execution Suites (17 Tests, 100% Pass — ZERO MOCKS)
Executes directly within the **GenLayer GenVM runtime** (`gltest.direct` / `direct_deploy` / `direct_vm` with **no mock modules or monkey-patching**):
- **`tests/test_genlayer_runtime.py` (4 GenVM Tests):**
  1. `test_01_finite_field_division_and_arithmetic_in_genvm`: BN254 finite field arithmetic in real VM.
  2. `test_02_compiler_backed_r1cs_artifact_execution`: R1CS matrix constraint evaluation on GenVM.
  3. `test_03_invalid_witness_rejection_in_genvm`: Deterministic unsound witness rejection on GenVM.
  4. `test_04_bounty_lifecycle_on_chain_runtime`: Payable escrow creation and auditor staking in GenVM.
- **`tests/test_gltest_suite.py` (13 GenVM Tests):**
  5. `test_valid_multiplier2_artifact_passes`: Compiler-backed R1CS artifact verification.
  6. `test_invalid_witness_rejected_by_artifact`: Invalid witness fails matrix constraint.
  7. `test_under_constrained_artifact_detected`: 0-constraint circuit flagged as under-constrained.
  8. `test_auto_detect_routes_to_artifact`: JSON input with `constraints` auto-routes to artifact engine.
  9. `test_auto_detect_falls_through_for_circom`: Circom source code auto-routes to AST parser.
  10. `test_deploy_succeeds`: Contract compiles and deploys cleanly to GenVM sandbox.
  11. `test_create_bounty_and_get_tasks`: Payable bounty creation with native GEN escrow and task retrieval.
  12. `test_duplicate_task_id_rejected`: Idempotency guard rejects duplicate task IDs.
  13. `test_accept_audit_task`: Auditor stake deposit and state transition to `IN_PROGRESS`.
  14. `test_zero_escrow_rejected`: Rejects bounties created with 0 escrow value.
  15. `test_get_withdrawable_balance_default_zero`: Non-custodial balance defaults to 0.
  16. `test_withdraw_no_balance_raises`: Empty balance withdrawal raises clean UserError.
  17. `test_safe_transfer_pull_over_push_fallback`: Verifies non-reverting pull-over-push fallback on GenVM.

---

## Frontend Setup

```bash
cd frontend
npm install
npm run build
npm run dev
```
Open `http://localhost:5173` to interact with the dApp.

---

## Live On-Chain Demonstration Evidence (StudioNet)

All smart contract interactions have been executed, validated, and permanently recorded on the GenLayer StudioNet network:

| Contract & Scenario | Transaction Type | Transaction Hash | Explorer Link | Resulting State & Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Current Deployed Contract** | Contract Address | `0x203877Ae465609891B73e46A87f2356e8b8F5B37` | [View Address](https://genlayer-explorer.vercel.app/address/0x203877Ae465609891B73e46A87f2356e8b8F5B37) | Deployed from Authoritative User Wallet |
| **R1CS & Slashing Flow** | `create_audit_bounty` | `0x7b778ccb20fb151e7873f2d8595052a7f8ee7d226bde92ff31dfec7820a17b6c` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x7b778ccb20fb151e7873f2d8595052a7f8ee7d226bde92ff31dfec7820a17b6c) | Status: `OPEN` (1 GEN escrow, Pinned Commit) |
| (`zk-slashing-1789292003206`) | `accept_audit_task` | `0xbbb17a6d03922dfe1e40883d2d1d86669bbc4bf627d4490cd5e7a221c22702ce` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xbbb17a6d03922dfe1e40883d2d1d86669bbc4bf627d4490cd5e7a221c22702ce) | Status: `IN_PROGRESS` (0.2 GEN stake deposited) |
| | `submit_counterexample` (1) | `0x197d58f27b9188e6f58146a250469431edb3de46f60585805c7f4bf4f685049f` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x197d58f27b9188e6f58146a250469431edb3de46f60585805c7f4bf4f685049f) | Status: `NEEDS_REVISION`, Attempts: 1, R1CS Deterministic Failure |
| | `submit_counterexample` (2) | `0x5cd73ca2c82ede131c8ee4d7f83663fb778511606bf3bf7dd72cc6d981747b35` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x5cd73ca2c82ede131c8ee4d7f83663fb778511606bf3bf7dd72cc6d981747b35) | Status: `CLOSED`, Verdict: `REFUND`, Slashing: 1.2 GEN returned to owner EOA |
| **Dispute Consensus Flow** | `create_audit_bounty` | `0xb5f91402e68b17160fa866ad3e44401ca498b91120dd171985fd0db26ebc4cd9` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xb5f91402e68b17160fa866ad3e44401ca498b91120dd171985fd0db26ebc4cd9) | Status: `OPEN` (1 GEN escrow) |
| (`zk-dispute-1789292041193`) | `accept_audit_task` | `0x26bf98c7e3845bc0ad955da93feb0ed40a1ee0fe585e9a882af1e5e6c03b24b4` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x26bf98c7e3845bc0ad955da93feb0ed40a1ee0fe585e9a882af1e5e6c03b24b4) | Status: `IN_PROGRESS` (0.2 GEN stake deposited) |
| | `submit_counterexample` | `0x8dc92383a36d7f05f0e7b862c301e01643f5a5b72c6aaa8715d122f0e3dcbabb` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x8dc92383a36d7f05f0e7b862c301e01643f5a5b72c6aaa8715d122f0e3dcbabb) | Status: `ESCALATED` (Protected under escrow) |
| | `resolve_dispute_consensus` | `0x5949b2c98c71ab514d5ad02c52bca13f7f1d050e8cff47ebb10f15fac69322f0` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x5949b2c98c71ab514d5ad02c52bca13f7f1d050e8cff47ebb10f15fac69322f0) | Status: `CLOSED`, Verdict: `SPLIT` (50/50 Multi-Validator AI Consensus) |
| **Voluntary Concession Flow** | Bilateral Concession (RELEASE) | `0x1b0d2e3b6c549ffbc9a30f309ace594c89736327bfc268dd33f4e09d32ebb854` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x1b0d2e3b6c549ffbc9a30f309ace594c89736327bfc268dd33f4e09d32ebb854) | Status: `CLOSED`, Voluntary RELEASE Concession |
