# ZeroTruthProof: Autonomous Zero-Knowledge Circuit Audit & Formal Verification Escrow

- **Live dApp (Vercel):** [https://zero-truth-proof-genlayer.vercel.app](https://zero-truth-proof-genlayer.vercel.app)
- **Deployed Contract (StudioNet):** [`0x2Ab04C85AD702DCe5b067Bcd7E4A06ADa6a868CB`](https://genlayer-explorer.vercel.app/address/0x2Ab04C85AD702DCe5b067Bcd7E4A06ADa6a868CB)
- **Studio Contract IDE:** [https://studio.genlayer.com/contracts/0x2Ab04C85AD702DCe5b067Bcd7E4A06ADa6a868CB](https://studio.genlayer.com/contracts/0x2Ab04C85AD702DCe5b067Bcd7E4A06ADa6a868CB)
- **GitHub Repository:** [https://github.com/luongnhan9999/zero-truth-proof-genlayer](https://github.com/luongnhan9999/zero-truth-proof-genlayer)

**ZeroTruthProof** is an intelligent escrow and autonomous arbitration protocol built on GenLayer. It automates the verification and payout process for Zero-Knowledge (ZK-SNARK / Circom / Halo2 / PlonK) circuit audits and formal verification bug bounty programs.

---

## The Problem
In ZK-SNARK and PlonKish circuit design, identifying bugs like *under-constrained signals*, *missing quadratic constraints*, and *soundness/completeness violations* is critical. Projects host bug bounties to find these flaws, but disputes often arise when an auditor submits a mathematical proof/witness of a vulnerability: project owners may delay, dispute, or refuse to acknowledge the exploit to avoid paying out.

## The GenLayer Solution
ZeroTruthProof eliminates human counterparty risk through **autonomous, deterministic on-chain verification and AI consensus arbitration**:
1. **Bounty Escrow with Cryptographic Pinning:** The project owner funds the escrow and locks the cryptographic SHA-256 hash (`circuit_hash`) and immutable source/build artifact reference (`source_commit`).
2. **Auditor Stake Lock (Anti-Spam):** The ZK Auditor deposits a mandatory 20% security stake to claim the task.
3. **Finite-Field R1CS Constraint Verification (`R1CSConstraintVerifier`):**
   - The contract retrieves the circuit code and submitted witness using non-deterministic web rendering and verifies SHA-256 integrity.
   - Circuit tokenizer & AST parser parse Circom constraints (`<==`, `==>`, `===`), components (`component c = Template()`), include directives, and array signals (`signal input a[N]`).
   - Evaluates all arithmetic over the **BN254 scalar field** ($p = 21888242871839275222246405745257275088548364400416034343698204186575808495617$) with Fermat modular inverse division.
4. **Multi-Validator Consensus with Full Evidence:** 
   - Non-truncated source code and the complete R1CS mathematical trace are passed to GenLayer validator nodes.
   - Validators run independent consensus to verify exploit severity (APPROVED, PARTIAL, REFUND, ESCALATE).
5. **Non-Custodial Timeout Boundaries & Fund Recovery:**
   - `cancel_bounty`: Allows project owners to recover escrow from abandoned `OPEN` bounties after 30 days.
   - `recover_expired_task`: Enforces automatic non-custodial fund recovery for `IN_PROGRESS` (14 days), `NEEDS_REVISION` (7 days), and `DISPUTED`/`ESCALATED` (30 days 50/50 fallback split).
6. **Decentralized Arbitration:**
   - Eliminates unilateral admin authority: disputes are adjudicated via GenLayer multi-validator consensus (`resolve_dispute_consensus`) or voluntary bilateral concession (`resolve_escalation`).

---

## Repository Structure

```
zeroTruthProof/
├── contracts/
│   └── ZeroTruthProof.py         # GenLayer Intelligent Smart Contract (BN254 R1CS Engine)
├── tests/
│   └── test_zero_truth_proof.py  # Comprehensive Test Suite (39 Tests, 100% Pass)
├── scripts/
│   └── verify_contract.py        # Automated test verification runner
├── frontend/                     # React 19 / TypeScript / Vite / Tailwind CSS
│   ├── src/
│   │   ├── App.tsx               # Web3 Terminal Interface with real balance queries
│   │   ├── main.tsx
│   │   └── index.css             # Quantum Noir styling
│   ├── vite.config.ts
│   ├── package.json
│   └── index.html
└── README.md
```

---

## Verification & Test Suite (39 Tests, 100% Pass)

### Running Contract Tests
```bash
python scripts/verify_contract.py
```

### Test Coverage Breakdown:
- **`TestR1CSVerifier` (16 Finite-Field & Parsing Tests):**
  1. `test_01_valid_witness_passes`: Verifies valid witness values satisfy all constraints.
  2. `test_02_wrong_arithmetic_rejected`: Rejects mathematically incorrect witness values ($c=99$ vs $c=21$).
  3. `test_03_arbitrary_text_rejected`: Rejects non-JSON arbitrary text / prose claiming to be a witness.
  4. `test_04_missing_input_signal_rejected`: Rejects witness missing required input signals.
  5. `test_05_zero_value_bypass_attempt`: Proves zero-value bypass attacks are prevented.
  6. `test_06_invalid_circuit_syntax`: Rejects circuits lacking `pragma circom` directive.
  7. `test_07_operator_precedence`: Verifies arithmetic operator precedence ($x + y \times z = x + (y \times z)$).
  8. `test_08_empty_json_rejected`: Rejects empty JSON objects `{}` with zero signals.
  9. `test_09_boolean_values_rejected`: Rejects non-numeric JSON values (booleans).
  10. `test_10_expression_evaluator_standalone`: Standalone arithmetic evaluator unit tests.
  11. `test_11_bn254_finite_field_overflow_wraps`: Verifies values wrap modulo BN254 prime.
  12. `test_12_bn254_modular_division_via_fermat_inverse`: Verifies division via Fermat's little theorem modular inverse.
  13. `test_13_bn254_division_by_zero_reverts`: Verifies division by zero raises an explicit error.
  14. `test_14_array_signals_parsed_and_verified`: Verifies array input signals (`signal input a[2]`) parse and evaluate correctly.
  15. `test_15_component_and_include_parsing`: Verifies component declarations and `include` directives are tracked.
  16. `test_16_compiler_version_extracted_from_pragma`: Verifies pragma version is extracted and pinned in trace.

- **`TestContractIntegration` (23 Full Lifecycle Integration Tests):**
  17. `test_01_under_staking_reverts`: Enforces 20% minimum auditor stake deposit.
  18. `test_02_valid_counterexample_approved_and_cooling_off`: Validates payout delay and release flow.
  19. `test_03_dispute_flow_and_validator_consensus`: Validates dispute locking and validator consensus adjudication.
  20. `test_04_voluntary_concession_release_and_refund`: Validates bilateral voluntary concession without admin.
  21. `test_05_unauthorized_dispute_caller_reverts`: Prevents unauthorized third parties from raising disputes.
  22. `test_06_untruncated_prompt_evidence`: Verifies 100% untruncated code delivery into LLM prompt.
  23. `test_07_failed_circuit_retrieval_escalates`: 404 target circuit escalates to protect auditor stake.
  24. `test_08_failed_exploit_retrieval_escalates`: 404 exploit witness triggers REFUND verdict.
  25. `test_09_circuit_hash_mismatch_escalates`: SHA-256 mismatch escalates immediately.
  26. `test_10_validator_disagreement_raises_consensus_error`: Disagreement between validators aborts transaction.
  27. `test_11_accounting_conservation_on_approval`: Total escrow + stake conserved on approved payout.
  28. `test_12_accounting_conservation_on_slashing`: Slashed stake + escrow returned to owner on 2nd failure.
  29. `test_13_accounting_conservation_on_split`: Total funds strictly conserved on 50/50 split.
  30. `test_14_repeated_bounty_creation_rejected`: Rejects duplicate task IDs.
  31. `test_15_double_accept_rejected`: Rejects duplicate acceptance of claimed task.
  32. `test_16_double_finalize_rejected`: Rejects double-finalization of closed tasks.
  33. `test_17_self_audit_rejected`: Prevents project owner from auditing own circuit.
  34. `test_18_cancel_bounty_before_timeout_reverts`: Prevents premature bounty cancellation.
  35. `test_19_cancel_bounty_after_timeout_succeeds`: Allows owner to cancel after 30 days.
  36. `test_20_recover_expired_in_progress_task`: Recovers funds if auditor abandons task (> 14 days).
  37. `test_21_recover_expired_needs_revision_task`: Recovers funds if auditor abandons revision (> 7 days).
  38. `test_22_recover_expired_dispute_auto_splits`: Automatically executes 50/50 fallback split after 30 days.
  39. `test_23_dispute_after_cooling_off_reverts`: Rejects disputes raised after 24h cooling-off window.

---

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` to interact with the dApp.

---

## Live On-Chain Demonstration Evidence (StudioNet)

All smart contract interactions have been executed, validated, and permanently recorded on the GenLayer StudioNet network:

| Contract & Scenario | Transaction Type | Transaction Hash | Explorer Link | Resulting State & Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Current Deployed Contract** | Contract Address | `0x2Ab04C85AD702DCe5b067Bcd7E4A06ADa6a868CB` | [View Address](https://genlayer-explorer.vercel.app/address/0x2Ab04C85AD702DCe5b067Bcd7E4A06ADa6a868CB) | Active StudioNet Deployment |
| **R1CS & Slashing Flow** | `create_audit_bounty` | `0xa655b10781658515d6ac96fff7592c6cdf1a59905eeeba4a0ec11cd3c122256e` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xa655b10781658515d6ac96fff7592c6cdf1a59905eeeba4a0ec11cd3c122256e) | Status: `OPEN` (1 GEN escrow) |
| (`zk-bounty-1789276777029`) | `accept_audit_task` | `0xeecb8277c138fb9c310a2ead81b2a422464d3aa9b972dfe141bdc5b3ac3fb845` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xeecb8277c138fb9c310a2ead81b2a422464d3aa9b972dfe141bdc5b3ac3fb845) | Status: `IN_PROGRESS` (0.2 GEN stake) |
| | `submit_counterexample` (1) | `0x17df2ac8fa6a203f946bc91cb153cca7e9bebd719097410dabbb19c8130ede27` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x17df2ac8fa6a203f946bc91cb153cca7e9bebd719097410dabbb19c8130ede27) | Status: `NEEDS_REVISION`, Verdict: `REFUND` (Valid execution != exploit) |
| | `submit_counterexample` (2) | `0x39d5c16ae1993bc5395311c6fbccc3b3142df6bf6369ba8352a377cc94e893b6` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x39d5c16ae1993bc5395311c6fbccc3b3142df6bf6369ba8352a377cc94e893b6) | Status: `CLOSED`, Verdict: `REFUND`, Slashing: 1.2 GEN returned to owner |
| **Dispute Consensus Flow** | `create_audit_bounty` | `0x3a1e5cade20c908113f284f0ad1a3c581d679b1c5ee0a7e2bd79aa9367b3ded4` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x3a1e5cade20c908113f284f0ad1a3c581d679b1c5ee0a7e2bd79aa9367b3ded4) | Status: `OPEN` (1 GEN escrow) |
| (`zk-dispute-1789276854688`) | `accept_audit_task` | `0xab36ad5de7a34c84f5c6c1d9c1f04080604a605f1dc8a44d914be13dd49f1d54` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xab36ad5de7a34c84f5c6c1d9c1f04080604a605f1dc8a44d914be13dd49f1d54) | Status: `IN_PROGRESS` (0.2 GEN stake) |
| | `submit_counterexample` | `0xe91c3ec93af4f10d0060d505f675f18746ff341aef0928aee39d055c1cdd3508` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xe91c3ec93af4f10d0060d505f675f18746ff341aef0928aee39d055c1cdd3508) | Status: `NEEDS_REVISION`, Verdict: `REFUND` (Witness hash mismatch) |
| | `resolve_dispute_consensus` | `0x7f5117ca84709fd3ba458d4bbcb252bd6fe7d28d5d293223ed452601af77536c` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x7f5117ca84709fd3ba458d4bbcb252bd6fe7d28d5d293223ed452601af77536c) | Multi-Validator Consensus Adjudication |
| **Additional Testnet Runs** | Contract Deployment | `0x7f725c58834721c07ce0e17470d8a495a45313f0c319818335b12743ea6d5a19` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x7f725c58834721c07ce0e17470d8a495a45313f0c319818335b12743ea6d5a19) | Initial Deployment (Consensus 5/5) |
| | Bilateral Concession (RELEASE) | `0x1b0d2e3b6c549ffbc9a30f309ace594c89736327bfc268dd33f4e09d32ebb854` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x1b0d2e3b6c549ffbc9a30f309ace594c89736327bfc268dd33f4e09d32ebb854) | Status: `CLOSED`, Voluntary RELEASE Concession |


