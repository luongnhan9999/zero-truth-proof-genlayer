# ZeroTruthProof: Autonomous Zero-Knowledge Circuit Audit & Formal Verification Escrow

- **Live dApp (Vercel):** [https://zero-truth-proof-genlayer.vercel.app](https://zero-truth-proof-genlayer.vercel.app)
- **Deployed Contract (StudioNet):** [`0x09e20A423Acc58258CEAE3c27742D817801CF819`](https://genlayer-explorer.vercel.app/address/0x09e20A423Acc58258CEAE3c27742D817801CF819)
- **Studio Contract IDE:** [https://studio.genlayer.com/contracts/0x09e20A423Acc58258CEAE3c27742D817801CF819](https://studio.genlayer.com/contracts/0x09e20A423Acc58258CEAE3c27742D817801CF819)
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
| **Current Deployed Contract** | Contract Deployment | `0x55d84cb679cec4bc49517c39cd647a5732ace7bae73dfd349b4ea4ecd09a2a05` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x55d84cb679cec4bc49517c39cd647a5732ace7bae73dfd349b4ea4ecd09a2a05) | Deployed at `0x09e20A423Acc58258CEAE3c27742D817801CF819` (Consensus 5/5) |
| **R1CS & Slashing Flow** | `create_audit_bounty` | `0x798110c3796ee5528aec546e04fff0d6514dc478f0b58a6c8430b4ea4654d8f1` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x798110c3796ee5528aec546e04fff0d6514dc478f0b58a6c8430b4ea4654d8f1) | Status: `OPEN` (1 GEN escrow, Pinned Commit) |
| (`zk-multiplier2-slashing-1789291159434`) | `accept_audit_task` | `0xd2b405a4b77f144165c76cb7dc34e589313db0f746f7a7defc1b6273f8cae3b8` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xd2b405a4b77f144165c76cb7dc34e589313db0f746f7a7defc1b6273f8cae3b8) | Status: `IN_PROGRESS` (0.2 GEN stake deposited) |
| | `submit_counterexample` (1) | `0x345d8dd45c6afc4b66c43f39b388b78d2944ca4b9e079af628e56eb4a26e479c` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x345d8dd45c6afc4b66c43f39b388b78d2944ca4b9e079af628e56eb4a26e479c) | Status: `NEEDS_REVISION`, Attempts: 1, R1CS Deterministic Failure |
| | `submit_counterexample` (2) | `0x991fb1a139273fccecaf81f79b43e353216b52959acd59a1aebd00403484502a` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x991fb1a139273fccecaf81f79b43e353216b52959acd59a1aebd00403484502a) | Status: `CLOSED`, Verdict: `REFUND`, Slashing: 1.2 GEN returned to owner EOA |
| **Dispute Consensus Flow** | `create_audit_bounty` | `0x4c6d004ba5b55cdd8213666f35323dd33571fc6b7c56c6bbdc15875969684d30` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x4c6d004ba5b55cdd8213666f35323dd33571fc6b7c56c6bbdc15875969684d30) | Status: `OPEN` (1 GEN escrow) |
| (`zk-multiplier2-live-1789291043327`) | `accept_audit_task` | `0x2b2e3b4e7e4296ee0e3a868f9ee5c161f7fcfc2f5e9ee66e6dcd5724048afa6e` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x2b2e3b4e7e4296ee0e3a868f9ee5c161f7fcfc2f5e9ee66e6dcd5724048afa6e) | Status: `IN_PROGRESS` (0.2 GEN stake deposited) |
| | `submit_counterexample` | `0x41aa7f304cd13115ee464d49efcc4894a836846a0e23f762a211edeb32ed9a4e` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x41aa7f304cd13115ee464d49efcc4894a836846a0e23f762a211edeb32ed9a4e) | Status: `ESCALATED` (Protected under escrow) |
| | `resolve_dispute_consensus` | `0xfb953057417f375f1f5a23e777509792ff0972f1612b50c29ba2c0a75a9f5fb8` | [View Tx](https://genlayer-explorer.vercel.app/tx/0xfb953057417f375f1f5a23e777509792ff0972f1612b50c29ba2c0a75a9f5fb8) | Status: `CLOSED`, Verdict: `SPLIT` (50/50 Multi-Validator AI Consensus) |
| **Voluntary Concession Flow** | Bilateral Concession (RELEASE) | `0x1b0d2e3b6c549ffbc9a30f309ace594c89736327bfc268dd33f4e09d32ebb854` | [View Tx](https://genlayer-explorer.vercel.app/tx/0x1b0d2e3b6c549ffbc9a30f309ace594c89736327bfc268dd33f4e09d32ebb854) | Status: `CLOSED`, Voluntary RELEASE Concession |


