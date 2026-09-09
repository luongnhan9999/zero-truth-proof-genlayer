# ZeroTruthProof: Autonomous Zero-Knowledge Circuit Audit & Formal Verification Escrow

- **Live dApp (Vercel):** [https://zero-truth-proof-genlayer.vercel.app](https://zero-truth-proof-genlayer.vercel.app)
- **Deployed Contract (StudioNet):** [`0xcb192605d8EAd7564bae6B2eb06Ff9588b5e9ab9`](https://genlayer-explorer.vercel.app/address/0xcb192605d8EAd7564bae6B2eb06Ff9588b5e9ab9)
- **Studio Contract IDE:** [https://studio.genlayer.com/contracts/0xcb192605d8EAd7564bae6B2eb06Ff9588b5e9ab9](https://studio.genlayer.com/contracts/0xcb192605d8EAd7564bae6B2eb06Ff9588b5e9ab9)
- **GitHub Repository:** [https://github.com/luongnhan9999/zero-truth-proof-genlayer](https://github.com/luongnhan9999/zero-truth-proof-genlayer)

**ZeroTruthProof** is an intelligent escrow and autonomous arbitration protocol built on GenLayer. It automates the verification and payout process for Zero-Knowledge (ZK-SNARK / Circom / Halo2 / PlonK) circuit audits and formal verification bug bounty programs.

---

## The Problem
In ZK-SNARK and PlonKish circuit design, identifying bugs like *under-constrained signals*, *missing quadratic constraints*, and *soundness/completeness violations* is critical. Projects host bug bounties to find these flaws, but disputes often arise when an auditor submits a mathematical proof/witness of a vulnerability: project owners may delay, dispute, or refuse to acknowledge the exploit to avoid paying out.

## The GenLayer Solution
ZeroTruthProof eliminates human counterparty risk through **autonomous, deterministic on-chain verification and AI consensus arbitration**:
1. **Bounty Escrow with Cryptographic Pinning:** The project owner funds the escrow and locks the cryptographic SHA-256 hash (`circuit_hash`) of the circuit source code.
2. **Auditor Stake Lock (Anti-Spam):** The ZK Auditor deposits a mandatory 20% security stake to claim the task.
3. **Deterministic R1CS Constraint Verification (`R1CSConstraintVerifier`):**
   - The contract retrieves the circuit code and submitted witness using non-deterministic web rendering and verifies their SHA-256 integrity.
   - A built-in tokenizer and recursive-descent AST parser parses Circom constraints (`<==`, `==>`, `===`) with strict operator precedence (`*`, `/` over `+`, `-`).
   - The contract evaluates the witness values mathematically against every constraint. Any arithmetic violation, missing input, or invalid format is immediately rejected on-chain before AI consensus is reached.
4. **Multi-Validator Consensus with Full Evidence:** 
   - Non-truncated source code and the complete R1CS mathematical trace are passed to GenLayer validator nodes.
   - Validators run independent consensus to verify exploit severity (APPROVED, PARTIAL, REFUND, ESCALATE).
5. **24-Hour Cooling-Off Window & Finalization:**
   - Approved submissions enter a 24-hour dispute window. If no dispute is raised, funds and stake are automatically released.
   - If disputed, the platform admin arbitrates (RELEASE, REFUND, SPLIT).

---

## Repository Structure

```
zeroTruthProof/
├── contracts/
│   └── ZeroTruthProof.py         # GenLayer Intelligent Smart Contract (R1CS Engine)
├── tests/
│   └── test_zero_truth_proof.py  # Comprehensive Test Suite (14 Tests, 100% Pass)
├── scripts/
│   └── verify_contract.py        # Automated test verification runner
├── frontend/                     # React 19 / TypeScript / Vite / Tailwind CSS
│   ├── src/
│   │   ├── App.tsx               # Web3 Terminal Interface & Simulation Mode
│   │   ├── main.tsx
│   │   └── index.css             # Quantum Noir styling
│   ├── vite.config.ts
│   ├── package.json
│   └── index.html
└── README.md
```

---

## Verification & Test Suite (14 Tests, 100% Pass)

### Running Contract Tests
```bash
python scripts/verify_contract.py
```

### Test Coverage Breakdown:
- **`TestR1CSVerifier` (10 Adversarial & Parsing Tests):**
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

- **`TestContractIntegration` (4 Full Lifecycle Integration Tests):**
  11. `test_01_under_staking_reverts`: Enforces 20% minimum auditor stake deposit.
  12. `test_02_valid_counterexample_approved_and_cooling_off`: Validates payout delay and release flow.
  13. `test_03_dispute_flow_and_arbitration`: Validates dispute locking and admin split resolution.
  14. `test_04_untruncated_prompt_evidence`: Verifies 100% untruncated code delivery into LLM prompt.

---

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` to interact with the dApp.
