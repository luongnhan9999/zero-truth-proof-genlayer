# ZeroTruthProof: Autonomous Zero-Knowledge Circuit Audit & Formal Verification Escrow

- **Live App (Vercel):** [https://zero-truth-proof-genlayer.vercel.app](https://zero-truth-proof-genlayer.vercel.app)
- **Deployed Contract (StudioNet):** [`0x8Eae7Ec0E04b41d407b605A724C55EF91E8d80C2`](https://genlayer-explorer.vercel.app/address/0x8Eae7Ec0E04b41d407b605A724C55EF91E8d80C2)
- **GitHub Repository:** [https://github.com/luongnhan9999/zero-truth-proof-genlayer](https://github.com/luongnhan9999/zero-truth-proof-genlayer)

**ZeroTruthProof** is an intelligent escrow and autonomous arbitration protocol built on GenLayer. It automates the verification and payout process for Zero-Knowledge (ZK-SNARK / Circom / Halo2 / PlonK) circuit audits and formal verification bounty programs.

---

## The Problem
In ZK-SNARK and PlonKish circuit design, identifying bugs like *under-constrained signals*, *missing polynomial constraints*, and *soundness/completeness violations* is crucial. Projects often host massive bug bounties to find these flaws. However, disputes often arise when a whitehat auditor submits a mathematical proof/witness of a vulnerability, and the project owner disputes, delays, or refuses to acknowledge the exploit to avoid paying out.

## The GenLayer Solution
ZeroTruthProof solves this by acting as an **autonomous, cryptographically secured escrow**. 
1. **Bounty Escrow:** The project owner funds the escrow and sets up the constraint target and framework.
2. **Auditor Stake Lock:** To prevent spam, the ZK Auditor deposits a 20% security stake to lock the task.
3. **Consensus Solver verification:** The Auditor submits the PoC counterexample witness URL. The GenLayer Intelligent Contract retrieves the original circuit source code and the counterexample from the endpoints using non-deterministic web rendering and runs an AI-consensus validation checking if the counterexample successfully bypasses constraints.
4. **Challenge Window & Settlement:** If approved, a 24-hour cooling-off window is activated. During this time, the project owner or auditor can raise a dispute if there are compiler/scope errors. If no dispute is raised, the auditor finalizes the release. If a dispute is raised, the platform administrator arbitrates the split (RELEASE, REFUND, or SPLIT).

---

## Repository Structure

```
zeroTruthProof/
├── contracts/
│   └── ZeroTruthProof.py         # GenLayer Intelligent Smart Contract
├── tests/
│   └── test_zero_truth_proof.py  # Local Unit Test Suite (Mock GenLayer SDK)
├── scripts/
│   └── verify_contract.py        # Helper script to execute unit tests
├── frontend/                     # React 19 / TypeScript / Vite / Tailwind CSS
│   ├── src/
│   │   ├── App.tsx               # Main dApp Interface (Vibe: Cryptographic Matrix Terminal)
│   │   ├── main.tsx
│   │   └── index.css             # Tailwind v4 directives & custom theme variables
│   ├── vite.config.ts
│   ├── package.json
│   └── index.html
└── README.md                     # Project documentation & instructions
```

---

## Smart Contract Integration & Verification

### Prerequisites
- Python 3.10 or higher.

### Running Local Smart Contract Tests
We have built a unit test suite mirroring the behavior of the GenLayer Intelligent VM. The tests cover:
1. Rejection of under-staking (depositing less than 20% of bounty amount).
2. Processing valid counterexamples, triggering LLM consensus validation, and enforcing the 24-hour payout cooling-off delay.
3. Registered dispute flows blocking finalization, and platform admin arbitration (SPLIT, RELEASE, REFUND).

Run the tests using the verification script:
```bash
python scripts/verify_contract.py
```

---

## Frontend Web Application

The frontend is a **Cryptographic Formal Matrix Terminal** designed with a dark, cyberpunk theme (Deep Quantum Noir backdrop, Zero-Knowledge Purple, and Laser Mint accents).

### Features
1. **Simulation HUD Mode:** Toggle between Simulated HUD and Live Studionet Chain. Simulation mode enables testing the complete end-to-end lifecycle of bounties (creation, lock, submit exploit, telemetry checks, dispute, and final release) inside React without a wallet.
2. **Interactive R1CS / PlonKish Constraint Visualizer:** A dual-pane inspector comparing original circuit source code side-by-side with the auditor's PoC exploit witness data.
3. **Consensus Telemetry HUD:** Active pipeline visualization representing the 4-step formal solver verification steps:
   - `[Circuit AST Ingestion]`
   - `[Signal Constraint Degree Check]`
   - `[Witness Inversion Validation]`
   - `[Consensus Escrow Release]`
4. **24h Challenge Window countdown:** A ticking timer showing hours:minutes:seconds remaining before the payout lock expires.
5. **MetaMask & genlayer-js connection:** Full EIP-1193 integration on `studionet` to write/read contract functions, wait for transaction receipts, and view live states.

### Setup and Execution

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Run the development server:
   ```bash
   npm run dev
   ```

3. Open your browser and navigate to `http://localhost:5173`.
