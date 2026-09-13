# ZeroTruthProof Frontend dApp

Web3 Matrix Terminal interface for **ZeroTruthProof** — an autonomous ZK-SNARK circuit audit escrow and arbitration protocol built on GenLayer.

- **Production URL:** [https://zero-truth-proof-genlayer.vercel.app](https://zero-truth-proof-genlayer.vercel.app)
- **Target Network:** GenLayer StudioNet
- **Connected Contract:** `0x203877Ae465609891B73e46A87f2356e8b8F5B37`

---

## Architecture & Tech Stack

- **Framework:** React 19 + TypeScript + Vite
- **Styling:** Tailwind CSS (Quantum Noir theme with Zero-Knowledge Purple & Laser Mint)
- **Web3 Integration:** `genlayer-js` + Viem + MetaMask (EIP-1193)
- **Hashing:** Web Crypto API (`crypto.subtle.digest`) for automatic client-side SHA-256 computation

---

## Features

1. **Dual Execution Engine:**
   - **Live Web3 Mode:** Connects to MetaMask on GenLayer StudioNet to trigger real on-chain contract methods (`create_audit_bounty`, `accept_audit_task`, `submit_counterexample`, `raise_dispute`, `finalize_payout`).
   - **Simulation HUD Mode:** Allows users to preview and test the complete verification workflow without gas fees.

2. **R1CS Circuit & Witness Visualizer:**
   - Side-by-side inspection of target circuit source code and auditor exploit witness scripts.
   - Automatic SHA-256 hash pre-calculation on URL input.

3. **Consensus Telemetry Pipeline:**
   - Visualizes the 4-stage validation lifecycle:
     - `[1/4] Circuit AST Ingestion & Tokenization`
     - `[2/4] Signal Constraint Degree & Wire Index Check`
     - `[3/4] R1CS Matrix Witness Evaluation`
     - `[4/4] Multi-Validator Consensus Settlement`

4. **24-Hour Dispute Cooling-Off Window:**
   - Real-time countdown timer tracking when escrow payouts can be finalized or disputed.

---

## Local Development

```bash
# Install dependencies
npm install

# Run Vite dev server
npm run dev

# Build production bundle
npm run build
```
