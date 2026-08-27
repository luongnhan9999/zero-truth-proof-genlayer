# v0.2.18
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import json

@allow_storage
@dataclass
class ZKAuditTask:
    project_owner: str
    auditor: str
    escrow_amount: bigint
    auditor_stake: bigint
    status: str            # OPEN, IN_PROGRESS, AWAITING_PAYOUT, NEEDS_REVISION, DISPUTED, ESCALATED, CLOSED
    circuit_url: str       # URL to original Circom/Halo2/Noir circuit source code
    circuit_hash: str      # SHA-256 hash of the target circuit file
    proof_of_exploit_url: str # URL to mathematical counterexample / PoC witness script
    exploit_hash: str      # SHA-256 hash of the submitted witness/exploit script
    circuit_framework: str # e.g., "Circom 2.1 / Groth16 / R1CS"
    constraint_focus: str  # e.g., "Under-constrained signals, Missing quadratic constraints"
    verdict: str           # APPROVED, PARTIAL, REFUND, ESCALATE
    reason: str
    confidence: bigint
    attempts: bigint
    payout_ready_at: bigint
    disputed_at: bigint

class Contract(gl.Contract):
    platform_admin: str
    tasks: TreeMap[str, ZKAuditTask]
    task_ids: DynArray[str]

    def __init__(self):
        self.platform_admin = str(gl.message.sender_address).lower()

    def _get_current_timestamp(self) -> bigint:
        """Derive trusted execution timestamp strictly from transaction context."""
        dt_raw = gl.message_raw.get("datetime", None) if isinstance(gl.message_raw, dict) else None
        if not dt_raw:
            raise UserError("Trusted execution timestamp missing from transaction context")
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(str(dt_raw).replace("Z", "+00:00"))
            ts = int(dt.timestamp())
            if ts > 0:
                return bigint(ts)
        except Exception as e:
            raise UserError(f"Failed to parse trusted execution timestamp: {str(e)}")
        raise UserError("Invalid execution timestamp in transaction context")

    def _parse_llm_json(self, response_str: str) -> dict:
        """Robust parser handling raw JSON or markdown code fences."""
        if isinstance(response_str, dict):
            return response_str
        if hasattr(response_str, "__dict__"):
            return response_str.__dict__
        t = str(response_str).strip()
        if t.startswith("```json"):
            t = t[7:]
        elif t.startswith("```"):
            t = t[3:]
        if t.endswith("```"):
            t = t[:-3]
        try:
            return json.loads(t.strip())
        except Exception as e:
            return {"verdict": "ESCALATE", "confidence": 0, "reason": f"JSON parse failure: {str(e)}"}

    def _effective_verdict(self, data: dict) -> str:
        """Enforces deterministic settlement verdict by applying confidence threshold."""
        verdict = str(data.get("verdict", "ESCALATE")).upper().strip()
        if verdict not in {"APPROVED", "PARTIAL", "REFUND", "ESCALATE"}:
            verdict = "ESCALATE"
        try:
            conf = int(data.get("confidence", 0))
        except Exception:
            conf = 0
        if conf < 65:
            verdict = "ESCALATE"
        return verdict

    @gl.public.write.payable
    def create_audit_bounty(
        self,
        task_id: str,
        circuit_url: str,
        circuit_hash: str,
        circuit_framework: str,
        constraint_focus: str
    ) -> None:
        if task_id in self.tasks:
            raise UserError(f"Audit task ID {task_id} already exists")
        
        escrow_amt = gl.message.value
        if escrow_amt <= bigint(0):
            raise UserError("Escrow bounty reward must be strictly positive")
        if not circuit_url.startswith("http"):
            raise UserError("Valid circuit repository HTTP/HTTPS URL required")
        if not circuit_hash or len(circuit_hash.strip()) != 64:
            raise UserError("Valid SHA-256 target circuit hash requirement not met")

        caller = str(gl.message.sender_address).lower()
        
        self.tasks[task_id] = ZKAuditTask(
            project_owner=caller,
            auditor="0x0000000000000000000000000000000000000000",
            escrow_amount=escrow_amt,
            auditor_stake=bigint(0),
            status="OPEN",
            circuit_url=circuit_url.strip(),
            circuit_hash=circuit_hash.strip().lower(),
            proof_of_exploit_url="",
            exploit_hash="",
            circuit_framework=circuit_framework.strip(),
            constraint_focus=constraint_focus.strip(),
            verdict="NONE",
            reason="Awaiting ZK Auditor acceptance",
            confidence=bigint(0),
            attempts=bigint(0),
            payout_ready_at=bigint(0),
            disputed_at=bigint(0)
        )
        self.task_ids.append(task_id)

    @gl.public.write.payable
    def accept_audit_task(self, task_id: str) -> None:
        """ZK Auditor deposits mandatory 20% stake to lock audit task."""
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status != "OPEN":
            raise UserError("Task is not in OPEN status")

        caller = str(gl.message.sender_address).lower()
        if caller == task.project_owner:
            raise UserError("Project Owner cannot audit their own circuit")

        min_stake = task.escrow_amount // bigint(5)  # 20% stake
        if gl.message.value < min_stake or gl.message.value <= bigint(0):
            raise UserError(f"Insufficient auditor stake. Minimum 20% required ({min_stake})")

        task.auditor = caller
        task.auditor_stake = gl.message.value
        task.status = "IN_PROGRESS"
        self.tasks[task_id] = task

    @gl.public.write
    def submit_counterexample(self, task_id: str, proof_of_exploit_url: str, exploit_hash: str) -> None:
        """Auditor submits PoC counterexample demonstrating circuit constraint bypass."""
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        caller = str(gl.message.sender_address).lower()
        
        if caller != task.auditor:
            raise UserError("Only the assigned ZK auditor can submit counterexample")
        if task.status not in ["IN_PROGRESS", "NEEDS_REVISION"]:
            raise UserError("Task is not ready for counterexample submission")
        if not proof_of_exploit_url.startswith("http"):
            raise UserError("Valid counterexample HTTP/HTTPS URL required")
        if not exploit_hash or len(exploit_hash.strip()) != 64:
            raise UserError("Valid SHA-256 exploit witness hash requirement not met")

        task.proof_of_exploit_url = proof_of_exploit_url.strip()
        task.exploit_hash = exploit_hash.strip().lower()
        task.attempts += bigint(1)
        
        circuit_str = task.circuit_url
        exploit_str = task.proof_of_exploit_url
        framework_str = task.circuit_framework
        focus_str = task.constraint_focus

        def leader_fn() -> dict:
            # 1. Fetch & Verify Target Circuit Code Integrity
            try:
                c_res = gl.nondet.web.render(circuit_str, mode="text")
                c_text = str(c_res)
                if any(err in c_text[:400].lower() for err in ["404 not found", "error 404", "not found"]):
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Circuit source URL is 404; escrow held to protect auditor."}
                
                # Check SHA256 integrity
                import hashlib
                c_hash_computed = hashlib.sha256(c_text.encode('utf-8')).hexdigest().lower()
                if c_hash_computed != task.circuit_hash:
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": f"Circuit integrity check failed. Expected: {task.circuit_hash}, Computed: {c_hash_computed}"}
            except Exception as e:
                return {"verdict": "ESCALATE", "confidence": 100, "reason": f"Circuit fetch failed: {str(e)}"}

            # 2. Fetch & Verify Counterexample Exploit Code Integrity
            try:
                e_res = gl.nondet.web.render(exploit_str, mode="text")
                e_text = str(e_res)
                if any(err in e_text[:400].lower() for err in ["404 not found", "error 404", "not found"]):
                    return {"verdict": "REFUND", "confidence": 100, "reason": "Counterexample URL is 404 or empty."}
                
                # Check SHA256 integrity
                import hashlib
                e_hash_computed = hashlib.sha256(e_text.encode('utf-8')).hexdigest().lower()
                if e_hash_computed != task.exploit_hash:
                    return {"verdict": "REFUND", "confidence": 100, "reason": f"Exploit witness integrity check failed. Expected: {task.exploit_hash}, Computed: {e_hash_computed}"}
            except Exception as e:
                return {"verdict": "REFUND", "confidence": 100, "reason": f"Counterexample fetch failed: {str(e)}"}

            # 3. Deterministic Compile Check & Signal/Proof Syntax Checking
            if "circom" in framework_str.lower():
                if "pragma circom" not in c_text:
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Deterministic check: Missing 'pragma circom' directive in circuit code."}
                if "template" not in c_text:
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Deterministic check: No template definition found in target Circom circuit."}
                if "signal input" not in c_text:
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Deterministic check: No signal inputs found in target Circom circuit."}
                
                import re
                inputs = re.findall(r"signal\s+input\s+([a-zA-Z0-9_]+)", c_text)
                if not inputs:
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Deterministic check: Failed to parse input signals from circuit code."}
                
                # Exploit must reference/assign values or test cases for at least one input signal
                found_ref = False
                for inp in inputs:
                    if inp in e_text:
                        found_ref = True
                        break
                if not found_ref:
                    return {"verdict": "REFUND", "confidence": 100, "reason": f"Deterministic check: Exploit witness does not reference any circuit input signals (Expected one of: {', '.join(inputs)})."}
                
                # Must contain some constraint operators
                if not any(op in c_text for op in ["<==", "==>", "==="]):
                    return {"verdict": "ESCALATE", "confidence": 100, "reason": "Deterministic check: No constraints operator found in target circuit."}

            if len(e_text.strip()) < 20:
                return {"verdict": "REFUND", "confidence": 100, "reason": "Deterministic check: Exploit witness script code too short."}

            prompt = f"""
You are a Principal Zero-Knowledge Cryptographer & Formal Circuit Verification Judge on GenLayer.
Evaluate the submitted mathematical counterexample / PoC witness against the target circuit source code.

CIRCUIT FRAMEWORK & COMPILER:
{framework_str}

FOCUS AREA / CONSTRAINT SPECIFICATION:
{focus_str}

ORIGINAL TARGET CIRCUIT CODE:
{c_text[:2500]}

SUBMITTED MATHEMATICAL COUNTEREXAMPLE / POC WITNESS:
{e_text[:2500]}

DECISION FRAMEWORK:
- APPROVED: The counterexample conclusively demonstrates a critical flaw (under-constrained signal, soundness break, fake proof generation, or missing polynomial constraint).
- PARTIAL: Demonstrates minor constraint redundancy, informational dead-code signals, or sub-optimal gate allocation without soundness failure.
- REFUND: The counterexample is invalid, mathematically flawed, hallucinates constraints, or fails to bypass circuit verification.
- ESCALATE: The circuit is too complex, uses unverified custom polynomial gates, or requires human cryptographic arbitration.

Respond ONLY with valid JSON:
{{"verdict": "APPROVED|PARTIAL|REFUND|ESCALATE", "confidence": 0-100, "reason": "Formal cryptographic justification"}}
"""
            res = gl.nondet.exec_prompt(prompt, response_format="json")
            if isinstance(res, dict):
                return res
            return self._parse_llm_json(str(res))

        def validator_fn(leader_res) -> bool:
            """Consensus verification comparing deterministic effective verdicts."""
            if not isinstance(leader_res, gl.vm.Return):
                return False
            leader_data = leader_res.calldata if hasattr(leader_res, "calldata") else leader_res
            if not isinstance(leader_data, dict):
                leader_data = self._parse_llm_json(str(leader_data))

            mine_data = leader_fn()
            return self._effective_verdict(leader_data) == self._effective_verdict(mine_data)

        result = gl.vm.run_nondet(leader_fn, validator_fn)
        if not isinstance(result, dict):
            result = self._parse_llm_json(str(result))

        final_verdict = self._effective_verdict(result)
        try:
            conf = int(result.get("confidence", 0))
        except Exception:
            conf = 0
        reason = str(result.get("reason", "No reason provided"))

        if conf < 65:
            reason = f"[Confidence {conf}% < 65%] " + reason

        task.verdict = final_verdict
        task.reason = reason
        task.confidence = bigint(conf)

        if final_verdict in ["APPROVED", "PARTIAL"]:
            task.status = "AWAITING_PAYOUT"
            task.payout_ready_at = self._get_current_timestamp() + bigint(86400) # 24h dispute window
        elif final_verdict == "REFUND":
            if task.attempts < bigint(2):
                task.status = "NEEDS_REVISION"
            else:
                # Slashing: 2 consecutive failures -> full escrow + slashed stake returned to project owner
                task.status = "CLOSED"
                total_refund = task.escrow_amount + task.auditor_stake
                task.escrow_amount = bigint(0)
                task.auditor_stake = bigint(0)
                gl.get_contract_at(Address(task.project_owner)).emit_transfer(value=u256(total_refund))
        else:
            task.status = "ESCALATED"

        self.tasks[task_id] = task

    @gl.public.write
    def raise_dispute(self, task_id: str, reason: str = "") -> None:
        """Transitions task from AWAITING_PAYOUT to DISPUTED within 24h, locking finalization."""
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status != "AWAITING_PAYOUT":
            raise UserError("Task is not in AWAITING_PAYOUT status")

        caller = str(gl.message.sender_address).lower()
        if caller != task.project_owner and caller != task.auditor:
            raise UserError("Only project owner or assigned auditor can raise a dispute")

        now = self._get_current_timestamp()
        if now > task.payout_ready_at:
            raise UserError("24-hour dispute window has elapsed")

        task.status = "DISPUTED"
        task.disputed_at = now
        if reason:
            task.reason = f"[DISPUTED by {caller[:8]}] {reason}"
        self.tasks[task_id] = task

    @gl.public.write
    def finalize_payout(self, task_id: str) -> None:
        """Disburses escrow funds strictly after 24h cooling-off when no active dispute exists."""
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status != "AWAITING_PAYOUT":
            raise UserError("Task is not awaiting payout or is currently disputed")

        caller = str(gl.message.sender_address).lower()
        if caller != task.project_owner and caller != task.auditor:
            raise UserError("Unauthorized caller")

        now = self._get_current_timestamp()
        if now < task.payout_ready_at:
            raise UserError("24-hour cooling-off period has not elapsed yet")

        escrow = task.escrow_amount
        stake = task.auditor_stake
        task.status = "CLOSED"
        task.escrow_amount = bigint(0)
        task.auditor_stake = bigint(0)

        if task.verdict == "APPROVED":
            gl.get_contract_at(Address(task.auditor)).emit_transfer(value=u256(escrow + stake))
        elif task.verdict == "PARTIAL":
            half = escrow // bigint(2)
            rem = escrow - half
            gl.get_contract_at(Address(task.auditor)).emit_transfer(value=u256(half + stake))
            gl.get_contract_at(Address(task.project_owner)).emit_transfer(value=u256(rem))

        self.tasks[task_id] = task

    @gl.public.write
    def resolve_escalation(self, task_id: str, action: str) -> None:
        """Arbitration path for ESCALATED or DISPUTED tasks."""
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status not in ["ESCALATED", "DISPUTED"]:
            raise UserError("Task is not in ESCALATED or DISPUTED status")

        caller = str(gl.message.sender_address).lower()
        act = action.upper().strip()

        # Project Owner can only voluntarily concede (RELEASE)
        if caller == task.project_owner and caller != self.platform_admin:
            if act != "RELEASE":
                raise UserError("Project owners can only voluntarily RELEASE funds. Only platform admin can enforce REFUND or SPLIT.")

        if caller != self.platform_admin and caller != task.project_owner:
            raise UserError("Unauthorized caller")

        escrow = task.escrow_amount
        stake = task.auditor_stake
        task.status = "CLOSED"
        task.escrow_amount = bigint(0)
        task.auditor_stake = bigint(0)

        if act == "RELEASE":
            gl.get_contract_at(Address(task.auditor)).emit_transfer(value=u256(escrow + stake))
        elif act == "REFUND":
            gl.get_contract_at(Address(task.project_owner)).emit_transfer(value=u256(escrow + stake))
        elif act == "SPLIT":
            half = escrow // bigint(2)
            rem = escrow - half
            gl.get_contract_at(Address(task.auditor)).emit_transfer(value=u256(half + stake))
            gl.get_contract_at(Address(task.project_owner)).emit_transfer(value=u256(rem))
        else:
            raise UserError("Invalid action. Must be RELEASE, REFUND, or SPLIT")

        self.tasks[task_id] = task

    @gl.public.view
    def get_all_tasks(self) -> str:
        res = []
        for tid in self.task_ids:
            if tid in self.tasks:
                t = self.tasks[tid]
                res.append({
                    "id": tid,
                    "project_owner": t.project_owner,
                    "auditor": t.auditor,
                    "escrow_amount": str(t.escrow_amount),
                    "auditor_stake": str(t.auditor_stake),
                    "status": t.status,
                    "circuit_url": t.circuit_url,
                    "circuit_hash": t.circuit_hash,
                    "proof_of_exploit_url": t.proof_of_exploit_url,
                    "exploit_hash": t.exploit_hash,
                    "circuit_framework": t.circuit_framework,
                    "constraint_focus": t.constraint_focus,
                    "verdict": t.verdict,
                    "reason": t.reason,
                    "confidence": str(t.confidence),
                    "attempts": str(t.attempts),
                    "payout_ready_at": str(t.payout_ready_at),
                    "disputed_at": str(t.disputed_at)
                })
        return json.dumps(res)
