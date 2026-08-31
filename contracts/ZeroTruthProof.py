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

class DeterministicCircomCompiler:
    """
    On-chain deterministic AST compiler and R1CS witness constraint verifier.
    Parses Circom syntax to extract templates, signals, and constraint equations,
    and programmatically evaluates witness values against constraints.
    """
    @staticmethod
    def parse_circuit_ast(circuit_code: str) -> dict:
        import re
        ast = {
            "templates": [],
            "input_signals": [],
            "output_signals": [],
            "intermediate_signals": [],
            "constraints": [],
            "assignments": [], # list of {"var": name, "expr": expression}
            "valid_syntax": True,
            "errors": []
        }
        
        # Strip comments
        code_clean = re.sub(r"/\*.*?\*/", "", circuit_code, flags=re.DOTALL)
        code_clean = re.sub(r"//.*", "", code_clean)

        if "pragma circom" not in code_clean:
            ast["valid_syntax"] = False
            ast["errors"].append("Missing 'pragma circom' directive")
            return ast

        template_matches = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{", code_clean, re.DOTALL)
        if not template_matches:
            ast["valid_syntax"] = False
            ast["errors"].append("No template definition found in circuit source")
            return ast
            
        for tname, tparams in template_matches:
            ast["templates"].append({"name": tname, "params": tparams.strip()})

        inputs = re.findall(r"signal\s+input\s+([a-zA-Z0-9_]+)", code_clean)
        outputs = re.findall(r"signal\s+output\s+([a-zA-Z0-9_]+)", code_clean)
        intermediates = re.findall(r"signal\s+([a-zA-Z0-9_]+)", code_clean)
        
        intermediates = [s for s in intermediates if s not in inputs and s not in outputs and s != "input" and s != "output"]

        ast["input_signals"] = inputs
        ast["output_signals"] = outputs
        ast["intermediate_signals"] = intermediates

        if not inputs:
            ast["valid_syntax"] = False
            ast["errors"].append("Circuit contains no 'signal input' declarations")
            return ast

        # Parse assignments and constraints
        statements = re.findall(r"([^;\n]+);", code_clean)
        for stmt in statements:
            stmt_clean = stmt.strip()
            if not stmt_clean:
                continue
            
            if "<==" in stmt_clean:
                parts = stmt_clean.split("<==")
                var_name = parts[0].strip()
                expr = parts[1].strip()
                ast["assignments"].append({"var": var_name, "expr": expr})
                ast["constraints"].append({"lhs": var_name, "op": "===", "rhs": expr})
            elif "==>" in stmt_clean:
                parts = stmt_clean.split("==>")
                var_name = parts[1].strip()
                expr = parts[0].strip()
                ast["assignments"].append({"var": var_name, "expr": expr})
                ast["constraints"].append({"lhs": var_name, "op": "===", "rhs": expr})
            elif "===" in stmt_clean:
                parts = stmt_clean.split("===")
                ast["constraints"].append({"lhs": parts[0].strip(), "op": "===", "rhs": parts[1].strip()})

        if not ast["constraints"]:
            ast["valid_syntax"] = False
            ast["errors"].append("No R1CS constraint operators (<==, ==>, ===) found in circuit")

        return ast

    @staticmethod
    def parse_witness(witness_code: str) -> dict:
        import json, re
        witness = {"signals": {}, "valid_format": True, "error": ""}
        
        # STRICT REQUIREMENT: Witness must be a valid JSON representation of signal assignments
        try:
            json_match = re.search(r"\{[\s\S]*\}", witness_code)
            if json_match:
                data = json.loads(json_match.group(0))
                if isinstance(data, dict):
                    parsed_signals = {}
                    for k, v in data.items():
                        try:
                            if isinstance(v, str):
                                if v.startswith("0x"):
                                    parsed_signals[str(k)] = int(v, 16)
                                else:
                                    parsed_signals[str(k)] = int(v) if v.isdigit() else float(v)
                            elif isinstance(v, (int, float)):
                                parsed_signals[str(k)] = v
                            else:
                                raise ValueError("Invalid signal value type")
                        except Exception:
                            raise ValueError(f"Signal '{k}' has non-numeric value: {v}")
                    witness["signals"] = parsed_signals
                    return witness
        except Exception as e:
            witness["valid_format"] = False
            witness["error"] = f"Strict witness validation failed: {str(e)}"
            return witness

        witness["valid_format"] = False
        witness["error"] = "Witness code is not a valid JSON object of signal assignments (e.g. {'x': 5, 'y': 10})"
        return witness

    @staticmethod
    def _evaluate_expression(expr: str, signal_values: dict) -> int:
        """Safely evaluate simple arithmetic expressions (combinations of signals and operations +, -, *, /)"""
        import re
        expr_clean = expr.strip()
        
        if re.match(r"^-?[0-9]+$", expr_clean):
            return int(expr_clean)
        if re.match(r"^0x[0-9a-fA-F]+$", expr_clean):
            return int(expr_clean, 16)
            
        if expr_clean in signal_values:
            return signal_values[expr_clean]

        for op in ["*", "+", "-", "/"]:
            if op in expr_clean:
                parts = expr_clean.split(op)
                if len(parts) == 2:
                    left = DeterministicCircomCompiler._evaluate_expression(parts[0], signal_values)
                    right = DeterministicCircomCompiler._evaluate_expression(parts[1], signal_values)
                    if op == "*":
                        return left * right
                    elif op == "+":
                        return left + right
                    elif op == "-":
                        return left - right
                    elif op == "/":
                        return left // right if right != 0 else 0
                        
        raise ValueError(f"Expression '{expr}' contains unassigned/unknown signals or unsupported operators")

    @staticmethod
    def compile_and_verify(circuit_code: str, witness_code: str) -> dict:
        ast = DeterministicCircomCompiler.parse_circuit_ast(circuit_code)
        if not ast["valid_syntax"]:
            return {
                "verified": False,
                "stage": "COMPILATION",
                "reason": f"Circuit compilation failed: {'; '.join(ast['errors'])}",
                "ast": ast,
                "witness": None,
                "trace": []
            }

        witness = DeterministicCircomCompiler.parse_witness(witness_code)
        if not witness["valid_format"]:
            return {
                "verified": False,
                "stage": "WITNESS_PARSING",
                "reason": f"Witness verification failed: {witness['error']}",
                "ast": ast,
                "witness": witness,
                "trace": []
            }

        trace = []
        signal_values = {}
        missing_inputs = []

        # 1. Bind inputs
        for inp in ast["input_signals"]:
            if inp in witness["signals"]:
                val = witness["signals"][inp]
                signal_values[inp] = val
                trace.append(f"Input signal '{inp}' bound to witness value: {val}")
            else:
                missing_inputs.append(inp)
                trace.append(f"WARNING: Input signal '{inp}' missing from witness")

        if missing_inputs:
            return {
                "verified": False,
                "stage": "CONSTRAINT_EVALUATION",
                "reason": f"Deterministic proof check failed: Witness does not supply values for input signals: {', '.join(missing_inputs)}",
                "ast": ast,
                "witness": witness,
                "trace": trace
            }

        # 2. Evaluate assignments/intermediate signals
        try:
            for assign in ast["assignments"]:
                var_name = assign["var"]
                expr = assign["expr"]
                if var_name not in witness["signals"]:
                    computed_val = DeterministicCircomCompiler._evaluate_expression(expr, signal_values)
                    signal_values[var_name] = computed_val
                    trace.append(f"Evaluated intermediate/output signal '{var_name}': {computed_val} (via expression: {expr})")
                else:
                    signal_values[var_name] = witness["signals"][var_name]
                    trace.append(f"Using explicit witness value for signal '{var_name}': {witness['signals'][var_name]}")
        except Exception as e:
            return {
                "verified": False,
                "stage": "CONSTRAINT_EVALUATION",
                "reason": f"Signal propagation/assignment evaluation failed: {str(e)}",
                "ast": ast,
                "witness": witness,
                "trace": trace
            }

        # 3. Mathematically evaluate R1CS equations
        failed_constraints = []
        for idx, c in enumerate(ast["constraints"]):
            lhs_expr = c["lhs"]
            rhs_expr = c["rhs"]
            
            try:
                lhs_val = DeterministicCircomCompiler._evaluate_expression(lhs_expr, signal_values)
                rhs_val = DeterministicCircomCompiler._evaluate_expression(rhs_expr, signal_values)
                
                if lhs_val == rhs_val:
                    trace.append(f"Constraint #{idx+1} [{lhs_expr} === {rhs_expr}]: PASSED ({lhs_val} == {rhs_val})")
                else:
                    failed_constraints.append(f"Constraint #{idx+1} [{lhs_expr} === {rhs_expr}] failed: Left combination ({lhs_val}) != Right combination ({rhs_val})")
                    trace.append(f"Constraint #{idx+1} [{lhs_expr} === {rhs_expr}]: FAILED ({lhs_val} != {rhs_val})")
            except Exception as e:
                failed_constraints.append(f"Constraint #{idx+1} [{lhs_expr} === {rhs_expr}] failed evaluation: {str(e)}")
                trace.append(f"Constraint #{idx+1} [{lhs_expr} === {rhs_expr}]: ERROR ({str(e)})")

        if failed_constraints:
            return {
                "verified": False,
                "stage": "CONSTRAINT_EVALUATION",
                "reason": f"Deterministic mathematical verification failed: {'; '.join(failed_constraints)}",
                "ast": ast,
                "witness": witness,
                "trace": trace
            }

        return {
            "verified": True,
            "stage": "COMPLETE",
            "reason": f"Deterministic Circom compilation & witness evaluation passed. Compiled {len(ast['templates'])} template(s), {len(ast['input_signals'])} input signal(s), and {len(ast['constraints'])} R1CS constraint(s). Evaluated and verified all {len(ast['constraints'])} constraint(s) mathematically.",
            "ast": ast,
            "witness": witness,
            "trace": trace
        }

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

            # 3. On-Chain Deterministic Circom AST Compilation & R1CS Witness Constraint Verification
            if "circom" in framework_str.lower():
                compile_res = DeterministicCircomCompiler.compile_and_verify(c_text, e_text)
                if not compile_res["verified"]:
                    return {
                        "verdict": "REFUND" if compile_res["stage"] == "WITNESS_PARSING" else "ESCALATE",
                        "confidence": 100,
                        "reason": f"Deterministic compilation check: {compile_res['reason']}"
                    }
                eval_trace = compile_res["trace"]
            else:
                eval_trace = ["Symbolic verification target for non-Circom framework"]

            if len(e_text.strip()) < 20:
                return {"verdict": "REFUND", "confidence": 100, "reason": "Deterministic check: Exploit witness script code too short."}

            prompt = f"""
You are a Principal Zero-Knowledge Cryptographer & Formal Circuit Verification Judge on GenLayer.
Evaluate the submitted mathematical counterexample / PoC witness against the target circuit source code.

CIRCUIT FRAMEWORK & COMPILER:
{framework_str}

FOCUS AREA / CONSTRAINT SPECIFICATION:
{focus_str}

DETERMINISTIC COMPILER & WITNESS EVALUATION TRACE:
{json.dumps(eval_trace, indent=2)}

ORIGINAL TARGET CIRCUIT CODE (FULL UNTRUNCATED SOURCE):
{c_text}

SUBMITTED MATHEMATICAL COUNTEREXAMPLE / POC WITNESS (FULL UNTRUNCATED SOURCE):
{e_text}

DECISION FRAMEWORK:
- APPROVED: The counterexample conclusively demonstrates a critical flaw (under-constrained signal, soundness break, fake proof generation, or missing polynomial constraint).
- PARTIAL: Demonstrates minor constraint redundancy, informational dead-code signals, or sub-optimal gate allocation without soundness failure.
- REFUND: The counterexample is invalid, mathematically flawed, hallucinates constraints, or fails to bypass circuit verification.
- ESCALATE: The circuit is too complex, uses unverified custom polynomial gates, or requires human cryptographic arbitration.

REPRODUCIBILITY REQUIREMENT:
Provide a step-by-step mathematical witness evaluation trace showing how the counterexample evaluates against the declared R1CS/PlonKish constraints.

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
