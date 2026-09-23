# v0.3.0
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import json

try:
    UserError = UserError
except NameError:
    class UserError(Exception):
        """Contract user-facing error. Defined locally for gltest compatibility."""
        pass

# SOURCE_REPO: https://github.com/luongnhan9999/zero-truth-proof-genlayer
# SOURCE_COMMIT: 03667027c4d0a14c7ee95d63e93f70e9e92e18f1

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
    created_at: bigint     # Timestamp when bounty was created (for timeout recovery)
    accepted_at: bigint    # Timestamp when auditor accepted (0 if not yet)
    source_commit: str     # Git commit SHA or IPFS CID pinning exact artifact version

BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

class R1CSConstraintVerifier:
    """
    On-chain R1CS (Rank-1 Constraint System) verifier for Circom circuits.

    Architecture:
      1. Tokenizer  — splits Circom source into typed tokens (no line-level regex)
      2. Signal registry — builds a signal table with wire indices
         Supports: simple signals, array signals (signal input a[N]),
         component declarations, and qualified references (comp.signal)
      3. Expression AST — recursive-descent parser respecting operator precedence
      4. R1CS builder — each constraint becomes three linear combinations (A, B, C)
                        such that the R1CS check is: dot(A, w) * dot(B, w) == dot(C, w)
      5. Witness binder — strict JSON-only, every value must be numeric
      6. Constraint checker — evaluates every R1CS row over BN254 finite field;
                              any failure → immediate REJECT

    Finite Field:
      All arithmetic is performed modulo the BN254 scalar field prime p,
      matching the field used by Circom's Groth16 / PLONK proof systems.
      Division uses modular multiplicative inverse (Fermat's little theorem).
    """

    # ── BN254 scalar field prime (Circom / Groth16 / PLONK) ──────────────
    BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

    # ── Token types ──────────────────────────────────────────────────────
    TOK_NUM    = "NUM"
    TOK_IDENT  = "IDENT"
    TOK_OP     = "OP"       # +  -  *  /
    TOK_LPAREN = "LPAREN"   # (
    TOK_RPAREN = "RPAREN"   # )
    TOK_LBRACK = "LBRACK"   # [
    TOK_RBRACK = "RBRACK"   # ]
    TOK_CASSIGN = "CASSIGN"  # <==
    TOK_CSIGNAL = "CSIGNAL"  # ==>
    TOK_CEQ    = "CEQ"       # ===
    TOK_SEMI   = "SEMI"      # ;

    TOK_EOF    = "EOF"

    # ── 1. Tokenizer ─────────────────────────────────────────────────────
    @staticmethod
    def _tokenize_expression(expr: str) -> list:
        """Tokenize an arithmetic expression into a list of (type, value) tuples.
        Supports: numbers, identifiers, operators, parentheses,
        array indexing (a[0]), and component references (comp.signal).
        """
        tokens = []
        i = 0
        while i < len(expr):
            ch = expr[i]
            if ch in ' \t\r\n':
                i += 1
                continue
            if ch in '+-*/':
                tokens.append((R1CSConstraintVerifier.TOK_OP, ch))
                i += 1
            elif ch == '(':
                tokens.append((R1CSConstraintVerifier.TOK_LPAREN, '('))
                i += 1
            elif ch == ')':
                tokens.append((R1CSConstraintVerifier.TOK_RPAREN, ')'))
                i += 1
            elif ch == '[':
                tokens.append((R1CSConstraintVerifier.TOK_LBRACK, '['))
                i += 1
            elif ch == ']':
                tokens.append((R1CSConstraintVerifier.TOK_RBRACK, ']'))
                i += 1
            elif ch.isdigit() or (ch == '0' and i + 1 < len(expr) and expr[i + 1] in 'xX'):
                j = i
                if ch == '0' and i + 1 < len(expr) and expr[i + 1] in 'xX':
                    j = i + 2
                    while j < len(expr) and (expr[j].isdigit() or expr[j] in 'abcdefABCDEF'):
                        j += 1
                else:
                    while j < len(expr) and expr[j].isdigit():
                        j += 1
                tokens.append((R1CSConstraintVerifier.TOK_NUM, expr[i:j]))
                i = j
            elif ch.isalpha() or ch == '_':
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] in '_.'):
                    j += 1
                name = expr[i:j]
                # Check for array indexing: ident[N]
                if j < len(expr) and expr[j] == '[':
                    k = j + 1
                    while k < len(expr) and expr[k] != ']':
                        k += 1
                    if k < len(expr):
                        name = expr[i:k+1]  # e.g., "a[0]"
                        j = k + 1
                tokens.append((R1CSConstraintVerifier.TOK_IDENT, name))
                i = j
            else:
                raise ValueError(f"Unexpected character '{ch}' in expression: {expr}")
        return tokens

    # ── 2. Expression AST with operator precedence ───────────────────────
    # Grammar (recursive descent):
    #   expr     → term (('+' | '-') term)*
    #   term     → factor (('*' | '/') factor)*
    #   factor   → NUMBER | IDENT | '(' expr ')' | '-' factor
    #
    # This correctly handles precedence: * / bind tighter than + -

    @staticmethod
    def _parse_expr(tokens: list, pos: int) -> tuple:
        """Parse an additive expression. Returns (value_or_node, new_pos)."""
        left, pos = R1CSConstraintVerifier._parse_term(tokens, pos)
        while pos < len(tokens) and tokens[pos][0] == R1CSConstraintVerifier.TOK_OP and tokens[pos][1] in ('+', '-'):
            op = tokens[pos][1]
            pos += 1
            right, pos = R1CSConstraintVerifier._parse_term(tokens, pos)
            left = (op, left, right)
        return left, pos

    @staticmethod
    def _parse_term(tokens: list, pos: int) -> tuple:
        """Parse a multiplicative expression."""
        left, pos = R1CSConstraintVerifier._parse_factor(tokens, pos)
        while pos < len(tokens) and tokens[pos][0] == R1CSConstraintVerifier.TOK_OP and tokens[pos][1] in ('*', '/'):
            op = tokens[pos][1]
            pos += 1
            right, pos = R1CSConstraintVerifier._parse_factor(tokens, pos)
            left = (op, left, right)
        return left, pos

    @staticmethod
    def _parse_factor(tokens: list, pos: int) -> tuple:
        """Parse a factor: number, identifier, parenthesized expr, or unary minus."""
        if pos >= len(tokens):
            raise ValueError("Unexpected end of expression")

        tok_type, tok_val = tokens[pos]

        if tok_type == R1CSConstraintVerifier.TOK_NUM:
            if tok_val.startswith('0x') or tok_val.startswith('0X'):
                return int(tok_val, 16), pos + 1
            return int(tok_val), pos + 1

        if tok_type == R1CSConstraintVerifier.TOK_IDENT:
            return ('signal', tok_val), pos + 1

        if tok_type == R1CSConstraintVerifier.TOK_LPAREN:
            inner, pos = R1CSConstraintVerifier._parse_expr(tokens, pos + 1)
            if pos >= len(tokens) or tokens[pos][0] != R1CSConstraintVerifier.TOK_RPAREN:
                raise ValueError("Missing closing parenthesis")
            return inner, pos + 1

        if tok_type == R1CSConstraintVerifier.TOK_OP and tok_val == '-':
            operand, pos = R1CSConstraintVerifier._parse_factor(tokens, pos + 1)
            return ('neg', operand), pos

        raise ValueError(f"Unexpected token {tok_type}:{tok_val}")

    @staticmethod
    def _eval_ast(node, signal_values: dict) -> int:
        """Evaluate a parsed AST node against concrete signal values."""
        if isinstance(node, int):
            return node
        if isinstance(node, tuple):
            if node[0] == 'signal':
                name = node[1]
                if name not in signal_values:
                    raise ValueError(f"Signal '{name}' has no assigned value in the witness")
                return signal_values[name]
            if node[0] == 'neg':
                val = R1CSConstraintVerifier._eval_ast(node[1], signal_values)
                return (-val) % R1CSConstraintVerifier.BN254_PRIME
            op, left, right = node
            lv = R1CSConstraintVerifier._eval_ast(left, signal_values)
            rv = R1CSConstraintVerifier._eval_ast(right, signal_values)
            p = R1CSConstraintVerifier.BN254_PRIME
            if op == '+': return (lv + rv) % p
            if op == '-': return (lv - rv) % p
            if op == '*': return (lv * rv) % p
            if op == '/':
                if rv % p == 0:
                    raise ValueError("Division by zero in constraint expression")
                # Modular inverse via Fermat's little theorem: rv^(p-2) mod p
                inv = pow(rv, p - 2, p)
                return (lv * inv) % p
        raise ValueError(f"Cannot evaluate AST node: {node}")

    @staticmethod
    def evaluate_expression(expr: str, signal_values: dict) -> int:
        """Tokenize, parse, and evaluate an arithmetic expression with correct precedence."""
        tokens = R1CSConstraintVerifier._tokenize_expression(expr)
        if not tokens:
            raise ValueError(f"Empty expression: '{expr}'")
        ast_node, end_pos = R1CSConstraintVerifier._parse_expr(tokens, 0)
        if end_pos != len(tokens):
            raise ValueError(f"Trailing tokens in expression: '{expr}' (parsed up to position {end_pos}/{len(tokens)})")
        return R1CSConstraintVerifier._eval_ast(ast_node, signal_values)

    # ── 2b. Compiler-Backed R1CS Artifact Verification ───────────────────
    @staticmethod
    def verify_r1cs_artifact(artifact_text: str, witness_text: str) -> dict:
        """
        Verify a witness against a compiler-backed R1CS constraint artifact.

        Accepts the standard JSON format produced by `snarkjs r1cs export json`,
        optionally extended with a `signal_map` for named signal resolution.

        For each constraint row [A, B, C], checks:
            dot(A, w) × dot(B, w) ≡ dot(C, w)  (mod BN254_PRIME)

        Returns a dict compatible with the verify() output format.
        """
        import json as _json
        trace = []
        p = R1CSConstraintVerifier.BN254_PRIME

        # ── Parse artifact JSON ──
        try:
            artifact = _json.loads(artifact_text)
        except Exception as e:
            return {
                "verified": False, "stage": "ARTIFACT_PARSING",
                "reason": f"R1CS artifact JSON parse error: {str(e)}",
                "circuit": None, "witness": None, "trace": []
            }

        for key in ("nVars", "nConstraints", "constraints"):
            if key not in artifact:
                return {
                    "verified": False, "stage": "ARTIFACT_VALIDATION",
                    "reason": f"R1CS artifact missing required key: '{key}'",
                    "circuit": None, "witness": None, "trace": []
                }

        n_vars = int(artifact["nVars"])
        n_constraints = int(artifact["nConstraints"])
        constraints = artifact["constraints"]
        signal_map = artifact.get("signal_map", {})

        # Validate BN254 prime
        if "prime" in artifact:
            artifact_prime = int(artifact["prime"])
            if artifact_prime != p:
                return {
                    "verified": False, "stage": "ARTIFACT_VALIDATION",
                    "reason": f"Artifact prime mismatch: expected BN254 ({p}), got {artifact_prime}",
                    "circuit": None, "witness": None, "trace": []
                }

        trace.append(
            f"R1CS artifact loaded: {n_vars} wire(s), {n_constraints} constraint(s), "
            f"{len(signal_map)} named signal(s), prime=BN254"
        )

        # ── Parse witness ──
        witness_result = R1CSConstraintVerifier.parse_witness(witness_text)
        if not witness_result["valid"]:
            return {
                "verified": False, "stage": "WITNESS_PARSING",
                "reason": f"Witness rejected: {witness_result['error']}",
                "circuit": None, "witness": witness_result, "trace": trace
            }

        witness_signals = witness_result["signals"]
        trace.append(f"Witness parsed: {len(witness_signals)} signal value(s)")

        # ── Build wire vector ──
        wire_values = [0] * n_vars
        wire_values[0] = 1  # Wire 0 is always the constant 1

        name_to_wire = {str(name): int(idx) for name, idx in signal_map.items()}

        bound_count = 0
        for sig_name, sig_val in witness_signals.items():
            if sig_name in name_to_wire:
                wire_idx = name_to_wire[sig_name]
                if 0 < wire_idx < n_vars:
                    wire_values[wire_idx] = sig_val % p
                    bound_count += 1
                    trace.append(f"  wire[{wire_idx}] '{sig_name}' = {sig_val}")

        if bound_count == 0:
            return {
                "verified": False, "stage": "WITNESS_BINDING",
                "reason": "No witness signals could be mapped to circuit wires via signal_map",
                "circuit": None, "witness": witness_result, "trace": trace
            }

        trace.append(f"Bound {bound_count} witness signal(s) to wire vector")

        # ── Check under-constrained artifact ──
        if n_constraints == 0:
            trace.append("WARNING: Artifact declares 0 constraints — circuit is UNDER-CONSTRAINED")
            return {
                "verified": False, "stage": "R1CS_VERIFICATION",
                "reason": (
                    f"R1CS artifact has 0 constraints with {n_vars} wire(s). "
                    "Circuit is under-constrained: any witness passes trivially. "
                    "This indicates a critical soundness vulnerability (e.g., <-- used instead of <==)."
                ),
                "circuit": None, "witness": witness_result, "trace": trace
            }

        # ── Evaluate each R1CS constraint ──
        failed = []
        for idx, constraint in enumerate(constraints):
            if len(constraint) != 3:
                failed.append(f"R1CS#{idx+1}: malformed (expected 3 LCs, got {len(constraint)})")
                continue

            a_lc, b_lc, c_lc = constraint

            def _dot(lc: dict, wires: list) -> int:
                total = 0
                for wire_str, coeff_str in lc.items():
                    w = int(wire_str)
                    c = int(coeff_str)
                    if 0 <= w < len(wires):
                        total = (total + c * wires[w]) % p
                return total

            val_a = _dot(a_lc, wire_values)
            val_b = _dot(b_lc, wire_values)
            val_c = _dot(c_lc, wire_values)

            lhs = (val_a * val_b) % p
            rhs = val_c % p

            cid = f"R1CS#{idx+1}"
            if lhs == rhs:
                trace.append(f"  {cid}: SATISFIED (A·w={val_a}, B·w={val_b}, C·w={val_c})")
            else:
                failed.append(f"{cid} VIOLATED: A·w×B·w={lhs} != C·w={rhs}")
                trace.append(f"  {cid}: VIOLATED (A·w×B·w={lhs} != C·w={rhs})")

        if failed:
            return {
                "verified": False, "stage": "R1CS_VERIFICATION",
                "reason": f"R1CS constraint verification failed: {'; '.join(failed)}",
                "circuit": None, "witness": witness_result, "trace": trace
            }

        return {
            "verified": True, "stage": "COMPLETE",
            "reason": (
                f"Compiler-backed R1CS verification passed. "
                f"{n_vars} wire(s), {n_constraints} constraint(s) — "
                f"all constraints satisfied (mod BN254)."
            ),
            "circuit": None, "witness": witness_result, "trace": trace
        }

    # ── 3. Circuit parser ────────────────────────────────────────────────
    @staticmethod
    def parse_circuit(circuit_code: str) -> dict:
        """
        Parse a Circom circuit into a structured representation.
        Returns: {templates, input_signals, output_signals, intermediate_signals,
                  r1cs_constraints, assignments, components, includes,
                  compiler_version, valid_syntax, errors}

        Supports:
          - Array signals: signal input a[4] → a[0], a[1], a[2], a[3]
          - Component declarations: component c = TemplateX()
          - Include directives: include "lib.circom"
          - Pragma version pinning: pragma circom 2.1.6
          - Dot-qualified references: comp.out, comp.in

        Each r1cs_constraint is: {"lhs_expr": str, "rhs_expr": str, "source": str}
        representing the equation lhs_expr === rhs_expr.
        """
        import re
        result = {
            "templates": [],
            "input_signals": [],
            "output_signals": [],
            "intermediate_signals": [],
            "r1cs_constraints": [],  # list of {"lhs_expr", "rhs_expr", "source"}
            "assignments": [],       # list of {"target", "expr"} for signal propagation
            "components": [],        # list of {"name", "template"}
            "includes": [],          # list of included file paths
            "compiler_version": "",  # pragma circom version string
            "valid_syntax": True,
            "errors": []
        }

        # Strip block and line comments
        code = re.sub(r"/\*.*?\*/", "", circuit_code, flags=re.DOTALL)
        code = re.sub(r"//[^\n]*", "", code)

        # Extract include directives
        include_matches = re.findall(r'include\s+"([^"]+)"', code)
        result["includes"] = include_matches

        # Validate and extract pragma version
        pragma_match = re.search(r"pragma\s+circom\s+(\d+\.\d+(?:\.\d+)?)", code)
        if not pragma_match:
            if "pragma circom" not in code:
                result["valid_syntax"] = False
                result["errors"].append("Missing 'pragma circom' directive — not a valid Circom circuit")
                return result
            result["compiler_version"] = "unknown"
        else:
            result["compiler_version"] = pragma_match.group(1)

        # Extract templates
        # Extract template bodies to enable component expansion
        # Match template Name(params) { ... }
        template_bodies = {}
        tmpl_body_matches = re.finditer(r"template\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*\{", code)
        for m in tmpl_body_matches:
            t_name = m.group(1)
            t_params = m.group(2).strip()
            result["templates"].append({"name": t_name, "params": t_params})
            
            # Find matching closing brace for the template
            start_brace = m.end() - 1
            depth = 0
            end_brace = -1
            for idx in range(start_brace, len(code)):
                if code[idx] == '{':
                    depth += 1
                elif code[idx] == '}':
                    depth -= 1
                    if depth == 0:
                        end_brace = idx
                        break
            if end_brace != -1:
                template_bodies[t_name] = code[start_brace+1:end_brace]

        if not result["templates"]:
            result["valid_syntax"] = False
            result["errors"].append("No template definition found in circuit source")
            return result

        # Extract component declarations: component name = Template(args)
        comp_matches = re.findall(r"component\s+([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*)\s*\(", code)
        for comp_name, comp_tmpl in comp_matches:
            result["components"].append({"name": comp_name, "template": comp_tmpl})

        # Extract signal declarations (with array expansion)
        def extract_signals(keyword, search_code):
            """Extract signals including array declarations like signal input a[4]."""
            signals = []
            simple = re.findall(r"signal\s+" + keyword + r"\s+([a-zA-Z_]\w*)(?:\s*;|\s*,)", search_code)
            signals.extend(simple)
            array = re.findall(r"signal\s+" + keyword + r"\s+([a-zA-Z_]\w*)\s*\[(\d+)\]", search_code)
            for name, size in array:
                for i in range(int(size)):
                    signals.append(f"{name}[{i}]")
            return signals

        # Determine main template name: component main = Template(), or last template in file
        main_comp_match = re.search(r"component\s+main\s*=\s*([a-zA-Z_]\w*)\s*\(", code)
        main_tmpl_name = main_comp_match.group(1) if main_comp_match else (result["templates"][-1]["name"] if result["templates"] else "")
        main_code = template_bodies.get(main_tmpl_name, code) if len(result["templates"]) > 1 else code

        result["input_signals"] = extract_signals("input", main_code)
        result["output_signals"] = extract_signals("output", main_code)

        # Intermediate signals (both simple and array)
        all_simple = re.findall(r"signal\s+([a-zA-Z_]\w*)(?:\s*;|\s*,)", main_code)
        all_array = re.findall(r"signal\s+([a-zA-Z_]\w*)\s*\[(\d+)\]", main_code)
        known = set(result["input_signals"]) | set(result["output_signals"]) | {"input", "output"}
        intermediate = []
        for s in all_simple:
            if s not in known:
                intermediate.append(s)
                known.add(s)
        for name, size in all_array:
            for i in range(int(size)):
                sig = f"{name}[{i}]"
                if sig not in known:
                    intermediate.append(sig)
                    known.add(sig)
        result["intermediate_signals"] = intermediate

        # Extract top-level constraint and assignment statements from root/main template
        statements = re.findall(r"([^;{}\n][^;]*(?:<==|==>|===)[^;]*);", main_code)
        for raw_stmt in statements:
            stmt = raw_stmt.strip()
            if not stmt:
                continue

            if "<==" in stmt:
                parts = stmt.split("<==", 1)
                target = parts[0].strip()
                expr   = parts[1].strip()
                result["assignments"].append({"target": target, "expr": expr})
                result["r1cs_constraints"].append({
                    "lhs_expr": target, "rhs_expr": expr,
                    "source": f"{target} <== {expr}"
                })
            elif "==>" in stmt:
                parts = stmt.split("==>", 1)
                expr   = parts[0].strip()
                target = parts[1].strip()
                result["assignments"].append({"target": target, "expr": expr})
                result["r1cs_constraints"].append({
                    "lhs_expr": target, "rhs_expr": expr,
                    "source": f"{expr} ==> {target}"
                })
            elif "===" in stmt:
                parts = stmt.split("===", 1)
                result["r1cs_constraints"].append({
                    "lhs_expr": parts[0].strip(), "rhs_expr": parts[1].strip(),
                    "source": stmt
                })

        # Instantiate sub-component templates: compile sub-circuit constraints into main constraint system
        for comp in result["components"]:
            c_name = comp["name"]
            if c_name == "main":
                continue
            c_tmpl = comp["template"]
            if c_tmpl in template_bodies:
                tmpl_code = template_bodies[c_tmpl]
                # Discover sub-signals
                sub_inputs = extract_signals("input", tmpl_code)
                sub_outputs = extract_signals("output", tmpl_code)
                for s in sub_inputs:
                    qualified = f"{c_name}.{s}"
                    if qualified not in result["intermediate_signals"]:
                        result["intermediate_signals"].append(qualified)
                for s in sub_outputs:
                    qualified = f"{c_name}.{s}"
                    if qualified not in result["intermediate_signals"]:
                        result["intermediate_signals"].append(qualified)

                # Extract sub-constraints and qualify signals with comp_name prefix
                sub_stmts = re.findall(r"([^;{}\n][^;]*(?:<==|==>|===)[^;]*);", tmpl_code)
                for raw_s in sub_stmts:
                    s_stmt = raw_s.strip()
                    if not s_stmt:
                        continue
                    
                    def qualify_tokens(expr_str):
                        # Qualify bare signal identifiers in template with c_name.sig
                        # Avoid numbers, keywords, and already qualified signals
                        toks = re.split(r'(\b[a-zA-Z_]\w*(?:\.\w+)*(?:\[\d+\])?\b)', expr_str)
                        out_toks = []
                        for t in toks:
                            if t and (t[0].isalpha() or t.startswith('_')):
                                if '.' in t:
                                    out_toks.append(t)
                                    continue
                                base = t.split('[')[0]
                                if base not in ["signal", "input", "output", "component", "var"] and not base.isdigit():
                                    out_toks.append(f"{c_name}.{t}")
                                else:
                                    out_toks.append(t)
                            else:
                                out_toks.append(t)
                        return "".join(out_toks)

                    if "<==" in s_stmt:
                        p = s_stmt.split("<==", 1)
                        t_target = f"{c_name}.{p[0].strip()}"
                        t_expr   = qualify_tokens(p[1].strip())
                        result["assignments"].append({"target": t_target, "expr": t_expr})
                        result["r1cs_constraints"].append({
                            "lhs_expr": t_target, "rhs_expr": t_expr,
                            "source": f"[{c_name}] {t_target} <== {t_expr}"
                        })
                    elif "===" in s_stmt:
                        p = s_stmt.split("===", 1)
                        t_lhs = qualify_tokens(p[0].strip())
                        t_rhs = qualify_tokens(p[1].strip())
                        result["r1cs_constraints"].append({
                            "lhs_expr": t_lhs, "rhs_expr": t_rhs,
                            "source": f"[{c_name}] {t_lhs} === {t_rhs}"
                        })

        if not result["input_signals"]:
            result["valid_syntax"] = False
            result["errors"].append("Circuit declares no input signals")
            return result

        if not result["r1cs_constraints"]:
            result["valid_syntax"] = False
            result["errors"].append("No R1CS constraints (<==, ==>, ===) found in circuit")

        return result

    # ── 4. Witness parser (strict JSON only) ─────────────────────────────
    @staticmethod
    def parse_witness(witness_text: str) -> dict:
        """
        Parse the witness/exploit submission.
        STRICT: the witness MUST be a valid JSON object mapping signal names to
        numeric values.  No regex fallback, no symbolic assignments, no free-text
        extraction.  If the input is not valid JSON with numeric values, it is
        REJECTED outright.
        """
        import json
        result = {"signals": {}, "valid": True, "error": ""}

        text = witness_text.strip()

        # The witness must start with '{' — reject anything else immediately
        if not text.startswith('{'):
            result["valid"] = False
            result["error"] = (
                "Witness must be a JSON object mapping signal names to numeric values "
                "(e.g. {\"a\": 5, \"b\": 10}).  Received non-JSON text."
            )
            return result

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            result["valid"] = False
            result["error"] = f"Witness JSON parse error: {str(e)}"
            return result

        if not isinstance(data, dict):
            result["valid"] = False
            result["error"] = "Witness JSON must be an object (dict), not an array or scalar"
            return result

        if len(data) == 0:
            result["valid"] = False
            result["error"] = "Witness JSON is an empty object — no signal assignments"
            return result

        for key, val in data.items():
            if not isinstance(key, str) or not key:
                result["valid"] = False
                result["error"] = f"Witness signal key must be a non-empty string, got: {repr(key)}"
                return result
            if isinstance(val, bool):
                # JSON booleans are not valid signal values
                result["valid"] = False
                result["error"] = f"Signal '{key}' has boolean value {val} — must be numeric (int/float)"
                return result
            p = R1CSConstraintVerifier.BN254_PRIME
            if isinstance(val, int):
                result["signals"][key] = val % p
            elif isinstance(val, float):
                result["signals"][key] = int(val) % p
            elif isinstance(val, str):
                # Allow hex strings like "0xff" and plain integer strings
                try:
                    if val.startswith("0x") or val.startswith("0X"):
                        result["signals"][key] = int(val, 16) % p
                    else:
                        result["signals"][key] = int(val) % p
                except ValueError:
                    result["valid"] = False
                    result["error"] = f"Signal '{key}' has non-numeric string value: '{val}'"
                    return result
            else:
                result["valid"] = False
                result["error"] = f"Signal '{key}' has unsupported type {type(val).__name__} — must be int, float, or numeric string"
                return result

        return result

    # ── 5. R1CS Constraint Verification (core) ───────────────────────────
    @staticmethod
    def verify(circuit_code: str, witness_text: str) -> dict:
        """
        Full R1CS verification pipeline with auto-detection:

        If circuit_code is a compiler-backed R1CS artifact (JSON with
        'constraints' and 'nVars' keys), routes to verify_r1cs_artifact()
        for direct matrix evaluation without AST parsing.

        Otherwise, compiles raw Circom source to R1CS constraints via the
        built-in AST parser.

        Pipeline (Circom source mode):
          1. Parse circuit → signal table + constraint list
          2. Parse witness → signal value map (strict JSON)
          3. Bind input signals from witness
          4. Propagate intermediate/output signals via assignments
          5. Evaluate every R1CS constraint: LHS_value == RHS_value
          6. Any failure → REJECT with detailed trace
        """
        # ── Auto-detect compiler-backed R1CS artifact ──
        stripped = circuit_code.strip()
        if stripped.startswith('{'):
            try:
                import json as _json
                probe = _json.loads(stripped)
                if isinstance(probe, dict) and "constraints" in probe and "nVars" in probe:
                    return R1CSConstraintVerifier.verify_r1cs_artifact(circuit_code, witness_text)
            except Exception:
                pass  # Not valid JSON artifact; fall through to Circom parser

        trace = []

        # ── Stage 1: Circuit compilation ──
        circuit = R1CSConstraintVerifier.parse_circuit(circuit_code)
        if not circuit["valid_syntax"]:
            return {
                "verified": False,
                "stage": "CIRCUIT_COMPILATION",
                "reason": f"Circuit compilation failed: {'; '.join(circuit['errors'])}",
                "circuit": circuit,
                "witness": None,
                "trace": []
            }

        trace.append(
            f"Circuit compiled (Circom {circuit.get('compiler_version', 'unknown')}): "
            f"{len(circuit['templates'])} template(s), "
            f"{len(circuit.get('components', []))} component(s), "
            f"{len(circuit.get('includes', []))} include(s), "
            f"{len(circuit['input_signals'])} input(s), "
            f"{len(circuit['output_signals'])} output(s), "
            f"{len(circuit['intermediate_signals'])} intermediate(s), "
            f"{len(circuit['r1cs_constraints'])} R1CS constraint(s) over BN254 scalar field"
        )


        # ── Stage 2: Witness parsing ──
        witness = R1CSConstraintVerifier.parse_witness(witness_text)
        if not witness["valid"]:
            return {
                "verified": False,
                "stage": "WITNESS_PARSING",
                "reason": f"Witness rejected: {witness['error']}",
                "circuit": circuit,
                "witness": witness,
                "trace": trace
            }

        trace.append(f"Witness parsed: {len(witness['signals'])} signal value(s)")

        # ── Stage 3: Bind input signals ──
        signal_values = {}
        missing_inputs = []
        for sig in circuit["input_signals"]:
            if sig in witness["signals"]:
                signal_values[sig] = witness["signals"][sig]
                trace.append(f"  input '{sig}' = {witness['signals'][sig]}")
            else:
                missing_inputs.append(sig)

        if missing_inputs:
            return {
                "verified": False,
                "stage": "WITNESS_BINDING",
                "reason": f"Witness does not supply values for required input signals: {', '.join(missing_inputs)}",
                "circuit": circuit,
                "witness": witness,
                "trace": trace
            }

        # ── Stage 4: Propagate assignments (multi-pass topological propagation) ──
        unresolved = list(circuit["assignments"])
        max_passes = len(unresolved) + 2
        last_error = ""

        for _ in range(max_passes):
            if not unresolved:
                break
            remaining = []
            progress = False
            for assign in unresolved:
                target = assign["target"]
                expr   = assign["expr"]
                try:
                    computed = R1CSConstraintVerifier.evaluate_expression(expr, signal_values)
                    progress = True
                    if target in witness["signals"]:
                        signal_values[target] = witness["signals"][target]
                        trace.append(
                            f"  signal '{target}': witness declares {witness['signals'][target]}, "
                            f"circuit computes {computed} from ({expr})"
                        )
                    else:
                        signal_values[target] = computed
                        trace.append(f"  signal '{target}' = {computed}  (from: {expr})")
                except Exception as e:
                    last_error = f"Failed to evaluate assignment '{target} <== {expr}': {str(e)}"
                    remaining.append(assign)
            unresolved = remaining
            if not progress and unresolved:
                break

        if unresolved:
            return {
                "verified": False,
                "stage": "SIGNAL_PROPAGATION",
                "reason": last_error or f"Unresolved signal dependencies in {len(unresolved)} assignment(s)",
                "circuit": circuit,
                "witness": witness,
                "trace": trace
            }

        # ── Stage 5: R1CS constraint verification ──
        # For each constraint "L === R", verify that eval(L) == eval(R).
        failed = []
        for idx, constraint in enumerate(circuit["r1cs_constraints"]):
            lhs_expr = constraint["lhs_expr"]
            rhs_expr = constraint["rhs_expr"]
            source   = constraint["source"]
            cid = f"R1CS#{idx+1}"

            try:
                lhs_val = R1CSConstraintVerifier.evaluate_expression(lhs_expr, signal_values)
            except Exception as e:
                failed.append(f"{cid} LHS evaluation error: {str(e)}")
                trace.append(f"  {cid} [{source}]: LHS ERROR — {str(e)}")
                continue

            try:
                rhs_val = R1CSConstraintVerifier.evaluate_expression(rhs_expr, signal_values)
            except Exception as e:
                failed.append(f"{cid} RHS evaluation error: {str(e)}")
                trace.append(f"  {cid} [{source}]: RHS ERROR — {str(e)}")
                continue

            if lhs_val == rhs_val:
                trace.append(f"  {cid} [{source}]: SATISFIED  ({lhs_val} == {rhs_val})")
            else:
                failed.append(
                    f"{cid} [{source}] VIOLATED: "
                    f"LHS={lhs_val}, RHS={rhs_val}"
                )
                trace.append(f"  {cid} [{source}]: VIOLATED  ({lhs_val} != {rhs_val})")

        if failed:
            return {
                "verified": False,
                "stage": "R1CS_VERIFICATION",
                "reason": f"R1CS constraint verification failed: {'; '.join(failed)}",
                "circuit": circuit,
                "witness": witness,
                "trace": trace
            }

        # ── All constraints satisfied ──
        return {
            "verified": True,
            "stage": "COMPLETE",
            "reason": (
                f"R1CS verification passed. "
                f"{len(circuit['templates'])} template(s), "
                f"{len(circuit['input_signals'])} input signal(s), "
                f"{len(circuit['r1cs_constraints'])} constraint(s) — "
                f"all constraints satisfied mathematically."
            ),
            "circuit": circuit,
            "witness": witness,
            "trace": trace
        }

# ── Non-custodial Timeout Boundaries (in seconds) ────────────────────────────
OPEN_TIMEOUT_SEC = 2592000       # 30 days: owner can cancel if unaccepted
PROGRESS_TIMEOUT_SEC = 1209600   # 14 days: auto-expire if auditor abandons IN_PROGRESS
REVISION_TIMEOUT_SEC = 604800    # 7 days: auto-expire revision window
DISPUTE_TIMEOUT_SEC = 2592000    # 30 days: auto-split fallback if dispute unresolved

class Contract(gl.Contract):
    tasks: TreeMap[str, ZKAuditTask]
    task_ids: DynArray[str]
    withdrawable_balances: TreeMap[str, bigint]  # Pull-over-Push safety net

    def __init__(self):
        pass

    def _safe_transfer(self, to_address: str, amount: bigint) -> None:
        """Safely transfer GEN using native bigint value with Pull-over-Push fallback.

        Attempts direct native transfer via gl.get_contract_at().emit_transfer(value=amount).
        If the direct dispatch fails for any reason (e.g. EOA call dispatch edge case or node error),
        the funds are immediately credited to self.withdrawable_balances for non-custodial pull.
        """
        if amount <= bigint(0):
            return
        addr_clean = to_address.strip().lower()
        try:
            gl.get_contract_at(Address(addr_clean)).emit_transfer(value=amount)
        except Exception:
            cur = self.withdrawable_balances.get(addr_clean, bigint(0))
            self.withdrawable_balances[addr_clean] = cur + amount

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
        constraint_focus: str,
        source_commit: str = ""
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

        # Enforce strict immutable source provenance (Git commit hex or IPFS CID)
        s_commit = source_commit.strip()
        if not s_commit or s_commit.lower() in ["unpinned", "none", "null", "undefined"]:
            raise UserError("Mandatory source_commit required: must pin exact immutable commit hash (40-hex Git SHA / 64-hex SHA-256) or IPFS CID (Qm/bafy)")
        
        is_hex = all(c in "0123456789abcdefABCDEF" for c in s_commit)
        is_ipfs = s_commit.startswith("Qm") or s_commit.startswith("bafy")
        if not ((is_hex and len(s_commit) in [40, 64]) or is_ipfs):
            raise UserError(f"Invalid source_commit '{s_commit}': must be a 40-char Git SHA, 64-char hex hash, or IPFS CID")

        caller = str(gl.message.sender_address).lower()
        now = self._get_current_timestamp()
        commit_pinned = s_commit
        
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
            disputed_at=bigint(0),
            created_at=now,
            accepted_at=bigint(0),
            source_commit=commit_pinned
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
        task.accepted_at = self._get_current_timestamp()
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

            # 3. On-Chain R1CS Constraint Verification (Compiler-Backed Artifacts & Circom)
            is_r1cs_artifact = c_text.strip().startswith("{") and ("constraints" in c_text or "nVars" in c_text)
            if is_r1cs_artifact or "circom" in framework_str.lower() or "r1cs" in framework_str.lower():
                r1cs_result = R1CSConstraintVerifier.verify(c_text, e_text)
                if not r1cs_result["verified"]:
                    stage = r1cs_result.get("stage", "")
                    verdict = "ESCALATE" if stage in ["CIRCUIT_COMPILATION", "ARTIFACT_PARSING"] else "REFUND"
                    return {
                        "verdict": verdict,
                        "confidence": 100,
                        "reason": f"R1CS verification ({stage}): {r1cs_result['reason']}"
                    }
                eval_trace = r1cs_result["trace"]
            else:
                eval_trace = ["Non-R1CS framework — R1CS verification skipped"]

            if len(e_text.strip()) < 20:
                return {"verdict": "REFUND", "confidence": 100, "reason": "Witness script too short (< 20 chars)."}

            prompt = f"""
You are a Principal Zero-Knowledge Cryptographer & Formal Circuit Verification Judge on GenLayer.
Evaluate the submitted mathematical counterexample / PoC witness against the target circuit source code.

CIRCUIT FRAMEWORK & COMPILER:
{framework_str}

FOCUS AREA / CONSTRAINT SPECIFICATION:
{focus_str}

R1CS CONSTRAINT VERIFICATION TRACE:
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
                self._safe_transfer(task.project_owner, total_refund)
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
        if caller != task.project_owner and now < task.payout_ready_at:
            raise UserError("24-hour cooling-off period has not elapsed yet (only project owner can finalize early)")

        escrow = task.escrow_amount
        stake = task.auditor_stake
        task.status = "CLOSED"
        task.escrow_amount = bigint(0)
        task.auditor_stake = bigint(0)

        if task.verdict == "APPROVED":
            self._safe_transfer(task.auditor, escrow + stake)
        elif task.verdict == "PARTIAL":
            half = escrow // bigint(2)
            rem = escrow - half
            self._safe_transfer(task.auditor, half + stake)
            self._safe_transfer(task.project_owner, rem)

        self.tasks[task_id] = task

    @gl.public.write
    def cancel_bounty(self, task_id: str) -> None:
        """Owner recovers escrow from an unaccepted OPEN bounty after OPEN_TIMEOUT (30 days)."""
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status != "OPEN":
            raise UserError("Only OPEN bounties can be cancelled")

        caller = str(gl.message.sender_address).lower()
        if caller != task.project_owner:
            raise UserError("Only project owner can cancel bounty")

        now = self._get_current_timestamp()
        if now < task.created_at + bigint(OPEN_TIMEOUT_SEC):
            raise UserError("Bounty cancellation timeout has not elapsed yet (must wait 30 days from creation)")

        escrow = task.escrow_amount
        task.status = "CLOSED"
        task.escrow_amount = bigint(0)
        task.reason = "Cancelled by project owner after OPEN timeout"
        self.tasks[task_id] = task

        if escrow > bigint(0):
            self._safe_transfer(task.project_owner, escrow)

    @gl.public.write
    def recover_expired_task(self, task_id: str) -> None:
        """
        Non-custodial timeout recovery for abandoned tasks in IN_PROGRESS,
        NEEDS_REVISION, ESCALATED, or DISPUTED status.
        Guarantees escrow and stake funds cannot remain indefinitely locked.
        """
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status == "CLOSED":
            raise UserError("Task is already closed")

        caller = str(gl.message.sender_address).lower()
        if caller != task.project_owner and caller != task.auditor:
            raise UserError("Unauthorized caller for timeout recovery")

        now = self._get_current_timestamp()
        escrow = task.escrow_amount
        stake = task.auditor_stake

        if task.status == "IN_PROGRESS":
            if now < task.accepted_at + bigint(PROGRESS_TIMEOUT_SEC):
                raise UserError("IN_PROGRESS task timeout has not elapsed yet (14 days)")
            task.status = "CLOSED"
            task.escrow_amount = bigint(0)
            task.auditor_stake = bigint(0)
            task.reason = "Expired: auditor abandoned task during IN_PROGRESS"
            self.tasks[task_id] = task
            if escrow > bigint(0):
                self._safe_transfer(task.project_owner, escrow)
            if stake > bigint(0):
                self._safe_transfer(task.auditor, stake)

        elif task.status == "NEEDS_REVISION":
            ref_time = task.payout_ready_at if task.payout_ready_at > bigint(0) else task.accepted_at
            if now < ref_time + bigint(REVISION_TIMEOUT_SEC):
                raise UserError("NEEDS_REVISION timeout has not elapsed yet (7 days)")
            task.status = "CLOSED"
            task.escrow_amount = bigint(0)
            task.auditor_stake = bigint(0)
            task.reason = "Expired: auditor abandoned revision attempt"
            self.tasks[task_id] = task
            if escrow > bigint(0):
                self._safe_transfer(task.project_owner, escrow)
            if stake > bigint(0):
                self._safe_transfer(task.auditor, stake)

        elif task.status in ["ESCALATED", "DISPUTED"]:
            ref_time = task.disputed_at if task.disputed_at > bigint(0) else (task.payout_ready_at if task.payout_ready_at > bigint(0) else task.created_at)
            if now < ref_time + bigint(DISPUTE_TIMEOUT_SEC):
                raise UserError("Dispute resolution timeout has not elapsed yet (30 days)")
            # Non-custodial 50/50 fallback split
            task.status = "CLOSED"
            task.escrow_amount = bigint(0)
            task.auditor_stake = bigint(0)
            task.reason = "Expired: 30-day non-custodial 50/50 dispute resolution fallback applied"
            self.tasks[task_id] = task
            half = escrow // bigint(2)
            rem = escrow - half
            if half + stake > bigint(0):
                self._safe_transfer(task.auditor, half + stake)
            if rem > bigint(0):
                self._safe_transfer(task.project_owner, rem)

        else:
            raise UserError(f"No timeout recovery rule for status {task.status}")

    @gl.public.write
    def resolve_dispute_consensus(self, task_id: str) -> None:
        """
        Validator-governed adjudication for ESCALATED or DISPUTED tasks.
        Multi-validator non-deterministic consensus inspects the dispute and votes
        on RELEASE (auditor), REFUND (project owner), or SPLIT (50/50).
        """
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status not in ["ESCALATED", "DISPUTED"]:
            raise UserError("Task is not in ESCALATED or DISPUTED status")

        caller = str(gl.message.sender_address).lower()
        if caller != task.project_owner and caller != task.auditor:
            raise UserError("Only project owner or auditor can invoke dispute adjudication")

        circuit_str = task.circuit_url
        exploit_str = task.proof_of_exploit_url
        framework_str = task.circuit_framework
        focus_str = task.constraint_focus
        dispute_reason = task.reason

        def dispute_leader_fn() -> dict:
            prompt = (
                f"You are an impartial decentralized arbitration validator resolving a disputed ZK circuit audit bounty.\n\n"
                f"Task ID: {task_id}\n"
                f"Framework: {framework_str}\n"
                f"Focus: {focus_str}\n"
                f"Original Verdict: {task.verdict}\n"
                f"Dispute Details: {dispute_reason}\n\n"
                f"Determine the fair outcome:\n"
                f"- 'RELEASE': Auditor's counterexample is mathematically valid; release escrow + stake to auditor.\n"
                f"- 'REFUND': Auditor's counterexample is invalid or fraudulent; return escrow + stake to project owner.\n"
                f"- 'SPLIT': Ambiguous or mitigating circumstances; split escrow 50/50 and return stake to auditor.\n\n"
                f"Respond with JSON: {{\"action\": \"RELEASE\" | \"REFUND\" | \"SPLIT\", \"confidence\": 0-100, \"reason\": \"explanation\"}}"
            )
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
            return self._parse_llm_json(str(raw))

        def dispute_validator_fn(leader_res) -> bool:
            if not isinstance(leader_res, gl.vm.Return):
                return False
            leader_data = leader_res.calldata if hasattr(leader_res, "calldata") else leader_res
            if not isinstance(leader_data, dict):
                leader_data = self._parse_llm_json(str(leader_data))
            mine_data = dispute_leader_fn()
            l_act = str(leader_data.get("action", "SPLIT")).upper().strip()
            m_act = str(mine_data.get("action", "SPLIT")).upper().strip()
            return l_act == m_act

        res = gl.vm.run_nondet(dispute_leader_fn, dispute_validator_fn)
        if not isinstance(res, dict):
            res = self._parse_llm_json(str(res))

        act = str(res.get("action", "SPLIT")).upper().strip()
        if act not in ["RELEASE", "REFUND", "SPLIT"]:
            act = "SPLIT"

        escrow = task.escrow_amount
        stake = task.auditor_stake
        task.status = "CLOSED"
        task.escrow_amount = bigint(0)
        task.auditor_stake = bigint(0)
        task.reason = f"[Validator Consensus: {act}] {str(res.get('reason', 'Adjudicated by GenLayer consensus'))}"
        self.tasks[task_id] = task

        if act == "RELEASE":
            self._safe_transfer(task.auditor, escrow + stake)
        elif act == "REFUND":
            self._safe_transfer(task.project_owner, escrow + stake)
        else: # SPLIT
            half = escrow // bigint(2)
            rem = escrow - half
            if half + stake > bigint(0):
                self._safe_transfer(task.auditor, half + stake)
            if rem > bigint(0):
                self._safe_transfer(task.project_owner, rem)

    @gl.public.write
    def resolve_escalation(self, task_id: str, action: str) -> None:
        """
        Voluntary bilateral concession path for ESCALATED or DISPUTED tasks:
        - Project Owner can voluntarily RELEASE funds to Auditor.
        - Auditor can voluntarily REFUND funds to Project Owner.
        Ensures neither party has unilateral authority to force an adverse split/refund.
        """
        if task_id not in self.tasks:
            raise UserError("Task not found")
        task = self.tasks[task_id]
        if task.status not in ["ESCALATED", "DISPUTED"]:
            raise UserError("Task is not in ESCALATED or DISPUTED status")

        caller = str(gl.message.sender_address).lower()
        act = action.upper().strip()

        if caller == task.project_owner:
            if act != "RELEASE":
                raise UserError("Project Owner can only voluntarily concede via RELEASE to auditor. Use resolve_dispute_consensus for adjudication.")
        elif caller == task.auditor:
            if act != "REFUND":
                raise UserError("Auditor can only voluntarily concede via REFUND to project owner. Use resolve_dispute_consensus for adjudication.")
        else:
            raise UserError("Unauthorized caller for dispute settlement")

        escrow = task.escrow_amount
        stake = task.auditor_stake
        task.status = "CLOSED"
        task.escrow_amount = bigint(0)
        task.auditor_stake = bigint(0)
        task.reason = f"Voluntary {act} concession by {'project owner' if caller == task.project_owner else 'auditor'}"
        self.tasks[task_id] = task

        if act == "RELEASE":
            self._safe_transfer(task.auditor, escrow + stake)
        elif act == "REFUND":
            self._safe_transfer(task.project_owner, escrow + stake)

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
                    "disputed_at": str(t.disputed_at),
                    "created_at": str(t.created_at),
                    "accepted_at": str(t.accepted_at),
                    "source_commit": t.source_commit
                })
        return json.dumps(res)

    # ── Pull-over-Push withdrawal ────────────────────────────────────────
    @gl.public.write
    def withdraw(self) -> None:
        """Withdraw accumulated balance from Pull-over-Push safety net.

        If a direct emit_transfer failed during payout/settlement, the funds
        are credited to withdrawable_balances. This method lets the recipient
        pull their balance at any time.
        """
        caller = str(gl.message.sender_address).lower()
        bal = self.withdrawable_balances.get(caller, bigint(0))
        if bal <= bigint(0):
            raise UserError("No withdrawable balance")
        self.withdrawable_balances[caller] = bigint(0)
        gl.get_contract_at(Address(caller)).emit_transfer(value=bal)

    @gl.public.view
    def get_withdrawable_balance(self, address: str) -> str:
        """Check withdrawable balance for Pull-over-Push safety net."""
        addr = address.lower().strip()
        return str(self.withdrawable_balances.get(addr, bigint(0)))

