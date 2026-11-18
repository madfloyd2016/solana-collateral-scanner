#!/usr/bin/env python3
"""Protocol-aware Solana Rust source triage for v0.5.

This module adds structured Anchor account-constraint extraction, Token-2022
extension policy signals, arithmetic review leads, and flash-repay path coverage.
It is intentionally heuristic and never emits a confirmed vulnerability verdict.
"""
from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import scanner

EXTENSIONS = (
    "PermanentDelegate",
    "TransferHook",
    "Pausable",
    "PausableConfig",
    "DefaultAccountState",
    "MintCloseAuthority",
    "ConfidentialTransferMint",
    "ConfidentialTransferAccount",
    "ScaledUiAmount",
    "InterestBearingConfig",
    "NonTransferable",
    "TransferFeeConfig",
    "TransferFeeAmount",
    "MetadataPointer",
    "TokenMetadata",
    "GroupPointer",
    "GroupMemberPointer",
)

FINANCIAL_WORD_RE = re.compile(
    r"balance|available|liquidity|collateral|debt|shares?|amount|reserve|vault|supply|borrow|principal|withdraw|repay|loan|token",
    re.I,
)
SELECTOR_NAME_RE = re.compile(
    r"(?:^|_)(?:asset|collateral|reserve|market|bank|mint|token|config)(?:_?(?:id|index|idx|key|selector|type))?$",
    re.I,
)


def _matching(text: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    paren = bracket = brace = angle = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == "{":
            brace += 1
        elif char == "}":
            brace = max(0, brace - 1)
        elif char == "<":
            angle += 1
        elif char == ">":
            angle = max(0, angle - 1)
        elif char == delimiter and paren == bracket == brace == angle == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _field_items(context_body: str) -> list[str]:
    clean = scanner.strip_comments_and_strings(context_body)
    brace = clean.find("{")
    if brace < 0:
        return []
    end = _matching(clean, brace, "{", "}")
    if end is None:
        return []
    return _split_top_level(context_body[brace + 1:end])


def _extract_account_attr(field_item: str) -> str:
    clean = scanner.strip_comments_and_strings(field_item)
    match = re.search(r"#\s*\[\s*account\s*\(", clean, re.I)
    if not match:
        return ""
    open_paren = clean.find("(", match.start())
    close_paren = _matching(clean, open_paren, "(", ")")
    if close_paren is None:
        return ""
    return field_item[open_paren + 1:close_paren]


def _parse_field(field_item: str) -> dict[str, Any] | None:
    attr = _extract_account_attr(field_item)
    clean_item = scanner.strip_comments_and_strings(field_item)
    clean_attr = scanner.strip_comments_and_strings(attr)
    if attr:
        attr_match = re.search(r"#\s*\[\s*account\s*\(", clean_item, re.I)
        if attr_match:
            close = _matching(clean_item, clean_item.find("(", attr_match.start()), "(", ")")
            if close is not None:
                clean_item = clean_item[:attr_match.start()] + " " + clean_item[close + 1:]
    clean_item = re.sub(r"#\s*\[[^]]*\]", " ", clean_item, flags=re.S)
    match = re.search(r"(?:pub(?:\s*\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$", clean_item, re.S)
    if not match:
        return None
    name = match.group(1)
    type_text = match.group(2).strip()
    if not type_text:
        return None
    has_one = re.findall(r"\bhas_one\s*=\s*([A-Za-z_]\w*)", clean_attr, re.I)
    token_mint = re.findall(r"(?:token|associated_token)::mint\s*=\s*([A-Za-z_]\w*)", clean_attr, re.I)
    address_exprs = re.findall(r"\baddress\s*=\s*([^,]+)", clean_attr, re.I)
    owner_exprs = re.findall(r"\bowner\s*=\s*([^,]+)", clean_attr, re.I)
    seed_exprs = re.findall(r"\bseeds\s*=\s*(\[[^]]*\])", attr, re.I)
    has_bump = bool(re.search(r"\bbump(?:\s*=|\s*[,)]|$)", clean_attr, re.I))
    constraints = []
    for cm in re.finditer(
        r"\bconstraint\s*=\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*|\s*\.\s*key\s*\(\))*)\s*(==|!=)\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*|\s*\.\s*key\s*\(\))*)",
        clean_attr,
        re.I,
    ):
        constraints.append({"left": re.sub(r"\s+", "", cm.group(1)), "operator": cm.group(2), "right": re.sub(r"\s+", "", cm.group(3))})
    return {
        "name": name,
        "type": type_text,
        "role": _field_role(name, type_text),
        "account_constraints": clean_attr.strip(),
        "has_one": sorted(set(has_one)),
        "token_mint_constraints": sorted(set(token_mint)),
        "address_constraints": [re.sub(r"\s+", "", item.strip()) for item in address_exprs],
        "owner_constraints": [re.sub(r"\s+", "", item.strip()) for item in owner_exprs],
        "pda_seeds": [item.strip() for item in seed_exprs],
        "pda_bump": has_bump,
        "equality_constraints": constraints,
    }


def _field_role(name: str, type_text: str) -> str:
    combined = f"{name} {type_text}".lower()
    if "tokenaccount" in combined.replace("_", "") or re.search(r"token_account|tokenaccount", combined):
        return "token_account"
    if re.search(r"\bmint\b", name, re.I) or re.search(r"\bMint\b", type_text):
        return "mint_account"
    if re.search(r"oracle|price_feed", combined):
        return "oracle_account"
    if re.search(r"market|reserve|bank|config|asset", combined):
        return "config_account"
    return "other"


def parse_anchor_accounts(source: str) -> dict[str, dict[str, Any]]:
    """Return per-Accounts-struct field constraints and derived identity guards."""
    contexts = scanner.extract_anchor_contexts(source)
    parsed: dict[str, dict[str, Any]] = {}
    for context_name, context in contexts.items():
        fields = []
        for item in _field_items(context["body"]):
            field = _parse_field(item)
            if field:
                fields.append(field)
        by_name = {field["name"]: field for field in fields}
        has_one_links = {
            target
            for field in fields
            if field["role"] == "config_account"
            for target in field["has_one"]
        }
        token_mint_links = {
            target
            for field in fields
            if field["role"] == "token_account"
            for target in field["token_mint_constraints"]
        }
        address_mint_links = set()
        address_oracle_links = set()
        direct_mint = []
        direct_oracle = []
        for field in fields:
            for expr in field["address_constraints"]:
                if re.search(r"(?:collateral|debt|liquidity)?_?mint", expr, re.I):
                    address_mint_links.add(field["name"])
                if re.search(r"(?:primary_)?oracle", expr, re.I):
                    address_oracle_links.add(field["name"])
            for constraint in field["equality_constraints"]:
                joined = f"{constraint['left']} {constraint['right']}"
                if re.search(r"\.mint\b", joined, re.I) and re.search(r"(?:market|reserve|bank|config|asset).*mint|mint.*(?:market|reserve|bank|config|asset)", joined, re.I):
                    direct_mint.append({"field": field["name"], **constraint})
                if re.search(r"oracle", joined, re.I) and re.search(r"key\(\)|primary_oracle", joined, re.I):
                    direct_oracle.append({"field": field["name"], **constraint})

        # A token-account mint constraint plus a config has_one/address binding
        # creates a two-edge identity chain within the same Anchor context.
        mint_chain_targets = token_mint_links & has_one_links
        address_chain_targets = token_mint_links & {
            field["name"] for field in fields if field["name"] in address_mint_links
        }
        mint_guard = bool(direct_mint or mint_chain_targets or address_chain_targets)
        unbound_mint_fields = [
            field["name"] for field in fields
            if field["role"] == "mint_account"
            and not field["address_constraints"]
            and not field["equality_constraints"]
            and field["name"] not in has_one_links
            and not mint_guard
        ]

        oracle_has_one = {
            target
            for field in fields
            if field["role"] == "config_account"
            for target in field["has_one"]
        }
        oracle_guard = bool(direct_oracle or (oracle_has_one & {f["name"] for f in fields if f["role"] == "oracle_account"}) or address_oracle_links)

        constraints_summary = []
        for field in fields:
            if field["account_constraints"]:
                constraints_summary.append({
                    "field": field["name"],
                    "role": field["role"],
                    "has_one": field["has_one"],
                    "token_mint_constraints": field["token_mint_constraints"],
                    "address_constraints": field["address_constraints"],
                    "owner_constraints": field["owner_constraints"],
                    "pda_seeds": field["pda_seeds"],
                    "pda_bump": field["pda_bump"],
                    "equality_constraints": field["equality_constraints"],
                })
        parsed[context_name] = {
            "context": context_name,
            "fields": fields,
            "constraints": constraints_summary,
            "mint_guard": mint_guard,
            "oracle_guard": oracle_guard,
            "unbound_mint_account_fields": unbound_mint_fields,
            "mint_guard_evidence": {
                "direct_constraints": direct_mint,
                "token_mint_to_has_one_targets": sorted(mint_chain_targets),
                "token_mint_to_address_targets": sorted(address_chain_targets),
            },
            "oracle_guard_evidence": {
                "direct_constraints": direct_oracle,
                "has_one_targets": sorted(oracle_has_one & {f["name"] for f in fields if f["role"] == "oracle_account"}),
                "address_targets": sorted(address_oracle_links),
            },
            "interpretation_limit": (
                "Anchor attribute patterns are parsed structurally but macro expansion, account deserialization, constraint execution order, "
                "and whether the handler uses the same accounts are not proven. Confirm with the exact Anchor version and compiled program."
            ),
        }
    return parsed


def _function_line(fn: dict[str, Any], body_offset: int = 0) -> int:
    return int(fn.get("line", 1)) + str(fn.get("clean_body", "")).count("\n", 0, body_offset)


def analyze_rust_file(path: Path) -> list[dict[str, Any]]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    clean = scanner.strip_comments_and_strings(source)
    functions = scanner.extract_functions(source, path)
    anchor_contexts = parse_anchor_accounts(source)
    findings: list[dict[str, Any]] = []

    for context_name, context in anchor_contexts.items():
        findings.append({
            "file": str(path),
            "function": f"Accounts::{context_name}",
            "line": 0,
            "analysis_type": "anchor_accounts_constraint_map",
            "status": "mint_and_oracle_binding_patterns_observed" if context["mint_guard"] or context["oracle_guard"] else "anchor_context_constraints_need_review",
            "priority": "INFO" if context["mint_guard"] and context["oracle_guard"] else "LOW_REVIEW",
            "mint_guard": context["mint_guard"],
            "oracle_guard": context["oracle_guard"],
            "evidence": context,
            "summary": f"Parsed {len(context['fields'])} Anchor account fields; mint_guard={context['mint_guard']}, oracle_guard={context['oracle_guard']}.",
        })
        if context.get("unbound_mint_account_fields"):
            findings.append({
                "file": str(path),
                "function": f"Accounts::{context_name}",
                "line": 0,
                "analysis_type": "anchor_unchecked_mint_account_key_review",
                "status": "mint_account_key_not_bound_in_anchor_attributes_review_required",
                "priority": "LOW_REVIEW",
                "fields": context["unbound_mint_account_fields"],
                "summary": "A Mint account field is present without a recognized local Anchor address/equality/config binding. Verify whether the handler or token transfer instruction enforces the expected Mint; this is a hygiene review lead only.",
                "interpretation_limit": "This rule does not inspect every handler/helper check or SPL Token CPI semantic. A missing Anchor attribute is not proof that the Mint is unchecked at runtime.",
            })

    for fn in functions:
        body = fn["body"]
        clean_body = fn["clean_body"]
        # Token-2022 extension policy signals.
        extensions = [name for name in EXTENSIONS if re.search(r"\b" + re.escape(name) + r"\b", clean_body)]
        if extensions:
            policy_tokens = bool(re.search(
                r"UnsupportedTokenExtension|unsupported|reject|disallow|not_supported|is_supported|allowed_extensions|deny_extension",
                clean_body,
                re.I,
            ))
            findings.append({
                "file": str(path),
                "function": fn["name"],
                "line": fn["line"],
                "analysis_type": "token_2022_extension_policy",
                "status": "extension_rejection_or_allowlist_logic_observed" if policy_tokens else "extension_present_policy_not_obvious",
                "priority": "LOW_REVIEW" if policy_tokens else "MEDIUM_REVIEW",
                "extensions": extensions,
                "policy_signal": policy_tokens,
                "summary": (
                    "Token-2022 extension names and a policy/rejection signal occur in this function; verify every extension is rejected or handled as intended."
                    if policy_tokens else
                    "Token-2022 extension names occur in this function, but no local rejection/allowlist policy was recognized; review protocol acceptance and downstream accounting."
                ),
                "interpretation_limit": "Extension mention is not proof that a mint can use the extension or that the authority can exercise it. Inspect mint data, authority, policy, and deployed version.",
            })

        # Financial arithmetic: detect naked subtraction and explicit checked/wrapping operations.
        operand = r"(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|(?:0x)?[0-9][0-9_]*(?:u(?:8|16|32|64|128))?)"
        arithmetic_patterns = [
            ("-", "unchecked_subtraction", "unchecked_subtraction_review_required", "Inspect underflow preconditions and actual-balance versus internal-accounting invariants."),
            ("*", "unchecked_multiplication", "unchecked_multiplication_overflow_review_required", "Inspect multiplication bounds, intermediate widths, decimal scaling, and checked overflow behavior."),
            ("+", "unchecked_addition", "unchecked_addition_overflow_review_required", "Inspect addition bounds and whether aggregate balances or liabilities can overflow."),
        ]
        for operator, operation, status, explanation in arithmetic_patterns:
            pattern = re.compile(r"\b(" + operand + r")\s*" + re.escape(operator) + r"\s*(" + operand + r")\b")
            for match in pattern.finditer(clean_body):
                left, right = match.group(1), match.group(2)
                if not (FINANCIAL_WORD_RE.search(left) or FINANCIAL_WORD_RE.search(right) or FINANCIAL_WORD_RE.search(fn["name"])):
                    continue
                priority = "HIGH_REVIEW" if operation == "unchecked_subtraction" and re.search(r"balance|available|liquidity|vault|reserve|collateral|debt", left + " " + right, re.I) else "MEDIUM_REVIEW"
                if operation in {"unchecked_multiplication", "unchecked_addition"} and re.search(r"amount|price|decimal|scale|share|debt|collateral|balance|liquidity", left + " " + right, re.I):
                    priority = "HIGH_REVIEW"
                findings.append({
                    "file": str(path),
                    "function": fn["name"],
                    "line": _function_line(fn, match.start()),
                    "analysis_type": "financial_arithmetic_review",
                    "status": status,
                    "priority": priority,
                    "operation": operation,
                    "expression": match.group(0),
                    "summary": f"A financial-looking expression uses the Rust '{operator}' operator. {explanation}",
                    "interpretation_limit": "Static pattern only. The expression may be range-constrained, unreachable for invalid states, or protected by surrounding checks. This is not a confirmed arithmetic bug.",
                })

        if not FINANCIAL_WORD_RE.search(fn["name"] + " " + clean_body):
            continue
        for method in ("checked_sub", "saturating_sub", "wrapping_sub", "overflowing_sub", "checked_mul", "saturating_mul", "wrapping_mul", "checked_add", "saturating_add", "wrapping_add"):
            for match in re.finditer(r"\.\s*" + method + r"\s*\(", clean_body):
                line = _function_line(fn, match.start())
                tail = clean_body[match.start():min(len(clean_body), match.start() + 220)]
                if method.startswith("wrapping"):
                    status, priority = "wrapping_arithmetic_review_required", "HIGH_REVIEW"
                elif method.startswith("saturating"):
                    status, priority = "saturating_arithmetic_semantics_review", "LOW_REVIEW"
                elif method.startswith("overflowing"):
                    status, priority = "overflow_flag_handling_review_required", "MEDIUM_REVIEW"
                elif method.startswith("checked") and re.search(r"\.\s*(?:unwrap_or|unwrap_or_else|unwrap|expect)\s*\(", tail):
                    status, priority = "checked_arithmetic_fallback_semantics_review", "MEDIUM_REVIEW"
                else:
                    status, priority = "checked_arithmetic_observed_manual_semantics_review", "INFO"
                findings.append({
                    "file": str(path),
                    "function": fn["name"],
                    "line": line,
                    "analysis_type": "financial_arithmetic_review",
                    "status": status,
                    "priority": priority,
                    "operation": method,
                    "expression": clean_body[match.start():min(len(clean_body), match.start() + 100)].strip(),
                    "summary": f"Detected {method}; inspect how None/overflow results are handled and whether the chosen semantics preserve the accounting invariant.",
                    "interpretation_limit": "Method presence alone does not establish safe or unsafe arithmetic semantics.",
                })

        # Flash-repay is always surfaced as a dedicated account-flow review root.
        if re.search(r"flash_?repay", fn["name"], re.I) or re.search(r"flash_?repay", clean_body, re.I):
            dynamic_accounts = bool(re.search(r"remaining_accounts|AccountInfo|UncheckedAccount", clean_body))
            token_ops = bool(re.search(r"transfer|repay|borrow|token", clean_body, re.I))
            findings.append({
                "file": str(path),
                "function": fn["name"],
                "line": fn["line"],
                "analysis_type": "flash_repay_account_flow",
                "status": "flash_repay_path_requires_identity_and_balance_review",
                "priority": "HIGH_REVIEW" if dynamic_accounts and token_ops else "MEDIUM_REVIEW",
                "dynamic_accounts": dynamic_accounts,
                "token_or_debt_operations": token_ops,
                "summary": "Flash-repay path detected. Verify repayment mint, borrowed mint, reserve/config identity, signer/authority, amount conservation, and failure atomicity across the full instruction sequence.",
                "interpretation_limit": "This is a coverage marker, not a claim that flash_repay is vulnerable. The specific account/repayment gap must be demonstrated from code and a local harness.",
            })

    return findings


def write_reports(findings: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "protocol_analysis.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    fields = ["file", "function", "line", "analysis_type", "status", "priority", "summary", "operation", "expression", "extensions"]
    with (out_dir / "protocol_analysis.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
    review_dir = out_dir / "protocol_analysis_review"
    review_dir.mkdir(exist_ok=True)
    for index, finding in enumerate(findings, 1):
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{finding.get('analysis_type','review')}_{finding.get('function','item')}_{finding.get('line',0)}")
        body = [
            f"# {finding.get('analysis_type')}: {finding.get('function')}",
            "",
            f"- File: `{finding.get('file')}`",
            f"- Line: `{finding.get('line')}`",
            f"- Status: `{finding.get('status')}`",
            f"- Priority: `{finding.get('priority')}`",
            "",
            "## Summary",
            "",
            str(finding.get("summary", "")),
            "",
            "## Evidence",
            "",
            "```json",
            json.dumps(finding, indent=2, ensure_ascii=False),
            "```",
            "",
            "This is a static review lead, not a confirmed vulnerability or deployment-equivalence claim.",
        ]
        (review_dir / f"{index:04d}_{slug}.md").write_text("\n".join(body), encoding="utf-8")
