#!/usr/bin/env python3
"""Conservative source-level asset-identity dataflow triage for Solana Rust (v0.5).

This is deliberately not a Rust compiler, borrow checker, or proof engine. It
tracks simple assignments, selected account/config field reads, same-file
helper arguments/returns, and explicit equality guards. Every result is a
manual-review lead, never a vulnerability verdict.
"""
from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import scanner
import protocol_analysis

IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
PARAM_TOKEN_ACCOUNT_RE = re.compile(
    r"(?:user|source|from|deposit|depositor|collateral|owner|input|payer)?\w*token_?account\w*", re.I
)
ACTUAL_MINT_NAME_RE = re.compile(r"^(?:actual|source|user|input|deposited|token)_mint$", re.I)
CONFIG_MINT_NAME_RE = re.compile(r"(?:config|reserve|market|bank|expected|asset|collateral)_mint$", re.I)
CONFIG_OBJECT_NAME_RE = re.compile(r"(?:config|reserve|market|bank|asset_config|collateral_config)$", re.I)
AMOUNT_NAME_RE = re.compile(r"(?:amount|quantity|atoms|shares|principal|deposit_amount|collateral_atoms)$", re.I)
DECIMAL_NAME_RE = re.compile(r"decimals?|precision|scale$", re.I)
ASSET_SELECTOR_NAME_RE = re.compile(
    r"^(?:asset|collateral|reserve|market|bank|mint|token|config)(?:_?(?:id|index|idx|selector|key))$|^(?:asset|collateral|reserve|market|bank|mint|token|config)_?(?:id|index|idx)$",
    re.I,
)
NUMERIC_SELECTOR_TYPES = {"u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64", "isize"}

VALUE_SINK_RE = re.compile(
    r"(?:collateral.*value|asset.*value|token.*value|value.*collateral|value_usd|usd_value|"
    r"borrow.*capacity|borrow.*limit|max_borrow|calculate_ltv|loan_to_value|health(?:_factor)?|"
    r"update_health|refresh_health|calculate_health)", re.I
)
BORROW_SINK_RE = re.compile(r"(?:^|_)(?:borrow|borrow_max|take_loan)(?:$|_)", re.I)
LIQUIDATION_SINK_RE = re.compile(r"liquidat|settle_matured|maturity_settle", re.I)
WITHDRAW_SINK_RE = re.compile(r"withdraw|redeem|unstake", re.I)
ORACLE_VALUE_RE = re.compile(r"(?:read|load|get|fetch|calculate)?_?(?:oracle_)?price|pyth|switchboard|price_feed", re.I)

RUST_KEYWORDS = {
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
    "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "Some", "None", "Ok", "Err",
}


def _function_key(fn: dict[str, Any]) -> str:
    return f"{fn['file']}::{fn['name']}@{fn['line']}"


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    paren = bracket = brace = angle = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == "<":
            # Generic type brackets are useful here; comparison operators in
            # function arguments are rare and only affect a conservative split.
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        elif ch == delimiter and paren == bracket == brace == angle == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _matching_paren(text: str, open_index: int) -> int | None:
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _function_signature_and_body(fn: dict[str, Any]) -> tuple[str, str]:
    clean = fn["clean_body"]
    brace = clean.find("{")
    if brace < 0:
        return clean, ""
    return clean[:brace], clean[brace + 1:-1]


def _parse_parameters(fn: dict[str, Any]) -> list[dict[str, str]]:
    signature, _ = _function_signature_and_body(fn)
    fn_match = re.search(r"\bfn\s+[A-Za-z_]\w*\s*\(", signature)
    if not fn_match:
        return []
    open_index = signature.find("(", fn_match.start())
    close_index = _matching_paren(signature, open_index)
    if close_index is None:
        return []
    result = []
    for item in _split_top_level(signature[open_index + 1:close_index]):
        if not item or item == "self" or item.startswith("&self"):
            continue
        if ":" not in item:
            continue
        name, type_text = item.split(":", 1)
        name = re.sub(r"\b(?:mut|ref)\b|[&*]", "", name).strip()
        if re.fullmatch(r"[A-Za-z_]\w*", name):
            result.append({"name": name, "type": type_text.strip()})
    return result


def _split_statements(body: str) -> list[tuple[str, int]]:
    """Split at semicolons outside parens/brackets; retain rough line numbers."""
    out: list[tuple[str, int]] = []
    start = 0
    paren = bracket = 0
    for i, ch in enumerate(body):
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == ";" and paren == 0 and bracket == 0:
            statement = body[start:i].strip()
            if statement:
                line = body.count("\n", 0, start) + 1
                out.append((statement, line))
            start = i + 1
    tail = body[start:].strip()
    if tail:
        out.append((tail, body.count("\n", 0, start) + 1))
    return out


def _assignments(body: str) -> list[dict[str, Any]]:
    assignments = []
    for statement, line in _split_statements(body):
        match = re.match(
            r"^\s*(?:let\s+(?:mut\s+)?|mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(?!=|>)\s*(.*?)\s*$",
            statement,
            re.S,
        )
        if not match:
            continue
        lhs, rhs = match.group(1), match.group(2)
        # Ignore equality/arrow expressions accidentally resembling assignments.
        if not lhs or not rhs:
            continue
        assignments.append({"lhs": lhs, "rhs": rhs, "statement": statement, "line": line})
    return assignments


def _call_sites(body: str) -> list[dict[str, Any]]:
    calls = []
    pattern = re.compile(r"\b([A-Za-z_]\w*)\s*(!)?\s*\(")
    for match in pattern.finditer(body):
        name = match.group(1)
        if name in scanner.CONTROL_CALLS or name in {"require_keys_eq", "require_eq", "require"}:
            continue
        open_index = body.find("(", match.start())
        close_index = _matching_paren(body, open_index)
        if close_index is None:
            continue
        args = _split_top_level(body[open_index + 1:close_index])
        calls.append({
            "name": name,
            "is_macro": bool(match.group(2)),
            "args": args,
            "start": match.start(),
            "end": close_index + 1,
            "line": body.count("\n", 0, match.start()) + 1,
        })
    return calls


def _identifiers(text: str) -> set[str]:
    return {name for name in IDENT_RE.findall(text) if name not in RUST_KEYWORDS}


def _looks_like_actual_token_account(text: str) -> bool:
    return bool(PARAM_TOKEN_ACCOUNT_RE.search(text)) or bool(
        re.search(r"\b(?:user|source|from|depositor|deposit|collateral)_token\b", text, re.I)
    )


def _looks_like_config_object(text: str) -> bool:
    return bool(re.search(r"\b(?:market|reserve|asset_config|collateral_config|bank|config)\b", text, re.I))


def _looks_like_actual_mint_expr(text: str, lhs: str = "") -> bool:
    if ACTUAL_MINT_NAME_RE.search(lhs):
        return True
    if _looks_like_actual_token_account(text) and re.search(r"\.\s*mint\b|mint\s*\(|\.\s*key\s*\(", text, re.I):
        return True
    return bool(re.search(r"\b(?:source|user|input|deposited|actual|token)_mint\b", text, re.I))


def _looks_like_config_mint_expr(text: str, lhs: str = "") -> bool:
    if CONFIG_MINT_NAME_RE.search(lhs):
        return True
    if _looks_like_config_object(text) and re.search(r"\b(?:mint|collateral_mint|debt_mint|liquidity_mint|token_mint)\b", text, re.I):
        return True
    return bool(re.search(r"\b(?:config|reserve|market|bank|asset)_mint\b", text, re.I))


def _seed_for_parameter(param: dict[str, str]) -> set[str]:
    name = param["name"].lower()
    type_text = param["type"].lower()
    labels: set[str] = set()
    if ACTUAL_MINT_NAME_RE.search(name):
        labels.add("actual_mint")
    if CONFIG_MINT_NAME_RE.search(name):
        labels.add("config_mint")
    if _looks_like_actual_token_account(name) or (
        "tokenaccount" in type_text.replace("_", "") and re.search(r"source|user|from|deposit|collateral|input", name)
    ):
        labels.add("actual_token_account")
    if CONFIG_OBJECT_NAME_RE.search(name) or (
        re.search(r"config|reserve|market|bank", type_text) and re.search(r"config|reserve|market|bank|asset", name)
    ):
        labels.add("config_object")
    if re.search(r"oracle|price_feed", name) or ("accountinfo" in type_text and "oracle" in name):
        labels.add("oracle_account")
    if AMOUNT_NAME_RE.search(name):
        labels.add("amount_input")
    normalized_type = re.sub(r"[&*\s]", "", type_text).split("<", 1)[0]
    if (
        ASSET_SELECTOR_NAME_RE.search(name)
        or name in {"asset", "collateral", "reserve", "market", "bank", "token", "config", "id", "index", "idx", "selector"}
    ) and (normalized_type in NUMERIC_SELECTOR_TYPES or re.search(r"(?:id|index|idx|selector)$", name)):
        labels.add("asset_selector")
    return labels


def _seed_for_expression(lhs: str, rhs: str) -> set[str]:
    labels: set[str] = set()
    if _looks_like_actual_mint_expr(rhs, lhs):
        labels.add("actual_mint")
    if _looks_like_config_mint_expr(rhs, lhs):
        labels.add("config_mint")
    if _looks_like_actual_token_account(rhs):
        labels.add("actual_token_account")
    if (CONFIG_OBJECT_NAME_RE.search(lhs) and _looks_like_config_object(rhs)) or re.search(
        r"(?:load|get|fetch|select)_\w*(?:config|reserve|market|asset)", rhs, re.I
    ):
        labels.add("config_object")
    if _looks_like_config_object(rhs) and re.search(r"\.\s*(?:key|to_account_info)\s*\(", rhs, re.I):
        labels.add("config_object")
    if re.search(r"\b(?:bank|config|reserve|market)\w*\s*\.\s*(?:primary_)?oracle\b", rhs, re.I):
        labels.add("config_oracle")
    if re.search(r"\boracle\w*\b", rhs, re.I) and re.search(r"account|remaining_accounts|ctx\.accounts", rhs, re.I):
        labels.add("oracle_account")
    if ORACLE_VALUE_RE.search(rhs) or re.search(r"\.\s*(?:price|twap)\b", rhs, re.I):
        labels.add("oracle_value")
    if re.search(r"\.\s*(?:[A-Za-z_]\w*_)?decimals\b", rhs, re.I):
        if _looks_like_config_object(rhs):
            labels.add("config_decimals")
        elif _looks_like_actual_mint_expr(rhs) or re.search(r"\bmint\w*\s*\.\s*decimals", rhs, re.I):
            labels.add("mint_decimals")
        else:
            labels.add("decimal_value")
    if AMOUNT_NAME_RE.search(lhs):
        labels.add("amount_input")
    selector_ref = re.search(
        r"\b(?:asset|collateral|reserve|market|bank|mint|token|config)_?(?:id|index|idx|selector)\b|\b(?:id|index|idx|selector)\b",
        rhs,
        re.I,
    )
    indexed_selection = bool(re.search(
        r"(?:\[[^]]*(?:asset|collateral|reserve|market|bank|config)_?(?:id|index|idx|selector)|\[[^]]*\b(?:id|index|idx|selector)\b[^]]*\]|\.\s*(?:get|nth)\s*\([^)]*(?:asset|collateral|reserve|market|bank|config)_?(?:id|index|idx|selector)|\.\s*(?:get|nth)\s*\([^)]*\b(?:id|index|idx|selector)\b)",
        rhs,
        re.I,
    ))
    if ASSET_SELECTOR_NAME_RE.search(lhs):
        labels.add("asset_selector")
    if selector_ref and indexed_selection:
        labels.update({"asset_selector", "selector_selected_config", "config_object"})
    elif indexed_selection and re.search(r"assets?|reserves?|markets?|configs?|banks?|collaterals?", rhs, re.I):
        labels.update({"selector_selected_config", "config_object"})
    return labels


def _root_is_financial_entrypoint(fn: dict[str, Any]) -> bool:
    name = fn["name"]
    if re.search(r"deposit|borrow|withdraw|redeem|liquidat|repay|settle|match|pledge|unlock|create_market|open_loan|flash_?repay", name, re.I):
        return True
    clean = fn["clean_body"]
    if name.lower().endswith("_checks") and re.search(r"balance|available|liquidity|reserve|vault|collateral|token|debt", name + " " + clean, re.I):
        return True
    financial = scanner.PATTERNS["financial"].search(clean)
    movement = scanner.PATTERNS["token_transfer"].search(clean)
    return bool((fn.get("context_name") and financial) or (financial and movement))


def _reachable(root: dict[str, Any], by_name: dict[str, list[dict[str, Any]]], max_depth: int) -> list[dict[str, Any]]:
    return [root] + scanner.reachable_functions(root, by_name, max_depth=max_depth)


def _parse_function_info(fn: dict[str, Any]) -> dict[str, Any]:
    signature, body = _function_signature_and_body(fn)
    params = _parse_parameters(fn)
    assignments = _assignments(body)
    known = {p["name"] for p in params}
    known.update(a["lhs"] for a in assignments)
    # Explicit return values are represented by a synthetic __return__ node.
    known.add("__return__")
    key = _function_key(fn)
    deps: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    seeds: dict[tuple[str, str], set[str]] = defaultdict(set)
    seed_evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    assignment_meta: list[dict[str, Any]] = []

    for param in params:
        node = (key, param["name"])
        labels = _seed_for_parameter(param)
        if labels:
            seeds[node].update(labels)
            for label in labels:
                seed_evidence[label].append({"function": fn["name"], "variable": param["name"], "line": fn["line"], "source": "parameter name/type"})

    for assignment in assignments:
        lhs, rhs = assignment["lhs"], assignment["rhs"]
        node = (key, lhs)
        refs = _identifiers(rhs) & known
        for ref in refs:
            if ref != lhs:
                deps[node].add((key, ref))
        labels = _seed_for_expression(lhs, rhs)
        if labels:
            seeds[node].update(labels)
            for label in labels:
                seed_evidence[label].append({"function": fn["name"], "variable": lhs, "line": fn["line"] + assignment["line"] - 1, "source": rhs[:180]})
        assignment_meta.append({**assignment, "node": node, "refs": refs})

    # Explicit returns and common tail expressions (including Ok(value)).
    return_exprs = []
    for match in re.finditer(r"\breturn\s+([^;]+);", body, re.S):
        return_exprs.append(match.group(1))
    statements = _split_statements(body)
    if statements:
        tail = statements[-1][0].strip()
        if tail and not tail.endswith("}") and not re.match(r"^(?:if|while|for|match)\b", tail):
            return_exprs.append(tail)
    for expression in return_exprs:
        for ref in (_identifiers(expression) & known) - {"__return__"}:
            deps[(key, "__return__")].add((key, ref))
        if re.search(r"\[[^]]*(?:asset|collateral|reserve|market|bank|config)_?(?:id|index|idx|selector)|\[[^]]*\b(?:id|index|idx|selector)\b[^]]*\]", expression, re.I):
            seeds[(key, "__return__")].update({"selector_selected_config", "config_object"})
        elif re.search(r"\bmatch\s+(?:asset|collateral|reserve|market|bank|config)_?(?:id|index|idx|selector)\b", expression, re.I) and re.search(r"reserve|market|config|asset|bank", expression, re.I):
            seeds[(key, "__return__")].update({"selector_selected_config", "config_object"})

    return {
        "fn": fn,
        "key": key,
        "signature": signature,
        "body": body,
        "params": params,
        "known": known,
        "assignments": assignment_meta,
        "deps": deps,
        "seeds": seeds,
        "seed_evidence": seed_evidence,
        "return_exprs": return_exprs,
    }


def _build_interprocedural_graph(infos: list[dict[str, Any]], by_name: dict[str, list[dict[str, Any]]]) -> tuple[dict, dict, list[dict[str, Any]], dict]:
    info_by_key = {info["key"]: info for info in infos}
    helper_edges: list[dict[str, Any]] = []
    all_deps: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    all_seeds: dict[tuple[str, str], set[str]] = defaultdict(set)
    seed_evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for info in infos:
        for node, dependencies in info["deps"].items():
            all_deps[node].update(dependencies)
        for node, labels in info["seeds"].items():
            all_seeds[node].update(labels)
        for label, records in info["seed_evidence"].items():
            seed_evidence[label].extend(records)

    for info in infos:
        caller_fn = info["fn"]
        for call in _call_sites(info["body"]):
            candidates = by_name.get(call["name"], [])
            same_file = [item for item in candidates if item["file"] == caller_fn["file"]]
            if same_file:
                candidates = same_file
            elif len(candidates) > 1:
                continue
            if len(candidates) != 1:
                continue
            child = candidates[0]
            child_key = _function_key(child)
            child_info = info_by_key.get(child_key)
            if child_info is None:
                continue
            formals = child_info["params"]
            for index, arg in enumerate(call["args"]):
                if index >= len(formals):
                    break
                formal = formals[index]["name"]
                formal_node = (child_key, formal)
                actual_refs = _identifiers(arg) & info["known"]
                for ref in actual_refs:
                    all_deps[formal_node].add((info["key"], ref))
                expr_labels: set[str] = set()
                if _looks_like_actual_token_account(arg):
                    expr_labels.add("actual_token_account")
                if _looks_like_actual_mint_expr(arg):
                    expr_labels.add("actual_mint")
                if _looks_like_config_object(arg):
                    expr_labels.add("config_object")
                if _looks_like_config_mint_expr(arg):
                    expr_labels.add("config_mint")
                if re.search(r"oracle|price_feed", arg, re.I):
                    expr_labels.add("oracle_account")
                if AMOUNT_NAME_RE.search(formal):
                    expr_labels.add("amount_input")
                if ASSET_SELECTOR_NAME_RE.search(formal) or re.search(
                    r"\b(?:asset|collateral|reserve|market|bank|config)_?(?:id|index|idx|selector)\b", arg, re.I
                ):
                    expr_labels.add("asset_selector")
                if expr_labels:
                    all_seeds[formal_node].update(expr_labels)
                    for label in expr_labels:
                        seed_evidence[label].append({"function": child["name"], "variable": formal, "line": child["line"], "source": f"argument from {caller_fn['name']}::{arg[:120]}"})

            # If a helper's result is assigned, propagate its return summary to
            # the caller's LHS. Arguments are also retained as conservative deps.
            for assignment in info["assignments"]:
                if re.search(r"\b" + re.escape(call["name"]) + r"\s*\(", assignment["rhs"]):
                    all_deps[assignment["node"]].add((child_key, "__return__"))

            helper_edges.append({
                "caller": caller_fn["name"],
                "callee": child["name"],
                "line": caller_fn["line"] + call["line"] - 1,
                "argument_count": len(call["args"]),
                "parameter_count": len(formals),
            })

    # Derived fields: reading .mint from a token-account/config object, and
    # reading decimals from a config or Mint, preserve the object's provenance.
    changed = True
    while changed:
        changed = False
        for info in infos:
            for assignment in info["assignments"]:
                node = assignment["node"]
                rhs = assignment["rhs"]
                current = all_seeds[node]
                before = len(current)
                dep_labels = set()
                for dep in all_deps.get(node, set()):
                    dep_labels.update(all_seeds[dep])
                if re.search(r"\.\s*(?:mint|collateral_mint|debt_mint|liquidity_mint)\b", rhs, re.I):
                    if "actual_token_account" in dep_labels or _looks_like_actual_token_account(rhs):
                        current.add("actual_mint")
                    if "config_object" in dep_labels or _looks_like_config_object(rhs):
                        current.add("config_mint")
                if re.search(r"\.\s*(?:[A-Za-z_]\w*_)?decimals\b", rhs, re.I):
                    if "config_object" in dep_labels or "config_mint" in dep_labels:
                        current.add("config_decimals")
                    elif "actual_mint" in dep_labels:
                        current.add("mint_decimals")
                if "asset_selector" in dep_labels and (
                    CONFIG_OBJECT_NAME_RE.search(assignment["lhs"])
                    or re.search(r"\[[^]]+\]|\.\s*(?:get|nth)\s*\(", rhs)
                ):
                    current.update({"selector_selected_config", "config_object"})
                if ORACLE_VALUE_RE.search(rhs) or re.search(r"\.\s*(?:price|twap)\b", rhs, re.I):
                    current.add("oracle_value")
                if len(current) > before:
                    changed = True
        for node, dependencies in all_deps.items():
            before = len(all_seeds[node])
            for dep in dependencies:
                all_seeds[node].update(all_seeds.get(dep, set()))
            if len(all_seeds[node]) > before:
                changed = True

    return all_deps, all_seeds, helper_edges, seed_evidence


def _node_labels(node_refs: set[str], info: dict[str, Any], taints: dict[tuple[str, str], set[str]]) -> set[str]:
    labels: set[str] = set()
    for name in node_refs:
        labels.update(taints.get((info["key"], name), set()))
    return labels


def _guard_records(infos: list[dict[str, Any]], taints: dict[tuple[str, str], set[str]]) -> list[dict[str, Any]]:
    guards = []
    for info in infos:
        for statement, line in _split_statements(info["body"]):
            lower = statement.lower()
            if not ("==" in statement or "!=" in statement or "require_keys_eq" in lower or "require_eq" in lower or "has_one" in lower):
                continue
            refs = _identifiers(statement) & info["known"]
            labels = _node_labels(refs, info, taints)
            direct_actual_config_mint = bool(
                (
                    re.search(r"(?:source|user|from|deposit|depositor|collateral|input)\w*(?:token_?account)?\w*\s*\.\s*mint", statement, re.I)
                    or re.search(r"\b(?:source|user|actual|input|deposited|token)_mint\b", statement, re.I)
                )
                and re.search(r"(?:config|market|reserve|bank|asset)\w*(?:\s*\.\s*|_)(?:collateral_)?(?:debt_)?mint", statement, re.I)
            )
            account_object_mint_compare = (
                "actual_token_account" in labels and "config_object" in labels
                and re.search(r"\b\w+\s*\.\s*mint\b", statement, re.I)
                and re.search(r"\b(?:config|market|reserve|bank|asset)\w*\s*\.\s*(?:collateral_)?(?:debt_)?mint\b", statement, re.I)
            )
            if ("actual_mint" in labels and "config_mint" in labels) or direct_actual_config_mint or account_object_mint_compare:
                guards.append({
                    "kind": "actual_mint_to_config_mint_comparison",
                    "function": info["fn"]["name"],
                    "line": info["fn"]["line"] + line - 1,
                    "variables": sorted(refs),
                    "expression": statement[:240],
                    "strength": "explicit_comparison_pattern",
                })
            direct_oracle_compare = (
                "oracle_account" in labels and "config_object" in labels
                and re.search(r"(?:primary_)?oracle", statement, re.I)
            )
            if ("oracle_account" in labels and "config_oracle" in labels) or direct_oracle_compare:
                guards.append({
                    "kind": "oracle_account_to_config_oracle_comparison",
                    "function": info["fn"]["name"],
                    "line": info["fn"]["line"] + line - 1,
                    "variables": sorted(refs),
                    "expression": statement[:240],
                    "strength": "explicit_comparison_pattern",
                })

        context = info["fn"].get("context_clean", "")
        if context:
            # Anchor constraints are reported separately as patterns because
            # their semantics depend on the exact account struct and macro.
            for match in re.finditer(
                r"(?:constraint\s*=\s*)?([A-Za-z_]\w*(?:\.\w+)*\.mint)\s*==\s*([A-Za-z_]\w*(?:\.\w+)*\.(?:collateral_mint|debt_mint|mint))",
                context,
                re.I,
            ):
                guards.append({
                    "kind": "anchor_context_mint_equality_pattern",
                    "function": f"Accounts::{info['fn'].get('context_name')}",
                    "line": info["fn"]["line"],
                    "variables": [],
                    "expression": match.group(0)[:240],
                    "strength": "anchor_constraint_pattern_requires_manual_confirmation",
                })
            for match in re.finditer(
                r"(?:constraint\s*=\s*)?([A-Za-z_]\w*(?:\.\w+)*\.key\s*\(\s*\))\s*==\s*([A-Za-z_]\w*(?:\.\w+)*\.(?:primary_)?oracle)",
                context,
                re.I,
            ):
                guards.append({
                    "kind": "anchor_context_oracle_equality_pattern",
                    "function": f"Accounts::{info['fn'].get('context_name')}",
                    "line": info["fn"]["line"],
                    "variables": [],
                    "expression": match.group(0)[:240],
                    "strength": "anchor_constraint_pattern_requires_manual_confirmation",
                })
    return guards


def _sink_records(infos: list[dict[str, Any]], taints: dict[tuple[str, str], set[str]]) -> list[dict[str, Any]]:
    sinks = []
    for info in infos:
        body = info["body"]
        for call in _call_sites(body):
            name = call["name"]
            if not (VALUE_SINK_RE.search(name) or BORROW_SINK_RE.search(name) or LIQUIDATION_SINK_RE.search(name) or WITHDRAW_SINK_RE.search(name)):
                continue
            refs = set()
            for arg in call["args"]:
                refs.update(_identifiers(arg) & info["known"])
            labels = _node_labels(refs, info, taints)
            if VALUE_SINK_RE.search(name):
                sink_type = "valuation_or_health"
            elif BORROW_SINK_RE.search(name):
                sink_type = "borrow"
            elif LIQUIDATION_SINK_RE.search(name):
                sink_type = "liquidation_or_settlement"
            else:
                sink_type = "withdraw_or_redeem"
            sinks.append({
                "function": info["fn"]["name"],
                "callee": name,
                "line": info["fn"]["line"] + call["line"] - 1,
                "sink_type": sink_type,
                "variables": sorted(refs),
                "taint_categories": sorted(labels),
                "expression": body[call["start"]:call["end"]][:260],
            })

        for assignment in info["assignments"]:
            lhs = assignment["lhs"]
            if not VALUE_SINK_RE.search(lhs):
                continue
            labels = _node_labels({lhs}, info, taints)
            sinks.append({
                "function": info["fn"]["name"],
                "callee": f"assignment::{lhs}",
                "line": info["fn"]["line"] + assignment["line"] - 1,
                "sink_type": "valuation_or_health_assignment",
                "variables": [lhs],
                "taint_categories": sorted(labels),
                "expression": assignment["statement"][:260],
            })
    return sinks


def _direct_context_guard(fn: dict[str, Any]) -> bool:
    context = fn.get("context_clean", "")
    if not context:
        return False
    return bool(re.search(
        r"\b(?:user|source|from|deposit|collateral)\w*token\w*\.mint\s*==\s*\w*(?:config|market|reserve|bank)\w*\.(?:mint|collateral_mint|debt_mint)",
        context,
        re.I,
    ))



def _extract_struct_fields(source: str) -> dict[str, set[str]]:
    clean = scanner.strip_comments_and_strings(source)
    structs: dict[str, set[str]] = {}
    pattern = re.compile(r"\bstruct\s+([A-Za-z_]\w*)\b")
    for match in pattern.finditer(clean):
        brace = clean.find("{", match.end())
        if brace < 0:
            continue
        depth = 0
        end = None
        for index in range(brace, len(clean)):
            if clean[index] == "{":
                depth += 1
            elif clean[index] == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            continue
        body = clean[brace + 1:end]
        fields = set()
        for line in body.splitlines():
            field_match = re.match(r"\s*(?:pub(?:\s*\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:", line)
            if field_match:
                fields.add(field_match.group(1))
        if fields:
            structs[match.group(1)] = fields
    return structs


def _context_alias_types(fn: dict[str, Any], struct_fields: dict[str, set[str]]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    context = fn.get("context_clean", "")
    account_type_re = re.compile(
        r"\b([A-Za-z_]\w*)\s*:\s*(?:Box\s*<\s*)?(?:Account|AccountLoader|InterfaceAccount)\s*<\s*'?[A-Za-z_]\w*\s*,\s*([A-Za-z_]\w*)",
        re.I,
    )
    for match in account_type_re.finditer(context):
        if match.group(2) in struct_fields:
            aliases[match.group(1)] = match.group(2)
    return aliases


def _field_role(field: str) -> str:
    name = field.lower()
    if "mint" in name or name.endswith("asset_id") or name.endswith("token_id"):
        return "mint_or_asset_identity"
    if "oracle" in name or "feed" in name:
        return "oracle_identity"
    if "decimal" in name or "precision" in name or "scale" in name:
        return "decimal_precision"
    if "ltv" in name or "weight" in name or "threshold" in name or "risk" in name:
        return "risk_parameter"
    if "share" in name or "collateral" in name or "balance" in name or "available" in name:
        return "collateral_or_liquidity_accounting"
    if "value" in name or "price" in name or "debt" in name or "borrow" in name:
        return "valuation_or_debt_accounting"
    return "other_state"


def _cross_instruction_state_map(source: str, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map state fields written by one handler and read by other handlers.

    This is a structural field-reference map, not a proof that the same runtime
    account instance or value is used on every path.
    """
    struct_fields = _extract_struct_fields(source)
    if not struct_fields:
        return []
    accesses: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: {"writers": [], "readers": []})

    for fn in functions:
        signature, body = _function_signature_and_body(fn)
        aliases = _context_alias_types(fn, struct_fields)
        for param in _parse_parameters(fn):
            type_text = param["type"]
            type_match = re.search(r"(?:Account|AccountLoader|InterfaceAccount)\s*<\s*'?[A-Za-z_]\w*\s*,\s*([A-Za-z_]\w*)", type_text)
            if type_match and type_match.group(1) in struct_fields:
                aliases[param["name"]] = type_match.group(1)
            elif re.fullmatch(r"&?\s*(?:mut\s+)?([A-Za-z_]\w*)", type_text.strip()) and type_match is None:
                plain = re.fullmatch(r"&?\s*(?:mut\s+)?([A-Za-z_]\w*)", type_text.strip())
                if plain and plain.group(1) in struct_fields:
                    aliases[param["name"]] = plain.group(1)

        field_access = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\b")
        for match in field_access.finditer(body):
            alias, field = match.group(1), match.group(2)
            struct_type = aliases.get(alias)
            if not struct_type or field not in struct_fields.get(struct_type, set()):
                continue
            tail = body[match.end():].lstrip()
            is_write = bool(re.match(r"(?:=(?!=)|\+=|-=|\*=|/=)", tail))
            line = fn["line"] + body.count("\n", 0, match.start())
            record = {"function": fn["name"], "file": fn["file"], "line": line, "access": "write" if is_write else "read", "alias": alias}
            bucket = "writers" if is_write else "readers"
            accesses[(struct_type, field)][bucket].append(record)

        # Include common struct literal initialization, e.g. MarketFixed { mint: ... }.
        for struct_type, fields in struct_fields.items():
            init_re = re.compile(r"\b" + re.escape(struct_type) + r"\s*\{")
            for init_match in init_re.finditer(body):
                open_index = body.find("{", init_match.start())
                depth = 0
                end = None
                for index in range(open_index, len(body)):
                    if body[index] == "{":
                        depth += 1
                    elif body[index] == "}":
                        depth -= 1
                        if depth == 0:
                            end = index
                            break
                if end is None:
                    continue
                literal = body[open_index + 1:end]
                for field in fields:
                    if re.search(r"\b" + re.escape(field) + r"\s*:", literal):
                        line = fn["line"] + body.count("\n", 0, init_match.start())
                        accesses[(struct_type, field)]["writers"].append({
                            "function": fn["name"], "file": fn["file"], "line": line,
                            "access": "write", "alias": struct_type, "source": "struct_literal",
                        })

    function_lookup = {fn["name"]: fn for fn in functions}
    links = []
    for (struct_type, field), buckets in sorted(accesses.items()):
        writers = buckets["writers"]
        readers = buckets["readers"]
        if not writers or not readers:
            continue
        writer_names = {item["function"] for item in writers}
        reader_names = {item["function"] for item in readers}
        if not any(writer != reader for writer in writer_names for reader in reader_names):
            continue
        cross_instruction = any(
            writer != reader
            and writer in function_lookup and reader in function_lookup
            and _root_is_financial_entrypoint(function_lookup[writer])
            and _root_is_financial_entrypoint(function_lookup[reader])
            for writer in writer_names for reader in reader_names
        )
        links.append({
            "struct_type": struct_type,
            "field": field,
            "role": _field_role(field),
            "writers": writers,
            "readers": readers,
            "cross_function_candidate": True,
            "cross_instruction_candidate": cross_instruction,
            "interpretation_limit": "Field-name linkage only; does not prove same account instance, PDA, serialization layout, or value identity across instructions.",
        })
    return links

def analyze_rust_file(path: Path, max_depth: int = 3) -> list[dict[str, Any]]:
    """Analyze financial instruction roots in one Rust file."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    functions = scanner.extract_functions(source, path)
    if not functions:
        return []
    _, by_name = scanner.build_call_graph(functions)
    state_field_links = _cross_instruction_state_map(source, functions)
    anchor_contexts = protocol_analysis.parse_anchor_accounts(source)
    findings = []

    for root in functions:
        if not _root_is_financial_entrypoint(root):
            continue
        reachable = _reachable(root, by_name, max_depth=max_depth)
        infos = [_parse_function_info(fn) for fn in reachable]
        deps, taints, helper_edges, seed_evidence = _build_interprocedural_graph(infos, by_name)
        guards = _guard_records(infos, taints)
        anchor_context = anchor_contexts.get(root.get("context_name") or "", {})
        if anchor_context.get("mint_guard"):
            guards.append({
                "kind": "anchor_accounts_struct_mint_identity_chain",
                "function": f"Accounts::{root.get('context_name')}",
                "line": root["line"],
                "variables": [],
                "expression": json.dumps(anchor_context.get("mint_guard_evidence", {}), ensure_ascii=False),
                "strength": "structured_anchor_attribute_chain_manual_validation_required",
            })
        if anchor_context.get("oracle_guard"):
            guards.append({
                "kind": "anchor_accounts_struct_oracle_identity_chain",
                "function": f"Accounts::{root.get('context_name')}",
                "line": root["line"],
                "variables": [],
                "expression": json.dumps(anchor_context.get("oracle_guard_evidence", {}), ensure_ascii=False),
                "strength": "structured_anchor_attribute_chain_manual_validation_required",
            })
        sinks = _sink_records(infos, taints)
        actual_mint_seen = any("actual_mint" in labels for labels in taints.values())
        config_mint_seen = any("config_mint" in labels for labels in taints.values())
        config_to_sink = any(
            set(item["taint_categories"]) & {"config_object", "config_mint", "config_decimals", "config_oracle", "selector_selected_config"}
            for item in sinks
        )
        asset_selector_seen = any("asset_selector" in labels for labels in taints.values())
        selector_to_sink = any(
            "selector_selected_config" in item["taint_categories"]
            for item in sinks
        )
        amount_to_sink = any("amount_input" in item["taint_categories"] for item in sinks)
        oracle_to_sink = any("oracle_value" in item["taint_categories"] for item in sinks)
        decimals_to_sink = any(
            set(item["taint_categories"]) & {"mint_decimals", "config_decimals", "decimal_value"}
            for item in sinks
        )
        mint_guard = any(item["kind"] in {
            "actual_mint_to_config_mint_comparison", "anchor_context_mint_equality_pattern",
            "anchor_accounts_struct_mint_identity_chain",
        } for item in guards) or _direct_context_guard(root)
        oracle_guard = any(item["kind"] in {
            "oracle_account_to_config_oracle_comparison", "anchor_context_oracle_equality_pattern",
            "anchor_accounts_struct_oracle_identity_chain",
        } for item in guards)

        if actual_mint_seen and config_mint_seen and config_to_sink:
            status = (
                "binding_guard_and_config_value_flow_observed_manual_validation_required"
                if mint_guard else "potential_unbound_mint_to_config_value_flow_review_required"
            )
        elif actual_mint_seen and config_to_sink:
            status = "actual_mint_seen_config_identity_unresolved"
        elif selector_to_sink and not mint_guard:
            status = "untyped_asset_selector_to_config_value_flow_review_required"
        elif selector_to_sink and mint_guard:
            status = "selector_config_value_flow_with_anchor_identity_guard_observed_manual_validation_required"
        elif config_to_sink:
            status = "config_to_value_flow_observed_actual_mint_source_unresolved"
        elif actual_mint_seen and config_mint_seen:
            status = "identity_sources_seen_no_config_value_sink_flow"
        else:
            status = "insufficient_identity_dataflow_evidence"

        labels_by_var = []
        for info in infos:
            for name in sorted(info["known"]):
                labels = sorted(taints.get((info["key"], name), set()))
                if labels:
                    labels_by_var.append({"function": info["fn"]["name"], "variable": name, "labels": labels})

        all_evidence = {
            "sources": dict(seed_evidence),
            "variable_provenance": labels_by_var,
            "guards": guards,
            "sinks": sinks,
            "helper_edges": helper_edges,
            "cross_instruction_state_field_links": state_field_links,
            "anchor_context_constraints": anchor_context,
            "flows": {
                "actual_mint_seen": actual_mint_seen,
                "asset_selector_seen": asset_selector_seen,
                "selector_to_config_value_sink": selector_to_sink,
                "config_mint_seen": config_mint_seen,
                "config_to_value_sink": config_to_sink,
                "amount_to_sink": amount_to_sink,
                "oracle_value_to_sink": oracle_to_sink,
                "decimals_to_sink": decimals_to_sink,
                "mint_binding_guard_observed": mint_guard,
                "oracle_binding_guard_observed": oracle_guard,
            },
        }
        review_reasons = []
        if actual_mint_seen:
            review_reasons.append("actual token-account Mint provenance was identified in the reachable source flow")
        else:
            review_reasons.append("actual token-account Mint provenance was not identified; absence is not proof of a missing check")
        if config_mint_seen:
            review_reasons.append("config/reserve/market Mint provenance was identified")
        if asset_selector_seen:
            review_reasons.append("an untyped or numeric asset selector was identified in the analyzed path")
        if selector_to_sink:
            review_reasons.append("selector-derived configuration reaches a valuation or financial sink; verify selector-to-Mint binding")
        if config_to_sink:
            review_reasons.append("configuration-derived data reaches a valuation, health, borrow, liquidation, or withdrawal sink")
        if mint_guard:
            review_reasons.append("an actual-Mint-to-config-Mint comparison pattern was observed; validate its runtime semantics")
        elif actual_mint_seen and config_mint_seen and config_to_sink:
            review_reasons.append("no matching actual-Mint-to-config-Mint guard was observed in the analyzed scope")
        if not sinks:
            review_reasons.append("no recognized valuation/borrow/liquidation/withdrawal sink was found in the analyzed call graph")

        findings.append({
            "file": str(path),
            "function": root["name"],
            "line": root["line"],
            "analysis_type": "rust_asset_identity_dataflow_v0.5",
            "dataflow_status": status,
            "review_priority": "HIGH_REVIEW" if status in {
                "potential_unbound_mint_to_config_value_flow_review_required",
                "untyped_asset_selector_to_config_value_flow_review_required",
            } else (
                "MEDIUM_REVIEW" if config_to_sink or actual_mint_seen else "LOW_REVIEW"
            ),
            "scope": "same-file helper call graph with conservative argument/parameter and return propagation, structured Anchor account-constraint mapping, selector provenance, and cross-instruction state-field reference mapping",
            "max_depth": max_depth,
            "summary": "; ".join(review_reasons),
            "evidence": all_evidence,
            "limitations": (
                "Heuristic source analysis only. Anchor account attributes are parsed structurally but not macro-expanded; this is not compiler-grade def-use analysis. Rust traits, macros, dynamic dispatch, "
                "complex generics, generated code, CPI semantics, account deserialization, PDA derivations and cross-crate "
                "aliasing may be missed. Cross-instruction state links use struct/field names and do not prove same-account "
                "identity or value preservation. Pattern presence is not proof of an enforced runtime invariant; missing patterns "
                "are not proof of exploitability. Source-to-deployment equivalence is not established."
            ),
        })
    return findings


def write_reports(findings: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "identity_dataflow.json"
    csv_path = out_dir / "identity_dataflow.csv"
    json_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    fields = ["file", "function", "line", "analysis_type", "dataflow_status", "review_priority", "scope", "max_depth", "summary", "limitations"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)

    review_dir = out_dir / "identity_dataflow_review"
    review_dir.mkdir(parents=True, exist_ok=True)
    for index, finding in enumerate(findings, 1):
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{finding['function']}_{finding['line']}")
        evidence = finding.get("evidence", {})
        content = [
            f"# Asset identity dataflow review: {finding['function']}",
            "",
            f"- File: `{finding['file']}`",
            f"- Line: {finding['line']}",
            f"- Status: `{finding['dataflow_status']}`",
            f"- Priority: `{finding['review_priority']}`",
            f"- Scope: {finding['scope']}",
            "",
            "## Summary",
            "",
            finding["summary"],
            "",
            "## Evidence",
            "",
            "```json",
            json.dumps(evidence, indent=2, ensure_ascii=False),
            "```",
            "",
            "## Limitations",
            "",
            finding["limitations"],
            "",
            "## Required manual validation",
            "",
            "1. Confirm the source token account's owner and Mint from the actual instruction accounts.",
            "2. Confirm the selected config/PDA and the exact Mint field it stores.",
            "3. Verify the equality guard executes before any collateral credit or borrow-capacity update.",
            "4. Trace the oracle account owner/feed identity and the decimals source.",
            "5. Verify the same validated asset identity is used in deposit, borrow, liquidation, withdraw and redeem paths.",
            "6. Match the reviewed source commit to the deployed program before making a mainnet conclusion.",
            "",
            "This report is a static triage artifact, not a confirmed vulnerability or a security certification.",
        ]
        (review_dir / f"{index:04d}_{slug}.md").write_text("\n".join(content), encoding="utf-8")
    print(f"[DATAFLOW] {len(findings)} instruction-flow reviews")
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")
