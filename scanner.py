#!/usr/bin/env python3
"""Solana collateral identity scanner v0.5.0.

Read-only static triage for Anchor/Rust source and on-chain Anchor IDLs.
It does not sign transactions, submit instructions, borrow assets, or exploit live programs.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
import zlib
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

VERSION = "0.5.0"
SKIP_DIRS = {".git", "target", "node_modules", "vendor", "build", "dist", ".anchor"}
RUST_SUFFIXES = {".rs"}
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PDA_MARKER = b"ProgramDerivedAddress"
ED25519_P = 2**255 - 19
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P

PATTERNS = {
    "financial": re.compile(r"\b(collateral|borrow|deposit|withdraw|loan|ltv|liquidat|health_factor|repay|redeem|reserve)\w*\b", re.I),
    "asset_selector": re.compile(r"\b(asset_id|asset_identifier|asset_index|collateral_id|reserve_index|market_info|asset_config|config_index|reserve_key)\b", re.I),
    "token_transfer": re.compile(r"\b(transfer|transfer_checked|transfer_tokens|token_interface|spl_token|invoke_signed)\b", re.I),
    "oracle_price": re.compile(r"\b(oracle|price_feed|price|pyth|switchboard|feed_account)\w*\b", re.I),
    "decimals_scale": re.compile(r"\b(decimals|pow10|scale|checked_pow|ui_amount|decimal_multiplier)\b|10\s*(?:u64|u128|i64|i128)?\s*\.\s*pow", re.I),
    "dynamic_accounts": re.compile(r"\b(remaining_accounts|UncheckedAccount|AccountInfo)\b", re.I),
    "mint_reference": re.compile(r"\b(mint|token_mint|collateral_mint|reserve_mint)\b", re.I),
    "config_reference": re.compile(r"\b(config|asset_config|collateral_config|reserve|market)\b", re.I),
    "borrow_limit": re.compile(r"\b(borrow_limit|max_borrow|borrow_capacity|available_borrow|health_factor|ltv|loan_to_value)\b", re.I),
    "value_calculation": re.compile(r"\b(collateral_value|asset_value|token_value|usd_value|value_usd|total_collateral|account_value)\b", re.I),
}

# These patterns intentionally require mint-like references on both sides or an
# Anchor account constraint involving a mint. Generic require_eq! is not enough.
MINT_BINDING_PATTERNS = [
    re.compile(r"require_keys_eq!\s*\([^;]{0,500}mint[^;]{0,500}mint", re.I | re.S),
    re.compile(r"require_eq!\s*\([^;]{0,500}mint[^;]{0,500}mint", re.I | re.S),
    re.compile(r"has_one\s*=\s*\w*mint\w*", re.I),
    re.compile(r"constraint\s*=\s*[^\n,;]{0,250}mint[^\n,;]{0,250}==[^\n,;]{0,250}mint", re.I),
    re.compile(r"(?:token|associated_token)::mint\s*=\s*\w+", re.I),
    re.compile(r"seeds\s*=\s*\[[^]]{0,300}\bmint\b", re.I | re.S),
    re.compile(r"address\s*=\s*[^,\n]{0,250}\bmint\b", re.I),
    re.compile(r"\.mint\s*==\s*[^;\n]{0,250}\.mint", re.I),
    re.compile(r"mint[^;\n]{0,250}\.key\(\)\s*==\s*[^;\n]{0,250}mint", re.I),
]
ORACLE_BINDING_PATTERNS = [
    re.compile(r"require_keys_eq!\s*\([^;]{0,500}oracle[^;]{0,500}oracle", re.I | re.S),
    re.compile(r"has_one\s*=\s*\w*oracle\w*", re.I),
    re.compile(r"\.oracle\s*==\s*[^;\n]{0,250}\.key\(\)", re.I),
]

CONTROL_CALLS = {
    "if", "while", "for", "match", "loop", "return", "Some", "None", "Ok", "Err",
    "require", "require_eq", "require_keys_eq", "msg", "assert", "assert_eq", "vec",
    "format", "panic", "unwrap", "expect", "map", "and_then", "ok_or", "ok_or_else",
}

WEIGHTS = {
    "financial": 1,
    "asset_selector": 3,
    "token_transfer": 2,
    "oracle_price": 2,
    "decimals_scale": 2,
    "dynamic_accounts": 2,
    "mint_reference": 1,
    "config_reference": 1,
    "borrow_limit": 2,
    "value_calculation": 2,
}


def strip_comments_and_strings(source: str) -> str:
    """Replace comments and string/char literal contents with spaces, preserving offsets."""
    out = list(source)
    i = 0
    n = len(source)
    state = "code"
    raw_hashes = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            if ch == '"':
                out[i] = " "
                i += 1
                state = "string"
                continue
            if ch == "'":
                # Lifetimes such as 'info are not character literals.
                if i + 1 < n and (source[i + 1].isalpha() or source[i + 1] == "_"):
                    i += 1
                    continue
                out[i] = " "
                i += 1
                state = "char"
                continue
            if ch == "r" and (nxt == '"' or (nxt == "#")):
                j = i + 1
                while j < n and source[j] == "#":
                    j += 1
                if j < n and source[j] == '"':
                    raw_hashes = j - (i + 1)
                    for k in range(i, j + 1):
                        out[k] = " "
                    i = j + 1
                    state = "raw_string"
                    continue
            i += 1
            continue
        if state == "line_comment":
            if ch == "\n":
                state = "code"
            else:
                out[i] = " "
            i += 1
            continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
            else:
                if ch != "\n":
                    out[i] = " "
                i += 1
            continue
        if state == "string":
            if ch == "\\":
                out[i] = " "
                if i + 1 < n:
                    if source[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                else:
                    i += 1
                continue
            if ch == '"':
                out[i] = " "
                i += 1
                state = "code"
            else:
                if ch != "\n":
                    out[i] = " "
                i += 1
            continue
        if state == "char":
            if ch == "\\":
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                    i += 2
                else:
                    i += 1
                continue
            if ch == "'":
                out[i] = " "
                i += 1
                state = "code"
            else:
                if ch != "\n":
                    out[i] = " "
                i += 1
            continue
        if state == "raw_string":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, i):
                for k in range(i, i + len(terminator)):
                    out[k] = " "
                i += len(terminator)
                state = "code"
            else:
                if ch != "\n":
                    out[i] = " "
                i += 1
    return "".join(out)


def extract_anchor_contexts(source: str) -> dict[str, dict[str, str]]:
    """Extract Anchor #[derive(Accounts)] structs so constraints can be reviewed with handlers."""
    clean = strip_comments_and_strings(source)
    struct_re = re.compile(
        r"#\s*\[\s*derive\s*\([^]]*\bAccounts\b[^]]*\)\s*\]"
        r"(?:\s*#\s*\[[^]]*\]\s*)*"
        r"\s*(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+([A-Za-z_]\w*)"
    )
    contexts: dict[str, dict[str, str]] = {}
    for match in struct_re.finditer(clean):
        brace = clean.find("{", match.end())
        if brace < 0:
            continue
        depth = 0
        end = None
        for idx in range(brace, len(clean)):
            if clean[idx] == "{":
                depth += 1
            elif clean[idx] == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        if end is not None:
            contexts[match.group(1)] = {"body": source[match.start():end], "clean_body": clean[match.start():end]}
    return contexts


def extract_functions(source: str, path: Path) -> list[dict[str, Any]]:
    """Extract Rust function bodies using sanitized source and balanced braces."""
    clean = strip_comments_and_strings(source)
    contexts = extract_anchor_contexts(source)
    fn_re = re.compile(r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\b")
    functions = []
    for match in fn_re.finditer(clean):
        brace = clean.find("{", match.end())
        semi = clean.find(";", match.end())
        if brace < 0 or (semi >= 0 and semi < brace):
            continue
        depth = 0
        end = None
        for idx in range(brace, len(clean)):
            if clean[idx] == "{":
                depth += 1
            elif clean[idx] == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        if end is None:
            continue
        start = match.start()
        line = source.count("\n", 0, start) + 1
        signature = clean[start:brace]
        context_match = re.search(r"Context\s*<\s*(?:'[^,>]+\s*,\s*)?([A-Za-z_]\w*)", signature)
        context_name = context_match.group(1) if context_match else None
        context = contexts.get(context_name, {}) if context_name else {}
        functions.append({
            "name": match.group(1),
            "line": line,
            "file": str(path),
            "body": source[start:end],
            "clean_body": clean[start:end],
            "context_name": context_name,
            "context_body": context.get("body", ""),
            "context_clean": context.get("clean_body", ""),
        })
    return functions


def function_calls(clean_body: str) -> set[str]:
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*!?\s*\(", clean_body))
    return {name for name in calls if name not in CONTROL_CALLS}


def has_any(patterns: Iterable[re.Pattern], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def function_signals(clean_body: str) -> dict[str, bool]:
    signals = {name: bool(pattern.search(clean_body)) for name, pattern in PATTERNS.items()}
    signals["mint_binding_check"] = has_any(MINT_BINDING_PATTERNS, clean_body)
    signals["oracle_binding_check"] = has_any(ORACLE_BINDING_PATTERNS, clean_body)
    return signals


def build_call_graph(functions: list[dict[str, Any]]) -> tuple[dict[str, set[str]], dict[str, list[dict[str, Any]]]]:
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fn in functions:
        by_name[fn["name"]].append(fn)
    graph: dict[str, set[str]] = {}
    for fn in functions:
        calls = function_calls(fn["clean_body"])
        graph[fn["file"] + "::" + fn["name"] + "@" + str(fn["line"])] = {
            name for name in calls if name in by_name
        }
    return graph, by_name


def reachable_functions(root: dict[str, Any], by_name: dict[str, list[dict[str, Any]]], max_depth: int = 3) -> list[dict[str, Any]]:
    found = []
    seen = {(root["file"], root["name"], root["line"])}
    queue = deque([(root, 0)])
    while queue:
        current, depth = queue.popleft()
        if current is not root:
            found.append(current)
        if depth >= max_depth:
            continue
        for name in function_calls(current["clean_body"]):
            children = by_name.get(name, [])
            same_file = [child for child in children if child["file"] == current["file"]]
            if same_file:
                children = same_file
            elif len(children) > 1:
                # Avoid merging unrelated helpers that happen to share a Rust name.
                children = []
            for child in children:
                key = (child["file"], child["name"], child["line"])
                if key not in seen:
                    seen.add(key)
                    queue.append((child, depth + 1))
    return found


def analyze_function(root: dict[str, Any], by_name: dict[str, list[dict[str, Any]]], max_depth: int = 3) -> dict[str, Any] | None:
    related = [root] + reachable_functions(root, by_name, max_depth=max_depth)
    per_fn = []
    aggregate = defaultdict(bool)
    for fn in related:
        signals = function_signals(fn["clean_body"])
        for key, value in signals.items():
            aggregate[key] = aggregate[key] or value
        per_fn.append({"name": fn["name"], "file": fn["file"], "line": fn["line"], "signals": signals})
    if root.get("context_clean"):
        context_signals = function_signals(root["context_clean"])
        for key, value in context_signals.items():
            aggregate[key] = aggregate[key] or value
        per_fn.append({"name": f"Accounts::{root.get('context_name')}", "file": root["file"],
                       "line": root["line"], "signals": context_signals})

    # Do not treat generic validation as a mint/config binding proof.
    candidate = aggregate["financial"] and aggregate["asset_selector"] and (
        aggregate["token_transfer"] or aggregate["oracle_price"] or aggregate["decimals_scale"]
    )
    if not candidate:
        return None

    score = sum(WEIGHTS.get(key, 0) for key, value in aggregate.items() if value)
    if aggregate["mint_binding_check"]:
        score -= 3
    if aggregate["oracle_binding_check"]:
        score -= 1

    if score >= 12 and not aggregate["mint_binding_check"]:
        priority = "HIGH_REVIEW"
    elif score >= 8:
        priority = "MEDIUM_REVIEW"
    else:
        priority = "LOW_REVIEW"

    evidence = []
    for item in per_fn:
        active = [key for key, value in item["signals"].items() if value]
        if active:
            evidence.append({"function": item["name"], "file": item["file"], "line": item["line"], "signals": active})

    root_clean = root["clean_body"]
    calls = sorted(name for name in function_calls(root_clean) if name != root["name"])
    reasons = []
    if aggregate["asset_selector"]:
        reasons.append("asset/config selector appears in the instruction call graph")
    if aggregate["token_transfer"]:
        reasons.append("SPL token movement appears in the instruction call graph")
    if aggregate["oracle_price"]:
        reasons.append("oracle/price handling appears in the instruction call graph")
    if aggregate["decimals_scale"]:
        reasons.append("decimal or unit scaling appears in the instruction call graph")
    if aggregate["borrow_limit"] or aggregate["value_calculation"]:
        reasons.append("collateral value or borrow-capacity calculation appears in the call graph")
    if aggregate["dynamic_accounts"]:
        reasons.append("dynamic or loosely typed account access appears in the call graph")
    if aggregate["mint_binding_check"]:
        reasons.append("mint-binding-like check found; manually confirm it binds the supplied mint to the selected config")
    else:
        reasons.append("no mint-to-config binding pattern found in the reachable functions; this is not proof of absence")
    if aggregate["oracle_price"] and not aggregate["oracle_binding_check"]:
        reasons.append("no obvious oracle-to-config binding pattern found in the reachable functions")

    # This is deliberately a heuristic triage label, not a security verdict.
    # Seeing both patterns is evidence to review, not proof that the complete
    # runtime path is safe. Missing patterns are likewise not proof of a bug.
    if aggregate["mint_binding_check"] and aggregate["oracle_binding_check"]:
        identity_assessment = "binding_patterns_present_manual_validation_required"
    elif not aggregate["mint_binding_check"] and aggregate["oracle_price"]:
        identity_assessment = "mint_binding_pattern_missing_review_required"
    elif aggregate["mint_binding_check"] and aggregate["oracle_price"] and not aggregate["oracle_binding_check"]:
        identity_assessment = "oracle_binding_pattern_missing_review_required"
    else:
        identity_assessment = "insufficient_static_evidence_manual_review_required"

    snippet = "\n".join(root["body"].splitlines()[:35])
    if root.get("context_body"):
        snippet += "\n\n// Anchor account context: " + str(root.get("context_name")) + "\n" + "\n".join(root["context_body"].splitlines()[:45])
    return {
        "file": root["file"],
        "function": root["name"],
        "line": root["line"],
        "score": score,
        "priority": priority,
        "signals": ",".join(key for key, value in aggregate.items() if value),
        "reasons": "; ".join(reasons),
        "direct_calls": ",".join(calls),
        "related_functions": json.dumps(evidence, ensure_ascii=False),
        "snippet": snippet,
        "analysis_type": "rust_interprocedural_heuristic",
        "identity_assessment": identity_assessment,
        "assessment_limit": "Pattern-based triage only; does not prove runtime account constraints, value flow, or deployment equivalence.",
    }


def scan_rust(path: Path, max_depth: int = 3) -> list[dict[str, Any]]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    functions = extract_functions(source, path)
    _, by_name = build_call_graph(functions)
    results = []
    # Lazy import avoids a module cycle: protocol_analysis reuses this module's
    # source sanitizer and Anchor struct extractor.
    try:
        from protocol_analysis import parse_anchor_accounts
        anchor_contexts = parse_anchor_accounts(source)
    except Exception:
        anchor_contexts = {}
    for fn in functions:
        result = analyze_function(fn, by_name, max_depth=max_depth)
        if result:
            context = anchor_contexts.get(fn.get("context_name") or "", {})
            if context:
                result["anchor_context_constraint_map"] = context
                if context.get("mint_guard"):
                    result["signals"] = ",".join(filter(None, [result.get("signals", ""), "anchor_struct_mint_binding"]))
                    result["identity_assessment"] = "anchor_accounts_struct_mint_identity_chain_observed_manual_validation_required"
                    result["reasons"] = str(result.get("reasons", "")) + "; structured Anchor account attributes link the token Mint to the config identity"
                    result["score"] = max(0, int(result.get("score", 0)) - 3)
                if context.get("oracle_guard"):
                    result["signals"] = ",".join(filter(None, [result.get("signals", ""), "anchor_struct_oracle_binding"]))
                    result["reasons"] = str(result.get("reasons", "")) + "; structured Anchor account attributes link the oracle account to config identity"
                if result.get("score", 0) >= 12 and not context.get("mint_guard"):
                    result["priority"] = "HIGH_REVIEW"
                elif result.get("score", 0) >= 8:
                    result["priority"] = "MEDIUM_REVIEW"
                else:
                    result["priority"] = "LOW_REVIEW"
            results.append(result)
    return results


def recursive_idl_accounts(items: Any) -> list[str]:
    names = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        names.append(str(item.get("name", "")))
        names.extend(recursive_idl_accounts(item.get("accounts", [])))
    return names


def scan_idl(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [{"file": str(path), "function": "IDL_PARSE_ERROR", "line": 0, "score": 0,
                 "priority": "ERROR", "signals": "invalid_json", "reasons": str(exc),
                 "direct_calls": "", "related_functions": "[]", "snippet": "", "analysis_type": "idl"}]
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("instructions"), list):
        instructions = data.get("instructions", [])
    else:
        # Codama IDL v1 wraps instructions under program.instructions.
        instructions = data.get("program", {}).get("instructions", []) if isinstance(data.get("program"), dict) else []
    results = []
    for ix in instructions:
        if not isinstance(ix, dict):
            continue
        name = str(ix.get("name", "unknown"))
        if not re.search(r"deposit|borrow|collateral|withdraw|repay|liquidat|redeem|refresh_reserve", name, re.I):
            continue
        accounts = recursive_idl_accounts(ix.get("accounts", []))
        raw_args = ix.get("args", ix.get("arguments", []))
        args = [str(a.get("name", "")) for a in raw_args if isinstance(a, dict)]
        joined = " ".join(accounts + args).lower()
        roles = []
        for role, terms in {
            "mint": ("mint",), "token_account": ("token", "source", "destination", "vault"),
            "asset_config": ("asset", "reserve", "config", "market", "collateral"),
            "oracle": ("oracle", "pyth", "switchboard", "feed"),
        }.items():
            if any(term in joined for term in terms):
                roles.append(role)
        if roles:
            results.append({
                "file": str(path), "function": f"IDL::{name}", "line": 0,
                "score": 0, "priority": "IDL_REVIEW", "signals": ",".join(roles),
                "reasons": "financial instruction exposes asset-related accounts/args; IDL does not prove runtime account constraints",
                "direct_calls": "", "related_functions": "[]",
                "snippet": "accounts=" + ",".join(accounts) + " args=" + ",".join(args),
                "analysis_type": "idl",
            })
    return results


def iter_files(root: Path):
    if not root.exists():
        return
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in RUST_SUFFIXES or path.name.endswith(".idl.json") or path.name == "idl.json":
            yield path


def b58decode(value: str) -> bytes:
    number = 0
    for char in value:
        if char not in B58_ALPHABET:
            raise ValueError(f"invalid base58 character: {char}")
        number = number * 58 + B58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    pad = len(value) - len(value.lstrip("1"))
    return b"\x00" * pad + raw


def b58encode(raw: bytes) -> str:
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    number = int.from_bytes(raw, "big")
    chars = ""
    while number:
        number, rem = divmod(number, 58)
        chars = B58_ALPHABET[rem] + chars
    return "1" * zeros + (chars or ("" if zeros else "1"))


def is_ed25519_point(encoded: bytes) -> bool:
    if len(encoded) != 32:
        return False
    y_full = int.from_bytes(encoded, "little")
    y = y_full & ((1 << 255) - 1)
    if y >= ED25519_P:
        return False
    y2 = (y * y) % ED25519_P
    numerator = (y2 - 1) % ED25519_P
    denominator = (ED25519_D * y2 + 1) % ED25519_P
    x2 = numerator * pow(denominator, ED25519_P - 2, ED25519_P) % ED25519_P
    x = pow(x2, (ED25519_P + 3) // 8, ED25519_P)
    if (x * x - x2) % ED25519_P != 0:
        sqrt_m1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)
        x = x * sqrt_m1 % ED25519_P
    if (x * x - x2) % ED25519_P != 0:
        return False
    sign = y_full >> 255
    if x == 0 and sign == 1:
        return False
    return True


def find_program_address(seeds: list[bytes], program_id: str) -> tuple[str, int]:
    program_bytes = b58decode(program_id)
    if len(program_bytes) != 32:
        raise ValueError("program id must decode to 32 bytes")
    if any(len(seed) > 32 for seed in seeds):
        raise ValueError("PDA seed exceeds 32 bytes")
    for bump in range(255, -1, -1):
        digest = hashlib.sha256(b"".join(seeds + [bytes([bump]), program_bytes, PDA_MARKER])).digest()
        if not is_ed25519_point(digest):
            return b58encode(digest), bump
    raise RuntimeError("unable to find PDA bump")


def rpc_call(rpc_url: str, method: str, params: list[Any], timeout: int = 25) -> dict[str, Any]:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    return data.get("result", {})


def account_data(rpc_url: str, pubkey: str) -> tuple[bytes, dict[str, Any]]:
    result = rpc_call(rpc_url, "getAccountInfo", [pubkey, {"encoding": "base64", "commitment": "finalized"}])
    value = result.get("value")
    if not value:
        raise RuntimeError(f"account not found: {pubkey}")
    data = value.get("data")
    if not isinstance(data, list) or not data:
        raise RuntimeError(f"account has no base64 data: {pubkey}")
    return base64.b64decode(data[0]), {"context_slot": result.get("context", {}).get("slot"),
                                      "owner": value.get("owner"), "executable": value.get("executable"),
                                      "lamports": value.get("lamports")}


def decode_anchor_idl(raw: bytes) -> dict[str, Any]:
    # Legacy Anchor IdlAccount: 8-byte discriminator, 32-byte authority, 4-byte
    # compressed payload length, followed by zlib-compressed JSON bytes.
    if len(raw) < 44:
        raise ValueError("IDL account data is shorter than the Anchor account header")
    compressed_len = int.from_bytes(raw[40:44], "little")
    payload = raw[44:44 + compressed_len] if compressed_len and len(raw) >= 44 + compressed_len else raw[44:]
    candidates = []
    try:
        candidates.append(zlib.decompress(payload))
    except zlib.error:
        pass
    try:
        candidates.append(zlib.decompress(payload, -zlib.MAX_WBITS))
    except zlib.error:
        pass
    candidates.append(payload)
    for candidate in candidates:
        try:
            parsed = json.loads(candidate.decode("utf-8"))
            if isinstance(parsed, dict) and ("instructions" in parsed or "program" in parsed):
                return parsed
        except Exception:
            continue
    raise ValueError("could not decode compressed Anchor IDL JSON")


def anchor_legacy_idl_address(program_id: str) -> str:
    # Legacy Anchor does NOT use a PDA with [b"anchor:idl"] directly.
    # It derives a program signer PDA with empty seeds, then create_with_seed(base,
    # "anchor:idl", owner=program_id).
    program_bytes = b58decode(program_id)
    if len(program_bytes) != 32:
        raise ValueError("program id must decode to 32 bytes")
    program_signer, _ = find_program_address([], program_id)
    address = hashlib.sha256(b58decode(program_signer) + b"anchor:idl" + program_bytes).digest()
    return b58encode(address)


def fetch_anchor_idl_legacy(rpc_url: str, program_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    idl_address = anchor_legacy_idl_address(program_id)
    raw, meta = account_data(rpc_url, idl_address)
    if meta.get("owner") != program_id:
        raise RuntimeError(f"legacy IDL account owner mismatch: expected {program_id}, got {meta.get('owner')}")
    idl = decode_anchor_idl(raw)
    meta.update({"idl_account": idl_address, "idl_account_bytes": len(raw),
                 "idl_authority": b58encode(raw[8:40]), "idl_provider": "legacy_anchor_rpc"})
    return idl, meta


def fetch_idl_explorer(program_id: str, cluster: str = "mainnet-beta") -> tuple[dict[str, Any], dict[str, Any]]:
    # The Solana Foundation IDL Explorer resolves canonical PMP, fndn fallback PMP,
    # then legacy Anchor IDL. This avoids reimplementing the evolving PMP account layout.
    from urllib.parse import urlencode
    query = urlencode({"programId": program_id, "cluster": cluster})
    url = "https://idl-one.vercel.app/api/idl?" + query
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"solana-collateral-scanner/{VERSION}"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    content = payload.get("content")
    if isinstance(content, str):
        idl = json.loads(content)
    elif isinstance(content, dict):
        idl = content
    else:
        raise ValueError("IDL Explorer response has no JSON content")
    has_anchor_instructions = isinstance(idl, dict) and isinstance(idl.get("instructions"), list)
    has_codama_instructions = isinstance(idl, dict) and isinstance(idl.get("program"), dict) and isinstance(idl["program"].get("instructions"), list)
    if not (has_anchor_instructions or has_codama_instructions):
        raise ValueError("IDL Explorer returned an unsupported IDL shape")
    return idl, {"idl_provider": payload.get("type", "idl_explorer"), "idl_address": payload.get("address"),
                  "idl_authority": payload.get("authority"), "idl_endpoint": url}


def fetch_any_idl(rpc_url: str, program_id: str, cluster: str = "mainnet-beta") -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        return fetch_idl_explorer(program_id, cluster=cluster)
    except Exception as explorer_error:
        try:
            idl, meta = fetch_anchor_idl_legacy(rpc_url, program_id)
            meta["idl_explorer_error"] = str(explorer_error)
            return idl, meta
        except Exception as anchor_error:
            raise RuntimeError(f"IDL Explorer failed ({explorer_error}); legacy Anchor fallback failed ({anchor_error})")


def fetch_program_metadata(rpc_url: str, program_id: str) -> dict[str, Any]:
    raw, meta = account_data(rpc_url, program_id)
    meta["program_id"] = program_id
    if not meta.get("executable"):
        meta["status"] = "not_executable"
        return meta
    loader = meta.get("owner")
    upgradeable_loader = "BPFLoaderUpgradeab1e11111111111111111111111"
    if loader != upgradeable_loader:
        meta["status"] = "executable_non_upgradeable_or_unknown_loader"
        meta["program_data"] = None
        return meta
    if len(raw) < 36:
        meta["status"] = "truncated_program_account"
        return meta
    # UpgradeableLoaderState::Program has enum tag 2 then ProgramData pubkey.
    state_tag = int.from_bytes(raw[:4], "little")
    if state_tag != 2:
        meta["status"] = f"unexpected_loader_state_{state_tag}"
        return meta
    programdata = b58encode(raw[4:36])
    pd_raw, pd_meta = account_data(rpc_url, programdata)
    pd_tag = int.from_bytes(pd_raw[:4], "little") if len(pd_raw) >= 4 else -1
    if pd_tag != 3 or len(pd_raw) < 45:
        meta["status"] = "unexpected_programdata_state"
        meta["program_data"] = programdata
        return meta
    slot = int.from_bytes(pd_raw[4:12], "little")
    has_authority = pd_raw[12]
    # Loader-v3 reserves a fixed 45-byte ProgramData header even when the
    # optional upgrade authority is None. SBF payload always starts at offset 45.
    offset = 45
    authority = b58encode(pd_raw[13:45]) if has_authority == 1 else None
    binary = pd_raw[offset:]
    meta.update({
        "status": "upgradeable_program",
        "program_data": programdata,
        "program_data_slot": slot,
        "upgrade_authority": authority,
        "program_data_payload_sha256": hashlib.sha256(binary).hexdigest(),
        "program_data_payload_bytes": len(binary),
        "hash_note": "Hash covers the raw ProgramData payload after loader metadata; allocated trailing padding may be included and this is not a source-verification result.",
        "program_data_context_slot": pd_meta.get("context_slot"),
    })
    return meta


def safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "target"


def clone_targets(targets_file: Path, repo_root: Path):
    targets = json.loads(targets_file.read_text(encoding="utf-8"))
    repo_root.mkdir(parents=True, exist_ok=True)
    for target in targets:
        repo = target.get("repo")
        if not repo:
            print(f"[SKIP] {target['name']}: no public source URL configured")
            continue
        dest = repo_root / safe_slug(target["name"])
        if (dest / ".git").exists():
            print(f"[EXISTS] {target['name']}: {dest}")
            continue
        print(f"[CLONE] {target['name']}: {repo}")
        try:
            subprocess.run(["git", "clone", "--depth", "1", repo, str(dest)], check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"[ERROR] {target['name']}: {exc}")


def git_metadata(repo: Path) -> dict[str, Any]:
    if not (repo / ".git").exists():
        return {}
    def run(args: list[str]) -> str | None:
        try:
            return subprocess.check_output(["git", "-C", str(repo)] + args, stderr=subprocess.DEVNULL, text=True).strip()
        except Exception:
            return None
    return {"git_commit": run(["rev-parse", "HEAD"]), "git_remote": run(["config", "--get", "remote.origin.url"]),
            "git_dirty": bool(run(["status", "--porcelain"]))}


def generate_review_files(results: list[dict[str, Any]], out_dir: Path):
    review_dir = out_dir / "review"
    review_dir.mkdir(parents=True, exist_ok=True)
    for index, item in enumerate(results, start=1):
        if item.get("analysis_type") == "idl":
            title = "IDL review"
        else:
            title = str(item.get("priority", "REVIEW"))
        filename = f"{index:04d}_{safe_slug(str(item.get('function', 'candidate')))}.md"
        content = [
            f"# {title}: {item.get('function')}", "",
            f"- File: `{item.get('file')}`", f"- Line: `{item.get('line')}`",
            f"- Score: `{item.get('score')}`", f"- Signals: `{item.get('signals')}`", "",
            "## Why this was flagged", "", str(item.get("reasons", "")), "",
            "## Related functions", "", "```json", str(item.get("related_functions", "[]")), "```", "",
            "## Source snippet", "", "```rust", str(item.get("snippet", "")), "```", "",
            "## Required manual checks", "",
            "1. Identify the exact SPL Mint for the user source account and vault destination account.",
            "2. Trace the selected collateral/reserve config PDA and prove it is bound to that Mint.",
            "3. Verify the oracle account owner, feed identity, and config-to-oracle binding.",
            "4. Compare Mint decimals with every decimal value used in normalization.",
            "5. Trace the calculated value into health, LTV, and borrow capacity.",
            "6. Match this source commit to the deployed program binary before making a mainnet claim.", "",
            "## Local-only invariant tests", "",
            "- Valid Mint A + Config A + Oracle A should succeed.",
            "- Mint A + Config B should be rejected before collateral value is credited.",
            "- Mint A with a different-decimals Config B must not change the credited value.",
            "- Oracle B supplied for Config A must be rejected.",
            "- A failed deposit must leave collateral and borrow capacity unchanged.",
            "",
            "This is a static-review lead, not a confirmed vulnerability. Do not test against live user funds.",
        ]
        (review_dir / filename).write_text("\n".join(content), encoding="utf-8")


def write_reports(results: list[dict[str, Any]], out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "findings.json"
    csv_path = out_dir / "findings.csv"
    json_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    fields = ["file", "function", "line", "score", "priority", "signals", "reasons", "direct_calls", "related_functions", "analysis_type", "identity_assessment", "assessment_limit", "snippet"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    print(f"[DONE] {len(results)} review candidates")
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")


def fetch_targets(targets_file: Path, rpc_url: str, idl_dir: Path, metadata_file: Path,
                  fetch_idls: bool = True, fetch_metadata: bool = True, cluster: str = "mainnet-beta"):
    targets = json.loads(targets_file.read_text(encoding="utf-8"))
    idl_dir.mkdir(parents=True, exist_ok=True)
    metadata = []
    for target in targets:
        program_id = target.get("program_id")
        if not program_id:
            continue
        name = target.get("name", program_id)
        slug = safe_slug(name)
        print(f"[RPC] {name} ({program_id})")
        entry: dict[str, Any] = {"name": name, "program_id": program_id}
        if fetch_idls:
            try:
                idl, idl_meta = fetch_any_idl(rpc_url, program_id, cluster=cluster)
                idl_path = idl_dir / f"{slug}.idl.json"
                idl_path.write_text(json.dumps(idl, indent=2, ensure_ascii=False), encoding="utf-8")
                entry["idl"] = {"status": "fetched", "path": str(idl_path), **idl_meta}
                print(f"  [OK] IDL ({idl_meta.get('idl_provider')}): {idl_path}")
            except Exception as exc:
                entry["idl"] = {"status": "unavailable", "error": str(exc)}
                print(f"  [WARN] IDL unavailable: {exc}")
        if fetch_metadata:
            try:
                entry["deployment"] = fetch_program_metadata(rpc_url, program_id)
                print(f"  [OK] program metadata: {entry['deployment'].get('status')}")
            except Exception as exc:
                entry["deployment"] = {"status": "unavailable", "error": str(exc)}
                print(f"  [WARN] deployment metadata unavailable: {exc}")
        metadata.append(entry)
    metadata_file.parent.mkdir(parents=True, exist_ok=True)
    metadata_file.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Read-only Solana collateral identity scanner v0.5.0")
    parser.add_argument("--version", action="version", version=f"Solana Collateral Scanner {VERSION}")
    parser.add_argument("--root", default="repos", help="Directory containing checked-out Rust source")
    parser.add_argument("--out", default="reports", help="Output directory")
    parser.add_argument("--clone", action="store_true", help="Clone public source repositories from targets.json")
    parser.add_argument("--targets", default="targets.json", help="Target list JSON")
    parser.add_argument("--fetch-idls", action="store_true", help="Fetch current IDLs via Solana IDL Explorer (PMP/fndn/Anchor fallback)")
    parser.add_argument("--fetch-program-metadata", action="store_true", help="Fetch executable/ProgramData metadata and deployed binary hash")
    parser.add_argument("--cluster", choices=["mainnet-beta", "devnet"], default="mainnet-beta", help="Cluster for IDL Explorer")
    parser.add_argument("--rpc-url", default=os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"), help="Solana JSON-RPC URL (or set SOLANA_RPC_URL)")
    parser.add_argument("--idl-dir", default="idls", help="Directory for fetched Anchor IDLs")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum helper-call traversal depth for heuristic and dataflow passes (default: 3)")
    parser.add_argument("--no-dataflow", action="store_true", help="Disable the v0.5 asset-identity dataflow pass")
    parser.add_argument("--no-protocol-analysis", action="store_true", help="Disable structured Anchor, Token-2022, arithmetic, and flash-repay analysis")
    parser.add_argument("--no-review-files", action="store_true", help="Do not generate per-candidate Markdown review files")
    args = parser.parse_args()

    root = Path(args.root)
    out_dir = Path(args.out)
    if args.clone:
        clone_targets(Path(args.targets), root)
    if args.fetch_idls or args.fetch_program_metadata:
        fetch_targets(Path(args.targets), args.rpc_url, Path(args.idl_dir), out_dir / "program_metadata.json",
                      fetch_idls=args.fetch_idls, fetch_metadata=args.fetch_program_metadata, cluster=args.cluster)

    results: list[dict[str, Any]] = []
    dataflow_results: list[dict[str, Any]] = []
    protocol_results: list[dict[str, Any]] = []
    if not args.no_dataflow:
        # Import after scanner definitions are loaded; identity_dataflow reuses
        # the existing Rust/Anchor extractor without changing the v0.2 API.
        from identity_dataflow import analyze_rust_file
    if not args.no_protocol_analysis:
        from protocol_analysis import analyze_rust_file as analyze_protocol_rust_file
    for path in iter_files(root) or []:
        if path.suffix == ".rs":
            results.extend(scan_rust(path, max_depth=max(0, args.max_depth)))
            if not args.no_dataflow:
                dataflow_results.extend(analyze_rust_file(path, max_depth=max(0, args.max_depth)))
            if not args.no_protocol_analysis:
                protocol_results.extend(analyze_protocol_rust_file(path))
        elif path.name.endswith(".idl.json") or path.name == "idl.json":
            results.extend(scan_idl(path))
    idl_dir = Path(args.idl_dir)
    for path in iter_files(idl_dir) or []:
        if path.name.endswith(".idl.json") or path.name == "idl.json":
            results.extend(scan_idl(path))

    # Include the source commit for each repository in the finding metadata.
    metadata_cache: dict[str, dict[str, Any]] = {}
    for item in results + dataflow_results + protocol_results:
        file_path = Path(item.get("file", ""))
        repo_root = None
        for parent in [file_path.parent] + list(file_path.parents):
            if (parent / ".git").exists():
                repo_root = parent
                break
        if repo_root:
            key = str(repo_root)
            if key not in metadata_cache:
                metadata_cache[key] = git_metadata(repo_root)
            item["source_repo"] = key
            item["source_commit"] = metadata_cache[key].get("git_commit")
            item["source_remote"] = metadata_cache[key].get("git_remote")

    priority_order = {"HIGH_REVIEW": 0, "MEDIUM_REVIEW": 1, "LOW_REVIEW": 2, "IDL_REVIEW": 3, "ERROR": 4}
    results.sort(key=lambda item: (priority_order.get(item.get("priority"), 9), -int(item.get("score", 0)), item.get("file", ""), item.get("line", 0)))
    write_reports(results, out_dir)
    if not args.no_dataflow:
        from identity_dataflow import write_reports as write_dataflow_reports
        write_dataflow_reports(dataflow_results, out_dir)
    if not args.no_protocol_analysis:
        from protocol_analysis import write_reports as write_protocol_reports
        write_protocol_reports(protocol_results, out_dir)
    if not args.no_review_files:
        generate_review_files(results, out_dir)
        print(f"Review files: {out_dir / 'review'}")
    if not args.no_dataflow:
        print(f"Identity dataflow: {out_dir / 'identity_dataflow.json'}")
    if not args.no_protocol_analysis:
        print(f"Protocol analysis: {out_dir / 'protocol_analysis.json'}")
    if args.fetch_idls or args.fetch_program_metadata:
        print(f"Program metadata: {out_dir / 'program_metadata.json'}")


if __name__ == "__main__":
    main()
