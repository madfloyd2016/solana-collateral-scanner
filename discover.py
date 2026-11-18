#!/usr/bin/env python3
"""Discover Solana DeFi lending/collateral programs (read-only, stdlib only)."""
from __future__ import annotations
import argparse, json, os, re, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.5.0"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PROGRAM_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])")
LENDING_TERMS = re.compile(r"\b(lend(?:ing)?|borrow(?:ing)?|collateral|margin|vault|reserve|liquidat(?:ion|e)|credit market)\b", re.I)

class Fetcher:
    def __init__(self, cache_dir: Path, ttl: int = 21600, timeout: int = 15, delay: float = 0.4):
        self.cache_dir, self.ttl, self.timeout, self.delay = cache_dir, ttl, timeout, delay
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.last_request = 0.0
        self.failures: list[dict[str, str]] = []

    def get(self, url: str, headers: dict[str, str] | None = None) -> bytes | None:
        key = __import__('hashlib').sha256(url.encode()).hexdigest()
        cache = self.cache_dir / (key + '.json')
        if cache.exists() and time.time() - cache.stat().st_mtime < self.ttl:
            try: return json.loads(cache.read_text()).get('body', '').encode()
            except Exception: pass
        wait = self.delay - (time.monotonic() - self.last_request)
        if wait > 0: time.sleep(wait)
        req_headers = {"User-Agent": "solana-collateral-scanner/0.5.0", "Accept": "application/json,text/plain,*/*"}
        req_headers.update(headers or {})
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=req_headers), timeout=self.timeout) as r:
                body = r.read()
            self.last_request = time.monotonic()
            cache.write_text(json.dumps({"url": url, "body": body.decode('utf-8', 'replace')}, ensure_ascii=False))
            return body
        except Exception as e:
            self.failures.append({"url": url, "error": str(e)[:500]})
            return None

    def json(self, url: str, headers: dict[str, str] | None = None) -> Any:
        body = self.get(url, headers)
        if body is None: return None
        try: return json.loads(body)
        except Exception as e:
            self.failures.append({"url": url, "error": "invalid JSON: " + str(e)[:300]})
            return None


def valid_pubkey(value: str) -> bool:
    if not isinstance(value, str) or not 32 <= len(value) <= 44: return False
    n = 0
    try:
        for c in value: n = n * 58 + B58.index(c)
    except ValueError: return False
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    raw = b'\0' * (len(value) - len(value.lstrip('1'))) + raw
    return len(raw) == 32


def extract_program_ids(text: str) -> list[str]:
    return sorted({x for x in PROGRAM_RE.findall(text or '') if valid_pubkey(x)})


def score_candidate(name: str, category: str = '', description: str = '', repo_url: str | None = None,
                    program_id: str | None = None, idl_found: bool = False, rpc_valid: bool = False) -> tuple[int, list[str]]:
    text = ' '.join([name or '', category or '', description or ''])
    score, reasons = 0, []
    if re.search(r"\blending\b|\blending protocol\b|\blend\b", text, re.I): score += 25; reasons.append('lending terminology')
    if re.search(r"collateral|borrow|loan|credit market|money market", text, re.I): score += 20; reasons.append('collateral/borrow terminology')
    if re.search(r"vault|margin|liquid staking|reserve", text, re.I): score += 10; reasons.append('vault/margin/reserve terminology')
    if repo_url: score += 10; reasons.append('public source repository URL')
    if program_id and valid_pubkey(program_id): score += 20; reasons.append('valid Solana public-key format')
    if idl_found: score += 5; reasons.append('IDL artifact discovered')
    if rpc_valid: score += 10; reasons.append('RPC confirms executable program account')
    return min(score, 100), reasons


def candidate_template(name: str, source: str, evidence: str, category: str = '', description: str = '',
                       repo_url: str | None = None, docs_url: str | None = None, program_id: str | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {"protocol_name": name.strip() or "Unknown", "program_id": program_id, "category": category or "unknown",
            "repo_url": repo_url, "source_commit": None, "docs_url": docs_url,
            "discovery_source": [source], "evidence": [evidence], "description": description[:1200],
            "confidence": "low", "score": 0, "score_reasons": [], "priority": "P3", "last_seen": now,
            "rpc_validation": {"checked": False, "exists": None, "executable": None, "owner": None, "error": None},
            "source_mapping": "unverified"}


def discover_defillama(fetcher: Fetcher) -> list[dict[str, Any]]:
    data = fetcher.json('https://api.llama.fi/protocols')
    out = []
    if not isinstance(data, list): return out
    for p in data:
        if 'Solana' not in (p.get('chains') or []): continue
        category = str(p.get('category') or '')
        name = str(p.get('name') or p.get('slug') or 'Unknown')
        desc = str(p.get('description') or '')
        if not (LENDING_TERMS.search(category) or LENDING_TERMS.search(name) or LENDING_TERMS.search(desc)): continue
        url = p.get('url') or p.get('gecko_id')
        out.append(candidate_template(name, 'defillama', f"DeFiLlama protocol directory: category={category}; chains include Solana", category, desc, docs_url=url if isinstance(url, str) and url.startswith('http') else None))
    return out


def classify_repo_role(full_name: str, description: str = '', readme: str = '') -> str:
    """Conservative role hint; never asserts that a repository is official source."""
    text = (full_name + "\n" + description + "\n" + readme[:20000]).lower()
    if any(term in text for term in ("reproduction harness", "proof of concept", "proof-of-concept", "poc", "exploit reproduction", "security research", "single-finding reproduction")):
        return "research_poc"
    if any(term in text for term in ("security audit report", "smart contract audit", "audit findings", "auditor report")):
        return "audit"
    if any(term in text for term in ("sdk", "client library", "typescript client", "rust client")) and "program source" not in text:
        return "sdk_or_client"
    return "unverified_repository_candidate"


def discover_github(fetcher: Fetcher, token: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
    queries = ['solana lending language:Rust', 'solana collateral protocol language:Rust', 'solana borrow vault protocol language:Rust']
    out, seen = [], set()
    headers = {'Accept': 'application/vnd.github+json'}
    if token: headers['Authorization'] = 'Bearer ' + token
    for q in queries:
        url = 'https://api.github.com/search/repositories?' + urllib.parse.urlencode({'q': q, 'sort': 'updated', 'per_page': min(limit, 100)})
        data = fetcher.json(url, headers)
        for repo in (data or {}).get('items', []) if isinstance(data, dict) else []:
            full = repo.get('full_name')
            if not full or full in seen: continue
            seen.add(full)
            repo_url = repo.get('html_url')
            branch = repo.get('default_branch') or 'main'
            raw_url = f"https://raw.githubusercontent.com/{full}/{urllib.parse.quote(branch)}/README.md"
            commit_data = fetcher.json(f"https://api.github.com/repos/{full}/commits/{urllib.parse.quote(branch)}", headers)
            source_commit = ((commit_data or {}).get('sha') if isinstance(commit_data, dict) else None)
            readme = fetcher.get(raw_url)
            readme_text = readme.decode('utf-8', 'replace') if readme else ''
            desc = str(repo.get('description') or '')
            ids = extract_program_ids(desc + '\n' + readme_text)
            evidence = f"GitHub repository search result {full}; stars={repo.get('stargazers_count', 0)}; default_branch={branch}"
            if readme: evidence += '; README fetched and searched for program IDs'
            c = candidate_template(repo.get('name') or full, 'github', evidence, 'Lending/DeFi (repository-search inference)', desc,
                                   repo_url=repo_url, docs_url=repo.get('homepage'))
            c['source_commit'] = source_commit
            c['repo_role'] = classify_repo_role(full, desc, readme_text)
            c['source_mapping'] = 'repository_candidate_only; official-source and deployment equivalence not established'
            c['evidence'].append('Repository role is a conservative text heuristic; it is not an official-source verification')
            c['github'] = {'full_name': full, 'default_branch': branch, 'pushed_at': repo.get('pushed_at'), 'stars': repo.get('stargazers_count', 0)}
            if len(ids) == 1:
                c['program_id'] = ids[0]
                c['evidence'].append('A single valid base58 32-byte public key was extracted from repository description/README; semantic role still requires verification')
            elif len(ids) > 1:
                c['program_id_candidates'] = ids
                c['evidence'].append(f'{len(ids)} valid public-key strings found; none auto-selected because role is ambiguous')
            out.append(c)
    return out


def rpc_validate(fetcher: Fetcher, program_id: str, rpc_url: str) -> dict[str, Any]:
    if not valid_pubkey(program_id): return {"checked": False, "exists": False, "executable": False, "owner": None, "error": "invalid public key"}
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":[program_id,{"encoding":"base64","commitment":"confirmed"}]}).encode()
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type":"application/json", "User-Agent":"solana-collateral-scanner/0.5.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r: data = json.loads(r.read())
        value = (data.get('result') or {}).get('value')
        if value is None: return {"checked": True, "exists": False, "executable": False, "owner": None, "error": None}
        return {"checked": True, "exists": True, "executable": bool(value.get('executable')), "owner": value.get('owner'), "lamports": value.get('lamports'), "error": None}
    except Exception as e:
        return {"checked": True, "exists": None, "executable": None, "owner": None, "error": str(e)[:500]}


def merge_candidates(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in items:
        key = item.get('program_id') or (('repo:' + str(item.get('repo_url'))) if item.get('repo_url') else ('name:' + item['protocol_name'].lower()))
        if key not in merged: merged[key] = item; continue
        cur = merged[key]
        for field in ('discovery_source', 'evidence'):
            cur[field] = list(dict.fromkeys(cur.get(field, []) + item.get(field, [])))
        for field in ('repo_url', 'docs_url', 'description'):
            if not cur.get(field) and item.get(field): cur[field] = item[field]
        if item.get('program_id') and not cur.get('program_id'): cur['program_id'] = item['program_id']
    return list(merged.values())


def run_discovery(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out); out_dir.mkdir(parents=True, exist_ok=True)
    fetcher = Fetcher(Path(args.cache_dir), args.cache_ttl, args.timeout, args.delay)
    items: list[dict[str, Any]] = []
    if args.sources in ('all', 'defillama'): items.extend(discover_defillama(fetcher))
    if args.sources in ('all', 'github'): items.extend(discover_github(fetcher, os.getenv('GITHUB_TOKEN'), args.github_limit))
    items = merge_candidates(items)
    for c in items:
        pid = c.get('program_id')
        if pid and args.rpc_url:
            c['rpc_validation'] = rpc_validate(fetcher, pid, args.rpc_url)
        rv = c['rpc_validation']
        score, reasons = score_candidate(c['protocol_name'], c.get('category',''), c.get('description',''), c.get('repo_url'), pid,
                                         bool(c.get('idl_path')), rv.get('executable') is True)
        c['score'], c['score_reasons'] = score, reasons
        c['confidence'] = 'high' if score >= 70 and rv.get('executable') is True else 'medium' if score >= 45 else 'low'
        c['priority'] = 'P1' if score >= 70 else 'P2' if score >= 45 else 'P3'
        if c.get('repo_url'): c['source_mapping'] = 'repository-found; deployed commit not verified'
        if rv.get('exists') is False: c['evidence'].append('RPC account lookup returned null; this candidate is not a validated deployed program')
        elif rv.get('executable') is False and rv.get('exists'): c['evidence'].append('RPC account exists but is not executable; may be a mint, wallet, data account, or non-program account')
    items.sort(key=lambda x: (-x['score'], x['protocol_name'].lower(), x.get('program_id') or ''))
    report = {"scanner_version": VERSION, "cluster": args.cluster, "generated_at": datetime.now(timezone.utc).isoformat(),
              "sources_requested": args.sources, "candidate_count": len(items), "candidates": items, "source_failures": fetcher.failures}
    (out_dir/'discovery.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    with (out_dir/'discovery.csv').open('w', newline='', encoding='utf-8') as f:
        import csv
        fields = ['protocol_name','program_id','category','score','confidence','priority','repo_url','repo_role','source_commit','docs_url','discovery_source','source_mapping']
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for c in items: w.writerow({**c, 'discovery_source': ';'.join(c['discovery_source'])})
    if args.export_targets:
        targets = []
        for c in items:
            if not c.get('program_id'): continue
            if c.get('rpc_validation', {}).get('executable') is not True and not args.include_unvalidated_targets: continue
            targets.append({"name": c['protocol_name'], "program_id": c['program_id'], "repo": c.get('repo_url'),
                            "repo_role": c.get('repo_role', 'unverified_repository_candidate'),
                            "priority": c['priority'], "note": f"Auto-discovered from {', '.join(c['discovery_source'])}; score={c['score']}; confidence={c['confidence']}. Repository role={c.get('repo_role', 'unverified_repository_candidate')}; verify official source, program role, deployment and source commit before treating code as deployed source."})
        Path(args.export_targets).write_text(json.dumps(targets, indent=2, ensure_ascii=False) + '\n')
    if args.scan and args.export_targets:
        import subprocess, sys
        cmd = [sys.executable, str(Path(__file__).with_name('scanner.py')), '--clone', '--targets', args.export_targets,
               '--root', args.scan_root, '--out', args.scan_out]
        if args.fetch_idls: cmd.append('--fetch-idls')
        if args.fetch_program_metadata: cmd.append('--fetch-program-metadata')
        if args.rpc_url: cmd += ['--rpc-url', args.rpc_url]
        subprocess.run(cmd, check=False)
    return report


def main() -> None:
    p = argparse.ArgumentParser(description='Discover Solana DeFi lending/collateral programs (read-only).')
    p.add_argument('--version', action='version', version=f'Solana Collateral Scanner discovery {VERSION}')
    p.add_argument('--cluster', choices=['mainnet-beta','devnet'], default='mainnet-beta')
    p.add_argument('--out', default='discovery'); p.add_argument('--dry-run', action='store_true', help='Discover and report only; no cloning or scanning')
    p.add_argument('--sources', choices=['all','defillama','github'], default='all')
    p.add_argument('--cache-dir', default='.discovery-cache'); p.add_argument('--cache-ttl', type=int, default=21600)
    p.add_argument('--timeout', type=int, default=15); p.add_argument('--delay', type=float, default=0.4)
    p.add_argument('--github-limit', type=int, default=15); p.add_argument('--rpc-url', default=os.getenv('SOLANA_RPC_URL') or 'https://api.mainnet-beta.solana.com')
    p.add_argument('--export-targets'); p.add_argument('--include-unvalidated-targets', action='store_true', help='Allow export without RPC executable=true; review manually')
    p.add_argument('--scan', action='store_true')
    p.add_argument('--scan-root', default='repos'); p.add_argument('--scan-out', default='reports-discovered')
    p.add_argument('--fetch-idls', action='store_true'); p.add_argument('--fetch-program-metadata', action='store_true')
    args = p.parse_args()
    if args.cluster == 'devnet' and not os.getenv('SOLANA_RPC_URL') and args.rpc_url == 'https://api.mainnet-beta.solana.com': args.rpc_url = 'https://api.devnet.solana.com'
    if args.scan and not args.export_targets: p.error('--scan requires --export-targets')
    report = run_discovery(args)
    print(f"Discovery complete: {report['candidate_count']} candidates; report: {args.out}/discovery.json")
    if report['source_failures']: print(f"Source failures: {len(report['source_failures'])} (see discovery.json)")

if __name__ == '__main__': main()
