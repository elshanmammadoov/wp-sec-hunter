import json
from functools import lru_cache
from pathlib import Path

CONTEXT_LINES = 15      # total window size, centred on the finding line
MIN_CONFIDENCE = 85     # "high confidence" threshold
REPORT_SEVERITIES = {"HIGH": 1, "CRITICAL": 2}


@lru_cache(maxsize=256)
def _lines(file):
    try:
        return tuple(Path(file).read_text(errors="ignore").splitlines())
    except OSError:
        return ()


def context(file, line, size=CONTEXT_LINES):
    """Return `size` lines of code around `line` as [{line, code, hit}]; window shifts at file edges."""
    lines = _lines(file)
    if not lines:
        return []
    start = max(1, min(line - size // 2, len(lines) - size + 1))
    end = min(len(lines), start + size - 1)
    return [{"line": i, "code": lines[i - 1], "hit": i == line} for i in range(start, end + 1)]


def _rank(f):
    return (-REPORT_SEVERITIES.get(f.severity, 0), -f.confidence, f.file, f.line)


def high_confidence(findings, min_confidence=MIN_CONFIDENCE):
    return sorted((f for f in findings if f.severity in REPORT_SEVERITIES and f.confidence >= min_confidence), key=_rank)


def entry_chains(f):
    """Human-readable chains: entry point -> vulnerable function -> sink."""
    where = f.function or "global scope"
    hops = f.evidence.propagation
    tail = f"{where}: {f.evidence.sink} @ {f.file}:{f.line}"
    return [" -> ".join([e["label"], *hops, tail]) for e in f.entry_points]


def to_records(findings, min_confidence=MIN_CONFIDENCE):
    """Filter to HIGH/CRITICAL >= min_confidence and merge findings that share file:line."""
    merged = {}
    for f in high_confidence(findings, min_confidence):
        key = (f.file, f.line)
        if key in merged:  # list is rank-sorted, so the first one is the primary finding
            rec = merged[key]
            rec["also"].append({"rule_id": f.rule_id, "kind": f.kind, "severity": f.severity, "confidence": f.confidence})
            known = {e["label"] for e in rec["entry_points"]}
            rec["entry_points"] += [e for e in f.entry_points if e["label"] not in known]
            continue
        d = f.to_dict()
        d["also"] = []
        d["entry_chains"] = entry_chains(f)
        d["context"] = context(f.file, f.line)
        merged[key] = d
    return list(merged.values())


def to_markdown(records):
    md = [f"# High-confidence findings ({len(records)})", ""]
    for r in records:
        ev = r["evidence"]
        md += [f"## {r['rule_id']} — `{r['file']}:{r['line']}`",
               f"- Severity/confidence: {r['severity']} / {r['confidence']}%",
               f"- Source → sink: `{ev['source']}` → `{ev['sink']}`",
               f"- {r['message']}"]
        if r.get("function"):
            md.append(f"- Function: `{r['function']}`")
        if r["also"]:
            md.append("- Also at this line: " + ", ".join(a["rule_id"] for a in r["also"]))
        if ev.get("propagation"):
            md.append("- Propagation: " + "; ".join(ev["propagation"]))
        for c in r["entry_chains"] or []:
            md.append(f"- Entry point: {c}")
        md += ["", "```php"]
        md += [f"{c['line']:>5}{'>' if c['hit'] else ' '} {c['code']}" for c in r["context"]]
        md += ["```", ""]
    return "\n".join(md)


def write(findings, name='latest.json', min_confidence=MIN_CONFIDENCE):
    """Write HIGH/CRITICAL, >=min_confidence findings as <name>.json and <name>.md under reports/."""
    Path('reports').mkdir(exist_ok=True)
    recs = to_records(findings, min_confidence)
    p = Path('reports') / name
    p.write_text(json.dumps(recs, indent=2, ensure_ascii=False), encoding="utf-8")
    p.with_suffix('.md').write_text(to_markdown(recs), encoding="utf-8")
    return p
