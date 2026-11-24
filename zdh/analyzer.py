from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .models import Finding, Evidence
from .project import Project, CALL_KINDS
from .wp_audit import collect_entries, audit, public_entry

SOURCES = {"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"}

# Only methods on a $wpdb object are SQL sinks; `$this->DB->exec()` / `$obj->query()` are not guessed at.
WPDB_METHODS = {"query", "get_results", "get_var", "get_row", "get_col"}
WPDB_NAMES = {"wpdb"}
REST_GETTERS_PREFIX = "get_"   # $request->get_param() etc. on a tainted WP_REST_Request

ALL = slice(None)
FIRST = slice(0, 1)
_SQL = "User-controlled input reaches a database query without escaping or parameterization."
# name -> (context, kind, severity, confidence, reason, which-args)
FUNC_SINKS = {
    **{n: ("cmd", "command_injection", "HIGH", 88, "User-controlled input reaches a command-execution sink.", ALL)
       for n in ("system", "exec", "shell_exec", "passthru", "proc_open", "popen")},
    **{n: ("code", "unsafe_code", "HIGH", 86, "User-controlled input reaches a code-execution primitive.", ALL)
       for n in ("assert", "preg_replace")},
    "unserialize": ("deser", "object_injection", "CRITICAL", 90, "User-controlled data is unserialize()d (PHP Object Injection).", FIRST),
    **{n: ("file", "arbitrary_file_write_delete", "CRITICAL", 88, "User-controlled input reaches a file write/delete primitive.", ALL)
       for n in ("file_put_contents", "unlink")},
    **{n: ("file", "file_operation", "MEDIUM", 68, "User-controlled input reaches a file operation; path semantics require verification.", ALL)
       for n in ("fopen", "rename", "copy", "move_uploaded_file")},
    **{n: ("ssrf", "ssrf", "HIGH", 85, "User-controlled URL/path is fetched server-side (SSRF / arbitrary read).", FIRST)
       for n in ("file_get_contents", "curl_exec", "wp_remote_get", "wp_remote_post", "wp_remote_request")},
    "wp_redirect": ("redirect", "open_redirect", "MEDIUM", 80, "User-controlled URL reaches wp_redirect() without wp_validate_redirect().", FIRST),
    **{n: ("sql", "sql_injection", "HIGH", 86, _SQL, ALL) for n in ("mysqli_query", "pg_query", "sqlite_query")},
    "mysql_query": ("sql", "sql_injection", "HIGH", 86, _SQL, FIRST),
}

# Sanitizers are context specific: esc_html does not protect a SQL query.
_NUMERIC = {"intval", "absint", "floatval", "doubleval", "boolval", "abs", "count", "strlen", "is_numeric",
            "wp_verify_nonce", "wp_create_nonce"}
SANITIZERS = {
    "xss": _NUMERIC | {"htmlspecialchars", "htmlentities", "esc_html", "esc_attr", "esc_url", "esc_js",
                       "esc_textarea", "sanitize_text_field", "sanitize_title", "sanitize_key",
                       "wp_kses", "wp_kses_post", "wp_json_encode", "json_encode"},
    "sql": _NUMERIC | {"esc_sql", "mysqli_real_escape_string", "sanitize_key", "wpdb->prepare"},
    "cmd": _NUMERIC | {"escapeshellarg", "escapeshellcmd"},
    "file": _NUMERIC | {"basename", "sanitize_file_name", "wp_basename", "realpath", "validate_file"},
    "include": _NUMERIC | {"basename", "sanitize_file_name", "wp_basename", "validate_file"},
    "code": _NUMERIC,
    "deser": _NUMERIC,
    "ssrf": _NUMERIC | {"wp_http_validate_url"},
    "redirect": _NUMERIC | {"wp_validate_redirect", "sanitize_key"},
}
SAFE_CASTS = {"int", "double", "bool"}
MAX_DEPTH = 40


class Taint:
    """Per-scope, line-ordered variable taint environment over the parser's expression trees.

    env[var][ctx] -> source name or None: a value sanitized for XSS is still tainted for SQL.
    Function parameters are seeded with symbolic sources "PARAM:<i>" to build summaries.
    """

    def __init__(self):
        self.env: dict[str, dict] = {}
        self.controls: list[str] = []

    def _all(self, items, ctx, d):
        return next((s for s in (self.of(i, ctx, d) for i in items) if s), None)

    def of(self, e, ctx, depth=0):
        """Return the source name if expression `e` is tainted for sink context `ctx`, else None."""
        if not isinstance(e, dict) or depth > MAX_DEPTH:
            return None
        t = e.get("type"); d = depth + 1
        if t == "var":
            name = e.get("name")
            return name if name in SOURCES else self.env.get(name, {}).get(ctx)
        if t == "array_dim":
            return self.of(e.get("base"), ctx, d)
        if t == "cast":
            return None if e.get("to") in SAFE_CASTS else self.of(e.get("expr"), ctx, d)
        if t == "call":
            name = _lname(e.get("name"))
            args = e.get("args", [])
            if (name == "file_get_contents" and args and args[0].get("type") == "string"
                    and args[0].get("value", "").lower().startswith("php://input")):
                return "php://input"  # indirect source: raw request body
            if name in SANITIZERS.get(ctx, ()):
                self.controls.append(name)
                return None
            return self._all(args, ctx, d)  # json_decode(), trim(), base64_decode()... propagate
        if t == "method_call":
            if e.get("method") == "prepare" and ctx == "sql" and self._is_wpdb(e.get("base")):
                self.controls.append("wpdb->prepare")
                return None
            base_src = self.of(e.get("base"), ctx, d)
            if base_src and (e.get("method") or "").lower().startswith(REST_GETTERS_PREFIX):
                return base_src  # $request->get_param() on a tainted request object
            return self._all(e.get("args", []), ctx, d)
        if t == "static_call":
            return self._all(e.get("args", []), ctx, d)
        if t == "binary":
            if e.get("op") in {"+", "-", "*", "/", "%", "==", "===", "!=", "!==", "<", ">", "<=", ">=", "&&", "||", "and", "or"}:
                return None  # arithmetic/comparison yields numbers or booleans
            return self.of(e.get("left"), ctx, d) or self.of(e.get("right"), ctx, d)
        if t == "interp":
            return self._all(e.get("parts", []), ctx, d)
        if t == "ternary":
            return self.of(e.get("if"), ctx, d) or self.of(e.get("else"), ctx, d)
        if t == "assign":
            self.assign(e.get("left"), e.get("right"))
            return self.of(e.get("right"), ctx, d)
        return None

    def assign(self, left, right):
        base = left
        while isinstance(base, dict) and base.get("type") == "array_dim":
            base = base.get("base")
        if not (isinstance(base, dict) and base.get("type") == "var"):
            return
        name = base.get("name")
        per = {ctx: self.of(right, ctx) for ctx in SANITIZERS}
        if left is not base:  # $a['k'] = ...  taints $a if any element is tainted
            old = self.env.get(name, {})
            per = {c: per[c] or old.get(c) for c in per}
        self.env[name] = per

    @staticmethod
    def _is_wpdb(base):
        if not isinstance(base, dict):
            return False
        return base.get("type") in {"var", "property"} and base.get("name") in WPDB_NAMES


def _lname(n):
    return (n or "").lower().lstrip("\\").rsplit("\\", 1)[-1]


class Analyzer:
    def __init__(self, parser):
        self.parser = parser

    def analyze(self, path: Path):
        return self.analyze_project([Path(path)])

    def analyze_project(self, files, workers=8):
        files = [Path(f) for f in files]

        def parse(f):
            try:
                return f, self.parser.parse(str(f))
            except Exception as e:
                return f, (None, str(e))

        if len(files) > 1 and workers > 1:
            with ThreadPoolExecutor(workers) as ex:
                parsed = list(ex.map(parse, files))
        else:
            parsed = [parse(f) for f in files]

        proj, findings = Project(), []
        for f, (ast, _err) in parsed:
            if ast:
                proj.add_file(str(f), ast)
            else:  # fallback is deliberately LOW confidence: never HIGH without AST evidence
                findings += self._obvious_raw_findings(f, f.read_text(errors="ignore"))

        entries = collect_entries(proj)
        rest_keys = {k for e in entries if e["type"] == "rest" for k in e["callbacks"]}

        # Pass 1: parameter -> sink summaries, iterated so multi-hop chains converge.
        summaries: dict = {}
        for _ in range(4):
            new = {k: self._scan(proj, k, summaries, final=False, rest=False) for k in proj.defs}
            same = {k: set(v) for k, v in new.items()} == {k: set(v) for k, v in summaries.items()}
            summaries = new
            if same:
                break

        # Pass 2: real sources -> sinks, including calls into summarized functions.
        seen = set()
        for key in proj.scopes:
            for h in self._scan(proj, key, summaries, final=True, rest=key in rest_keys):
                sig = (h["kind"], h["file"], h["line"], h["sink"])
                if sig in seen:
                    continue
                seen.add(sig)
                f = self._finding(h["file"], h["line"], h["kind"], h["sev"], h["conf"], h["src"], h["sink"], h["reason"])
                f.evidence.controls = sorted(set(h["controls"]))
                f.evidence.propagation = list(h["chain"])
                f.function = h["scope"]
                scopes = {(h["file"], h["scope"]), *h["via"]}
                f.entry_points = [public_entry(e) for e in entries if e["scopes"] & scopes]
                findings.append(f)

        findings += audit(proj, entries)
        return findings

    # ------------------------------------------------------------------
    def _scan(self, proj, key, summaries, final, rest):
        """final=False -> {sig: summary entry} of param->sink flows; final=True -> list of hits."""
        file, scope = key
        d = proj.defs.get(key)
        taint = Taint()
        if d:
            for i, p in enumerate(d.params):
                src = ("REST_request" if rest and i == 0 else None) if final else f"PARAM:{i}"
                if src:
                    taint.env[p] = {c: src for c in SANITIZERS}
        hits = []
        for n in proj.scopes[key]:
            if n.get("kind") == "Assign":
                taint.assign(n.get("left"), n.get("right"))
                continue
            for h in self._sink_hits(n, taint):
                h.update(file=file, scope=scope, chain=[], via=[])
                hits.append(h)
            if n.get("kind") in CALL_KINDS:
                args = n.get("args", [])
                for callee in proj.resolve_call(n, file, scope):
                    for entry in summaries.get(callee.key, {}).values():
                        if entry["param"] >= len(args):
                            continue
                        taint.controls = []
                        src = taint.of(args[entry["param"]], entry["ctx"])
                        if src:
                            hits.append({**entry, "src": src, "controls": entry["controls"] + taint.controls,
                                         "chain": [f"{scope or 'global'}() -> {callee.scope}(param {entry['param']})"] + entry["chain"],
                                         "via": [key] + entry["via"]})
        if final:
            return [h for h in hits if not str(h["src"]).startswith("PARAM:")]
        out = {}
        for h in hits:
            if str(h["src"]).startswith("PARAM:"):
                e = {**h, "param": int(h["src"].split(":")[1])}
                out[(e["param"], e["ctx"], e["kind"], e["file"], e["line"], e["sink"])] = e
        return out

    def _sink_hits(self, n, taint):
        kind, line, args = n.get("kind"), n.get("line", 0), n.get("args", [])
        spec, sink = None, None
        if kind == "FuncCall":
            name = _lname(n.get("name"))
            if name == "curl_setopt" and len(args) >= 3 and args[0].get("type") == "var":
                taint.controls = []
                src = taint.of(args[2], "ssrf")
                if src:  # curl_setopt($ch, CURLOPT_URL, $tainted) taints the handle
                    taint.env.setdefault(args[0]["name"], {})["ssrf"] = src
            spec, sink = FUNC_SINKS.get(name), name
        elif kind == "MethodCall":
            m = (n.get("method") or "").lower()
            if m in WPDB_METHODS and Taint._is_wpdb(n.get("base")):
                spec = ("sql", "sql_injection", "HIGH", 86, "User-controlled input reaches a $wpdb query without prepare().", FIRST)
                sink = f"wpdb->{m}"
        elif kind == "Include_":
            spec, sink = ("include", "file_inclusion", "HIGH", 86, "User-controlled input reaches an include/require sink.", ALL), "include/require"
        elif kind == "Eval_":
            spec, sink = ("code", "unsafe_code", "HIGH", 86, "User-controlled input reaches eval().", ALL), "eval"
        elif kind in {"Echo_", "Print_"}:
            spec, sink = ("xss", "xss", "HIGH", 90, "User-controlled output with no recognized escaping.", ALL), "echo/print"
        if not spec:
            return []
        ctx, k, sev, conf, reason, sl = spec
        taint.controls = []
        src = next((s for s in (taint.of(a, ctx) for a in args[sl]) if s), None)
        if not src:
            return []
        return [{"ctx": ctx, "kind": k, "sev": sev, "conf": conf, "src": src, "sink": sink, "reason": reason,
                 "controls": list(taint.controls), "line": line}]

    def _obvious_raw_findings(self, path, code):
        out = []
        # (?<![\w>:$]) rejects `$obj->exec(`, `Foo::system(`, and user-defined `my_exec(`.
        call = r'(?<![\w>:$])(system|exec|shell_exec|passthru|proc_open|popen)\s*\('
        inp = r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b'
        for i, line in enumerate(code.splitlines(), 1):
            if re.search(rf'\b(echo|print)\b.*{inp}', line, re.I):
                out.append(self._finding(path, i, "xss", "LOW", 45, "$_INPUT", "echo/print", "Regex-only candidate; AST verification is unavailable."))
            m = re.search(call + rf'.*{inp}', line, re.I)
            if m:
                out.append(self._finding(path, i, "command_injection", "LOW", 45, "$_INPUT", m.group(1), "Regex-only candidate; AST verification is unavailable."))
            m = re.search(rf'\b(include|include_once|require|require_once)\b\s*\(?.*{inp}', line, re.I)
            if m:
                out.append(self._finding(path, i, "file_inclusion", "LOW", 45, "$_INPUT", m.group(1), "Regex-only candidate; AST verification is unavailable."))
        return out

    def _finding(self, path, line, kind, severity, confidence, source, sink, reason):
        return Finding(rule_id="ZDH-" + kind.upper().replace("_", "-"), kind=kind, severity=severity,
                       confidence=confidence, file=str(path), line=line, message=reason,
                       evidence=Evidence(source=source, sink=sink, reason=reason))
