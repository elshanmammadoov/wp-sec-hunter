from pathlib import Path
from zdh.analyzer import Analyzer
from zdh.report import write, to_records, context


class FakeParser:
    def __init__(self, nodes): self.nodes = nodes
    def parse(self, f): return {"nodes": self.nodes}, None


def V(n): return {"type": "var", "name": n}
def GET(k="x"): return {"type": "array_dim", "base": V("_GET"), "dim": {"type": "string", "value": k}}
def CALL(n, *a): return {"type": "call", "name": n, "args": list(a)}
def S(v="s"): return {"type": "string", "value": v}
def kinds(nodes, tmp_path):
    f = tmp_path / "a.php"; f.write_text("<?php\n" * 40)
    return Analyzer(FakeParser(nodes)).analyze(f)


def echo(arg, line=2): return {"kind": "Echo_", "line": line, "args": [arg]}


def test_unsanitized_echo_flagged(tmp_path):
    assert [f.kind for f in kinds([echo(GET())], tmp_path)] == ["xss"]


def test_sanitized_echo_suppressed(tmp_path):
    for fn in ("esc_html", "esc_attr", "sanitize_text_field", "intval", "htmlspecialchars"):
        assert not kinds([echo(CALL(fn, GET()))], tmp_path), fn


def test_taint_through_variable_and_sanitized_variable(tmp_path):
    assign = lambda v, r, l: {"kind": "Assign", "line": l, "left": V(v), "right": r}
    assert kinds([assign("a", GET(), 1), echo(V("a"), 2)], tmp_path)
    assert not kinds([assign("a", CALL("esc_html", GET()), 1), echo(V("a"), 2)], tmp_path)
    # concatenation keeps taint; int cast removes it
    cat = {"type": "binary", "op": ".", "left": S(), "right": GET()}
    assert kinds([echo(cat)], tmp_path)
    assert not kinds([echo({"type": "cast", "to": "int", "expr": GET()})], tmp_path)


def test_sanitizer_is_context_specific(tmp_path):
    sys_call = lambda arg: {"kind": "FuncCall", "line": 3, "name": "system", "args": [arg]}
    assert kinds([sys_call(CALL("esc_html", GET()))], tmp_path)          # esc_html != shell escaping
    assert not kinds([sys_call(CALL("escapeshellarg", GET()))], tmp_path)


def test_object_methods_are_not_global_functions(tmp_path):
    this_db = {"type": "property", "base": V("this"), "name": "DB"}
    nodes = [
        {"kind": "MethodCall", "line": 2, "method": "exec", "base": this_db, "args": [GET()]},
        {"kind": "MethodCall", "line": 3, "method": "query", "base": V("obj"), "args": [GET()]},
        {"kind": "StaticCall", "line": 4, "class": "Foo", "method": "system", "args": [GET()]},
    ]
    assert not kinds(nodes, tmp_path)


def test_wpdb_query_and_prepare(tmp_path):
    wpdb = V("wpdb")
    bad = {"kind": "MethodCall", "line": 2, "method": "query", "base": wpdb, "args": [GET()]}
    prep = {"type": "method_call", "method": "prepare", "base": wpdb, "args": [S(), GET()]}
    good = {"kind": "MethodCall", "line": 3, "method": "query", "base": wpdb, "args": [prep]}
    assert [f.kind for f in kinds([bad], tmp_path)] == ["sql_injection"]
    assert not kinds([good], tmp_path)


def test_report_high_confidence_with_context(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "a.php"; f.write_text("\n".join(f"line{i}" for i in range(1, 41)))
    fs = Analyzer(FakeParser([echo(GET(), 20)])).analyze(f)
    low = Analyzer(type("P", (), {"parse": lambda s, p: (None, "no php")})()).analyze(f)
    recs = to_records(fs + low)
    assert len(recs) == 1
    ctx = recs[0]["context"]
    assert len(ctx) == 15 and [c for c in ctx if c["hit"]][0]["line"] == 20
    p = write(fs)
    assert p.exists() and p.with_suffix(".md").exists()
    assert len(context(str(f), 1)) == 15 and len(context(str(f), 40)) == 15


def test_regex_fallback_ignores_methods(tmp_path):
    f = tmp_path / "a.php"
    f.write_text("<?php\n$this->DB->exec($_GET['a']);\nsystem($_GET['a']);\n")
    P = type("P", (), {"parse": lambda s, p: (None, "no php")})()
    fs = Analyzer(P).analyze(f)
    assert [(x.kind, x.line) for x in fs] == [("command_injection", 3)]
