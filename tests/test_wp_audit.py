"""Entry-point, access-control, interprocedural-taint and new-sink tests (hand-built AST, no PHP needed)."""
from zdh.analyzer import Analyzer
from zdh.report import to_records


class MapParser:
    def __init__(self, files): self.files = files
    def parse(self, f):
        name = str(f).replace("\\", "/").rsplit("/", 1)[-1]
        return {"nodes": self.files[name]}, None


def run(tmp_path, files):
    paths = []
    for name in files:
        p = tmp_path / name; p.write_text("<?php\n" * 60); paths.append(p)
    return Analyzer(MapParser(files)).analyze_project(paths, workers=1)


S = lambda v: {"type": "string", "value": v}
V = lambda n: {"type": "var", "name": n}
GET = lambda k="x": {"type": "array_dim", "base": V("_GET"), "dim": S(k)}
POST = lambda k="x": {"type": "array_dim", "base": V("_POST"), "dim": S(k)}
CALL = lambda n, *a: {"type": "call", "name": n, "args": list(a)}
ARR = lambda *vals, **kv: {"type": "array", "items": [{"key": None, "value": v} for v in vals] +
                           [{"key": S(k), "value": v} for k, v in kv.items()]}
def fc(name, args, line, scope=""): return {"kind": "FuncCall", "name": name, "args": args, "line": line, "scope": scope}
def fn(name, params, line=1): return {"kind": "Function_", "name": name, "params": params, "line": line, "scope": name, "class": None}
def method(cls, name, params, line=1): return {"kind": "ClassMethod", "name": name, "params": params, "line": line, "scope": f"{cls}::{name}", "class": cls}
def rules(fs): return {f.rule_id for f in fs}


# ---- Broken access control / CSRF -----------------------------------------
def handler(extra=()):
    return [fn("save", []), fc("update_option", [S("k"), POST()], 5, "save"), *extra]


def test_nopriv_ajax_write_without_checks(tmp_path):
    nodes = [fc("add_action", [S("wp_ajax_nopriv_save_x"), S("save")], 20), *handler()]
    fs = run(tmp_path, {"p.php": nodes})
    assert {"ZDH-BROKEN-ACCESS-CONTROL", "ZDH-CSRF"} <= rules(fs)
    bac = next(f for f in fs if f.rule_id == "ZDH-BROKEN-ACCESS-CONTROL")
    assert bac.severity == "HIGH" and bac.line == 5
    assert "action=save_x" in bac.entry_points[0]["label"] and bac.entry_points[0]["access"] == "public"


def test_guards_in_callback_or_helper_suppress(tmp_path):
    reg = fc("add_action", [S("wp_ajax_save_x"), S("save")], 20)
    inline = [reg, *handler([fc("current_user_can", [S("manage_options")], 4, "save"),
                             fc("check_ajax_referer", [S("n")], 3, "save")])]
    assert not rules(run(tmp_path, {"a.php": inline})) & {"ZDH-BROKEN-ACCESS-CONTROL", "ZDH-CSRF"}
    helper = [reg, *handler([fc("guard", [], 3, "save")]), fn("guard", [], 30),
              fc("current_user_can", [S("x")], 31, "guard"), fc("wp_verify_nonce", [S("n")], 32, "guard")]
    assert not rules(run(tmp_path, {"b.php": helper})) & {"ZDH-BROKEN-ACCESS-CONTROL", "ZDH-CSRF"}


def test_write_in_helper_and_method_callback(tmp_path):
    nodes = [fc("add_action", [S("wp_ajax_go"), ARR(V("this"), S("go"))], 3, "Plug::__construct"),
             method("Plug", "go", []), {"kind": "MethodCall", "method": "do_it", "base": V("this"), "args": [], "line": 8, "scope": "Plug::go"},
             method("Plug", "do_it", []),
             {"kind": "MethodCall", "method": "delete", "base": V("wpdb"), "args": [], "line": 12, "scope": "Plug::do_it"}]
    fs = run(tmp_path, {"c.php": nodes})
    assert any(f.rule_id == "ZDH-BROKEN-ACCESS-CONTROL" and f.line == 12 for f in fs)


# ---- REST permission_callback ---------------------------------------------
def rest(perm):
    cfg = {"methods": S("POST"), "callback": S("rest_save"), **({"permission_callback": perm} if perm else {})}
    return [fc("register_rest_route", [S("my/v1"), S("/save"), ARR(**cfg)], 10),
            fn("rest_save", ["request"]), fc("wp_delete_post", [S("1")], 4, "rest_save")]


def test_rest_return_true_with_write_is_high(tmp_path):
    for perm in (S("__return_true"), None):
        fs = run(tmp_path, {"r.php": rest(perm)})
        f = next(f for f in fs if f.rule_id == "ZDH-BROKEN-ACCESS-CONTROL")
        assert f.severity == "HIGH" and f.confidence >= 85 and "/my/v1/save" in f.entry_points[0]["label"]


def test_rest_custom_permission_callback_ok(tmp_path):
    assert not run(tmp_path, {"r.php": rest(S("my_perm_check"))})


# ---- New sinks --------------------------------------------------------------
def test_unserialize_is_critical(tmp_path):
    fs = run(tmp_path, {"u.php": [fc("unserialize", [POST("d")], 3)]})
    assert [(f.kind, f.severity) for f in fs] == [("object_injection", "CRITICAL")]


def test_ssrf_redirect_file_write(tmp_path):
    fs = run(tmp_path, {"s.php": [fc("file_get_contents", [GET("u")], 2), fc("wp_redirect", [GET("r")], 3),
                                  fc("unlink", [GET("f")], 4), fc("file_put_contents", [GET("f"), S("x")], 5),
                                  fc("wp_redirect", [CALL("wp_validate_redirect", GET("r"))], 6)]})
    got = {(f.kind, f.line) for f in fs}
    assert got == {("ssrf", 2), ("open_redirect", 3), ("arbitrary_file_write_delete", 4), ("arbitrary_file_write_delete", 5)}
    assert next(f for f in fs if f.kind == "open_redirect").severity == "MEDIUM"


def test_indirect_sources(tmp_path):
    body = CALL("json_decode", CALL("file_get_contents", S("php://input")))
    files_name = {"type": "array_dim", "base": {"type": "array_dim", "base": V("_FILES"), "dim": S("f")}, "dim": S("name")}
    fs = run(tmp_path, {"i.php": [fc("unserialize", [body], 2), fc("unlink", [files_name], 3)]})
    assert {(f.kind, f.line) for f in fs} == {("object_injection", 2), ("arbitrary_file_write_delete", 3)}
    assert next(f for f in fs if f.line == 2).evidence.source == "php://input"


def test_curl_handle_ssrf(tmp_path):
    nodes = [{"kind": "Assign", "line": 2, "scope": "", "left": V("ch"), "right": CALL("curl_init")},
             fc("curl_setopt", [V("ch"), {"type": "const", "name": "CURLOPT_URL"}, GET("u")], 3),
             fc("curl_exec", [V("ch")], 4)]
    assert [(f.kind, f.line) for f in run(tmp_path, {"c.php": nodes})] == [("ssrf", 4)]


# ---- Interprocedural taint ---------------------------------------------------
def test_param_to_sink_across_files(tmp_path):
    lib = [fn("run_it", ["cmd", "other"]), fc("system", [V("cmd")], 7, "run_it")]
    main = [fc("run_it", [GET("c"), S("x")], 3)]
    fs = run(tmp_path, {"lib.php": lib, "main.php": main})
    assert [(f.kind, f.line, f.function) for f in fs] == [("command_injection", 7, "run_it")]
    assert fs[0].file.endswith("lib.php") and "run_it(param 0)" in fs[0].evidence.propagation[0]


def test_interprocedural_respects_sanitizers_and_param_index(tmp_path):
    lib = [fn("run_it", ["cmd", "other"]), fc("system", [V("cmd")], 7, "run_it"),
           fn("safe_run", ["cmd"]), fc("system", [CALL("escapeshellarg", V("cmd"))], 9, "safe_run")]
    main = [fc("run_it", [S("ls"), GET("c")], 3),       # tainted arg is the unused 2nd param
            fc("safe_run", [GET("c")], 4),              # sanitized inside the callee
            fc("run_it", [CALL("intval", GET("c")), S("")], 5)]  # sanitized by caller
    assert not run(tmp_path, {"lib.php": lib, "main.php": main})


def test_two_hop_chain_and_sanitize_in_caller(tmp_path):
    nodes = [fn("a", ["x"]), fc("b", [V("x")], 3, "a"),
             fn("b", ["y"]), {"kind": "Echo_", "line": 8, "scope": "b", "args": [V("y")]},
             fc("a", [POST("p")], 20), fc("a", [CALL("esc_html", POST("p"))], 21)]
    fs = run(tmp_path, {"m.php": nodes})
    assert [(f.kind, f.line) for f in fs] == [("xss", 8)]
    assert len(fs[0].evidence.propagation) == 2


def test_taint_via_rest_request_and_entry_chain(tmp_path):
    q = {"type": "method_call", "method": "get_param", "base": V("request"), "args": [S("id")]}
    nodes = rest(S("my_perm")) + [{"kind": "MethodCall", "method": "query", "base": V("wpdb"), "args": [q], "line": 6, "scope": "rest_save"}]
    fs = run(tmp_path, {"r.php": nodes})
    sqli = next(f for f in fs if f.kind == "sql_injection")
    assert sqli.evidence.source == "REST_request" and "REST route /my/v1/save" in sqli.entry_points[0]["label"]


# ---- Report ------------------------------------------------------------------
def test_report_filters_and_merges(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    nodes = [fc("add_action", [S("wp_ajax_nopriv_save_x"), S("save")], 20), *handler(),
             fc("unserialize", [POST()], 40), fc("wp_redirect", [GET()], 41)]
    fs = run(tmp_path, {"p.php": nodes})
    recs = to_records(fs)
    assert all(r["severity"] in {"HIGH", "CRITICAL"} and r["confidence"] >= 85 for r in recs)
    assert not any(r["kind"] == "open_redirect" for r in recs)           # MEDIUM dropped
    merged = [r for r in recs if r["line"] == 5]
    assert len(merged) == 1 and merged[0]["also"]                         # BAC + CSRF share file:line
    assert any("action=save_x" in c for c in merged[0]["entry_chains"])
