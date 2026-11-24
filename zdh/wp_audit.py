"""WordPress entry-point mapping and broken-access-control / CSRF audit."""
from __future__ import annotations
from .models import Finding, Evidence
from .project import Project, last_segment

WRITE_FUNCS = {"update_option", "add_option", "delete_option", "delete_post", "wp_delete_post", "wp_insert_post",
               "wp_update_post", "wp_insert_user", "wp_update_user", "wp_delete_user", "update_user_meta",
               "delete_user_meta", "update_post_meta", "delete_post_meta", "wp_set_object_terms",
               "move_uploaded_file"}
WPDB_WRITES = {"insert", "update", "delete", "replace"}
AUTHZ_GUARDS = {"current_user_can", "user_can", "current_user_can_for_blog"}
NONCE_GUARDS = {"wp_verify_nonce", "check_ajax_referer", "check_admin_referer"}
AUDITED = {"ajax", "ajax_nopriv", "admin_post", "admin_post_nopriv", "shortcode", "rest"}
PUBLIC_TYPES = {"ajax_nopriv", "admin_post_nopriv"}

HOOK_PREFIXES = (("wp_ajax_nopriv_", "ajax_nopriv"), ("wp_ajax_", "ajax"),
                 ("admin_post_nopriv_", "admin_post_nopriv"), ("admin_post_", "admin_post"))


def _text(e) -> str | None:
    """Static text of a string / interpolated-string expression ('*' for dynamic parts)."""
    if not isinstance(e, dict):
        return None
    if e.get("type") == "string":
        return e.get("value", "")
    if e.get("type") == "interp":
        return "".join(p.get("value", "") if p.get("type") == "string" else "*" for p in e.get("parts", []))
    if e.get("type") == "binary" and e.get("op") == ".":
        l, r = _text(e.get("left")), _text(e.get("right"))
        return (l if l is not None else "*") + (r if r is not None else "*")
    return None


def _is_wpdb(base):
    return isinstance(base, dict) and (
        (base.get("type") == "var" and base.get("name") == "wpdb") or
        (base.get("type") == "property" and base.get("name") == "wpdb"))


def write_ops(nodes):
    out = []
    for n in nodes:
        if n.get("kind") == "FuncCall" and last_segment(n.get("name", "")) in WRITE_FUNCS:
            out.append((n.get("line", 0), last_segment(n["name"])))
        elif n.get("kind") == "MethodCall" and _is_wpdb(n.get("base")) and (n.get("method") or "").lower() in WPDB_WRITES:
            out.append((n.get("line", 0), f"wpdb->{n['method'].lower()}"))
    return out


def guards(nodes):
    names = {last_segment(n.get("name", "")) for n in nodes if n.get("kind") == "FuncCall"}
    return bool(names & AUTHZ_GUARDS), bool(names & NONCE_GUARDS)


def _rest_configs(args_expr):
    """Yield route config arrays ({key: expr}) from register_rest_route's third argument."""
    if not isinstance(args_expr, dict) or args_expr.get("type") != "array":
        return
    cfg = {_text(i["key"]): i["value"] for i in args_expr["items"] if i.get("key")}
    if "callback" in cfg:
        yield cfg
    else:
        for i in args_expr["items"]:
            yield from _rest_configs(i["value"])


def collect_entries(proj: Project) -> list[dict]:
    entries = []
    for (file, scope), nodes in proj.scopes.items():
        for n in nodes:
            if n.get("kind") != "FuncCall":
                continue
            fn, args, line = last_segment(n.get("name", "")), n.get("args", []), n.get("line", 0)
            base = {"file": file, "line": line, "registered_in": scope}
            if fn in {"add_action", "add_filter"} and len(args) >= 2:
                hook = _text(args[0])
                if hook is None:
                    continue
                typ, name = "hook", hook
                for prefix, t in HOOK_PREFIXES:
                    if hook.startswith(prefix):
                        typ, name = t, hook[len(prefix):]
                        break
                cbs = proj.resolve_callback(args[1], file, scope)
                label = {"hook": f"hook {hook}", "ajax": f"AJAX action={name} (logged-in)",
                         "ajax_nopriv": f"AJAX action={name} (unauthenticated, wp_ajax_nopriv)",
                         "admin_post": f"admin-post action={name}",
                         "admin_post_nopriv": f"admin-post action={name} (unauthenticated)"}[typ]
                entries.append({**base, "type": typ, "name": name, "label": label, "callbacks": cbs,
                                "access": "public" if typ in PUBLIC_TYPES else "authenticated"})
            elif fn == "add_shortcode" and len(args) >= 2:
                tag = _text(args[0]) or "?"
                entries.append({**base, "type": "shortcode", "name": tag, "label": f"shortcode [{tag}]",
                                "callbacks": proj.resolve_callback(args[1], file, scope), "access": "public"})
            elif fn == "register_rest_route" and len(args) >= 3:
                route = f"/{(_text(args[0]) or '?').strip('/')}/{(_text(args[1]) or '?').lstrip('/')}"
                for cfg in _rest_configs(args[2]):
                    perm = cfg.get("permission_callback")
                    if perm is None:
                        access, ptxt = "public", "missing"
                    elif perm.get("type") == "string" and perm.get("value", "").lstrip("\\") == "__return_true":
                        access, ptxt = "public", "__return_true"
                    else:
                        access, ptxt = "restricted", "custom"
                    methods = _text(cfg.get("methods")) or ""
                    entries.append({**base, "type": "rest", "name": route, "permission_callback": ptxt,
                                    "label": f"REST route {route} [{methods or 'GET'}] permission_callback={ptxt}",
                                    "callbacks": proj.resolve_callback(cfg["callback"], file, scope),
                                    "access": access})
    for e in entries:
        e["scopes"] = set().union(*(proj.reach(k) for k in e["callbacks"])) if e["callbacks"] else set()
    return entries


def public_entry(e: dict) -> dict:
    return {k: e[k] for k in ("type", "name", "label", "access", "file", "line") if k in e}


def _finding(rule_kind, rule_id, conf, file, line, scope, entry, reason, sink):
    f = Finding(rule_id=rule_id, kind=rule_kind, severity="HIGH", confidence=conf, file=file, line=line,
                message=reason, evidence=Evidence(source=entry["label"], sink=sink, reason=reason),
                function=scope, entry_points=[public_entry(entry)])
    return f


def audit(proj: Project, entries: list[dict]) -> list[Finding]:
    """Flag state-changing callbacks lacking capability / nonce checks (callee-aware, flow-insensitive)."""
    out, seen = [], set()
    for e in entries:
        if e["type"] not in AUDITED:
            continue
        for cb in e["callbacks"]:
            reach = proj.reach(cb)
            nodes = [n for k in reach for n in proj.scopes.get(k, [])]
            ops = [(k, op) for k in sorted(reach) for op in write_ops(proj.scopes.get(k, []))]
            if not ops:
                continue
            (wfile, wscope), (wline, wname) = next(((k, o) for k, o in ops if k == cb), ops[0])
            has_authz, has_nonce = guards(nodes)
            findings = []
            if e["type"] == "rest":
                if e["access"] == "public" and not has_authz:
                    why = ("permission_callback is missing" if e["permission_callback"] == "missing"
                           else "permission_callback is '__return_true'")
                    findings.append(("broken_access_control", "ZDH-BROKEN-ACCESS-CONTROL", 92,
                                     f"Public REST route performs state-changing '{wname}' ({why}) with no current_user_can() check."))
            else:
                public = e["access"] == "public"
                if not has_authz:
                    findings.append(("broken_access_control", "ZDH-BROKEN-ACCESS-CONTROL", 90 if public else 86,
                                     f"Handler for {e['label']} performs state-changing '{wname}' without any current_user_can() check "
                                     f"in the callback or the helpers it calls."))
                if not has_nonce:
                    findings.append(("csrf", "ZDH-CSRF", 88 if public else 85,
                                     f"Handler for {e['label']} performs state-changing '{wname}' without wp_verify_nonce()/check_ajax_referer()."))
            for kind, rid, conf, msg in findings:
                key = (rid, wfile, wline)
                if key in seen:
                    continue
                seen.add(key)
                out.append(_finding(kind, rid, conf, wfile, wline, wscope, e, msg, wname))
    return out
