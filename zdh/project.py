"""Project-wide function index and call resolution (cross-file)."""
from __future__ import annotations
from dataclasses import dataclass, field

DEF_KINDS = {"Function_", "ClassMethod", "Closure", "ArrowFunction"}
CALL_KINDS = {"FuncCall", "MethodCall", "StaticCall"}
SELF_CLASSES = {"self", "static", "parent"}


@dataclass
class FuncDef:
    file: str
    scope: str            # unique name inside the file: "foo", "Cls::meth", "Cls::{closure}@12"
    name: str | None      # bare lowercase name for functions/methods; None for closures
    cls: str | None
    params: list = field(default_factory=list)
    line: int = 0

    @property
    def key(self):
        return (self.file, self.scope)


def last_segment(name: str) -> str:
    return (name or "").rsplit("\\", 1)[-1].lower()


def class_of_scope(scope: str):
    return scope.split("::", 1)[0] if "::" in scope else None


class Project:
    def __init__(self):
        self.scopes: dict[tuple, list] = {}
        self.defs: dict[tuple, FuncDef] = {}
        self.by_name: dict[str, list[FuncDef]] = {}
        self._callees: dict[tuple, set] = {}

    def add_file(self, file: str, ast: dict):
        for n in ast.get("nodes", []):
            scope = n.get("scope", "") or ""
            self.scopes.setdefault((file, scope), []).append(n)
            if n.get("kind") in DEF_KINDS and scope:
                name = n.get("name")
                d = FuncDef(file, scope, name.lower() if name else None, n.get("class"), n.get("params", []), n.get("line", 0))
                self.defs[d.key] = d
                if d.name:
                    self.by_name.setdefault(d.name, []).append(d)
        self.scopes.setdefault((file, ""), [])

    # --- resolution -------------------------------------------------------
    def resolve_call(self, node: dict, file: str, scope: str) -> list[FuncDef]:
        kind = node.get("kind")
        if kind == "FuncCall":
            return [d for d in self.by_name.get(last_segment(node.get("name", "")), []) if d.cls is None]
        if kind == "MethodCall":
            base = node.get("base") or {}
            if base.get("type") == "var" and base.get("name") == "this":
                return self._methods(node.get("method"), class_of_scope(scope))
            return []
        if kind == "StaticCall":
            cls = node.get("class") or ""
            cls = class_of_scope(scope) if cls.lower() in SELF_CLASSES else last_segment(cls)
            return self._methods(node.get("method"), cls) if cls else []
        return []

    def _methods(self, name, cls):
        if not name or not cls:
            return []
        return [d for d in self.by_name.get(name.lower(), []) if d.cls and d.cls.lower() == cls.lower()]

    def resolve_callback(self, expr: dict | None, file: str, scope: str) -> list[tuple]:
        """Map a callback expression (string / [obj,'m'] / closure) to function keys."""
        if not isinstance(expr, dict):
            return []
        t = expr.get("type")
        if t == "string":
            v = expr.get("value", "")
            if "::" in v:
                cls, m = v.split("::", 1)
                return [d.key for d in self._methods(m, last_segment(cls))]
            return [d.key for d in self.by_name.get(last_segment(v), []) if d.cls is None]
        if t == "closure":
            k = (file, expr.get("scope"))
            return [k] if k in self.scopes else []
        if t == "array":
            vals = [i["value"] for i in expr.get("items", [])]
            if len(vals) == 2 and vals[1].get("type") == "string":
                m, first, cls = vals[1]["value"].lower(), vals[0], None
                if first.get("type") == "var" and first.get("name") == "this":
                    cls = class_of_scope(scope)
                elif first.get("type") == "string":
                    cls = class_of_scope(scope) if first["value"].lower() in SELF_CLASSES else last_segment(first["value"])
                return [d.key for d in self.by_name.get(m, []) if d.cls and (cls is None or d.cls.lower() == cls.lower())]
        return []

    def callees(self, key: tuple) -> set:
        if key not in self._callees:
            out = set()
            for n in self.scopes.get(key, []):
                if n.get("kind") in CALL_KINDS:
                    out.update(d.key for d in self.resolve_call(n, key[0], key[1]))
            self._callees[key] = out
        return self._callees[key]

    def reach(self, key: tuple) -> set:
        """key plus every function transitively called from it."""
        seen, todo = set(), [key]
        while todo:
            k = todo.pop()
            if k in seen:
                continue
            seen.add(k)
            todo.extend(self.callees(k))
        return seen
