from __future__ import annotations
import json, os, subprocess
from pathlib import Path

class PHPParser:
    def __init__(self, project_root: str):
        self.root = Path(project_root)
        self.script = Path(__file__).resolve().parent.parent / "php_parser" / "parse.php"
        self.php = "php"

    def parse(self, file: str):
        p = subprocess.run([self.php, str(self.script), str(file)], capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            return None, p.stderr.strip()
        try:
            return json.loads(p.stdout), None
        except json.JSONDecodeError:
            return None, "invalid parser output"

def php_files(root, max_files=3000, max_bytes=2_000_000):
    root = Path(root)
    out=[]
    skip={".git","vendor","node_modules","dist","build","cache","storage","tmp"}
    for p in root.rglob("*.php"):
        if any(part in skip for part in p.parts): continue
        try:
            if p.stat().st_size <= max_bytes:
                out.append(p)
        except OSError: pass
        if len(out)>=max_files: break
    return out
