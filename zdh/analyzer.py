from __future__ import annotations
import re
from pathlib import Path
from .models import Finding, Evidence

SOURCES = {"_GET","_POST","_REQUEST","_COOKIE","_FILES","_SERVER"}
XSS_SINKS = {"echo","print","printf","vprintf"}
CMD_SINKS = {"system","exec","shell_exec","passthru","proc_open","popen"}
SQL_SINKS = {"mysqli_query","mysql_query","pg_query","sqlite_query","query","exec"}
INCLUDE_SINKS = {"include","include_once","require","require_once"}
FILE_SINKS = {"file_put_contents","fopen","unlink","rename","copy","move_uploaded_file"}
UNSAFE = {"eval","assert","unserialize","preg_replace"}
SAFE_XSS = {"htmlspecialchars","htmlentities","esc_html","esc_attr","wp_kses","wp_kses_post"}
SAFE_SQL = {"prepare","wpdb->prepare"}

class Analyzer:
    def __init__(self, parser): self.parser=parser

    def _source(self, text):
        return next((s for s in SOURCES if re.search(rf'\$_{s[1:]}\b', text)), None)

    def analyze(self, path: Path):
        code=path.read_text(errors="ignore")
        findings=[]
        ast, err=self.parser.parse(str(path))
        if ast:
            findings += self._ast_findings(path, code, ast)
        # Fallback is deliberately LOW confidence: it can never become HIGH without AST evidence.
        findings += self._obvious_raw_findings(path, code) if not ast else []
        return findings

    def _ast_findings(self, path, code, ast):
        nodes=ast.get("nodes",[]); out=[]
        recent_sources=[]
        for n in nodes:
            kind=n.get("kind"); line=n.get("line",0)
            if kind=="Variable" and n.get("name") in SOURCES:
                recent_sources.append((n.get("name"),line))
            if kind=="FuncCall":
                name=(n.get("name") or "").lower()
                args=n.get("args",[])
                argtext=str(args)
                src=next((s for s in SOURCES if s in argtext),None)
                if name in CMD_SINKS and src:
                    out.append(self._finding(path,line,"command_injection", "HIGH", 88, src,name,"User-controlled input reaches a command-execution sink in the same analyzed region."))
                elif name in INCLUDE_SINKS and src:
                    out.append(self._finding(path,line,"file_inclusion", "HIGH", 86, src,name,"User-controlled input reaches an include/require sink."))
                elif name in UNSAFE and src:
                    out.append(self._finding(path,line,"unsafe_deserialization_or_code", "HIGH", 84, src,name,"User-controlled input reaches a security-sensitive PHP primitive."))
                elif name in FILE_SINKS and src:
                    out.append(self._finding(path,line,"file_operation", "MEDIUM", 68, src,name,"User-controlled input reaches a file operation; path/filename semantics require verification."))
                elif name in SQL_SINKS and src and "prepare" not in name:
                    out.append(self._finding(path,line,"sql_injection", "HIGH", 82, src,name,"User-controlled input appears to reach a database query sink without evidence of a parameterized query."))
            if kind in {"Echo_","Print_"}:
                raw=code.splitlines()[line-1] if 0<line<=len(code.splitlines()) else ""
                src=self._source(raw)
                if src and not any(x in raw.lower() for x in SAFE_XSS):
                    out.append(self._finding(path,line,"xss", "HIGH", 90, src,"echo/print","Direct user-controlled output with no recognized HTML escaping on the same statement."))
        return out

    def _obvious_raw_findings(self,path,code):
        out=[]
        for i,line in enumerate(code.splitlines(),1):
            m=re.search(r'\b(echo|print)\b.*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b',line,re.I)
            if m:
                out.append(self._finding(path,i,"xss", "LOW", 45,"$_INPUT","echo/print","Regex-only candidate; AST verification is unavailable."))
            m=re.search(r'\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(.*\$_(GET|POST|REQUEST|COOKIE|SERVER)',line,re.I)
            if m:
                out.append(self._finding(path,i,"command_injection", "LOW", 45,"$_INPUT",m.group(1),"Regex-only candidate; AST verification is unavailable."))
            m=re.search(r'\b(include|include_once|require|require_once)\s*\(?.*\$_(GET|POST|REQUEST|COOKIE|SERVER)',line,re.I)
            if m:
                out.append(self._finding(path,i,"file_inclusion", "LOW", 45,"$_INPUT",m.group(1),"Regex-only candidate; AST verification is unavailable."))
        return out

    def _finding(self,path,line,kind,severity,confidence,source,sink,reason):
        return Finding(rule_id=f"ZDH-{kind.upper()}",kind=kind,severity=severity,confidence=confidence,file=str(path),line=line,message=reason,evidence=Evidence(source=source,sink=sink,reason=reason))
