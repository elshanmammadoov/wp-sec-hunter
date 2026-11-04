from __future__ import annotations
import argparse, os, subprocess, shutil
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from rich.console import Console
from rich.table import Table
from .config import Config
from .github import GitHubClient
from .scoring import repo_score
from .php import PHPParser, php_files
from .analyzer import Analyzer
from .db import DB
from .report import write

C=Console()

def scan_path(path):
    root=Path(path).resolve(); parser=PHPParser(str(root)); analyzer=Analyzer(parser); findings=[]
    files=[root] if root.suffix.lower()=='.php' else php_files(root)
    for f in files:
        try: findings += analyzer.analyze(f)
        except Exception as e: C.print(f'[yellow]skip[/] {f}: {e}')
    return findings

def clone_repo(item, base='repos'):
    name=item['full_name'].replace('/','__'); dest=Path(base)/name; dest.parent.mkdir(exist_ok=True)
    if (dest/'.git').exists():
        subprocess.run(['git','-C',str(dest),'fetch','--depth','1','origin'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
        subprocess.run(['git','-C',str(dest),'reset','--hard','origin/HEAD'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
    else:
        subprocess.run(['git','clone','--depth','1',item['clone_url'],str(dest)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120,check=True)
    return dest

def cmd_scan(a):
    fs=scan_path(a.path); p=write(fs,'local.json'); C.print(f'[bold]Findings:[/] {len(fs)}  [bold]Report:[/] {p}')
    for f in sorted(fs,key=lambda x:x.confidence,reverse=True): C.print(f'{f.severity:6} {f.confidence:3}% {f.kind:28} {f.file}:{f.line}')

def cmd_hunt(a):
    token=os.getenv('GITHUB_TOKEN'); gh=GitHubClient(token,Config.github_timeout)
    cutoff=(datetime.now(timezone.utc)-timedelta(days=int(a.days))).date().isoformat()
    terms=['school','booking','shop','store','cms','crm','lms','membership','ajax','api']
    queries=[f'language:PHP stars:<={a.stars} pushed:>={cutoff} fork:false archived:false {t}' for t in terms]
    repos=[]
    for q in queries: repos += gh.search_repositories(q,a.pages)
    repos=sorted({r['full_name']:r for r in repos}.values(), key=repo_score, reverse=True)
    C.print(f'[cyan]Discovered:[/] {len(repos)} repositories')
    allf=[]; db=DB()
    def worker(r):
        d=clone_repo(r); fs=scan_path(d)
        for f in fs: f.repo=r['full_name']
        try:
            f.commit=subprocess.check_output(['git','-C',str(d),'rev-parse','HEAD'],text=True).strip()
        except Exception: pass
        return r,fs
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futures=[ex.submit(worker,r) for r in repos]
        for fut in as_completed(futures):
            try:
                r,fs=fut.result(); allf += fs
                for f in fs: db.add(f,r['full_name'])
                C.print(f'[green]✓[/] {r["full_name"]}: {len(fs)} candidates')
            except Exception as e: C.print(f'[red]repo failed:[/] {e}')
    p=write(allf); C.print(f'[bold green]Done.[/] {len(allf)} candidates → {p}')

def main():
    ap=argparse.ArgumentParser(prog='zdh'); sub=ap.add_subparsers(required=True)
    s=sub.add_parser('scan'); s.add_argument('path'); s.set_defaults(fn=cmd_scan)
    h=sub.add_parser('hunt'); h.add_argument('--days',default=7); h.add_argument('--stars',type=int,default=10); h.add_argument('--pages',type=int,default=1); h.add_argument('--workers',type=int,default=4); h.set_defaults(fn=cmd_hunt)
    a=ap.parse_args(); a.fn(a)
if __name__=='__main__': main()
