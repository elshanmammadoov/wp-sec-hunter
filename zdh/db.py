import sqlite3, json
from pathlib import Path
class DB:
    def __init__(self,path='zdh.db'):
        self.c=sqlite3.connect(path); self.c.execute('''CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, repo TEXT, rule_id TEXT, kind TEXT, severity TEXT, confidence INTEGER, file TEXT, line INTEGER, data TEXT, UNIQUE(repo,rule_id,file,line))'''); self.c.commit()
    def add(self,f,repo=None):
        self.c.execute('INSERT OR IGNORE INTO findings(repo,rule_id,kind,severity,confidence,file,line,data) VALUES(?,?,?,?,?,?,?,?)',(repo,f.rule_id,f.kind,f.severity,f.confidence,f.file,f.line,json.dumps(f.to_dict()))); self.c.commit()
