import json, os
from pathlib import Path

def write(findings, name='latest.json'):
    Path('reports').mkdir(exist_ok=True)
    data=[f.to_dict() for f in sorted(findings,key=lambda x:x.confidence,reverse=True)]
    p=Path('reports')/name
    p.write_text(json.dumps(data,indent=2,ensure_ascii=False))
    return p
