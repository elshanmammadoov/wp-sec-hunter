# ZeroDayHunter

ZeroDayHunter is an authorized/public-source PHP security research engine. It discovers fresh, low-popularity repositories and performs evidence-oriented static analysis. It does **not** automatically exploit Internet targets.

## Design goals
- High signal over raw finding count
- AST-first PHP analysis
- Source → propagation → sink reasoning
- Security-control awareness
- WordPress AJAX/REST awareness
- Git history and dependency metadata
- Deduplication and confidence scoring
- Reproducible evidence

## Requirements
- Python 3.11+
- PHP 8.x
- Composer

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
composer install --no-interaction --prefer-dist
```

Optional GitHub token:
```bash
export GITHUB_TOKEN='YOUR_TOKEN'
```

## Safe local fixture test
```bash
python -m zdh.cli scan tests/fixtures/vulnerable.php
python -m pytest -q
```

## Hunt public repositories
```bash
python -m zdh.cli hunt --days 7 --stars 10 --pages 2 --workers 4
```

Results are written to `reports/` and `zdh.db`.

A `HIGH` result means **high-confidence candidate**, not a CVE. Manual verification and responsible disclosure are still required.
