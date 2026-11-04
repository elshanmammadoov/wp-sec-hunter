setup:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -r requirements.txt
	composer install --no-interaction --prefer-dist

test:
	. .venv/bin/activate && python -m pytest -q

scan:
	. .venv/bin/activate && python -m zdh.cli scan tests/fixtures/vulnerable.php
