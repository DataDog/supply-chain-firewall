.PHONY: checks coverage

checks: typecheck lint coverage

coverage: test coverage-report

typecheck:
	mypy --install-types --non-interactive scfw

lint:
	flake8 scfw --count --show-source --statistics --max-line-length=120

test:
	coverage run --source=scfw -m pytest tests/

coverage-report:
	coverage report
