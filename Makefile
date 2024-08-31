install:
	pip install .

install-dev:
	pip install -r requirements-dev.txt
	pip install .

checks: typecheck lint test

coverage: test coverage-report

test: test-cli test-pip test-npm test-verifiers

typecheck:
	mypy --install-types --non-interactive scfw

lint:
	flake8 scfw --count --show-source --statistics --max-line-length=120

test-cli:
	COVERAGE_FILE=.coverage.cli coverage run -m pytest tests/test_cli.py

test-pip:
	COVERAGE_FILE=.coverage.pip coverage run -m pytest tests/commands/test_pip.py tests/commands/test_pip_command.py

test-npm:
	COVERAGE_FILE=.coverage.npm coverage run -m pytest tests/commands/test_npm.py tests/commands/test_npm_command.py

test-verifiers:
	COVERAGE_FILE=.coverage.verifiers coverage run -m pytest tests/verifiers

coverage-report:
	coverage combine .coverage.cli .coverage.pip .coverage.npm .coverage.verifiers
	coverage report

docs:
	pdoc --docformat google ./scfw > /dev/null &

.PHONY: checks coverage test
