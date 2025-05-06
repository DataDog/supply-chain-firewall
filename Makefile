install:
	pip install .

install-dev:
	pip install -r requirements-dev.txt
	pip install .

checks: typecheck lint test

coverage: test coverage-report

test: test-cli test-python-executable test-pip test-pip-command test-poetry test-poetry-command test-npm test-npm-command test-verifiers

typecheck:
	mypy --install-types --non-interactive scfw

lint:
	flake8 scfw --count --show-source --statistics --max-line-length=120

test-cli:
	COVERAGE_FILE=.coverage.cli coverage run -m pytest tests/test_cli.py

test-python-executable:
	COVERAGE_FILE=.coverage.python.executable coverage run -m pytest tests/commands/test_pip_command.py -k test_executable

test-pip:
	COVERAGE_FILE=.coverage.pip coverage run -m pytest tests/commands/test_pip.py

test-pip-command:
	COVERAGE_FILE=.coverage.pip.command coverage run -m pytest tests/commands/test_pip_command.py -k 'not test_executable'

test-poetry:
	COVERAGE_FILE=.coverage.poetry coverage run -m pytest tests/commands/test_poetry.py

test-poetry-command:
	COVERAGE_FILE=.coverage.poetry.command coverage run -m pytest tests/commands/test_poetry_command.py

test-npm:
	COVERAGE_FILE=.coverage.npm coverage run -m pytest tests/commands/test_npm.py

test-npm-command:
	COVERAGE_FILE=.coverage.npm.command coverage run -m pytest tests/commands/test_npm_command.py

test-verifiers:
	COVERAGE_FILE=.coverage.verifiers coverage run -m pytest tests/verifiers

coverage-report:
	coverage combine .coverage.cli \
	.coverage.python.executable .coverage.pip .coverage.pip.command \
	.coverage.poetry .coverage.poetry.command \
	.coverage.npm .coverage.npm.command \
	.coverage.verifiers
	coverage report

docs:
	pdoc --docformat google ./scfw > /dev/null &

clean:
	rm -rf .mypy_cache .pytest_cache .coverage* build scfw.egg-info
	find . -name '__pycache__' -print0 | xargs -0 rm -rf

.PHONY: checks clean coverage install install-dev test
