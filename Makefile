install:
	pip install .

install-dev:
	pip install -r requirements-dev.txt
	pip install .

checks: typecheck lint test

coverage: test coverage-report

test: test-cli test-configure test-python-executable test-pip test-pip-class test-poetry test-poetry-class test-npm test-npm-class test-go test-go-class test-verifiers

typecheck:
	mypy --install-types --non-interactive scfw

lint:
	flake8 scfw --count --show-source --statistics --max-line-length=120

test-cli:
	COVERAGE_FILE=.coverage.cli coverage run -m pytest tests/test_cli.py

test-configure:
	COVERAGE_FILE=.coverage.configure coverage run -m pytest tests/test_configure.py

test-python-executable:
	COVERAGE_FILE=.coverage.python.executable coverage run -m pytest tests/package_managers/test_pip_class.py -k test_executable

test-pip:
	COVERAGE_FILE=.coverage.pip coverage run -m pytest tests/package_managers/test_pip.py

test-pip-class:
	COVERAGE_FILE=.coverage.pip.class coverage run -m pytest tests/package_managers/test_pip_class.py -k 'not test_executable'

test-poetry:
	COVERAGE_FILE=.coverage.poetry coverage run -m pytest tests/package_managers/test_poetry.py

test-poetry-class:
	COVERAGE_FILE=.coverage.poetry.class coverage run -m pytest tests/package_managers/test_poetry_class.py

test-npm:
	COVERAGE_FILE=.coverage.npm coverage run -m pytest tests/package_managers/test_npm.py

test-npm-class:
	COVERAGE_FILE=.coverage.npm.class coverage run -m pytest tests/package_managers/test_npm_class.py

test-go:
	COVERAGE_FILE=.coverage.go coverage run -m pytest tests/package_managers/test_go.py

test-go-class:
	COVERAGE_FILE=.coverage.go.class coverage run -m pytest tests/package_managers/test_go_class.py

test-verifiers:
	COVERAGE_FILE=.coverage.verifiers coverage run -m pytest tests/verifiers

coverage-report:
	coverage combine .coverage.cli .coverage.configure \
	.coverage.python.executable .coverage.pip .coverage.pip.class \
	.coverage.poetry .coverage.poetry.class \
	.coverage.npm .coverage.npm.class \
	.coverage.go .coverage.go.class \
	.coverage.verifiers
	coverage report

docs:
	pdoc --docformat google ./scfw > /dev/null &

clean:
	rm -rf .mypy_cache .pytest_cache .coverage* build scfw.egg-info
	find . -name '__pycache__' -print0 | xargs -0 rm -rf

.PHONY: checks clean coverage install install-dev test
