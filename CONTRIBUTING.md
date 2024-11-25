# Contributing to Supply Chain Firewall

We welcome community contributions to the supply chain firewall.

## :hammer_and_wrench: Setting up for development

To set up for development and testing, create a fresh `virtualenv`,
activate it and run `make install-dev`.  This will install `scfw` as
well as its development dependencices.

### Documentation

API documentation may be built via `pdoc` by running `make docs` in
your development environment.  This will automatically open the
documentation in your system's default browser.

### Testing

Execute the test suite by running `make test` in your development
environment.  To additionally view code coverage, run `make coverage`.

### Code quality

The test suite contains code quality checks in the form of
type-checking and linting.  Run `make typecheck` or `make lint`,
respectively, in your development environment.

You can run `make checks` to execute all tests and code quality
checks.  Up to matrix testing across `pip` and `npm` versions, this is
the same set of checks that run in the repository's CI for pull
requests.  The repository also contains a pre-commit hook to run these
checks on each commit, if so desired.

## :bug: Creating issues

Before opening a new issue, first check to see whether the same or a
similar issue already exists.  If not, please feel free to open a new
issue while selecting an appropriate label (bug, enhancement, etc.) to
assist with issue prioritization.

## :white_check_mark: Opening pull requests

To work on an issue, create a new branch following the naming scheme
`<GitHub username>/<branch-function>`.  When you have finished making
your changes, create a pull request with a succinct description of 1)
the issue your pull request addresses, 2) the changes you have made
and 3) any special information a reviewer should be aware of.
