# Contributing to Supply Chain Firewall

## :hammer_and_wrench: Setting up for development

To set up for development and testing, clone the repository and ensure you
can build the `scfw` binary:

```bash
git clone https://github.com/DataDog/supply-chain-firewall.git
cd supply-chain-firewall
git checkout v4
make
```

## :test_tube: Testing

Execute the full test suite by running `make test`. There are also recipes
for specific test suites (e.g., CLI tests, npm tests, etc.).  Refer to the
Makefile for details.

## :mag: Linting

Before opening a pull request, run `make lint`, which checks formatting
(`gofmt`) and runs `go vet`, as well as `make golangci-lint`, which runs
[`golangci-lint`][golangci-lint-install]. `golangci-lint` is not installed
automatically, so install it yourself, following the instructions at the
link above. It is strongly recommended to keep your local `golangci-lint`
version reasonably in sync with whatever version CI uses, so that
`make golangci-lint` behaves consistently in both places.

[golangci-lint-install]: https://golangci-lint.run/docs/welcome/install/

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
