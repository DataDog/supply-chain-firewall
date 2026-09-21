# Reverse-proxy lockfile risk commands

Run these commands only in disposable test projects. They create or update
dependency manifests, lockfiles, or generated requirement files. Because the
experimental reverse proxy replaces registry and artifact URLs with an
ephemeral loopback URL, commands that rewrite those files might persist a URL
that stops working when `scfw proxy` exits.

The examples use small public packages. Replace workspace names and input files
where indicated.

## npm

Potentially rewritten files: `package-lock.json` and `npm-shrinkwrap.json`.

```sh
scfw proxy -- npm install left-pad@1.3.0
scfw proxy -- npm install --package-lock-only left-pad@1.3.0
scfw proxy -- npm update left-pad
scfw proxy -- npm uninstall left-pad
scfw proxy -- npm shrinkwrap
```

The npm adapter enables `omit-lockfile-registry-resolved` and
`replace-registry-host`, so these are expected not to persist the ephemeral URL.
They are included as regression probes for that protection.

## Yarn (`yarn` and `yarnpkg`)

Potentially rewritten file: `yarn.lock`.

```sh
scfw proxy -- yarn add left-pad@1.3.0
scfw proxy -- yarn up left-pad
scfw proxy -- yarn upgrade left-pad
scfw proxy -- yarn remove left-pad
scfw proxy -- yarn workspace workspace-name add left-pad@1.3.0

scfw proxy -- yarnpkg add left-pad@1.3.0
```

Plain `yarn install` uses immutable mode for modern Yarn and pure-lockfile mode
for Yarn Classic. The mutating commands above are the risky cases.

## pnpm

Potentially rewritten file: `pnpm-lock.yaml`.

```sh
scfw proxy -- pnpm add left-pad@1.3.0
scfw proxy -- pnpm update left-pad
scfw proxy -- pnpm up left-pad
scfw proxy -- pnpm remove left-pad
scfw proxy -- pnpm import
```

Plain `pnpm install` uses `--frozen-lockfile`; the commands above intentionally
modify dependency state.

## Bun

Potentially rewritten files: `bun.lock` and, for older Bun versions,
`bun.lockb`.

```sh
scfw proxy -- bun add left-pad@1.3.0
scfw proxy -- bun update left-pad
scfw proxy -- bun remove left-pad
```

Plain `bun install` uses `--frozen-lockfile`; the commands above intentionally
modify dependency state.

## pip (`pip` and `pip3`)

Ordinary `pip install` does not write a project lockfile. Pip versions that
provide `pip lock` can generate `pylock.toml`, which should be checked for local
proxy URLs:

```sh
scfw proxy -- pip lock -r requirements.txt -o pylock.toml
scfw proxy -- pip3 lock -r requirements.txt -o pylock.toml
```

The `lock` command is version-dependent. Skip these probes if the installed pip
does not provide it.

## Poetry

Potentially rewritten files: `poetry.lock` and `pyproject.toml`.

```sh
scfw proxy -- poetry add idna@3.10
scfw proxy -- poetry update idna
scfw proxy -- poetry remove idna
scfw proxy -- poetry lock
```

`poetry install` and `poetry sync` require a current lockfile in proxy mode. The
commands above intentionally regenerate dependency state.

## uv

Potentially rewritten files: `uv.lock`, `pyproject.toml`, and generated
requirements files.

```sh
scfw proxy -- uv add idna==3.10
scfw proxy -- uv remove idna
scfw proxy -- uv lock
scfw proxy -- uv pip compile requirements.in --emit-index-url --output-file requirements.txt
```

`uv sync` uses `--frozen`; the commands above intentionally regenerate project
or requirements state.

## Checking the result

After each command, search generated dependency files for loopback URLs:

```sh
rg -n 'https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?/' \
  package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml \
  bun.lock poetry.lock uv.lock pylock.toml requirements.txt 2>/dev/null
```

Any match containing the proxy's ephemeral port is a persistence bug or a
known limitation of the reverse-proxy experiment.
