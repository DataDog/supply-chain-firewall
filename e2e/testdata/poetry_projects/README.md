# Poetry project lifecycle

`poetry-projects` runs real Poetry commands against public PyPI through the GoReleaser SCFW executable. It reuses the `poetry-uv-graph` discovery evidence and native locks from `poetry_uv_graph_cache`; the manifest, installed-package inspector and archive evidence helpers come from `poetry_baseline`. No registry or verifier is replaced.

| Scenario | Variants | Cells |
| --- | --- | --- |
| POETRY-01 | Fresh install, current-lock sync, add upgrade/downgrade, stale-lock update, current update | Poetry 2.0 and 2.5+, both modes |
| POETRY-02 | Fresh lock, regenerate a stale lock with warm metadata/cold artifacts, add --lock | Modern Poetry, proxy |
| POETRY-04 | --directory, -C, symlink followed by parent traversal | Modern Poetry, both modes |
| CORE-11 | Inspected command rejected; informational --version passes directly | Real Poetry 1.8.5, both modes |
| CORE-14 | Stale install, missing release, install failure after dependency approval | Modern Poetry, both modes |

Fresh installs, current-lock syncs, upgrades, downgrades, stale-lock updates and directory variants have ALLOW and exact-version BLOCK cases. Resolution denial must preserve live manifest and lock contents and existence. Proxy denial forbids installation of the blocked version while allowing native partial changes to unrelated dependencies. The failure cases compare exits and expected error diagnostics with an isolated native control; stale installs and missing releases preserve the live files. The post-approval failure installs dependencies but fails to install the deliberately missing local project, matching native Poetry's exit.

Directory cases use a distinguishable empty caller and check the selected repository in reports. Both projects have isolated virtual environments; a read-only native `env info --executable` control selects the installation oracle and rejects paths outside that pair. Symlink-plus-parent traversal can select a physical manifest and a lexically resolved environment; the other environment must remain empty. The inherited `poetry-project-selection` suite covers `--project`/`-P`, attached/equals/relative forms, discovered parents and physical symlink traversal in both modes, including preservation of both live projects on resolution denial.

Metadata-only operations carry a blocking finding for the exact root, retain the resulting native lock, and require no distribution decision or artifact cache entry. Current updates preserve the installed exact version and produce no package decisions. Selected versions, native locks, manifest snapshots, policy records, archive checksums, interpreter observations and cleanup evidence remain in the external run output.

Run with the shared harness inputs from `e2e/README.md`, `SCFW_E2E_SUITES=poetry-projects`, and this directory's matrix example updated to exact local executable paths. Modern cells declare `poetry-modern`; the 1.x negative cell declares `poetry-legacy`. Run `TestPlan`, `TestDiscover`, then `TestE2E` with a new output directory per run. Missing executables and failed assertions are failures. Capability N/A means a modern scenario on a legacy cell or the reverse.

Native validation is recorded for Linux arm64 with Python 3.12.10 and Poetry 2.0.0, 2.5.1 and 1.8.5. Native macOS and other architectures require their own runners; cross-platform release builds do not replace those runs.
