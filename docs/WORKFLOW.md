# WORKFLOW.md — TakeItToCloud tool development workflow

Canonical source: `TakeItoCloud/template-ps-tool` → `docs/WORKFLOW.md`.
Copies in other repos are mirrors. If a mirror disagrees with the canonical file, the
canonical file wins; fix the mirror, do not fork the rule.

Applies to every tool repo instantiated from `template-ps-tool`, plus `ps-toolbox`.
Single maintainer. There is no second reviewer, so the controls below substitute for one
deliberately.

## 1. Model

Trunk-based. One long-lived branch: `main`.

- `main` is always releasable and always GREEN.
- No `develop`, no long-lived feature or release branches.
- All work happens on short-lived branches merged into `main` via a pull request.
- A branch living longer than about two working days is a scope failure: split it.

## 2. Branches

| Purpose | Pattern | Example |
|---|---|---|
| PORT-PLAN phase work | `phase/<n>-<slug>` | `phase/3-graph-collector` |
| Feature (non-phase) | `feat/<slug>` | `feat/csv-export` |
| Bug fix | `fix/<slug>` | `fix/null-tenant-id` |
| Chore / deps / infra | `chore/<slug>` | `chore/bump-pester` |
| Docs only | `docs/<slug>` | `docs/readme-install` |

1. One phase = one branch = one PR. Batching phases into a single PR defeats the per-phase
   green gate and is not permitted.
2. Branch from current `main`, never from another branch.
3. Refresh a stale branch with `git pull --rebase origin main` — rebase, not merge.
4. Delete the branch after merge.

## 3. Commits

In-branch commits are free-form and squashed at merge, so `wip` never reaches `main`.

The PR title becomes the trunk commit message and must follow Conventional Commits:

```
<type>(<optional scope>): <imperative summary>
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`.
Breaking change: append `!` — `feat(graph)!: drop v1.0 endpoints`.

Release automation derives the version bump and release notes from these titles:
`feat` → minor, `fix`/`perf` → patch, `!` → major.

## 4. Pull requests

Every PR targets `main`, carries a Conventional Commits title, and has the checklist from
`.github/pull_request_template.md` ticked by hand on the PR page.

The checklist covers only what a machine cannot verify. Anything a test or linter can check
belongs in CI, not on the list.

CI on the PR:

- `test` — Pester v5 suite
- `lint` — PSScriptAnalyzer against `PSScriptAnalyzerSettings.psd1`
- `pr-hygiene` — fails on unticked boxes in the PR body and on a non-conforming PR title

## 5. Merge

- Squash and merge only. Merge commits and rebase merges are disabled at repo level.
- The squash commit message is the PR title; edit the body to the release-note-worthy summary.
- The head branch is deleted on merge.
- Never merge red. A failing build is not fixed "on main".

### Direct pushes to `main`

Not permitted, including for one-line documentation fixes. `.githooks/pre-push` refuses them.

Overriding with `git push --no-verify` requires a dated line in `CHANGELOG.md` stating what
was pushed and why. An unrecorded bypass is a process failure, not a mistake.

### Rewriting `main`

`git push --force`, `--force-with-lease`, and any reset of `main` to an earlier commit are
prohibited. A force push is a larger violation than the direct push it usually intends to
clean up: it destroys history other clones may already hold.

If a bad commit reaches `main`, revert it with `git revert` and a normal PR. An empty commit
is not worth rewriting history for — leave it.

If `main` is rewritten regardless, it requires a dated `CHANGELOG.md` entry recording the
prior SHA, the new SHA, and the reason — the same standard as a `--no-verify` bypass.

## 6. Versioning and releases

Semantic Versioning. The version of record is `ModuleVersion` in
`src\<ToolName>\<ToolName>.psd1`. Tags mirror it with a `v` prefix.

Releases are not per phase. A phase ticks `PORT-PLAN.md`; a release ships behaviour. Cut one
when `CHANGELOG.md`'s `Unreleased` section holds something worth distributing.

From a green `main`:

1. Branch `release/<version>`: bump `ModuleVersion`, promote `Unreleased` to
   `## [x.y.z] - YYYY-MM-DD`.
2. PR, squash merge with title `build: release vX.Y.Z`.
3. Tag: `git switch main; git pull; git tag -a vX.Y.Z -m "vX.Y.Z"; git push origin vX.Y.Z`
4. Package: `.\build\package.ps1` — it reads `ModuleVersion` from the manifest, writes
   `dist\<ToolName>-v<Version>.zip`, and prints the artifact path.
5. Create the GitHub Release for the tag and attach that zip.

`package.ps1` throws if `src\` does not hold exactly one module folder, if the manifest is
missing, or if `README.md`/`CHANGELOG.md` are absent. Do not work around those throws — they
are the release gate.

Distribution to any machine uses the packaged zip from GitHub Releases, never a clone of the
working tree.

Hotfix: same flow via a `fix/` branch and a patch bump. No hotfix branch off a tag.

## 7. Definition of GREEN

1. Pester v5 suite passes, including new tests for the change.
2. PSScriptAnalyzer clean against the repo settings file.
3. No stubs, `TODO`, or `NotImplemented` in anything declared delivered.
4. Verified against real, sanitized data — not only mocks — with the result stated explicitly.

The command that proves items 1 and 2 is defined per repository in its `README.md` under a
"Green gate" heading, because layouts differ. Where the README does not say, the gate is:

```powershell
Invoke-Pester -CI
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

A repository whose gate is not the default MUST state its command in the README. A repository
where the default command is red but a narrower one is green is not green — it is a defect
with a documented workaround, and it belongs in the plan as a phase.

"Passes the build" is necessary, not sufficient. Item 4 is what catches real defects.

## 8. What is actually enforced

The tool repos are private under a GitHub Free personal account. GitHub makes rulesets and
branch protection available for private repositories only on Pro, Team, and Enterprise Cloud.
So:

| Rule | Enforced by | Blocks? |
|---|---|---|
| No direct push to `main` | `.githooks/pre-push` (local) | Yes, unless `--no-verify` |
| No force-push / reset of `main` | `.githooks/pre-push` (any push to `refs/heads/main`) | Yes, unless `--no-verify` |
| Squash-only merge | Repo setting | Yes |
| Branch deleted on merge | Repo setting | Yes |
| Tests + lint green before merge | CI status check | No — advisory on Free |
| Checklist ticked, PR title format | `pr-hygiene` CI | No — advisory on Free |
| PR required before merge | — | No — convention only |

The gap is the reason the checklist exists: on this plan the discipline is the control.
Upgrading the account to GitHub Pro turns rows 4–6 into hard blocks with no file change —
`Set-GitHubRepoBaseline.ps1` applies the ruleset on its next run.

Git hooks are not cloned with a repository. `build/init-tool.ps1` sets `core.hooksPath` on
instantiation; an existing clone needs `git config core.hooksPath .githooks` run once.

## 9. Repo settings baseline

Applied and drift-checked by `Set-GitHubRepoBaseline.ps1` in `ps-toolbox` (table-driven,
`-WhatIf` by default). Repository settings are NOT inherited when a repo is created from a
template — GitHub copies files only — so the baseline must be applied to each new repo.

| Setting | Value |
|---|---|
| Default branch | `main` |
| Allow squash merge | Yes |
| Allow merge commit | No |
| Allow rebase merge | No |
| Auto-delete head branch on merge | Yes (withheld where long-lived branches exist) |
| Wiki / Projects | Off for tool repos; left untouched elsewhere |
| Main-branch ruleset | Applied where the plan permits; otherwise reported
  `NotEnforced (plan)` — never reported as applied |

## 10. CI cost

Private repos on the Free plan include 2,000 Actions minutes per month, and Windows minutes
drain that quota at 2x (macOS at 10x). Run lint and the cross-platform test leg on
`ubuntu-latest` with PowerShell 7; reserve `windows-latest` for genuinely Windows-dependent
tests.

## 11. Phase work

1. Read `PORT-PLAN.md`; confirm the previous phase is ticked and `main` is green. If not,
   stop and report.
2. `git switch -c phase/<n>-<slug>` from current `main`.
3. Implement that phase's scope only. Additive and isolated — it must not be able to break
   what already works.
4. Reach GREEN per §7.
5. Update `PORT-PLAN.md` (status Done, date), `CHANGELOG.md` (dated entry), and
   `PORT-PARITY.md` where parity or history is affected.
6. Open the PR, tick the checklist, paste the green-gate results verbatim into the PR body.
7. Squash-merge, branch deleted, then STOP. Do not start the next phase without confirmation.
