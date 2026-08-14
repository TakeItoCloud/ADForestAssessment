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

## The commands

This section is deliberately unnumbered so that §2 through §11 keep the numbers every other
document already cites.

Sections 2 to 6 are automated by three commands. They live in **`ps-toolbox`**, in
`misc/workflow/ToolWorkflow.ps1`, and they are not cloned with a tool repository — one
`ps-toolbox` clone serves every repo on the machine.

| Command | Replaces |
|---|---|
| `Start-ToolChange -Type <type> -Slug <slug> [-Phase <n>]` | §2, cutting the branch |
| `Complete-ToolChange -Title <title> ...` | §3 to §5, commit through merged and synced |
| `Publish-ToolRelease -Bump <major\|minor\|patch\|auto>` | §6, the whole release |

Make them available with `Install-ToolboxProfile`, which adds a sentinel-delimited
dot-source block to `$PROFILE`, backs up the existing profile first, and is safe to re-run.
Until it is run, or the file is dot-sourced by hand, the commands do not exist in the
session and the manual sequence each section describes is what remains.

**A repository with no CI merges anyway, and says so.** `Complete-ToolChange` waits for
checks that exist and treats a timeout as a failure. But a pull request reporting *zero*
checks is a determinate state, not a pending one — a repository with no CI workflows will
report none however long the command waits — so the step reports
`CiChecks / NotAssessed`, with the reason `no CI checks are configured on this repository;
nothing verified this change`, and the merge proceeds. That reason is carried in the
returned `CiChecks` **and** `Merge` objects, so it lands in whatever report the run is
written up in. Such a merge is verified by the local green gate of §7 and by nothing else,
and it is recorded rather than passed over quietly. There is no switch to assert this: the
command reads the repository's state, and a caller cannot claim "no CI here" about a
repository that has CI and is merely slow.

## 2. Branches

| Purpose | Pattern | Command |
|---|---|---|
| PORT-PLAN phase work | `phase/<n>-<slug>` | `Start-ToolChange -Type feat -Slug <slug> -Phase <n>` |
| Feature (non-phase) | `feat/<slug>` | `Start-ToolChange -Type feat -Slug <slug>` |
| Bug fix | `fix/<slug>` | `Start-ToolChange -Type fix -Slug <slug>` |
| Chore / deps / infra | `chore/<slug>` | `Start-ToolChange -Type chore -Slug <slug>` |
| Docs only | `docs/<slug>` | `Start-ToolChange -Type docs -Slug <slug>` |

1. One phase = one branch = one PR. Batching phases into a single PR defeats the per-phase
   green gate and is not permitted.
2. Branch from current `main`, never from another branch. `Start-ToolChange` refuses unless
   the working tree is clean, `main` is checked out, and `main` is not behind `origin/main`
   after a fast-forward pull — and it refuses if a branch of that name already exists
   locally or on origin, because that means an earlier change is unfinished.
3. Refresh a stale branch with `git pull --rebase origin main` — rebase, not merge. This one
   is not automated: rebasing can conflict, and a conflict needs a person.
4. Delete the branch after merge. `Complete-ToolChange` passes `--delete-branch`.

Every refusal names the fix. Nothing has been created when one fires, so there is no partial
state to clean up.

## 3. Commits

In-branch commits are squashed at merge, so `wip` never reaches `main`.
`Complete-ToolChange` stages and commits the working tree for you, using the PR title as the
commit message, so in practice there is one in-branch commit and it already reads correctly.
Committing by hand first is fine; the command then reports the tree as already clean and
commits nothing.

The PR title becomes the trunk commit message and must follow Conventional Commits:

```
<type>(<optional scope>): <imperative summary>
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`.
Breaking change: append `!` — `feat(graph)!: drop v1.0 endpoints`.

`Complete-ToolChange` validates `-Title` against the same pattern `pr-hygiene` greps for, so
a title that CI would reject is refused locally before anything is pushed. Omitting `-Title`
derives `<type>: <slug>` from the branch name and makes `-Summary` mandatory, because a
derived title carries no reasoning.

The **version bump** is derived from these titles: `feat` → minor, `fix`/`perf` → patch,
`!` or `BREAKING CHANGE` → major. That is what `Publish-ToolRelease -Bump auto` reads.
Release *notes* are not derived from titles — see §6.

## 4. Pull requests

Every PR targets `main`, carries a Conventional Commits title, and fills in the three
evidence lines from `.github/pull_request_template.md`:

```markdown
- **Read-only default:**
- **No fabricated data:**
- **Verified against real data:**
```

Each must state **how** the property was verified for this change. "Yes", a tick, or "N/A"
alone is not evidence; if a property genuinely does not apply, the line says why in a
sentence. `Complete-ToolChange` takes them as `-ReadOnlyDefault`, `-NoFabricatedData` and
`-RealDataCheck`, refuses a blank one, and reproduces all three verbatim in the body
alongside the verbatim green-gate output.

They replaced a seven-item tick-box checklist, and the reason is worth stating plainly: on a
single-maintainer repository the same agent that wrote the change also ticks the boxes, so a
checklist records a claim rather than controlling anything. A sentence that has to say how
is harder to write emptily and far more useful to read six months later — but it is still
written by the author of the change. **The assertions are not the control.** The controls
are CI, which the author does not get to grade, and the phase report, which is read against
the plan. The evidence lines make an unverified change visible; they do not make a verified
one true.

Evidence covers only what a machine cannot check. Anything a test or linter can check
belongs in CI, not on the list.

CI on the PR:

- `test` — Pester v5 suite
- `lint` — PSScriptAnalyzer against `PSScriptAnalyzerSettings.psd1`
- `pr-hygiene` — fails on a non-conforming PR title, on a missing `## Evidence` section, and
  on any of the three evidence lines left empty, naming each one. It does **not** fail on
  `- [ ]` any more: the checklist is gone, and a grep cannot tell a stray box in pasted gate
  output from a real unticked item.

## 5. Merge

Merging is `Complete-ToolChange`. From a change branch it runs the green gate, commits,
pushes, opens or updates the PR, waits for CI, squash-merges, deletes the branch, and
returns the clone to a synced `main` — emitting one object per step, so a run that stopped
half way says where and why.

It refuses to merge on any of three states, and each leaves the branch and the PR intact so
the failure can be read and fixed:

- **a red green gate** — nothing is committed, pushed, opened or merged;
- **red CI** — the failing checks are named;
- **a CI timeout** — a timeout is a failure, not a pass.

The standing rules it automates:

- Squash and merge only. Merge commits and rebase merges are disabled at repo level.
- The squash commit message is the PR title. The squash body is set to `BLANK` by the repo
  settings baseline, so there is no second body to keep in step with the PR.
- The head branch is deleted on merge.
- Never merge red. A failing build is not fixed "on main".

### Direct pushes to `main`

Not permitted, including for one-line documentation fixes. `.githooks/pre-push` refuses them.

Overriding with `git push --no-verify` requires a dated line in `CHANGELOG.md` stating what
was pushed and why. An unrecorded bypass is a process failure, not a mistake.

`Complete-ToolChange` has no path to `--no-verify` and no switch that adds one. It refuses
outright when `main` is the checked-out branch.

### Rewriting `main`

`git push --force`, `--force-with-lease`, and any reset of `main` to an earlier commit are
prohibited. A force push is a larger violation than the direct push it usually intends to
clean up: it destroys history other clones may already hold.

If a bad commit reaches `main`, revert it with `git revert` and a normal PR. An empty commit
is not worth rewriting history for — leave it.

If `main` is rewritten regardless, it requires a dated `CHANGELOG.md` entry recording the
prior SHA, the new SHA, and the reason — the same standard as a `--no-verify` bypass.

No command in `ToolWorkflow.ps1` issues a force push of any kind, and none takes a switch
that would.

## 6. Versioning and releases

Semantic Versioning. The version of record is `ModuleVersion` in
`src\<ToolName>\<ToolName>.psd1`. Tags mirror it with a `v` prefix.

Releases are not per phase. A phase ticks `PORT-PLAN.md`; a release ships behaviour. Cut one
when `CHANGELOG.md`'s `Unreleased` section holds something worth distributing.

From a green `main`:

```powershell
Publish-ToolRelease -Bump auto      # or -Bump major | minor | patch
```

`auto` reads the bump from the Conventional Commit titles since the last tag, per §3, and
refuses when there are no commits since it — guessing `patch` would ship a version number
for no change. The command then, in order: bumps `ModuleVersion`; promotes `Unreleased` to
`## [x.y.z] - YYYY-MM-DD`; routes the release commit through `Start-ToolChange` and
`Complete-ToolChange` with the title `build: release vX.Y.Z`, so it goes through a PR and CI
like every other change; pushes an annotated tag; runs `build\package.ps1`; and creates the
GitHub Release with the zip attached. One object per step; a step it never reached reports
`NotAssessed` rather than claiming to have checked anything.

**Release notes are the new version's own `CHANGELOG.md` section**, read back after the
merge — never generated from commit titles. Commit titles decide the bump; the changelog
decides what the release says.

`package.ps1` throws if `src\` does not hold exactly one module folder, if the manifest is
missing, or if `README.md`/`CHANGELOG.md` are absent. Do not work around those throws — they
are the release gate, and `Publish-ToolRelease` surfaces them rather than swallowing them.

Distribution to any machine uses the packaged zip from GitHub Releases, never a clone of the
working tree.

Hotfix: same flow via a `fix/` branch and a patch bump. No hotfix branch off a tag.

A failure after the merge is reported exactly as it happened. A pushed tag is never unwound.

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
| Evidence lines filled, PR title format | `pr-hygiene` CI | No — advisory on Free |
| PR required before merge | — | No — convention only |

The gap is the reason the evidence lines exist: on this plan the discipline is the control.
Upgrading the account to GitHub Pro turns rows 4–6 into hard blocks with no file change —
`Set-GitHubRepoBaseline.ps1` applies the ruleset on its next run.

`Complete-ToolChange` narrows the gap without closing it. It refuses to merge on a red gate,
red CI or a CI timeout, so on this plan an advisory check becomes a blocking one for anyone
using the command — but only for them. It is a local control, like the hook, and a merge
made through the GitHub web UI is subject to neither.

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
2. `Start-ToolChange -Type feat -Slug <slug> -Phase <n>` from current `main`.
3. Implement that phase's scope only. Additive and isolated — it must not be able to break
   what already works.
4. Reach GREEN per §7.
5. Update `PORT-PLAN.md` (status Done, date), `CHANGELOG.md` (dated entry), and
   `PORT-PARITY.md` where parity or history is affected.
6. `Complete-ToolChange` with the phase's PR title and the three evidence assertions. It
   pastes the green-gate results verbatim into the PR body, opens the PR, waits for CI and
   squash-merges. Reaching GREEN in step 4 is not optional theatre: the command runs the
   gate itself and stops on a red one.
7. Branch deleted, clone synced, then STOP. Do not start the next phase without confirmation.
