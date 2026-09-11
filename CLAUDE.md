# CLAUDE.md

Claude Code reads this file automatically at the start of every session in this repository.

Use it unchanged in **ADForestAssessment**, **ExchangeAssessment** and
**ExchangeEnvironmentToolkit**. It is identical in all three by design.

---

## THIS IS A REUSABLE PRODUCT, NOT A CLIENT PROJECT

These tools are used across many clients and engagements. **No client ever appears in this
repository** — not in code, not in tests, not in documentation, not in a comment, not in a
commit message.

Forbidden in this repository, without exception:

- Any real client name, organisation name or brand
- Any real host name, FQDN, domain, IP address, VLAN or subnet
- Any real server, DAG, database, certificate, connector or account name
- Any engagement, project or phase reference belonging to a client

Tests and examples use **obviously fictional** values (`CONTOSO`, `EX01.contoso.local`,
`192.0.2.0/24`). If a value could plausibly be a real client's, it is the wrong value.

**Client data arrives at run time**, through config files supplied with a path parameter and
kept out of source control. A tool that cannot run for a different client next week is broken,
however well it runs today.

---

## What each repository is for — the only scope that is fixed

| Repository | Scope |
| --- | --- |
| **ADForestAssessment** | Read-only Active Directory forest assessment — general purpose, usable on its own for any AD engagement. PowerShell 5.1-safe, runs on a stock domain controller |
| **ExchangeAssessment** | Read-only assessment of Exchange environments, **and readiness assessment for Exchange Server SE deployment**. Usable standalone for any Exchange engagement |
| **ExchangeEnvironmentToolkit** | Exchange configuration export, import and **implementation/configuration automation for Exchange Server SE** |

Exchange Server SE is a **product** scope, not a client scope. Encoding SE prerequisites, SE
build tables and SE configuration is correct. Encoding one client's servers is not.

A session works in **one** repository. Never edit another from it.

---

## Read first, in this order

1. **This repository's own conventions** — `README.md`, its plan file (`PORT-PLAN.md` where
   present), `docs/WORKFLOW.md`, `CHANGELOG.md`, `PSScriptAnalyzerSettings.psd1`, `build/`.
   **Follow THIS repository's workflow and gate, not a method from another repository.**
2. State the **current item and the next item, read from the plan file**, not from memory.
3. **Quote the exact gate command this repository uses.** Do not assume one.

---

## Discovered versus supplied

This distinction is the core design rule of these tools.

**Discovered** — never supplied, never guessed: forests, domains, trusts, domain controllers,
sites, FSMO holders, schema state, and Exchange servers that already exist.

**Supplied** — cannot be discovered, because nothing in a directory identifies a server that is
not yet an Exchange server: candidate target servers, the witness server, planned names, planned
volumes.

Supplied values come from a config file passed at run time. **With no config supplied, the
affected controls report `Unknown` with a cause naming the missing key and the command that
creates a fillable copy — never a pass, never an invented value, never a guess from the
directory.**

---

## Engineering rules that bind every session

- **No receipt, no claim.** Never assert how code behaves without quoting the line read or the
  command output, and state what that instrument cannot see.
- **A negative conclusion needs two instruments.** Never assert absence from one local command.
- **Fail closed.** A value not measured is reported as not measured with a named cause — never
  as zero, pass, good or compliant. An absent key and a measured absence are different claims,
  and a consumer cannot tell them apart if a key is omitted.
- **Assessment tooling is read-only.** Implementation and configuration automation is
  report-mode by default and changes nothing without an explicit apply switch, with `-WhatIf`
  support on every function that writes.
- **Volatile vendor facts are verified on Microsoft Learn in-session**, with the URL and read
  date recorded next to the value. A value the vendor does not publish is `$null` with a comment
  naming what is missing, or a pattern marked as measured — never an invented number.
- **Volatile values live in versioned config tables** with a path override, never hardcoded in
  code. A new product build or cumulative update must be a config edit.
- **Every enumeration carries a non-vacuity assertion naming its declared population.** "Greater
  than zero" is not that assertion.
- **Every new or narrowed guard is demonstrated able to fail**, with the red shown, then restored
  byte-for-byte and verified by hash.
- **Establish a green baseline before mutating.** Mutation reds measured against a red baseline
  prove nothing.
- **Commit before the gate.** If a commit fails, discard any gate that ran against the
  uncommitted tree and re-gate the real commit.
- **Never `git add -A` or `git add .`** — stage by name, confirm with `git status`.
- **Do not merge.** Merging is the operator's step. Zero CI checks is NOT ASSESSED, not a pass.
- **Nothing deferred silently.** Anything postponed becomes a plan row with a named owner.
- **Green over mocks proves the mocks.** A first run against real infrastructure is always a
  separate plan row owned by the operator.
- **Client-host scripts target Windows PowerShell 5.1** and declare it. PowerShell 7 only where
  a requirement demands it, with that requirement named. Dev-only tooling under `build/` is a
  separate population.
- **Output convention** for anything that produces a report: one timestamped folder per run under
  `C:\Scripts\Securnet\Reports\<ScriptName>-<yyyyMMdd-HHmmss>\`, overridable by parameter,
  containing a detailed log plus raw CSV, raw JSON and a human-readable report.

---

## If an engagement needs context these tools must not hold

It goes in the **engagement** repository, never here. Pass client values through config at run
time and leave this repository clean.
