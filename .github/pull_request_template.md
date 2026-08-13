## What and why

<!-- One paragraph. What changed and what problem it solves. -->

## Green gate results

<!-- Paste verbatim: Pester summary, PSScriptAnalyzer result, and the real-data check. -->

```
Pester:
PSScriptAnalyzer:
Real sanitized data check:
```

## Self-review

- [ ] Read-only default preserved — no new write/change path except behind an explicit switch
- [ ] No fabricated or extrapolated values; anything not collected reports as "Not Assessed", never 0 / Pass / good
- [ ] Verified against real sanitized data, not only mocks — result stated above
- [ ] No tenant identifiers, secrets, or customer data in code, tests, or fixtures
- [ ] Config is table-driven / versioned, not hardcoded literals
- [ ] `PORT-PLAN.md` phase ticked with date; `CHANGELOG.md` entry appended
- [ ] Anything deferred is recorded as a new `PORT-PLAN.md` item — nothing deferred silently
