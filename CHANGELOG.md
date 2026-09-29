# Changelog

Every version after v1.0 changes the storage layout and needs a fresh
deployment. Details of every finding are in [SECURITY.md](./SECURITY.md).

## v1.6 — second live run fix
- Requirements about something being added or absent are mapped to every
  excerpt; the review accepts extra plausibly relevant evidence; the judge
  sees every changed file name and how many it is shown (D1, found live on
  PR #100). 95 unit tests.

## v1.5 — live run fixes
- The diff is fetched with `gl.nondet.web.get` instead of `render`, which
  was measured on StudioNet to collapse whitespace (L1). HTTP 200 and UTF-8
  required; `evidence_root` is now the hash of the exact bytes GitHub serves.
- Test stub reproduces live `render` byte-for-byte; the exact live diff is a
  fixture; new invariant I20; mutants M12–M13. 91 unit tests, 13 mutants.
- First live pull-request run (PR base/head resolution by consensus works).

## v1.4 — strict pre-submission review
- Commit refs must be the full 40-character sha (A10).
- Requirement text fenced in the judgment prompt; specification marked as
  data in the decomposition prompt; non-string reasons stored as empty.
- Attestation is self-contained: `protocol_version`, the claim sentence, the
  full `requirements_text`, and each result's `round`.
- Frontend: parallel reads, reverted transactions reported as failures,
  full-sha validation.
- Docs: README rewritten for readers new to the project; SECURITY.md,
  CHANGELOG.md and docs/GENVM_LESSONS.md split out; every deliberate
  difference from ARCHITECTURE.md listed.
- Stale comments and unused legacy wrappers removed. 87 unit tests, 11 mutants.

## v1.3 — invariant fuzzing and mutation testing
- New: `tests/test_fuzz.py` (19 invariants after every transaction),
  `tests/mutation_test.py`, `tools/build_deploy.py` (deploy build proven
  equivalent to the source, checked in CI).
- Fixed: Unicode line separators could carve out a fake excerpt (A7); a
  timeout plus a self-challenge made a verdict unchallengeable (A8);
  non-canonical failure claims from a leader were accepted (A9, found by
  the fuzzer); 14 tests that could never fail (T1).
- Frontend: genlayer-js pinned to 1.1.8 (F1); stale renders isolated (F2).

## v1.2 — attacker-style review
- Only the submitter can freeze evidence (A1).
- The judgment validator requires the leader's exact canonical output (A2).
- PASS withheld when a file was too long for the judge to read in full (A3).
- Decomposition and mapping use propose-and-review, so one bad leader
  cannot make a spec fail permanently (A4).
- File labels read from the `+++` header (A5); paginated `list_specs` (A6).

## v1.1 — steward-style review
- Strict repository and ref parsing; exact-verdict consensus;
  reproduce-or-downgrade challenges; no repeated aggregation; the window
  re-opens once; PR pinned to base…head; size caps; timeout keeps judged
  verdicts; evidence fenced as untrusted; XSS-safe frontend; per-requirement
  judging; no LLM call without evidence; new views. 13 findings.

## v1.0 — first live deployment
- Full pipeline deployed on GenLayer Studio and exercised end to end:
  one FAILED verification with a challenge, one VERIFIED, both finalized
  after real 48-hour windows.
