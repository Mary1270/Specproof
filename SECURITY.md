# SpecProof — Security

SpecProof has been through six review passes, each of which found real
problems that were then fixed with a regression test that fails on the
previous version and passes on the next:

| Version | Review | Findings fixed |
|---|---|---|
| v1.1 | Steward-style review of the live-tested v1.0 | 13 |
| v1.2 | Attacker-style review | 6 |
| v1.3 | Invariant fuzzing, mutation testing, second attacker pass | 6 (incl. 14 tests that could never fail) |
| v1.4 | Strict line-by-line pre-submission review | 5 |
| v1.5 | Live run on StudioNet plus an on-chain probe | 1 |
| v1.6 | Second live run on StudioNet | 1 |

The test suites themselves are checked: `tests/mutation_test.py`
re-introduces 13 of these vulnerabilities one at a time, and both the unit
suite and the invariant fuzzer must catch every one.

## Claim

SpecProof attests one thing: *for this exact specification text and this
exact, hash-locked diff, GenLayer validators reached these per-requirement
verdicts under the rules below.* It does not claim the code is correct, and
no amount of testing can make an LLM's reading of code provably right.

## Assets and actors

- **Assets:** the verdict and attestation of a spec; the frozen evidence;
  the liveness of a spec (it must always be able to reach a final state).
- **Actors:** the submitter; the author of the code under review (may want a
  false VERIFIED); any third party (may want a false FAILED, or to stall);
  a malicious leader validator in any nondet round; the repository content
  itself (untrusted text read by the LLM).
- **Trust assumptions:** a majority of validators run honest nodes;
  GitHub serves the real diff for a commit sha; the LLMs follow their
  instructions most of the time (prompt injection is a known limitation).

## Invariants (checked by the fuzzer after every transaction)

| # | Invariant |
|---|---|
| I1 | Spec ids are sequential and unique; `spec_count` / `list_specs` agree with storage. |
| I2–I4 | Status is always a known state and changes only along the state machine's edges. |
| I3 | Stored repository and ref are canonical; `spec_hash = sha256(requirements_text)`. |
| I5 | Once set, the specification, frozen evidence, decomposition (ids, texts, hash) and mapping (refs, hash) never change. |
| I6 | A FINALIZED spec never changes again; the attestation is immutable. |
| I7 | The challenge window is re-opened at most once. |
| I8 | A verdict, once set, changes only through a challenge, and a challenge never turns a consensus PASS into FAIL or FAIL into PASS. |
| I9 | Frozen excerpts re-assemble into exactly the frozen diff; `evidence_root` is its hash; every label comes from its own file header. |
| I10–I11 | 1–12 unique, bounded requirements; mappings reference only frozen excerpts, without duplicates; hashes match content. |
| I12 | Every judged requirement has a canonical verdict, a recorded origin, a bounded reason and only in-mapping citations; no evidence ⇒ INSUFFICIENT_EVIDENCE. |
| I13 | PASS only comes from consensus and is impossible on truncated evidence. |
| I14 | At most one challenge per requirement, plus one after a late judgment. |
| I15 | The final verdict is always the strict aggregation (any FAIL ⇒ FAILED; any non-PASS ⇒ INSUFFICIENT_EVIDENCE; else VERIFIED). |
| I16 | The attestation matches storage and is only written after the challenge window closed. |
| I17 | Excerpt ids are globally unique. |
| I18 | Only the submitter can freeze evidence. |
| I19 | Honest validators never accept a non-canonical result from a malicious leader. |
| I20 | Evidence is frozen only from an HTTP 200 response. |

## Attack tree

Status legend: **Tested** — prevented by design and covered by a
regression test plus a fuzzer invariant; **Limitation** — cannot be fully
prevented by contract code, stated openly.

```
GOAL: a verdict the evidence does not support (false VERIFIED / false FAILED)
├── Manipulate the input
│   ├── point the fetch at another repo / host / branch ......... Tested (v1.1 #1, I3)
│   ├── abbreviated sha later collided by a new commit ........... Tested (A10, I3)
│   ├── choose the moment a PR is frozen ......................... Tested (A1, I18)
│   ├── swap the diff after freezing ............................. Tested (I5, I9)
│   ├── evidence altered by the fetch itself (whitespace) ........ Tested (L1, I9, live fixture)
│   └── oversized / non-diff / too-many-files content ............ Tested (v1.1 #7)
├── Manipulate the evidence the judge sees
│   ├── spoof a file's path label (" b/…" name, Unicode lines) ... Tested (A5, A7, I9)
│   ├── push the payload past the judge's view (padding) ......... Tested (A3, I13)
│   ├── prompt injection inside the repository or the spec ........ Limitation (fenced, marked as data; reduced, not eliminated)
│   └── a spec written to be trivially true ........................ By design: the spec text is published in the attestation
├── Malicious leader validator
│   ├── forge a non-canonical judgment / proposal ................ Tested (A2, A4, A9, I19)
│   ├── claim "no result possible" ............................... Tested (A2b, A9)
│   └── pick among several acceptable decompositions/mappings .... Limitation (reviewed, not reproduced)
├── Abuse the challenge
│   ├── re-roll a verdict until it flips ......................... Tested (v1.1 #3, I8)
│   ├── consume the only challenge via a timeout ................. Tested (A8, I14)
│   └── keep the spec from finalizing ............................ Tested (v1.1 #4–5, I7)
├── Abuse timeouts
│   └── stall a stage to force a failure state ................... Tested (every stage has a deadline; judged verdicts survive)
├── Break the commitments
│   └── two representations, one hash ............................ Informational (see below)
└── Trick the user in the frontend
    ├── XSS through repo text / LLM reasons ...................... Tested (textContent only; headless check)
    ├── swapped / compromised library ............................ Mitigated (F1: pinned version)
    ├── act on the wrong spec after navigating ................... Fixed (F2)
    └── a reverted transaction shown as a success ................ Fixed (H3)
```

**Hashes (informational).** `spec_hash`, `content_hash`, `evidence_root`,
`decomposition_hash` and `mapping_hash` are plain SHA-256 values over
well-defined inputs, exactly as ARCHITECTURE.md (locked) specifies. They are
not domain-separated, but no code path ever compares a hash of one kind
with a hash of another kind, so a cross-domain collision has no effect.
To recompute:

- `evidence_root = sha256(diff)`
- `content_hash = sha256(excerpt)`, where the excerpts are the diff split
  on `\n` at each `diff --git ` line
- `decomposition_hash = sha256(json.dumps(sorted(texts)))`
- `mapping_hash = sha256(json.dumps(mapping, sort_keys=True))`

## Known residual limitations

- A result is only as meaningful as the specification. Whoever submits it
  chooses the text, so a weak specification ("the code compiles") can be
  VERIFIED. That is why the full specification text is part of the
  attestation: a reader always sees exactly what was checked.
- Decomposition and evidence mapping are *reviewed*, not reproduced: a
  validator accepts any well-formed proposal its own LLM review finds
  faithful, since these proposals legitimately vary in wording. Only
  verdicts are exact-match bound. A leader can therefore still choose
  *which* acceptable decomposition or mapping is stored.
- The `reason` text stored with a verdict is the leader's; validators agree
  on the verdict and on the leader output being well-formed, not on wording.
- Prompt-injection hardening lowers risk but cannot remove it: every
  validator reads the same repository text.
- A very large file can never earn PASS if its excerpt exceeds the judge's
  view (v1.2); split such changes into smaller commits.
- A refused challenge (validators could not agree) does not use up the
  one challenge; it can be retried. A downgrade requires full validator
  agreement on a verdict different from the original.
- A late judgment re-opens the challenge window only if it is the first
  challenge on the spec; otherwise the second challenge must land in the
  time left in the window.
- The frontend trusts esm.sh to serve the pinned genlayer-js build as
  published; a self-hosted copy would remove that dependency.
- The fuzzer runs against the SDK stub: it proves the contract's own logic
  holds the invariants, not how real GenVM, GitHub or LLMs behave. Those
  are covered only by live testing.
- Challenges re-judge at the same validator count as the original round
  (validator count is not contract-controllable in the current SDK).
- The PR path depends on GitHub's unauthenticated API and diff endpoints
  and has not been live-verified.

Full details, non-goals, and explicit limitations are in
[`ARCHITECTURE.md`](./ARCHITECTURE.md) (§3, §21, §22).

## Review history

### v1.6 — second live run on StudioNet

| # | Severity | Finding in v1.5 | Fix in v1.6 |
|---|---|---|---|
| D1 | Medium (liveness / correctness) | For PR #100, "the change must add a license file" was mapped by the leader to no excerpt, and validators rejected the mapping in four consecutive rounds with four different leaders. The review criteria required every relevant excerpt, while a requirement about something being *absent* can only be judged from the whole change. Such requirements could neither be mapped nor ever receive the FAIL they deserve; the spec could only time out into MAPPING_FAILED. | Leader and validators are told that presence/absence requirements are mapped to every excerpt; citing extra plausibly relevant evidence is acceptable; the judge sees the names of all changed files and whether it is shown all of them. Regression tests reproduce the case with the exact live PR #100 diff (its `evidence_root` equals the value measured on StudioNet). |

### v1.5 — live run on StudioNet

The v1.4 deployment was run end to end on StudioNet (see the README's live
table). The first live pull-request run exposed a bug no offline test could
see, because the test stub modeled the fetch primitive too optimistically.

| # | Severity | Finding in v1.4 | Fix in v1.5 |
|---|---|---|---|
| L1 | High | The diff was fetched with `gl.nondet.web.render(url)`, which returns rendered page text: runs of spaces are collapsed and trailing spaces dropped. Measured on StudioNet with a probe contract: the same diff was 1331 bytes via `get` and 1322 via `render`; two-space indentation arrived as one space. Python's block structure lives in indentation, so an author could submit code whose real control flow differs from what the judge is shown and obtain a false PASS. `evidence_root` was also not the hash of what GitHub serves. | The diff is fetched with `gl.nondet.web.get(url)` (live-verified byte-exact), only HTTP 200 and valid UTF-8 are accepted, and `evidence_root` is the SHA-256 of the exact bytes. The stub's `render` now reproduces the live behavior byte-for-byte, the exact live diff is a fixture, and the fuzzer and mutation test cover it (I9, I20, M12, M13). |

### v1.4 — strict pre-submission review

A line-by-line review of the contract, frontend and documents against
ARCHITECTURE.md, as a competition judge would read them. Each code fix has a
`v1.4 …` regression test; the mutation test gained a mutant for A10 (11 in
total).

| # | Severity | Finding in v1.3 | Fix in v1.4 |
|---|---|---|---|
| A10 | Medium | Commit refs could be abbreviated shas (7+ hex). An abbreviation is unique only when it is resolved: anyone who can push to the repository can later add a commit with the same 7-character prefix (about 2^28 work), after which the attestation no longer identifies one commit. | Only full 40-character shas are accepted (stored lowercase). PR refs were already resolved to full base and head shas. |
| H1 | Low | A non-string `reason` from the judge was stored as its Python representation (e.g. `"None"`). | Non-string reasons are stored as empty. |
| H2 | Low | The requirement text in the judgment prompt was not fenced, and the decomposition proposal prompt did not say the specification is data (the review prompt did). Both are submitter-controlled text. | Requirement fenced with `<<<REQUIREMENT_START/END>>>` and declared a claim, not an instruction; the decomposition prompt now marks the specification as data. |
| H3 | Low (frontend) | A transaction that reached consensus while the contract raised (e.g. `invalid state`) was logged as accepted. | Reported as a failure with the explorer link. |
| Q1 | Info | Stale comments (judgment "never truncated"; validator-count note naming only `gl.eq_principle`), unused legacy wrappers, `*_PENDING` states defined but never entered without explanation. | Comments corrected, wrappers removed, the pending states documented; the attestation is now self-contained (`requirements_text`, `protocol_version`, the claim sentence, per-requirement `round`). |

### v1.3 — invariant fuzzing, mutation testing, second attacker pass

v1.3 adds an invariant fuzzer and a mutation test (see
[Invariants](#invariants-checked-by-the-fuzzer-after-every-transaction)), and fixes what they and a second
attacker pass found. Each fix has a `v1.3 …` regression test that fails on
v1.2 and passes on v1.3 (83 unit tests total).

| # | Severity | Finding in v1.2 | Fix in v1.3 |
|---|---|---|---|
| A7 | Medium | Bypass of the A5 fix: the diff was split with `str.splitlines()`, which also breaks lines on Unicode separators (`\u2028`, `\x0c`, `\x85`, …). One added line inside `notes.txt` containing `\u2028diff --git …\u2028+++ b/auth/secure.py` was carved into a separate excerpt labelled `auth/secure.py`. | Split on `\n` only, as git does. The fuzzer checks that the excerpts always re-assemble into the exact frozen diff and that every label comes from its own file header. |
| A8 | Medium | After a judgment timeout, the first real judgment came from `challenge()`, which also used up the requirement's single challenge. An attacker could let judgment time out, "challenge" the placeholder, and leave the resulting verdict unchallengeable. | A challenge that only produces a late first judgment is recorded as `late_judged` and does not use up the challenge; the late verdict can be challenged once more under reproduce-or-downgrade. |
| A9 | Low | Found by the fuzzer: validators accepted any non-`True` `ok` from the leader as a failure claim (e.g. `{"ok": 1, "value": […]}`) in decomposition and mapping. | A failure claim must be exactly `{"ok": false, "error": <bounded string>}`; a success must have exactly `{ok, value}`. Same tightening in the judgment validator. |
| T1 | High (test suite) | 14 tests written in v1.0 used `try: call(); assert False  except Exception: pass`. `AssertionError` is an `Exception`, so they could never fail. The mutation test showed that `finalize()` inside the challenge window went unnoticed. | All rewritten with `_expect_raises(fn, fragment)`; the expected message is now mandatory. |
| F1 | Medium (frontend) | `genlayer-js@latest` from esm.sh: any new release (or a compromised one) would silently change the code that builds and signs transactions. | Pinned to `genlayer-js@1.1.8` (checked: exports `createClient`, and `studionet` from `/chains`). |
| F2 | Low (frontend) | A slow render of the previously opened spec could append its panels and action buttons into the page of the spec now on screen, so a click could act on the wrong spec. | Every render writes into its own container; a stale render writes into a detached element. |

### v1.2 — hardening after an attacker-style review

A second review of v1.1, this time trying to break it as an attacker,
found six more working attacks. Each was reproduced against v1.1 first;
each has a `v1.2 attack …` regression test that **fails on v1.1 and passes
on v1.2** (79 tests total).

| # | Severity | Attack on v1.1 | Fix in v1.2 |
|---|---|---|---|
| A1 | High | Anyone could call `request_verification`. For a `PR#n` spec the diff is frozen at whatever the PR looks like at that moment, so the PR author could freeze a clean-looking head commit of their choosing — or freeze before a fix the submitter was waiting for. | Only the submitter can freeze evidence. The later steps stay permissionless (they cannot change *what* is verified). |
| A2 | High | The judgment validator normalized the leader's output before comparing, so a malicious leader could store a non-canonical judgment that honest validators still accepted: verdict `"pass"` (aggregated as INSUFFICIENT), a 100 KB reason, duplicate citations, extra fields — or claim "no judgment possible" whenever validators failed too. | The validator requires the leader's output to be byte-for-byte what an honest node would store (canonical verdict, bounded reason, deduplicated in-mapping citations, exact key set) before comparing verdicts. A leader's "could not judge" is accepted only if the validator also could not judge. |
| A3 | High | Excerpts longer than the judge's 12,000-character view are truncated. Padding a file with a long comment line pushed the harmful code past the cut-off; the judge saw only the padding and returned PASS. | A PASS on any truncated excerpt is withheld and stored as INSUFFICIENT_EVIDENCE with the reason naming the file. FAIL still stands (a violation that was seen is a violation). |
| A4 | Medium | Decomposition and mapping ran the leader's output through `prompt_comparative` and only validated it **after** consensus, so one malicious leader could propose a mapping to a made-up excerpt (or 13 requirements, or duplicates), have it "agreed", and push the spec into terminal `MAPPING_FAILED` / `DECOMPOSITION_FAILED` for everyone. | Propose-and-review (`_propose_and_review`): each validator first checks the leader's proposal is already in canonical, in-bounds form (known IDs only, caps, no duplicates), then independently reviews with its own LLM call that it is faithful to the specification/evidence. An invalid or unfaithful proposal is simply not accepted; the spec stays where it was for an honest leader to retry. |
| A5 | Low | The excerpt's `file_path` label was parsed from the `diff --git a/… b/…` header by splitting on ` b/`. A file literally named `evil b/auth/secure_check.py` was labelled `auth/secure_check.py`, so a verdict appeared to cite a trusted file. | The path comes from the `+++ b/` line (then `--- a/`, then `rename to`), which is unambiguous. |
| A6 | Low | `list_specs()` returned every spec ID in one call, so spam submissions could make the view (and the frontend's Explore page) unusably large. | `list_specs(offset, limit)` is paginated (newest first, `limit` 1–100) and `spec_count()` is added. |

### v1.1 — hardening after a steward-style review

A full review of v1.0 from a GenLayer steward's point of view found the
issues below. Each one was reproduced first, then fixed, and each fix has a
regression test that **fails on the v1.0 contract and passes on v1.1**
(70 tests total, up from 47).

| # | Severity | Finding in v1.0 | Fix in v1.1 |
|---|---|---|---|
| 1 | High | `repository_url` and `ref` were pasted straight into the fetch URL. A non-GitHub host was accepted, a branch name like `main` was stored as the "immutable" `commit_sha`, and a ref such as `../../../other/repo/commit/x` fetched a diff from a **different repository** than the one named in the attestation. | Strict parsing (`_parse_github_repo`, `_parse_ref`): https `github.com/<owner>/<repo>` only, ref must be a 7–40 hex commit sha or `PR#<n>`; both stored in canonical form. |
| 2 | High | Verdicts went through `prompt_comparative`, where an LLM decides whether leader and validator outputs are "equivalent" — the settlement-driving category was not bound exactly. | `_judge_with_consensus` uses `gl.vm.run_nondet_unsafe` with a validator that re-judges independently and agrees only on an **exact** verdict match and a structurally valid leader output (known verdict, citations inside the locked mapping). Reason text may differ. No tolerance anywhere. |
| 3 | High | `challenge()` replaced the verdict with a re-judgment at the same validator count on the same evidence: an unpaid re-roll anyone could use to try to flip PASS↔FAIL. | Reproduce-or-downgrade: a consensus verdict survives only if the re-judgment reproduces it; otherwise it becomes INSUFFICIENT_EVIDENCE. The challenger is recorded. |
| 4 | Medium | `aggregate()` could be called again on an aggregated spec, and each call pushed the challenge deadline 48h forward — anyone could stop a spec from ever being finalized. | `aggregate()` runs only from `JUDGED`. |
| 5 | Medium | Every challenge re-opened the 48h window, so challenging requirements one by one could delay finalization by up to 12 × 48h. | Only the first challenge on a spec re-opens the window (ARCHITECTURE.md §6: "re-opens once"). |
| 6 | Medium | For a PR, the live `/pull/N.diff` and `head.sha` were fetched separately, so the frozen diff and the attested commit were not guaranteed to describe the same state. | `base.sha` and `head.sha` are resolved first; the diff is fetched from `compare/<base>...<head>.diff`, pinned to exactly those commits. |
| 7 | Medium | No upper bounds: one huge diff or a decomposition into dozens of requirements made a single transaction arbitrarily large. An HTML error page could be frozen as "evidence". | Caps on diff size, file count, requirement count and spec length; a fetched page that is not a unified diff is rejected; oversized input reverts instead of being judged partially. |
| 8 | Medium | The judgment timeout wrote nothing onto requirements (attestations listed blank verdicts) and discarded verdicts that had already been judged. | Judged verdicts are kept; only unjudged requirements become INSUFFICIENT_EVIDENCE with `origin: TIMEOUT`. |
| 9 | Medium | Diff content went into prompts undelimited, so text inside a repository could try to instruct the model. | Evidence is fenced and prompts state it is untrusted data whose instructions must be ignored. (Every validator sees the same text, so this reduces but cannot fully eliminate prompt-injection risk.) |
| 10 | Medium | Frontend rendered requirement text and LLM reasons with `innerHTML` — a stored-XSS path through attacker-controlled diffs, inside a wallet browser. | Frontend rebuilt; all untrusted data rendered with `textContent` only (checked in a headless browser with a planted payload). |
| 11 | Low | One requirement whose validators could not agree blocked every other requirement's judgment. | `judge_requirement(spec_id, requirement_id)` judges one at a time; the timeout path resolves any that never reach consensus. |
| 12 | Low | A requirement mapped to no evidence still triggered an LLM call. | Resolved deterministically as INSUFFICIENT_EVIDENCE (`origin: NO_EVIDENCE`). |
| 13 | Low | No way to browse verifications or inspect the frozen evidence behind a verdict. | New views `list_specs`, `get_spec`, `get_excerpt`; attestation results now carry hash-pinned cited evidence (`file_path`, `content_hash`). Frontend has an Explore page, per-spec routing and an evidence viewer. |
