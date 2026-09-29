# SpecProof

[![tests](https://github.com/Mary1270/Specproof/actions/workflows/tests.yml/badge.svg)](https://github.com/Mary1270/Specproof/actions/workflows/tests.yml)

**Consensus-backed, evidence-pinned verification of software requirements —
a GenLayer Intelligent Contract.**

> SpecProof does not prove that software is bug-free. It verifies whether
> the available evidence supports each explicitly declared requirement for a
> specific, immutable specification and evidence snapshot.

Teams constantly claim that a change meets a requirement: "this PR fixes
the auth bypass", "withdrawals now check the balance first". Today that
claim is either unverified or rests on one AI reviewer's single opinion,
with no record of which code was read and no way to dispute it.

SpecProof turns such a claim into an on-chain record. You give it a public
GitHub repository, a commit or pull request, and requirements in plain
language. It freezes the exact diff, splits the specification into
independent requirements, maps each requirement to the specific files that
bear on it, and has GenLayer validators judge each one independently
(PASS / FAIL / INSUFFICIENT_EVIDENCE). The result is a hash-locked
attestation that anyone can challenge within 48 hours and re-check later.

## Why this needs GenLayer

This problem cannot be solved by a normal smart contract, and a normal
backend cannot make it trustworthy:

- **It needs judgment.** Whether a diff satisfies "unauthorized users
  cannot withdraw" is a question for a language model, not for arithmetic.
- **It needs the web.** The evidence lives on GitHub and must be fetched and
  frozen inside the contract, so nobody can swap it afterwards.
- **One model's opinion is not enough.** On GenLayer, every validator
  re-runs the judgment on the same frozen evidence with its own model, and
  a verdict is stored only if they reach the *identical* verdict. A single
  operator cannot pick the answer.

## How it works

```
submit_specification(repo, ref, text)          anyone
        │
request_verification(spec_id)                  submitter only — freezes the diff
        │   validators fetch the diff for the full commit sha (a PR is pinned to
        │   its base…head commits), split it per file and hash every excerpt
        ▼
propose_decomposition(spec_id)                 leader proposes requirements;
        │                                      each validator checks the form and
        │                                      reviews faithfulness with its own LLM
        ▼
propose_evidence_mapping(spec_id)              requirement → relevant excerpts;
        │                                      unknown excerpt ids are rejected
        ▼
judge_requirement(spec_id, requirement_id)     every validator re-judges; stored only
        │                                      on an identical verdict
        ▼
aggregate(spec_id)                             any FAIL → FAILED; any other non-PASS →
        │                                      INSUFFICIENT_EVIDENCE; else VERIFIED
        ▼
challenge(spec_id, requirement_id)  (48 h)     a verdict survives only if re-judgment
        │                                      reproduces it, else INSUFFICIENT_EVIDENCE
        ▼
finalize(spec_id) → attestation                spec text + hash, commit, evidence root,
                                               per-requirement verdicts with cited hashes
```

Every stage has a deadline; `expire_if_timed_out(spec_id)` resolves a
stalled stage, so no verification can hang forever.

| Step | Consensus primitive | What an honest validator checks |
|---|---|---|
| Freeze evidence | `gl.eq_principle.strict_eq` over `gl.nondet.web.get` | Byte-identical raw fetch of the diff, HTTP 200 only (and identical PR base/head shas) |
| Decomposition | `gl.vm.run_nondet_unsafe` (propose-and-review) | The proposal is canonical and in bounds, **and** its own LLM finds it faithful to the specification |
| Evidence mapping | `gl.vm.run_nondet_unsafe` (propose-and-review) | Only known excerpt ids, every requirement present, **and** its own LLM finds the mapping faithful |
| Judgment | `gl.vm.run_nondet_unsafe` (exact verdict) | The leader's output is canonical, **and** its own independent verdict is identical |

## Guarantees

Each of these is enforced by the contract, covered by regression tests, and
checked after every transaction by an invariant fuzzer
([SECURITY.md](./SECURITY.md) has the threat model, the 20 invariants and
the attack tree):

- The repository, commit and diff named in the attestation are exactly what
  was judged; `evidence_root` is the SHA-256 of the exact bytes GitHub
  served, and the evidence cannot change after freezing.
- A verdict is stored only when validators independently reach the same
  verdict; a malicious leader cannot slip in a malformed or forged result.
- A challenge can never flip PASS into FAIL or FAIL into PASS; it can only
  confirm a verdict or downgrade it to INSUFFICIENT_EVIDENCE.
- PASS is impossible on evidence the judge could not read in full.
- Every verification terminates: every stage has a deadline, the challenge
  window re-opens at most once, and no call can be repeated to stall it.

## Try it

Live frontend: https://mary1270.github.io/Specproof/frontend/ (contract
`0x2a6be2C3752CB8b7b131dade3F39Dd355E96e619` on GenLayer StudioNet).

The frontend is a single file, `frontend/index.html`, with no build step.
It reads without a wallet and uses Rabby (for example inside the Mises
browser) for writes. It lists every verification, shows the next valid
step for each one, and lets you open every frozen excerpt and the final
attestation.

Example input:

```
Repository:   https://github.com/octocat/Spoon-Knife
Ref:          bb4cc8d3b2e14b3af5df699876dd4ff3acd00b7f   (full commit sha, or PR#123)
Requirements: 1. The change must add a stylesheet.
              2. The README must be updated to describe the change.
```

## Live verification

v1.0 was deployed and exercised end to end on GenLayer Studio (StudioNet)
at [`0x5444d1A1d40809fbD082E442764E40016AA90d2D`](https://explorer-studio.genlayer.com/address/0x5444d1A1d40809fbD082E442764E40016AA90d2D):

| spec_id | repository | requirements | path | final result |
|---|---|---|---|---|
| `spec_0` | octocat/Hello-World @ `7fd1a60b…edf11d` | 1 | freeze → decomposition → mapping → judgment (FAIL) → aggregate → **challenge** (re-judged, still FAIL) → finalize | `FAILED`, `challenge_status: RESOLVED` |
| `spec_2` | octocat/Spoon-Knife @ `bb4cc8d3…d00b7f` | 2 (independent) | freeze → decomposition → mapping → judgment (both PASS) → aggregate → finalize | `VERIFIED`, `challenge_status: NONE` |

Both `finalize()` calls returned a complete, hash-locked attestation after
their real 48-hour challenge windows elapsed, and the frontend was tested
live against this deployment with a connected wallet.

v1.4 was then deployed at
[`0x7ea81b5D9D211111c8Ac85d1d3573FA4a98E4fa2`](https://explorer-studio.genlayer.com/address/0x7ea81b5D9D211111c8Ac85d1d3573FA4a98E4fa2)
and run live; every hash below was recomputed offline and matched:

| # | Call | Result on StudioNet | Check |
|---|---|---|---|
| 1 | `submit_specification(Spoon-Knife, bb4cc8d3…d00b7f, 2 requirements)` | `spec_0`; `spec_hash` `30ba6fda…938f82` | equals `sha256(text)` computed offline |
| 2 | `request_verification(spec_0)` | EVIDENCE_FROZEN; 2 excerpts (`README.md`, `styles.css`); `evidence_root` `e9cc2002…07bc76` | root and both `content_hash` values recomputed offline from the fetched diff: identical |
| 3 | `propose_decomposition(spec_0)` | propose-and-review accepted: 2 requirements; `decomposition_hash` `b3203b55…c6e53` | recomputed offline: identical |
| 4 | `propose_evidence_mapping(spec_0)` | stylesheet → `styles.css`, README → `README.md`; `mapping_hash` `e1f009aa…1903d` | recomputed offline: identical |
| 5 | `judge_requirement` × 2 | stylesheet: **PASS**; README: **INSUFFICIENT_EVIDENCE** ("no indication of what change the README should describe") | exact-verdict consensus reached on both |
| 6 | `aggregate(spec_0)` | `INSUFFICIENT_EVIDENCE`; 48 h challenge window opened | strict aggregation |
| 7 | `challenge(spec_0, spec_0_req_0)` | re-judged independently: PASS reproduced and kept; `round 1`, `challenge_count 1`, challenger recorded | reproduce-or-downgrade |
| 8 | negative: short sha `bb4cc8d` | rejected: `ref must be a full 40-character commit sha…` | A10 |
| 9 | negative: `aggregate(spec_0)` again | rejected: `invalid state … expected one of ('JUDGED',)` | v1.1 #4 |
| 10 | negative: `finalize(spec_0)` inside the window | rejected: `challenge window is still open` | I16 |
| 11 | negative: second `challenge(spec_0, spec_0_req_0)` | rejected: `already used its single challenge round` | I14 |

| 12 | `submit_specification(Hello-World, PR#100, …)` + `request_verification(spec_1)` | **first live PR run:** base/head resolved by consensus to `7fd1a60b…:549d7569…`; diff fetched between exactly those commits | `commit_sha` equals the PR head |

Note from (8)–(11): a transaction the contract rejects still shows status
ACCEPTED with execution result ERROR, which is why the frontend reads the
execution result instead of the status (H3).

**The live run found a real bug (L1, fixed in v1.5).** The PR's only change
adds trailing spaces to a line, yet the frozen diff showed none. A probe
contract deployed on StudioNet
([`0x2064e794…58F5e3`](https://explorer-studio.genlayer.com/address/0x2064e79494b12858449fE66a26b380Da7858F5e3))
then fetched the same diff three ways:

| Fetch | Length | Two-space indentation | SHA-256 |
|---|---|---|---|
| `gl.nondet.web.render(url)` (v1.0–v1.4) | 1322 | collapsed to one space | `e9cc2002…07bc76` = the v1.4 `evidence_root` above |
| `gl.nondet.web.render(url, mode="html")` | 1396 | kept, wrapped in `<pre>` | — |
| `gl.nondet.web.get(url)` (v1.5) | 1331 | kept | `55e74a6d…0da87` = SHA-256 of the exact file GitHub serves |

`render` returns page text with runs of spaces collapsed and trailing
spaces dropped. In Python, indentation is meaning, so the judge could have
been shown code whose block structure differs from the real change. v1.5
fetches the diff with `get`, accepts only HTTP 200 and valid UTF-8, and
`evidence_root` is now the hash of the exact bytes. The test stub's
`render` now reproduces the live behavior byte-for-byte (it yields
`e9cc2002…` on the same input), and the exact live diff is a test fixture,
so this cannot regress unnoticed.

v1.5 was deployed at
[`0x39542da6…B3d872`](https://explorer-studio.genlayer.com/address/0x39542da6cdc7d342e79F18Eaa13155D921B3d872)
and the fix confirmed live: the Spoon-Knife `evidence_root` is now
`55e74a6d…0da87` (the exact GitHub bytes, `styles.css` keeps its
indentation), and PR #100 freezes to `2a146592…9b9046`, trailing spaces
included, both matching values computed offline beforehand. The Spoon-Knife
spec then ran through decomposition, mapping, two judgments and
aggregation, all accepted.

**The v1.5 run found a second, design-level issue (D1, fixed in v1.6).**
For PR #100 the leader mapped "the change must add a license file" to no
excerpt, and validators rejected that mapping in four rounds with four
different leaders. Whether something was *not* added can only be judged by
looking at the whole change, so the old criteria ("disagree if a relevant
excerpt was left out") and the leader's reading could never meet: such a
requirement could neither be mapped nor ever receive a FAIL. v1.6 tells
leader and validators that presence/absence requirements are mapped to
every excerpt, accepts extra plausibly relevant evidence, and shows the
judge the names of all changed files and whether it is seeing all of them.
v1.6 is deployed at
[`0x2a6be2C3…96e619`](https://explorer-studio.genlayer.com/address/0x2a6be2C3752CB8b7b131dade3F39Dd355E96e619);
on the same PR #100 spec, the mapping that v1.5 validators rejected four
times was accepted at the first attempt, and freeze, decomposition,
mapping, `judge_requirements` and `aggregate` all reached consensus.

| Requirement | Verdict | Judge's reason (live) |
|---|---|---|
| The README must greet the world. | **PASS** | "The README contains the greeting "Hello World!"; the change only adds trailing spaces and does not remove the greeting." |
| The change must add a license file. | **FAIL** | "The only changed file shown is "README" … There is no added license file in the evidence." |

Final verdict **FAILED** (strict aggregation). `decomposition_hash`
`ee3d91cb…babbcc` and `mapping_hash` `a29072e3…ffb8b` were recomputed
offline and match. Two things are visible in the judge's own words: it saw
the trailing spaces that v1.4 had erased (L1 fixed end to end), and it could
rule on an *absent* file because it knew the full list of changed files
(D1 fixed end to end).

A challenge on the FAIL (`challenge(spec_0, spec_0_req_1)`) was then
re-judged independently and reproduced FAIL ("only 'README' was modified …
merely a whitespace adjustment. No license file was added."), so the
verdict was kept — reproduce-or-downgrade confirmed live on a FAIL as well
as on a PASS (v1.4 run, step 7).

The whole pipeline was then driven from the hosted frontend with a real
wallet (Rabby), on the same v1.6 contract, for `spec_1` (Spoon-Knife,
`bb4cc8d3…d00b7f`, the two requirements from the example above). Every step
was submitted from the UI and accepted with execution result SUCCESS:

| Step (button in the UI) | Result |
|---|---|
| Submit specification | `spec_1` registered, submitter shown |
| Freeze evidence from GitHub | 2 excerpts (README.md 15 lines, styles.css 23 lines); `evidence_root` `55e74a6d…0da87`, equal to the SHA-256 computed offline from the exact GitHub file |
| Propose decomposition | 2 requirements, texts identical to the submitted ones |
| Propose evidence mapping | accepted by validator review |
| Judge all remaining requirements | stylesheet: PASS (cites `styles.css`); README: INSUFFICIENT_EVIDENCE ("unclear what 'the change' refers to"), both by consensus |
| Aggregate verdicts | `INSUFFICIENT_EVIDENCE` (strict aggregation), 48 h challenge window opened with its closing time shown |

The frontend also showed the challenge button on both verdicts, the pinned
commit, the frozen excerpts and the deadline of every stage, all read
directly from the contract.

## Implementation vs ARCHITECTURE.md

[`ARCHITECTURE.md`](./ARCHITECTURE.md) is the locked v0.1 design. Where the
implementation differs, it is on purpose, and every difference makes the
protocol stricter, not looser:

| ARCHITECTURE.md | Implementation | Why |
|---|---|---|
| §9, §11, §13: decomposition, mapping and judgment use `prompt_comparative`; "no raw `gl.vm.run_nondet` custom tolerance logic" | Judgment and the two proposal steps use `gl.vm.run_nondet_unsafe` with an explicit validator | v1.0 used `prompt_comparative` as designed. Review showed an LLM deciding whether two outputs are "equivalent" does not bind the verdict exactly. The custom validator has **zero** tolerance: identical verdict, canonical leader output. The design's intent (no fuzzy tolerance) is kept, and made stronger. |
| §6: `DECOMPOSITION_PENDING`, `MAPPING_PENDING` states; disagreement → `*_FAILED` | Consensus completes inside one transaction; a rejected proposal is simply not accepted and another leader may try; `*_FAILED` is reached when validators agree nothing valid can be produced, or on timeout | A single bad leader could otherwise make a spec permanently fail (found in review, A4). |
| §16: the challenge re-judgment uses a larger validator set | Same validator count; reproduce-or-downgrade instead | Validator count is not a contract-level parameter of the current SDK. Reproduce-or-downgrade removes the reason to re-roll: a challenge cannot flip PASS and FAIL. |
| §16: one challenge per requirement | One challenge, plus one more if the first only produced a late first judgment after a timeout | Otherwise an attacker could let judgment time out and use up the only challenge (A8). |
| §5: anyone may call `request_verification` | Submitter only | For a PR, whoever freezes chooses which state of the PR is judged (A1). |
| §4, §7, §10: evidence = diff + referenced source + tests; excerpts as `{file_path, line_start, line_end, content_hash}` | Evidence is the diff, one excerpt per file; `line_start`/`line_end` count lines within that excerpt | Bounded, reproducible evidence from one fetch. Source and test files appear when the change touches them. |
| §10: the diff is fetched with `gl.nondet.web.render` | Fetched with `gl.nondet.web.get`; HTTP 200 and UTF-8 required | `render` collapses whitespace (measured live, L1); `evidence_root` must be the hash of the exact bytes. |
| §7: `ref` is a commit sha or PR number | Commits must be the full 40-character sha; PRs are resolved to full base and head shas | An abbreviated sha can be collided later (A10). |
| §12: the judge sees only the requirement's mapped evidence | It still judges and cites only mapped evidence, but also sees the *names* of every changed file and how many it is shown | Requirements about something being absent cannot be judged otherwise (D1, found live). |
| §15: `consensus_metadata` includes the validator count | Includes requirement count, freeze and finalize time; each result carries its `round`, `challenged` and `late_judgment` | The validator count is not visible to contract code. |
| §15 attestation fields | Adds `protocol_version`, the claim sentence, the full `requirements_text` and hash-pinned `cited_evidence` | Makes the attestation checkable on its own. |

## Repository layout

```
contracts/specproof.py         the Intelligent Contract (commented source)
contracts/specproof_deploy.py  deploy build: same code without comments
tools/build_deploy.py          builds it and proves it equivalent to the source
tests/test_specproof.py        95 unit and regression tests (no dependencies)
tests/test_fuzz.py             invariant fuzzer
tests/mutation_test.py         13 re-introduced vulnerabilities, all must be caught
tests/genlayer_stub.py         offline stub of the GenLayer SDK, used only by tests
tests/fixtures/                exact live GitHub diff used as a regression fixture
tools/probe_fetch.py           the StudioNet probe that measured the fetch primitives
frontend/index.html            no-build frontend (genlayer-js 1.1.8 via esm.sh)
ARCHITECTURE.md                protocol design (locked)
SECURITY.md                    threat model, invariants, attack tree, review history
CHANGELOG.md                   version history
docs/GENVM_LESSONS.md          GenVM / genlayer-js pitfalls confirmed on live deploys
```

## Tests

No dependencies, plain Python 3 (3.11–3.13):

```
python3 tools/build_deploy.py --check   # deploy file is current and equivalent
python3 tests/test_specproof.py         # 95 unit and regression tests
python3 tests/test_fuzz.py              # invariant fuzzer, 400 runs x 80 steps (~10 s)
python3 tests/mutation_test.py          # 13 mutants, each must be caught by both suites
```

CI runs all four on every push.

- **Unit and regression tests** cover every scenario in ARCHITECTURE.md §23
  and every finding in [SECURITY.md](./SECURITY.md); each finding's test
  fails on the version before its fix.
- **The invariant fuzzer** drives the contract with random call sequences
  from random senders, with adversarial input at every trust boundary:
  hostile diffs, malformed or injected LLM output for leader and
  validators, a malicious leader forging whole results, and time jumps
  across every deadline. After every transaction it checks 20 invariants. A
  failed call is rolled back as GenVM would. Beyond the CI run, 2,100 runs
  on fresh seeds (about 270,000 transactions) found no violation.
  `FUZZ_SEED=<n>` replays a failure exactly.
- **The mutation test** proves the suites are not vacuous. It found 14
  early tests that could never fail; they are fixed.
- `tests/genlayer_stub.py` really runs the contract's `validator_fn`
  against the leader's result, so the exact-match rules are exercised,
  not skipped. It cannot reproduce real GenVM, GitHub or LLM behavior;
  that is what live testing is for.

## Deploying

1. Deploy `contracts/specproof_deploy.py` on GenLayer Studio (no
   constructor arguments). It is built by `python3 tools/build_deploy.py`,
   which removes only comments and docstrings using Python's own tokenizer
   and refuses to write the file unless its syntax tree is identical to
   the source's.
2. Put the contract address into `CONTRACT_ADDRESS` near the top of
   `frontend/index.html`, and host that file anywhere static (e.g. GitHub
   Pages).

[docs/GENVM_LESSONS.md](./docs/GENVM_LESSONS.md) lists the GenVM and
genlayer-js pitfalls that were confirmed on live deploys (runner header,
storage initialization, exceptions inside nondet blocks, JSON mode, wallet
pattern).

## Scope

GitHub only (public repositories); one specification, one commit or PR,
one verification per `spec_id`; up to 12 requirements, 40 changed files and
200,000 characters of diff. SpecProof reads evidence; it does not run code
or tests. There is no staking or slashing yet, so challenges are open and
unstaked. The full list of limitations is in
[SECURITY.md](./SECURITY.md#known-residual-limitations).

## License

MIT — see [LICENSE](./LICENSE).
