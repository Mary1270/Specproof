# SpecProof

A GenLayer Intelligent Contract for decentralized, evidence-based
verification of software specifications.

> SpecProof does not prove that software is bug-free. It verifies whether
> the available evidence supports each explicitly declared requirement for a
> specific, immutable specification and evidence snapshot.

Given a GitHub repository, a commit or PR ref, and a natural-language
specification, SpecProof:

1. Decomposes the specification into independent, judgeable requirements
   (leader proposal + validator consensus).
2. Freezes the evidence (the diff, hashed) so nothing can move under a
   judgment after the fact.
3. Maps each requirement to the specific evidence excerpts relevant to it
   (leader proposal + validator consensus, with hallucinated-reference
   rejection).
4. Judges each requirement independently -- PASS / FAIL /
   INSUFFICIENT_EVIDENCE -- using only its own mapped evidence.
5. Aggregates strictly: any FAIL beats any INSUFFICIENT_EVIDENCE beats all
   PASS.
6. Publishes a narrow, structured attestation, and allows one challenge
   (reopened judgment only) per requirement within a challenge window.
   ARCHITECTURE.md §16 calls for the re-judgment round to use a larger
   validator set than the original; that is **not** implemented in
   `contracts/specproof.py` in v1, since validator-set size does not appear
   to be a contract-controllable parameter in the current GenLayer SDK (see
   the note above `challenge()` in the contract). A challenge currently
   re-judges at the same validator count as the original round.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full design: state
machine, data model, security model, and failure modes.

## Repository layout

```
contracts/specproof.py      the Intelligent Contract
tests/test_specproof.py     offline test suite (custom runner, no pip/pytest)
tests/genlayer_stub.py      local stub of the GenLayer SDK used only by tests
frontend/index.html         no-build frontend (genlayer-js via esm.sh)
ARCHITECTURE.md             full protocol design (locked)
```

## Running the tests

No dependencies to install -- plain Python 3:

```
python3 tests/test_specproof.py
```

This runs entirely offline against `tests/genlayer_stub.py`, a hand-written
stub of the GenLayer SDK surface the contract uses (`gl.public`,
`gl.message`, `gl.vm.run_nondet`, `gl.eq_principle`, `gl.nondet.web`,
`gl.nondet.exec_prompt`, storage types). It gives tests full control over
simulated wallet addresses, canned LLM responses, canned web-fetch pages, and
forced validator disagreement, without touching a network or a real GenVM.

CI (`.github/workflows/tests.yml`) runs the same command on every push.

## Deploying

Deployment and live testing happen through the GenLayer Studio UI. There is
no build step for the frontend -- it loads `genlayer-js` directly from
`esm.sh` and connects to an injected wallet (`window.ethereum`).

Known-working wallet pattern (validated on this project's prior contracts):

- `createClient({ chain: studionet, account })` alone is sufficient.
- Do not add a `provider:` option.
- Do not call `client.connect()` (fails on non-MetaMask wallets like Rabby).
- Do not call `client.initializeConsensusSmartContract()`.
- Do not repeat `account` inside individual `writeContract()` calls.

After deploying `contracts/specproof.py` on GenLayer Studio, paste the
deployed address into `CONTRACT_ADDRESS` near the top of
`frontend/index.html`.

## Known open items before deploying

- **Confirmed via a real Studio deploy attempt:** `gl.nondet.exec_prompt(...,
  response_format="json")` returns an **already-parsed Python object**
  (e.g. `{"requirements": [...]}`), never a JSON string -- calling
  `.strip()`/`json.loads()` on it crashed with `AttributeError: 'dict'
  object has no attribute 'strip'`. It also confirmed JSON mode wants a
  top-level *object*, not a bare array -- the model wrapped our requested
  array under a `"requirements"` key on its own. Fixed by having
  `_unwrap_json_list`/`_parse_mapping`/`_parse_judgment` accept the parsed
  object directly (no more `json.loads`), and by asking the decomposition
  prompt for that exact `{"requirements": [...]}` shape instead of a bare
  array. New offline tests exercise `_unwrap_json_list` directly against
  this shape.
- **Confirmed via a real Studio deploy attempt:** `gl.nondet.web.render()`
  raising inside a leader closure (e.g. a 404 on the diff URL) does **not**
  propagate back as a normal, catchable Python exception to a try/except
  wrapped around the *outer* `gl.eq_principle.strict_eq(...)` /
  `prompt_comparative(...)` call -- it surfaces as a fatal, whole-
  transaction "Contract Error" that bypasses ordinary error handling
  entirely (`Equivalence Principle Outputs: 0`, raw traceback in stderr).
  Fixed by routing every nondet call through two shared helpers
  (`_run_strict_eq`, `_run_prompt_comparative`) that catch inside the
  closure, turn a failure into a plain string sentinel, and only raise a
  normal `RuntimeError` once control is back in ordinary (non-nondet) code.
  Two new offline tests exercise this directly.
- **Confirmed via a real Studio deploy attempt:** the constructor crashed
  with `AssertionError: Is right the same storage type? \`TreeMap\` <- \`dict\``
  because `__init__` assigned a plain `{}` to each `TreeMap`-annotated
  field. GenVM zero-initializes `TreeMap`/`DynArray` fields automatically
  the moment they're declared -- they must not be assigned in `__init__` at
  all (confirmed against GenLayer's own storage docs and a working public
  example that only initializes its scalar fields, never its `TreeMap`/
  `DynArray` ones). Fixed by removing those five assignments; the offline
  stub's `Contract` base class now also zero-initializes `TreeMap`/
  `DynArray`-annotated fields itself, so this class of bug is caught
  offline going forward instead of only on a live deploy.
- **Confirmed via a real Studio deploy attempt:** the runner header must be
  two lines -- a plain version comment, then the `Depends` line:
  ```python
  # v0.2.16
  # { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
  ```
  Deploying with only the `Depends` line (no preceding version comment)
  makes GenVM log "runner comment does not start with version, using
  default" and silently fall back to an old default runtime -- which then
  crashed with `NameError: name 'dataclass' is not defined` at the
  `@dataclass` decorator, since `from genlayer import *` doesn't reliably
  export `dataclass` on that fallback runtime. Fixed by (1) adding the
  version line, and (2) importing `dataclass` explicitly from the stdlib
  (`from dataclasses import dataclass`, after the wildcard import so it
  always wins the binding) rather than depending on genlayer's own export
  list for it.
- `gl.eq_principle.strict_eq(fn)` and `gl.eq_principle.prompt_comparative(fn, principle=...)`
  are called directly (confirmed against sdk.genlayer.com's published API),
  not routed through `gl.vm.run_nondet`. What is **not** confirmed from the
  docs alone is the exact exception type GenVM raises when validators
  genuinely disagree -- `_consensus_categorical` / `_fetch_nondet` in
  `contracts/specproof.py` catch broadly (`except Exception`) as a
  placeholder until a live Studio test surfaces the real one.
- Leader LLM calls pass `response_format="json"` to `gl.nondet.exec_prompt`;
  the contract still validates/parses the result defensively either way.
- Validator-count escalation on `challenge()` is intentionally not
  implemented (see above) rather than faked with a parameter that would
  silently do nothing.
- A PR ref (e.g. `PR#42`) is resolved to its actual head commit sha via the
  GitHub API (`.../pulls/{n}`, `head.sha`) before anything is frozen, so an
  attestation's `commit_sha` is never an unresolved, mutable reference like
  `PR#42` itself. A plain commit sha ref is already immutable and is stored
  as-is.
- Evidence mapping (§11) shows the leader each excerpt's actual content
  (truncated to `MAPPING_EXCERPT_CONTENT_LIMIT`), not just its file path --
  a mapping judged from paths alone wouldn't be evidence-based.

## Scope (v1)

- Single specification, single GitHub commit or PR, single verification per
  `spec_id`. GitHub only (public repos).
- No staking/slashing economics -- open, unstaked challenges (deferred to a
  future version).
- Reads and reasons over evidence; does not execute code or run test suites.

Full details, non-goals, and explicit limitations are in
[`ARCHITECTURE.md`](./ARCHITECTURE.md) (§3, §21, §22).

## License

MIT -- see [`LICENSE`](./LICENSE).
