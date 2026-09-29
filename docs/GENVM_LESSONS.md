# GenVM and genlayer-js lessons

Every item below was learned from a real GenLayer Studio deployment of this
contract (or of the wallet pattern it reuses), not from documentation alone.
They are kept here because each one silently breaks a contract or a
frontend in a way that is hard to diagnose.

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
  (`_run_strict_eq`, and at the time `_run_prompt_comparative`, which
  v1.2 replaced with `_propose_and_review`) that catch inside the
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
- `gl.eq_principle.strict_eq(fn)` (evidence fetches) and
  `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` (all LLM steps since
  v1.2) are called directly (confirmed against sdk.genlayer.com's published API).
  When validators genuinely disagree the transaction is simply not accepted
  (it does not raise into contract code), which is why every pending stage
  has a timeout that `expire_if_timed_out()` resolves.
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

- **Confirmed via an on-chain probe on StudioNet:** `gl.nondet.web.render(url)`
  returns rendered page *text*: runs of spaces are collapsed to one and
  trailing spaces are removed, even for a plain-text `.diff`. For anything
  where exact bytes matter (code, hashes), use `gl.nondet.web.get(url)`,
  which returns a response with `.status` (int) and `.body` (bytes) and was
  byte-exact; `render(url, mode="html")` keeps whitespace but wraps the text
  in `<pre>`. `gl.nondet.web` in this build exposes `get`, `post`, `head`,
  `patch`, `delete`, `request` and `render`.
- Studio sometimes fails with "Could not load contract schema" on files
  with long comment blocks or non-ASCII characters; deploy files should be
  ASCII-only with just the two header lines before the code (the deploy
  build produced by `tools/build_deploy.py` is).

## Wallet pattern (genlayer-js, Rabby in the Mises browser)

- `createClient({ chain: studionet, account })` alone is sufficient.
- Do not add a `provider:` option.
- Do not call `client.connect()` (fails on non-MetaMask wallets like Rabby).
- Do not call `client.initializeConsensusSmartContract()`.
- Do not repeat `account` inside individual `writeContract()` calls.
- **`studionet` is exported from `genlayer-js/chains`, not from the
  top-level `genlayer-js` package.** Importing it from the top level is a
  `SyntaxError` for a missing named export, which silently kills the whole
  module script: every button just does nothing (confirmed live). Use:
  ```js
  import { createClient } from "https://esm.sh/genlayer-js@1.1.8";
  import { studionet } from "https://esm.sh/genlayer-js@1.1.8/chains";
  ```
- A read-only client needs no wallet: `createClient({ chain: studionet })`.
