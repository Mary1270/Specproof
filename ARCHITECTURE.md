# SpecProof Protocol — Architecture v0.1

> SpecProof does not prove that software is bug-free. It verifies whether the
> available evidence supports each explicitly declared requirement for a
> specific, immutable specification and evidence snapshot.

---

## 1. Problem Definition

Teams routinely assert that a change satisfies a requirement ("this PR fixes
the auth bypass", "withdrawals now check balance first") with no independent,
reproducible record of *why* that assertion is true. Existing AI code-review
tools give a single opinion from a single model call, with no consensus, no
frozen evidence, and no way to dispute a specific claim later. SpecProof is a
GenLayer Intelligent Contract that turns a natural-language specification and
a GitHub artifact (commit or PR) into a set of independently-judged,
consensus-backed, disputable claims about what the evidence does and does not
support.

## 2. Design Goals

- Every judgment is traceable to a specific, hashed piece of evidence — never
  a bare LLM opinion.
- Consensus applies to *structured* per-requirement judgments, not a single
  freeform verdict.
- Evidence and specification are frozen the moment verification starts; nothing
  can be edited out from under a judgment after the fact.
- A dispute reopens only the disputed requirement, not the whole verification.
- The protocol's own claims stay narrow enough to be true by construction.

## 3. Non-Goals (v1)

- SpecProof does not execute code, run test suites, or sandbox arbitrary
  repositories. It reads and reasons over evidence (diffs, source, existing
  test *files*, CI *result text* if supplied) — it does not run anything.
- SpecProof does not prove correctness, absence of bugs, or security.
- SpecProof does not natively support GitLab, Bitbucket, or non-Git artifacts
  in v1 — GitHub is the only evidence adapter.
- SpecProof does not do stake/slashing economics in v1 (see §20).

## 4. Core Concepts

| Term | Meaning |
|---|---|
| **Specification** | A user-submitted natural-language list of requirements about a piece of software. |
| **Requirement** | One independent, judgeable claim decomposed from the specification (e.g. "unauthorized users cannot withdraw"). |
| **Evidence Snapshot** | The frozen, hashed state of the target GitHub artifact (diff + referenced source + referenced tests) at verification time. |
| **Evidence Mapping** | The claim, per requirement, of which parts of the snapshot are relevant to judging it. |
| **Requirement Judgment** | A structured PASS / FAIL / INSUFFICIENT_EVIDENCE verdict for one requirement, with a reason and citations into the evidence. |
| **Verification** | The whole run: one specification against one evidence snapshot, producing one aggregated result. |
| **Attestation** | The final, published record of what was verified, against what, with what result — see §15. |
| **Challenge** | A dispute against one specific requirement's judgment, reopening only that requirement. |

## 5. End-to-End Lifecycle

```
1. submit_specification(repo, ref, requirements_text)
        │
        ▼
2. request_verification(spec_id)
        │  fetches diff/source/tests via gl.nondet.web, hashes everything
        ▼
3. EVIDENCE_FROZEN
        │
        ▼
4. propose_decomposition()          -- leader proposes; validators confirm
        │
        ▼
5. DECOMPOSITION_AGREED  (or DECOMPOSITION_FAILED -> terminal)
        │
        ▼
6. propose_evidence_mapping()       -- per requirement; validators confirm
        │
        ▼
7. MAPPING_AGREED  (or MAPPING_FAILED -> terminal)
        │
        ▼
8. judge_requirements()             -- per requirement, independent judgment + consensus
        │
        ▼
9. aggregate()                       -- strict ALL-PASS rule (§14)
        │
        ▼
10. VERIFIED / FAILED / INSUFFICIENT_EVIDENCE
        │
        │  optional, per requirement, within challenge window
        ▼
11. challenge(requirement_id)  -> reopen just that requirement -> re-judge -> re-aggregate
        │
        ▼
12. FINALIZED  -> attestation published
```

## 6. State Machine

```
SPEC_REGISTERED
     │  request_verification()
     ▼
EVIDENCE_FROZEN
     │  propose_decomposition()
     ▼
DECOMPOSITION_PENDING
     ├─ validators agree ──────────────► DECOMPOSITION_AGREED
     └─ validators disagree ───────────► DECOMPOSITION_FAILED  [terminal]
                                              │
DECOMPOSITION_AGREED
     │  propose_evidence_mapping()
     ▼
MAPPING_PENDING
     ├─ validators agree ──────────────► MAPPING_AGREED
     └─ validators disagree ───────────► MAPPING_FAILED  [terminal]

MAPPING_AGREED
     │  judge_requirements() -- one judgment round per requirement
     ▼
JUDGED
     │  aggregate()
     ▼
VERIFIED | FAILED | INSUFFICIENT_EVIDENCE   -- aggregate result, challenge window open
     │
     ├─ challenge window expires, no challenge ──► FINALIZED  [terminal]
     │
     └─ challenge(requirement_id) filed
              │
              ▼
        REQUIREMENT_REOPENED (that requirement only)
              │  re-judge that requirement (larger validator set, see §16)
              ▼
        re-aggregate()
              │
              ▼
        VERIFIED | FAILED | INSUFFICIENT_EVIDENCE  (challenge window re-opens once, capped — see §16)
              │
              ▼
        FINALIZED  [terminal]
```

Every non-final state has a hard timeout; an expired pending state resolves to
its failure branch (`*_FAILED` or, past aggregation, `INSUFFICIENT_EVIDENCE`)
so the machine can never hang indefinitely.

## 7. Data Model

```
Specification
  spec_id
  submitter
  repository_url
  ref (commit sha or PR number)
  requirements_text        # raw natural-language input, immutable once submitted
  spec_hash                # sha256(requirements_text)
  created_at

EvidenceSnapshot
  spec_id
  commit_sha               # resolved, immutable Git ref -- never "latest"
  diff_hash
  source_excerpts: [ {file_path, line_start, line_end, content_hash} ]
  frozen_at

Requirement
  requirement_id
  spec_id
  text                      # the decomposed, independent claim
  status                    # PENDING | JUDGED | CHALLENGED
  evidence_refs: [ {file_path, line_start, line_end, content_hash} ]
  judgment: RequirementJudgment | None
  challenge_count

RequirementJudgment
  requirement_id
  verdict                  # PASS | FAIL | INSUFFICIENT_EVIDENCE
  reason                   # short structured justification
  cited_evidence: [ {file_path, line_start, line_end} ]
  round                    # 0 = original judgment, 1+ = post-challenge

Verification
  spec_id
  status                   # see state machine, §6
  final_verdict            # VERIFIED | FAILED | INSUFFICIENT_EVIDENCE | None
  decomposition_hash        # hash of the agreed requirement set, once locked
  mapping_hash              # hash of the agreed evidence mapping, once locked
  attestation: Attestation | None
```

## 8. Specification Model

- `requirements_text` is a single free-text block, submitted once, immutable.
  Editing a specification means submitting a new `spec_id` — a `Verification`
  is always tied to exactly one immutable spec and one immutable evidence
  snapshot.
- `spec_hash = sha256(requirements_text)` is computed at submission and
  included in the attestation, so anyone can later confirm which exact text
  was verified.

## 9. Requirement Decomposition

- The leader proposes a decomposition: a list of independent requirement
  texts derived from `requirements_text`.
- Validators evaluate the proposal via `prompt_comparative` against three
  criteria stated explicitly in the prompt: **complete** (every distinct
  obligation in the spec text is covered by some requirement), **non-overlapping**
  (no two requirements test the same obligation), and **judgeable** (each
  requirement is concrete enough to be checked against evidence, not a vague
  restatement of the whole spec).
- If validators reach consensus that the decomposition satisfies all three →
  `DECOMPOSITION_AGREED`, and `decomposition_hash = sha256(sorted requirement
  texts)` is locked into `Verification`.
- If consensus is not reached → `DECOMPOSITION_FAILED`, terminal. The
  submitter may resubmit a clearer specification as a new `spec_id`; v1 does
  not auto-retry with a revised decomposition, to avoid an unbounded
  leader-proposes-in-a-loop pattern.

## 10. Evidence Model

- Evidence is never "the whole repository." Every piece of evidence is a
  `{file_path, line_start, line_end, content_hash}` tuple: a bounded excerpt,
  not a file reference alone.
- `content_hash = sha256(exact excerpt text)` — if the underlying file changes
  later, the hash reveals it; the excerpt actually judged is preserved
  regardless (the excerpt text itself is stored, not re-fetched at judgment
  time).
- The diff between the base ref and `commit_sha` is fetched once, at
  `request_verification()`, via `gl.nondet.web.render` (or the GitHub API
  through the same nondeterministic-fetch mechanism), and hashed as
  `diff_hash`. All later steps operate on this frozen snapshot, never a live
  fetch.

## 11. Evidence Mapping

- A separate, explicit step (§5 step 6) from decomposition. For each agreed
  requirement, the leader proposes which evidence excerpts are relevant.
- Validators confirm the mapping is *plausible and sufficient in principle*
  (not the judgment itself) via `prompt_comparative`: does the cited evidence
  plausibly bear on this requirement at all? This catches leader
  hallucination of nonexistent file references before it can poison a
  judgment.
- Locked as `mapping_hash` once agreed, same failure semantics as
  decomposition (`MAPPING_FAILED` is terminal for this spec_id).

## 12. Requirement Judgment

- Each requirement is judged independently, in its own nondet round, using
  *only* its mapped evidence excerpts — not the full diff, not other
  requirements' evidence. This is what makes a judgment's reasoning
  inspectable: "R2 failed because of exactly these 12 lines," not "the AI
  looked at the PR and didn't like it."
- Output is structured: `{verdict, reason, cited_evidence}` — `cited_evidence`
  must be a subset of the requirement's mapped evidence; a judgment citing
  evidence outside its own mapping is rejected as malformed (defensive
  validation, not itself a consensus round).
- Three verdicts only: `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE` (the mapped
  evidence doesn't actually let anyone tell either way — distinct from FAIL,
  which asserts the requirement is actively violated).

## 13. Validator Consensus

- Decomposition and evidence mapping use `prompt_comparative` against
  explicit written criteria (§9, §11) — a comparative judgment task, not a
  single categorical fact.
- Requirement judgment uses `prompt_comparative` as well: each validator
  independently derives its own `{verdict, reason, cited_evidence}` from the
  same frozen evidence excerpts, and GenLayer's comparative-consensus
  mechanism resolves agreement on the *verdict* field specifically (reasons
  may differ in wording; the categorical verdict must match).
- No raw `gl.vm.run_nondet` custom tolerance logic anywhere in this
  contract — every consensus point is a categorical/structured value through
  GenLayer's built-in comparative primitives, consistent with the pattern
  already validated safe in this project's prior work (see the Tribunal audit
  note in project history).

## 14. Aggregation Rules

Strict, no threshold:

```
ALL requirements = PASS           → VERIFICATION = VERIFIED
ANY requirement  = FAIL           → VERIFICATION = FAILED
ANY unresolved / INSUFFICIENT     → VERIFICATION = INSUFFICIENT_EVIDENCE
                                     (unless at least one FAIL exists, which
                                      takes priority — an active violation is
                                      never masked by an unrelated gap)
```

Priority order when a verification has a mix: **FAIL beats
INSUFFICIENT_EVIDENCE beats PASS.** No partial-credit threshold, and no
per-requirement weighting in v1 — deliberately, since requirements are not
declared with relative importance, and inventing an implicit weighting would
be a bigger integrity risk than being strict.

## 15. Attestation Model

The attestation is deliberately narrow. It never claims correctness — only
that a specific, hashed input reached a specific, hashed result:

```
Attestation
  spec_hash
  repository_url
  commit_sha
  evidence_root            # hash of the full set of evidence excerpts used
  decomposition_hash
  mapping_hash
  requirement_results: [ {requirement_id, verdict, reason} ]
  final_verdict
  consensus_metadata        # round count, validator count, timestamps
  challenge_status          # NONE | CHALLENGED | RESOLVED
```

Published, human-readable framing (always paired with the structured record):
*"For specification hash X and evidence snapshot Y, GenLayer's validators
reached requirement-level result Z."* Never *"this code is correct"* or
*"this PR is safe to merge."*

## 16. Challenge / Reverification

- A challenge names exactly one `requirement_id` and must be filed within the
  challenge window after the aggregate result is first reached.
- Reopening reruns **only** step 12 (judgment) for that requirement, against
  its *already-locked* evidence mapping — a challenge disputes the judgment,
  not the mapping or decomposition (those have their own agreement gates
  earlier and are not revisited).
- The re-judgment round uses a **larger validator set** than the original
  round (mirroring the escalation pattern already proven in this project's
  prior work), so a challenge is a genuine higher-scrutiny re-check, not a
  coin-flip do-over.
- After re-judgment, `aggregate()` reruns using the new result for that one
  requirement plus the untouched results for every other requirement.
- **Capped at one challenge per requirement.** A requirement's judgment
  becomes final after its single re-judgment round — this guarantees
  termination without needing an arbitrary round limit like the base
  verification's escalation counter, since the object being challenged
  (one requirement) never re-triggers itself.
- Filing a challenge is a stated v1 design point for economics (§20): open
  in v1 (no stake required) since bonding a challenge meaningfully needs a
  economic model this version deliberately defers.

## 17. Deterministic vs. Nondeterministic Boundary

| Operation | Type | Mechanism |
|---|---|---|
| Fetching diff/source from GitHub | Nondeterministic | `gl.nondet.web.render`, once, at freeze time |
| Hashing frozen evidence | Deterministic | plain `hashlib`, over already-fetched text |
| Decomposition proposal | Nondeterministic | LLM leader call |
| Decomposition agreement | Nondeterministic, consensus-bound | `prompt_comparative` |
| Evidence mapping proposal | Nondeterministic | LLM leader call |
| Evidence mapping agreement | Nondeterministic, consensus-bound | `prompt_comparative` |
| Requirement judgment | Nondeterministic, consensus-bound | `prompt_comparative`, evidence copied out of storage before entering the nondet block (per this project's established lesson on `self`-capture in closures) |
| Aggregation | Deterministic | pure function over already-agreed judgments |
| Attestation construction | Deterministic | pure function over already-agreed data |

Nothing storage-backed (a `Requirement` or `EvidenceSnapshot` object fetched
from a `TreeMap`) is ever passed directly into a nondet closure; only
plain, in-memory copies of the specific fields needed cross that boundary.

## 18. Security Model

- **Evidence integrity**: every excerpt is hash-pinned at freeze time; a
  judgment always cites hashes, so tampering after the fact is detectable.
- **Leader hallucination**: guarded at two points — evidence-mapping
  agreement (§11) rejects references validators can't confirm are plausible,
  and judgment citation validation (§12) rejects a verdict citing evidence
  outside its own agreed mapping.
- **Spec/evidence immutability**: `spec_id` and its `EvidenceSnapshot` never
  change after freezing; a new attempt is always a new `spec_id`.
- **Termination guarantee**: every pending state has a timeout; challenge is
  capped at one round per requirement (§16). No unbounded loop exists
  anywhere in the state machine.

## 19. Failure Modes

| Failure | Handling |
|---|---|
| Validators can't agree on decomposition | `DECOMPOSITION_FAILED`, terminal, resubmit as new spec |
| Validators can't agree on evidence mapping | `MAPPING_FAILED`, terminal, resubmit as new spec |
| GitHub artifact unreachable at freeze time | `request_verification()` reverts; nothing is frozen, submitter may retry |
| A requirement's evidence is genuinely absent/ambiguous | `INSUFFICIENT_EVIDENCE` for that requirement, not forced into PASS/FAIL |
| Malicious/contradictory specification text | Caught structurally: an incoherent spec tends to fail the decomposition agreement gate (§9) rather than needing special-case handling |
| Repeated challenge attempts on one requirement | Rejected after the first challenge round for that `requirement_id` (§16) |

## 20. Economic Model (conceptual only, v1)

No staking, slashing, or fees are implemented in v1. The protocol is
free to use while the verification mechanism itself is being proven out —
adding stake-gated challenges or paid verification requests is explicitly
deferred to v2, once the judgment pipeline above is validated end-to-end.
This mirrors the project's own principle from prior work: get the
adjudication mechanism right before layering economics on top of it.

## 21. v1 Scope

- Single specification, single GitHub commit or PR, single verification per
  `spec_id`.
- GitHub as the only evidence adapter (public repos; no private-repo auth
  flow in v1).
- Decomposition, mapping, and judgment each as their own on-chain,
  consensus-gated step.
- One challenge round per requirement.
- A no-build frontend to submit a spec, watch verification progress
  requirement-by-requirement, and read the attestation.

## 22. Explicit v1 Limitations

- SpecProof reads and reasons over evidence; it does not execute code, run
  test suites, or verify that cited test files actually pass. If a
  requirement's evidence includes a test file, the contract can only judge
  whether the test's *content* appears to address the requirement — not
  whether that test currently passes in CI.
- No cross-referencing against a live CI system in v1 (no GitHub Actions
  status check integration).
- No relative importance/weighting between requirements (§14) — a trivial
  requirement failing blocks `VERIFIED` exactly as a critical one would.
- Single evidence adapter (GitHub only); no GitLab/Bitbucket/raw-diff upload
  in v1.
- No economics (§20) — open, unstaked challenges in v1.
- Decomposition quality depends on specification clarity; a vague spec is
  expected to fail the decomposition-agreement gate rather than produce a
  misleading result, but this means poorly-written specifications may
  legitimately never reach a verdict.

## 23. Test Strategy

Offline suite (custom runner, no external dependencies, matching this
project's established pattern), covering at minimum:

- Decomposition: agreement path, `DECOMPOSITION_FAILED` path, hash locking.
- Evidence mapping: agreement path, `MAPPING_FAILED` path, hallucinated
  reference rejection.
- Judgment: PASS/FAIL/INSUFFICIENT_EVIDENCE per requirement, citation
  validation (rejecting out-of-mapping citations).
- Aggregation: all-PASS → VERIFIED, one FAIL → FAILED, one
  INSUFFICIENT + rest PASS → INSUFFICIENT_EVIDENCE, FAIL-beats-INSUFFICIENT
  priority.
- Challenge: single requirement reopened, others untouched, re-aggregation
  correctness, one-challenge-per-requirement cap enforced.
- Evidence/spec immutability: hash stability across the full lifecycle.
- Timeout paths: every pending state resolving correctly on expiry.
- End-to-end: a full run from `submit_specification` to `FINALIZED`
  attestation, both with and without a challenge.

## 24. Example End-to-End Verification

```
Specification (spec_id = S1):
  "1. Unauthorized users must not be able to withdraw funds.
   2. Every withdrawal must emit an event.
   3. The contract must reject withdrawals above the user's balance."

Repository: github.com/example/vault   Ref: PR #42

Decomposition (agreed):
  R1: "withdraw() must check msg.sender authorization before transferring funds"
  R2: "withdraw() must emit a Withdrawal event on every successful call"
  R3: "withdraw() must reject amount > balances[msg.sender] before mutating state"

Evidence mapping (agreed):
  R1 -> vault.py:L40-L58 (withdraw function body)
  R2 -> vault.py:L40-L58
  R3 -> vault.py:L40-L58, test/test_vault.py:L12-L30

Judgment:
  R1: PASS  -- "authorization check present at L41, precedes transfer at L55"
  R2: FAIL  -- "no event emission found in the cited excerpt"
  R3: PASS  -- "balance check at L44 precedes state mutation at L47"

Aggregation: ANY FAIL -> VERIFICATION = FAILED

Attestation published: FAILED, with R2's cited evidence and reason.

Challenge filed on R2 (submitter believes the event emission is elsewhere
in the file, outside the originally mapped excerpt -- but per §16, a
challenge reopens judgment on the LOCKED mapping only, so this specific
disagreement would in practice need a fresh spec_id with a corrected mapping
proposal, not a challenge -- illustrating why evidence mapping agreement in
step 6 matters as much as judgment itself).
```
