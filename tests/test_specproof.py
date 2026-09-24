"""
Offline test suite for SpecProof -- custom runner, zero external
dependencies (no pytest/pip install needed), matching this project's
established pattern. Run with:

    python3 tests/test_specproof.py

Covers every scenario listed in ARCHITECTURE.md S23:
  - decomposition: agreement path, DECOMPOSITION_FAILED path, hash locking
  - evidence mapping: agreement path, MAPPING_FAILED path, hallucinated
    reference rejection
  - judgment: PASS/FAIL/INSUFFICIENT_EVIDENCE, citation validation
  - aggregation: all four priority rules
  - challenge: single requirement reopened, others untouched,
    re-aggregation correctness, one-challenge-per-requirement cap
  - evidence/spec immutability: hash stability across the lifecycle
  - timeout paths: every pending state resolving correctly on expiry
  - end-to-end: full run to FINALIZED, with and without a challenge
"""
import json
import sys
import os
import traceback
import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "contracts"))

import genlayer_stub
genlayer_stub.install()

import specproof as sp  # noqa: E402


# ---------------------------------------------------------------------------
# tiny test runner
# ---------------------------------------------------------------------------

_PASS = []
_FAIL = []


def test(name):
    def decorator(fn):
        _TESTS.append((name, fn))
        return fn
    return decorator


_TESTS = []


def run_all():
    for name, fn in _TESTS:
        genlayer_stub.reset()
        try:
            fn()
        except AssertionError as e:
            _FAIL.append((name, f"assertion failed: {e}"))
            continue
        except Exception as e:
            _FAIL.append((name, f"{type(e).__name__}: {e}\n{traceback.format_exc()}"))
            continue
        _PASS.append(name)

    print(f"\n{'=' * 60}")
    print(f"{len(_PASS)} passed, {len(_FAIL)} failed (of {len(_TESTS)})")
    if _FAIL:
        print("\nFAILURES:")
        for name, msg in _FAIL:
            print(f"\n--- {name} ---\n{msg}")
    print("=" * 60)
    return 0 if not _FAIL else 1


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

SAMPLE_DIFF = """diff --git a/vault.py b/vault.py
index 111..222 100644
--- a/vault.py
+++ b/vault.py
@@ -38,10 +38,14 @@ class Vault:
+    def withdraw(self, amount):
+        if msg.sender != self.owner:
+            raise Exception("unauthorized")
+        if amount > self.balances[msg.sender]:
+            raise Exception("insufficient balance")
+        self.balances[msg.sender] -= amount
+        emit Withdrawal(msg.sender, amount)
diff --git a/test/test_vault.py b/test/test_vault.py
index 333..444 100644
--- a/test/test_vault.py
+++ b/test/test_vault.py
@@ -10,3 +10,8 @@
+def test_withdraw_rejects_unauthorized():
+    pass
"""

DIFF_URL = "https://github.com/example/vault/commit/abc123.diff"

DECOMPOSITION_RESPONSE = {"requirements": [
    "withdraw() must check msg.sender authorization before transferring funds",
    "withdraw() must emit a Withdrawal event on every successful call",
    "withdraw() must reject amount > balances[msg.sender] before mutating state",
]}

DECOMPOSITION_RESPONSE_TWO = {"requirements": [
    "requirement A",
    "requirement B",
]}


def _submit_and_freeze(requirements_text=None, diff=SAMPLE_DIFF, url=DIFF_URL):
    c = sp.SpecProof()
    spec_id = c.submit_specification(
        "https://github.com/example/vault",
        "abc123",
        requirements_text or "1. Auth check. 2. Emit event. 3. Balance check.",
    )
    genlayer_stub.gl.nondet.web.pages[url] = diff
    c.request_verification(spec_id)
    return c, spec_id


def _freeze_and_decompose(decomposition_response=DECOMPOSITION_RESPONSE):
    c, spec_id = _submit_and_freeze()
    # CONFIRMED LIVE: gl.nondet.exec_prompt(..., response_format="json")
    # returns an already-parsed Python object, not a JSON string -- so the
    # stub is fed the same shape (a dict/list), never json.dumps(...) of one.
    genlayer_stub.gl.nondet.responses.append(decomposition_response)
    c.propose_decomposition(spec_id)
    return c, spec_id


def _mapping_response(c, spec_id, excerpt_indices_per_req=None):
    v = c.get_verification(spec_id)
    snapshot = c.evidence_snapshots[spec_id]
    excerpt_ids = list(snapshot.excerpt_ids)
    mapping = {}
    for i, rid in enumerate(v["requirement_ids"]):
        if excerpt_indices_per_req is not None:
            idxs = excerpt_indices_per_req[i]
        else:
            idxs = list(range(len(excerpt_ids)))
        mapping[rid] = [excerpt_ids[j] for j in idxs]
    return mapping


def _freeze_decompose_map():
    c, spec_id = _freeze_and_decompose()
    genlayer_stub.gl.nondet.responses.append(_mapping_response(c, spec_id))
    c.propose_evidence_mapping(spec_id)
    return c, spec_id


def _judgment(verdict, reason="because", cited=None):
    return {"verdict": verdict, "reason": reason, "cited_evidence": cited or []}


# ---------------------------------------------------------------------------
# S8/S10: submission + evidence freezing + immutability
# ---------------------------------------------------------------------------

@test("submit_specification rejects empty fields")
def _():
    c = sp.SpecProof()
    try:
        c.submit_specification("", "abc", "text")
        assert False, "expected exception on empty repository_url"
    except Exception:
        pass
    try:
        c.submit_specification("https://github.com/x/y", "abc", "   ")
        assert False, "expected exception on blank requirements_text"
    except Exception:
        pass


@test("constructor never assigns a plain dict/list to a TreeMap/DynArray field")
def _():    # Regression test for a real Studio deploy crash: assigning `{}` to a
    # TreeMap-typed field fails with "Is right the same storage type?
    # TreeMap <- dict" on real GenVM. TreeMap/DynArray fields must start
    # zero-initialized instead. This inspects __init__'s own source so a
    # future edit that reintroduces `self.<treemap_field> = {}` fails loudly
    # offline instead of only on the next live deploy.
    import inspect
    source = inspect.getsource(sp.SpecProof.__init__)
    treemap_fields = ["specifications", "evidence_snapshots", "evidence_excerpts",
                       "requirements", "verifications"]
    for field in treemap_fields:
        assert f"self.{field} = {{}}" not in source, (
            f"__init__ must not assign a plain dict to TreeMap field '{field}'"
        )
    # And confirm a fresh instance already has them, zero-initialized, with
    # no assignment needed.
    c = sp.SpecProof()
    for field in treemap_fields:
        assert getattr(c, field) == {}


@test("submit_specification locks spec_hash immutably")
def _():
    c = sp.SpecProof()
    spec_id = c.submit_specification("https://github.com/x/y", "abc", "req text")
    spec = c.specifications[spec_id]
    assert spec.spec_hash == sp._sha256("req text")
    # requirements_text itself is stored verbatim and never mutated by any
    # later step
    assert spec.requirements_text == "req text"


@test("request_verification reverts (freezes nothing) if the diff is unreachable")
def _():
    c = sp.SpecProof()
    spec_id = c.submit_specification("https://github.com/x/y", "abc123", "req")
    # deliberately do not register a stub page for the diff URL
    try:
        c.request_verification(spec_id)
        assert False, "expected exception on unreachable evidence"
    except Exception:
        pass
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_SPEC_REGISTERED, "status must not advance on a failed freeze"
    assert spec_id not in c.evidence_snapshots, "nothing should be frozen on failure"


@test("request_verification freezes evidence and hashes it")
def _():
    c, spec_id = _submit_and_freeze()
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_EVIDENCE_FROZEN
    snapshot = c.evidence_snapshots[spec_id]
    assert snapshot.diff_hash == sp._sha256(SAMPLE_DIFF)
    assert len(snapshot.excerpt_ids) >= 2, "diff should split into per-file excerpts"


@test("a plain commit ref is stored as-is (it is already an immutable pin)")
def _():
    c, spec_id = _submit_and_freeze()
    snapshot = c.evidence_snapshots[spec_id]
    assert snapshot.commit_sha == "abc123"


@test("a PR ref is resolved to its real head commit sha, never stored raw")
def _():
    c = sp.SpecProof()
    spec_id = c.submit_specification("https://github.com/example/vault", "PR#42", "req text")
    diff_url = "https://github.com/example/vault/pull/42.diff"
    api_url = "https://api.github.com/repos/example/vault/pulls/42"
    genlayer_stub.gl.nondet.web.pages[diff_url] = SAMPLE_DIFF
    genlayer_stub.gl.nondet.web.pages[api_url] = json.dumps({"head": {"sha": "deadbeef1234"}})

    c.request_verification(spec_id)

    snapshot = c.evidence_snapshots[spec_id]
    assert snapshot.commit_sha == "deadbeef1234"
    assert snapshot.commit_sha != "PR#42", "a PR ref must never be stored raw as commit_sha"


@test("request_verification reverts (freezes nothing) if a PR's head sha can't be resolved")
def _():
    c = sp.SpecProof()
    spec_id = c.submit_specification("https://github.com/example/vault", "PR#99", "req text")
    diff_url = "https://github.com/example/vault/pull/99.diff"
    api_url = "https://api.github.com/repos/example/vault/pulls/99"
    genlayer_stub.gl.nondet.web.pages[diff_url] = SAMPLE_DIFF
    genlayer_stub.gl.nondet.web.pages[api_url] = json.dumps({"head": {}})  # no sha in the API response

    try:
        c.request_verification(spec_id)
        assert False, "expected exception when PR head sha is missing"
    except Exception:
        pass

    assert spec_id not in c.evidence_snapshots, "nothing should be frozen if sha resolution fails"
    assert c.get_verification(spec_id)["status"] == sp.STATUS_SPEC_REGISTERED


@test("evidence excerpt hashes are stable across the lifecycle (immutability)")
def _():
    c, spec_id = _freeze_decompose_map()
    snapshot_before = c.evidence_snapshots[spec_id]
    hashes_before = {eid: c.evidence_excerpts[eid].content_hash for eid in snapshot_before.excerpt_ids}

    genlayer_stub.gl.nondet.responses.extend([_judgment(sp.VERDICT_PASS) for _ in c.get_verification(spec_id)["requirement_ids"]])
    c.judge_requirements(spec_id)
    c.aggregate(spec_id)

    snapshot_after = c.evidence_snapshots[spec_id]
    hashes_after = {eid: c.evidence_excerpts[eid].content_hash for eid in snapshot_after.excerpt_ids}
    assert hashes_before == hashes_after, "evidence hashes must never change after freezing"


# ---------------------------------------------------------------------------
# S9: decomposition
# ---------------------------------------------------------------------------

@test("decomposition agreement path creates one Requirement per proposed text")
def _():
    c, spec_id = _freeze_and_decompose()
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_DECOMPOSITION_AGREED
    assert len(v["requirement_ids"]) == 3
    texts = {c.get_requirement(rid)["text"] for rid in v["requirement_ids"]}
    assert texts == set(DECOMPOSITION_RESPONSE["requirements"])


@test("decomposition_hash locks sorted requirement texts")
def _():
    c, spec_id = _freeze_and_decompose()
    v = c.get_verification(spec_id)
    expected = sp._sha256(json.dumps(sorted(DECOMPOSITION_RESPONSE["requirements"])))
    assert v["decomposition_hash"] == expected


@test("decomposition failure path (validators disagree) is terminal")
def _():
    c, spec_id = _submit_and_freeze()
    genlayer_stub.gl.eq_principle.force_fail_next()
    c.propose_decomposition(spec_id)
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_DECOMPOSITION_FAILED
    assert v["status"] in sp.TERMINAL_STATUSES
    # cannot proceed to mapping from a terminal failure
    try:
        c.propose_evidence_mapping(spec_id)
        assert False, "expected exception: cannot map after DECOMPOSITION_FAILED"
    except Exception:
        pass


@test("decomposition failure path also triggers on malformed leader output")
def _():
    c, spec_id = _submit_and_freeze()
    genlayer_stub.gl.nondet.responses.append("not valid json at all")
    c.propose_decomposition(spec_id)
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_DECOMPOSITION_FAILED


# ---------------------------------------------------------------------------
# S11: evidence mapping
# ---------------------------------------------------------------------------

@test("evidence mapping agreement path assigns evidence_refs per requirement")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_MAPPING_AGREED
    for rid in v["requirement_ids"]:
        req = c.get_requirement(rid)
        assert len(req["evidence_refs"]) > 0


@test("evidence mapping gives the leader actual excerpt content, not just file paths")
def _():
    c, spec_id = _freeze_and_decompose()
    genlayer_stub.gl.nondet.responses.append(_mapping_response(c, spec_id))
    c.propose_evidence_mapping(spec_id)
    prompt = genlayer_stub.gl.nondet.last_prompt
    assert prompt is not None
    # "Withdrawal" only appears inside the diff's file content (the emitted
    # event name), never in a file_path -- if this fails, the mapping step
    # regressed back to judging file paths alone.
    assert "Withdrawal" in prompt, "mapping prompt must include excerpt content, not just paths"


@test("mapping_hash locks once agreed")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    assert v["mapping_hash"] != ""


@test("mapping failure path (validators disagree) is terminal")
def _():
    c, spec_id = _freeze_and_decompose()
    genlayer_stub.gl.nondet.responses.append(_mapping_response(c, spec_id))
    genlayer_stub.gl.eq_principle.force_fail_next()
    c.propose_evidence_mapping(spec_id)
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_MAPPING_FAILED
    assert v["status"] in sp.TERMINAL_STATUSES


@test("mapping rejects a hallucinated (nonexistent) excerpt_id")
def _():
    c, spec_id = _freeze_and_decompose()
    v = c.get_verification(spec_id)
    mapping = {rid: ["totally_fake_excerpt_id"] for rid in v["requirement_ids"]}
    genlayer_stub.gl.nondet.responses.append(mapping)
    c.propose_evidence_mapping(spec_id)
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_MAPPING_FAILED, "hallucinated reference must be rejected, not silently accepted"


@test("mapping rejects a proposal missing a requirement")
def _():
    c, spec_id = _freeze_and_decompose()
    v = c.get_verification(spec_id)
    snapshot = c.evidence_snapshots[spec_id]
    partial = {v["requirement_ids"][0]: list(snapshot.excerpt_ids)}
    genlayer_stub.gl.nondet.responses.append(partial)
    c.propose_evidence_mapping(spec_id)
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_MAPPING_FAILED


# ---------------------------------------------------------------------------
# S12/S13: judgment + citation validation
# ---------------------------------------------------------------------------

@test("judgment: all PASS verdicts recorded per requirement")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    genlayer_stub.gl.nondet.responses.extend([_judgment(sp.VERDICT_PASS) for _ in v["requirement_ids"]])
    c.judge_requirements(spec_id)
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_JUDGED
    for rid in v["requirement_ids"]:
        req = c.get_requirement(rid)
        assert req["verdict"] == sp.VERDICT_PASS
        assert req["status"] == sp.REQ_JUDGED


@test("judgment: FAIL and INSUFFICIENT_EVIDENCE verdicts recorded correctly")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    rids = v["requirement_ids"]
    responses = [
        _judgment(sp.VERDICT_PASS),
        _judgment(sp.VERDICT_FAIL, reason="no event emission found"),
        _judgment(sp.VERDICT_INSUFFICIENT, reason="ambiguous"),
    ]
    genlayer_stub.gl.nondet.responses.extend(responses)
    c.judge_requirements(spec_id)
    got = [c.get_requirement(rid)["verdict"] for rid in rids]
    assert got == [sp.VERDICT_PASS, sp.VERDICT_FAIL, sp.VERDICT_INSUFFICIENT]


@test("judgment citing evidence outside its mapping is rejected, resolves to INSUFFICIENT_EVIDENCE")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    rids = v["requirement_ids"]
    bad = _judgment(sp.VERDICT_PASS, cited=["not_a_real_mapped_excerpt"])
    genlayer_stub.gl.nondet.responses.append(bad)
    genlayer_stub.gl.nondet.responses.extend([_judgment(sp.VERDICT_PASS) for _ in rids[1:]])
    c.judge_requirements(spec_id)
    first = c.get_requirement(rids[0])
    assert first["verdict"] == sp.VERDICT_INSUFFICIENT, "out-of-mapping citation must not be accepted as PASS"


@test("judgment: an invalid verdict string is rejected, resolves to INSUFFICIENT_EVIDENCE")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    rids = v["requirement_ids"]
    genlayer_stub.gl.nondet.responses.append({"verdict": "MAYBE", "reason": "?", "cited_evidence": []})
    genlayer_stub.gl.nondet.responses.extend([_judgment(sp.VERDICT_PASS) for _ in rids[1:]])
    c.judge_requirements(spec_id)
    assert c.get_requirement(rids[0])["verdict"] == sp.VERDICT_INSUFFICIENT


# ---------------------------------------------------------------------------
# S14: aggregation
# ---------------------------------------------------------------------------

@test("aggregation: all PASS -> VERIFIED")
def _():
    assert sp.SpecProof._aggregate_verdicts([sp.VERDICT_PASS, sp.VERDICT_PASS]) == sp.STATUS_VERIFIED


@test("aggregation: one FAIL -> FAILED")
def _():
    assert sp.SpecProof._aggregate_verdicts([sp.VERDICT_PASS, sp.VERDICT_FAIL]) == sp.STATUS_FAILED


@test("aggregation: one INSUFFICIENT + rest PASS -> INSUFFICIENT_EVIDENCE")
def _():
    result = sp.SpecProof._aggregate_verdicts([sp.VERDICT_PASS, sp.VERDICT_INSUFFICIENT, sp.VERDICT_PASS])
    assert result == sp.STATUS_INSUFFICIENT_EVIDENCE


@test("aggregation: FAIL beats INSUFFICIENT_EVIDENCE priority")
def _():
    result = sp.SpecProof._aggregate_verdicts([sp.VERDICT_FAIL, sp.VERDICT_INSUFFICIENT])
    assert result == sp.STATUS_FAILED


@test("aggregate() sets status/final_verdict and opens the challenge window")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    genlayer_stub.gl.nondet.responses.extend([_judgment(sp.VERDICT_PASS) for _ in v["requirement_ids"]])
    c.judge_requirements(spec_id)
    result = c.aggregate(spec_id)
    assert result == sp.STATUS_VERIFIED
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_VERIFIED
    assert v["challenge_deadline"] != ""


# ---------------------------------------------------------------------------
# S16: challenge
# ---------------------------------------------------------------------------

def _fully_judged_and_aggregated(verdicts):
    c, spec_id = _freeze_decompose_map()
    v = c.get_verification(spec_id)
    assert len(verdicts) == len(v["requirement_ids"])
    genlayer_stub.gl.nondet.responses.extend([_judgment(vd) for vd in verdicts])
    c.judge_requirements(spec_id)
    c.aggregate(spec_id)
    return c, spec_id


@test("challenge reopens only the named requirement; others stay untouched")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_FAIL, sp.VERDICT_PASS, sp.VERDICT_PASS])
    v = c.get_verification(spec_id)
    rids = v["requirement_ids"]
    other_before = [c.get_requirement(rid)["verdict"] for rid in rids[1:]]

    genlayer_stub.gl.nondet.responses.append(_judgment(sp.VERDICT_PASS, reason="event emission actually present"))
    c.challenge(spec_id, rids[0])

    challenged = c.get_requirement(rids[0])
    assert challenged["verdict"] == sp.VERDICT_PASS
    assert challenged["round"] == 1
    assert challenged["challenge_count"] == 1

    other_after = [c.get_requirement(rid)["verdict"] for rid in rids[1:]]
    assert other_before == other_after, "non-challenged requirements must be untouched"


@test("challenge triggers correct re-aggregation")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_FAIL, sp.VERDICT_PASS, sp.VERDICT_PASS])
    assert c.get_verification(spec_id)["final_verdict"] == sp.STATUS_FAILED

    rids = c.get_verification(spec_id)["requirement_ids"]
    genlayer_stub.gl.nondet.responses.append(_judgment(sp.VERDICT_PASS))
    c.challenge(spec_id, rids[0])

    v = c.get_verification(spec_id)
    assert v["final_verdict"] == sp.STATUS_VERIFIED, "flipping the only FAIL to PASS should flip the aggregate"


@test("challenge is capped at exactly one round per requirement")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_FAIL, sp.VERDICT_PASS, sp.VERDICT_PASS])
    rids = c.get_verification(spec_id)["requirement_ids"]
    genlayer_stub.gl.nondet.responses.append(_judgment(sp.VERDICT_PASS))
    c.challenge(spec_id, rids[0])
    try:
        c.challenge(spec_id, rids[0])
        assert False, "second challenge on the same requirement must be rejected"
    except Exception:
        pass


@test("challenge is rejected after the challenge window has closed")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_PASS, sp.VERDICT_PASS, sp.VERDICT_PASS])
    v = c.verifications[spec_id]
    # simulate window expiry by moving the deadline into the past
    v.challenge_deadline = sp._iso_plus_seconds(sp._now_iso(), -1)
    try:
        c.challenge(spec_id, v.requirement_ids[0])
        assert False, "challenge after window close must be rejected"
    except Exception:
        pass


@test("challenge does not re-touch the locked evidence mapping")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_FAIL, sp.VERDICT_PASS, sp.VERDICT_PASS])
    rids = c.get_verification(spec_id)["requirement_ids"]
    mapping_before = c.get_requirement(rids[0])["evidence_refs"]
    genlayer_stub.gl.nondet.responses.append(_judgment(sp.VERDICT_PASS))
    c.challenge(spec_id, rids[0])
    mapping_after = c.get_requirement(rids[0])["evidence_refs"]
    assert mapping_before == mapping_after
    assert c.get_verification(spec_id)["mapping_hash"] != ""


# ---------------------------------------------------------------------------
# timeouts (S6)
# ---------------------------------------------------------------------------

@test("timeout: EVIDENCE_FROZEN past decomposition_deadline -> DECOMPOSITION_FAILED")
def _():
    c, spec_id = _submit_and_freeze()
    v = c.verifications[spec_id]
    v.decomposition_deadline = sp._iso_plus_seconds(sp._now_iso(), -1)
    status = c.expire_if_timed_out(spec_id)
    assert status == sp.STATUS_DECOMPOSITION_FAILED


@test("timeout: DECOMPOSITION_AGREED past mapping_deadline -> MAPPING_FAILED")
def _():
    c, spec_id = _freeze_and_decompose()
    v = c.verifications[spec_id]
    v.mapping_deadline = sp._iso_plus_seconds(sp._now_iso(), -1)
    status = c.expire_if_timed_out(spec_id)
    assert status == sp.STATUS_MAPPING_FAILED


@test("timeout: MAPPING_AGREED past judgment_deadline -> INSUFFICIENT_EVIDENCE, opens challenge window")
def _():
    c, spec_id = _freeze_decompose_map()
    v = c.verifications[spec_id]
    v.judgment_deadline = sp._iso_plus_seconds(sp._now_iso(), -1)
    status = c.expire_if_timed_out(spec_id)
    assert status == sp.STATUS_INSUFFICIENT_EVIDENCE
    assert c.get_verification(spec_id)["challenge_deadline"] != ""


@test("timeout: a still-fresh deadline does not force any transition")
def _():
    c, spec_id = _submit_and_freeze()
    status = c.expire_if_timed_out(spec_id)
    assert status == sp.STATUS_EVIDENCE_FROZEN


# ---------------------------------------------------------------------------
# end-to-end (S24-style walkthrough)
# ---------------------------------------------------------------------------

@test("end-to-end: submit -> FINALIZED with no challenge")
def _():
    c, spec_id = _submit_and_freeze()
    genlayer_stub.gl.nondet.responses.append(DECOMPOSITION_RESPONSE)
    c.propose_decomposition(spec_id)
    v = c.get_verification(spec_id)
    assert v["status"] == sp.STATUS_DECOMPOSITION_AGREED

    genlayer_stub.gl.nondet.responses.append(_mapping_response(c, spec_id))
    c.propose_evidence_mapping(spec_id)
    assert c.get_verification(spec_id)["status"] == sp.STATUS_MAPPING_AGREED

    rids = c.get_verification(spec_id)["requirement_ids"]
    genlayer_stub.gl.nondet.responses.extend([
        _judgment(sp.VERDICT_PASS, reason="authorization check present"),
        _judgment(sp.VERDICT_FAIL, reason="no event emission found in cited excerpt"),
        _judgment(sp.VERDICT_PASS, reason="balance check precedes mutation"),
    ])
    c.judge_requirements(spec_id)

    result = c.aggregate(spec_id)
    assert result == sp.STATUS_FAILED

    v = c.verifications[spec_id]
    v.challenge_deadline = sp._iso_plus_seconds(sp._now_iso(), -1)  # fast-forward past the window
    attestation_json = c.finalize(spec_id)
    attestation = json.loads(attestation_json)

    assert attestation["final_verdict"] == sp.STATUS_FAILED
    assert attestation["challenge_status"] == "NONE"
    assert len(attestation["requirement_results"]) == 3
    assert c.get_verification(spec_id)["status"] == sp.STATUS_FINALIZED

    fetched = c.get_attestation(spec_id)
    assert fetched == attestation_json


@test("end-to-end: submit -> challenge -> FINALIZED, attestation reflects the resolved challenge")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_FAIL, sp.VERDICT_PASS, sp.VERDICT_PASS])
    rids = c.get_verification(spec_id)["requirement_ids"]

    genlayer_stub.gl.nondet.responses.append(_judgment(sp.VERDICT_PASS, reason="event emission found on re-review"))
    c.challenge(spec_id, rids[0])
    assert c.get_verification(spec_id)["final_verdict"] == sp.STATUS_VERIFIED

    v = c.verifications[spec_id]
    v.challenge_deadline = sp._iso_plus_seconds(sp._now_iso(), -1)
    attestation = json.loads(c.finalize(spec_id))

    assert attestation["final_verdict"] == sp.STATUS_VERIFIED
    assert attestation["challenge_status"] == "RESOLVED"
    assert c.get_verification(spec_id)["status"] == sp.STATUS_FINALIZED


@test("finalize() rejects finalizing while the challenge window is still open")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_PASS, sp.VERDICT_PASS, sp.VERDICT_PASS])
    try:
        c.finalize(spec_id)
        assert False, "expected exception: challenge window still open"
    except Exception:
        pass


@test("get_attestation() rejects reading before FINALIZED")
def _():
    c, spec_id = _fully_judged_and_aggregated([sp.VERDICT_PASS, sp.VERDICT_PASS, sp.VERDICT_PASS])
    try:
        c.get_attestation(spec_id)
        assert False, "expected exception: not finalized yet"
    except Exception:
        pass


# ---------------------------------------------------------------------------
# state-machine guard rails
# ---------------------------------------------------------------------------

@test("cannot skip states: judge_requirements before mapping is rejected")
def _():
    c, spec_id = _freeze_and_decompose()
    try:
        c.judge_requirements(spec_id)
        assert False, "expected exception: mapping not agreed yet"
    except Exception:
        pass


@test("cannot re-run propose_decomposition after it already succeeded")
def _():
    c, spec_id = _freeze_and_decompose()
    try:
        c.propose_decomposition(spec_id)
        assert False, "expected exception: already DECOMPOSITION_AGREED"
    except Exception:
        pass


@test("_unwrap_json_list handles the exact shape confirmed live: {'requirements': [...]}")
def _():
    # Regression test for a real Studio crash: gl.nondet.exec_prompt(...,
    # response_format="json") returns an ALREADY-PARSED Python object, not a
    # JSON string -- a real deploy crashed with AttributeError: 'dict'
    # object has no attribute 'strip' from calling .strip() on it.
    result = sp.SpecProof._unwrap_json_list({"requirements": ["a", "b", "c"]})
    assert result == ["a", "b", "c"]
    # A bare list must also work.
    assert sp.SpecProof._unwrap_json_list(["x", "y"]) == ["x", "y"]
    # Neither a list nor an object containing one -> a clean RuntimeError,
    # never an AttributeError from calling string methods on a dict/list.
    try:
        sp.SpecProof._unwrap_json_list({"other_key": "not a list"})
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass
    try:
        sp.SpecProof._unwrap_json_list("a plain string")
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass


@test("_run_strict_eq converts an exception raised inside fn into a catchable RuntimeError")
def _():
    # Regression test for a real Studio failure: gl.nondet.web.render()
    # hitting a 404 inside a leader closure surfaced as a fatal, whole-
    # transaction Contract Error that bypassed a try/except wrapped around
    # the *outer* gl.eq_principle.strict_eq(...) call. _run_strict_eq must
    # catch it *inside* the closure and turn it into an ordinary
    # RuntimeError afterward, in normal (non-nondet) code.
    def failing_fn():
        raise Exception("simulated WEBPAGE_LOAD_FAILED (404)")
    try:
        sp._run_strict_eq(failing_fn)
        assert False, "expected a catchable RuntimeError"
    except RuntimeError as e:
        assert "simulated WEBPAGE_LOAD_FAILED" in str(e)


@test("_run_prompt_comparative converts an exception raised inside leader_fn into a catchable RuntimeError")
def _():
    def failing_leader_fn():
        raise Exception("simulated LLM call failure")
    try:
        sp._run_prompt_comparative(failing_leader_fn, "some criteria")
        assert False, "expected a catchable RuntimeError"
    except RuntimeError as e:
        assert "simulated LLM call failure" in str(e)


@test("unknown spec_id raises on every accessor")
def _():
    c = sp.SpecProof()
    for fn in (c.get_verification, lambda sid: c.request_verification(sid)):
        try:
            fn("spec_999")
            assert False, "expected exception for unknown spec_id"
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(run_all())
