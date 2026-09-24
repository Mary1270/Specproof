# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
#
# SpecProof -- decentralized, evidence-based verification of software
# specifications. See ARCHITECTURE.md for the full design. This file
# implements it section by section:
#   S6  state machine        -> STATUS_* constants + method guards
#   S7  data model            -> the @allow_storage dataclasses below
#   S9  decomposition          -> propose_decomposition()
#   S11 evidence mapping       -> propose_evidence_mapping()
#   S12 requirement judgment  -> judge_requirements()
#   S14 aggregation            -> aggregate() / _aggregate_verdicts()
#   S15 attestation            -> get_attestation()
#   S16 challenge              -> challenge()
#
# NOTE ON THE CONSENSUS PRIMITIVE (read this before "fixing" a deploy error):
# Every earlier project in this history (Tribunal, Covenant, ModAppeal,
# JudgeChain...) needed at least one live-tested correction to the exact
# GenVM nondet/consensus call signature, because the installed GenVM build
# doesn't always match the public docs. This contract deliberately routes
# *every* nondet consensus decision through the two tiny wrappers below
# (_consensus_categorical / _fetch_nondet) instead of calling GenLayer
# primitives inline all over the file. If Studio throws a schema or runtime
# error mentioning `run_nondet`, `eq_principle`, or `nondet`, the fix almost
# certainly belongs in exactly one of these two functions.
import hashlib
import json
import datetime

from genlayer import *
from dataclasses import dataclass  # explicit stdlib import, deliberately
                                    # AFTER the wildcard import above so it
                                    # always wins the binding regardless of
                                    # what genlayer's own export list does
                                    # or doesn't include -- a real Studio
                                    # deploy crashed on `@dataclass` with
                                    # NameError: name 'dataclass' is not
                                    # defined when relying on the wildcard
                                    # import alone for this name.


# ---------------------------------------------------------------------------
# Consensus / nondet wrappers (see note above)
# ---------------------------------------------------------------------------
#
# CONFIRMED VIA A REAL STUDIO FAILURE: an exception raised *inside* a
# leader/fetch closure (e.g. gl.nondet.web.render() hitting a 404) does NOT
# propagate back as a normal, catchable Python exception to a try/except
# wrapped around the *outer* gl.eq_principle.strict_eq(...)/
# prompt_comparative(...) call. It surfaces instead as a fatal, whole-
# transaction "Contract Error" (exit_code 1, raw traceback in stderr,
# "Equivalence Principle Outputs: 0") that bypasses our own error handling
# entirely. The exception must be caught *inside* the closure and turned
# into an ordinary string return value; only after control returns to
# normal, non-nondet code can we look at that value and raise our own
# catchable RuntimeError. Every nondet call below goes through
# `_run_strict_eq` or `_run_prompt_comparative` for exactly this reason --
# never call `gl.eq_principle.*` directly with a closure that might raise.

_NONDET_FAILURE_MARKER = "\x00SPECPROOF_NONDET_FAILED\x00"


def _run_strict_eq(fn):
    """Runs a zero-arg `fn` through gl.eq_principle.strict_eq, safe against
    `fn` raising (see note above). Raises RuntimeError (catchable normally)
    if `fn` failed or consensus itself could not be reached."""
    def safe_fn():
        try:
            return fn()
        except Exception as e:
            return _NONDET_FAILURE_MARKER + str(e)

    try:
        result = gl.eq_principle.strict_eq(safe_fn)
    except Exception as e:
        raise RuntimeError(f"consensus not reached: {e}")

    if isinstance(result, str) and result.startswith(_NONDET_FAILURE_MARKER):
        raise RuntimeError(result[len(_NONDET_FAILURE_MARKER):])
    return result


def _run_prompt_comparative(leader_fn, criteria: str):
    """Runs a zero-arg `leader_fn` through gl.eq_principle.prompt_comparative,
    safe against `leader_fn` raising (see note above). Raises RuntimeError
    (catchable normally) if `leader_fn` failed or consensus itself could not
    be reached."""
    def safe_leader_fn():
        try:
            return leader_fn()
        except Exception as e:
            return _NONDET_FAILURE_MARKER + str(e)

    try:
        result = gl.eq_principle.prompt_comparative(safe_leader_fn, principle=criteria)
    except Exception as e:
        raise RuntimeError(f"consensus not reached: {e}")

    if isinstance(result, str) and result.startswith(_NONDET_FAILURE_MARKER):
        raise RuntimeError(result[len(_NONDET_FAILURE_MARKER):])
    return result


def _consensus_categorical(leader_fn, criteria: str):
    """
    Runs `leader_fn` (no args, returns a JSON-serializable dict/str) and
    reaches validator consensus on it using GenLayer's built-in *comparative*
    equivalence principle against the given natural-language `criteria` --
    never a hand-rolled numeric-tolerance validator_fn (see ARCHITECTURE.md
    S13: "No raw gl.vm.run_nondet custom tolerance logic anywhere in this
    contract"). This is the same class of primitive already validated safe
    in this project's Tribunal audit (strict_eq / prompt_comparative /
    prompt_non_comparative on categorical/string outputs only).

    Per the real GenLayer SDK docs (sdk.genlayer.com/main/api/genlayer.html),
    `gl.eq_principle.prompt_comparative(fn, principle)` IS the consensus
    call itself -- it is not a value to hand to `gl.vm.run_nondet`. It takes
    `fn` positionally and `principle` (not `criteria`) as the keyword.

    Returns the agreed-upon value, or raises RuntimeError if consensus was
    not reached, or if `leader_fn` itself raised (see module-level note).
    """
    return _run_prompt_comparative(leader_fn, criteria)


def _fetch_nondet(url: str) -> str:
    """
    One nondet fetch of a URL's content, resolved to a single agreed string
    across validators (ARCHITECTURE.md S10/S17: evidence is fetched once, at
    freeze time, and never re-fetched). Real-world pages are normally
    byte-identical across validators, so this uses strict equality rather
    than a comparative LLM judgment.

    Per the real SDK docs, `gl.eq_principle.strict_eq(fn)` IS the call --
    it takes `fn` directly and is not itself passed into `gl.vm.run_nondet`.
    """
    def fetch_fn() -> str:
        return gl.nondet.web.render(url)

    return _run_strict_eq(fetch_fn)


def _now_iso() -> str:
    # gl.message has no .timestamp attribute on this GenVM build; current
    # time must be read this way so it stays deterministic across
    # validators (lesson carried over from ModAppeal). Never use
    # datetime.min as a placeholder -- it crashes storage encoding.
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _iso_plus_seconds(iso: str, seconds: int) -> str:
    dt = datetime.datetime.fromisoformat(iso)
    return (dt + datetime.timedelta(seconds=seconds)).isoformat()


def _is_past(deadline_iso: str) -> bool:
    return datetime.datetime.fromisoformat(_now_iso()) > datetime.datetime.fromisoformat(deadline_iso)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Constants (ARCHITECTURE.md S6, S12, S14)
# ---------------------------------------------------------------------------

STATUS_SPEC_REGISTERED = "SPEC_REGISTERED"
STATUS_EVIDENCE_FROZEN = "EVIDENCE_FROZEN"
STATUS_DECOMPOSITION_PENDING = "DECOMPOSITION_PENDING"
STATUS_DECOMPOSITION_AGREED = "DECOMPOSITION_AGREED"
STATUS_DECOMPOSITION_FAILED = "DECOMPOSITION_FAILED"
STATUS_MAPPING_PENDING = "MAPPING_PENDING"
STATUS_MAPPING_AGREED = "MAPPING_AGREED"
STATUS_MAPPING_FAILED = "MAPPING_FAILED"
STATUS_JUDGED = "JUDGED"
STATUS_VERIFIED = "VERIFIED"
STATUS_FAILED = "FAILED"
STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATUS_FINALIZED = "FINALIZED"

# terminal states -- once here, nothing about this spec_id changes again
TERMINAL_STATUSES = {STATUS_DECOMPOSITION_FAILED, STATUS_MAPPING_FAILED, STATUS_FINALIZED}

# an aggregate result is one of these three; also used as requirement verdicts
VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
VALID_VERDICTS = {VERDICT_PASS, VERDICT_FAIL, VERDICT_INSUFFICIENT}

REQ_PENDING = "PENDING"
REQ_JUDGED = "JUDGED"
REQ_CHALLENGED = "CHALLENGED"

DECOMPOSITION_CRITERIA = (
    "The proposed decomposition must be: (1) COMPLETE -- every distinct "
    "obligation stated in the original specification text is covered by "
    "at least one requirement; (2) NON-OVERLAPPING -- no two requirements "
    "test the same obligation; (3) JUDGEABLE -- each requirement is "
    "concrete and specific enough to be checked directly against evidence, "
    "not a vague restatement of the whole specification. Agree only if all "
    "three hold."
)

MAPPING_CRITERIA = (
    "For each requirement, the cited evidence excerpts must plausibly bear "
    "on that requirement -- i.e. a reasonable reviewer would look at these "
    "specific excerpts, and only these, to judge this specific requirement. "
    "This is NOT asking whether the requirement passes or fails; only "
    "whether the mapping is a plausible and sufficient starting point. "
    "Disagree if any cited excerpt is irrelevant to its requirement, or if "
    "an obviously relevant excerpt (present in the evidence set) was left "
    "out."
)

JUDGMENT_CRITERIA_TEMPLATE = (
    "You are judging exactly one requirement against exactly one evidence "
    "excerpt set -- do not consider anything outside it. Requirement: "
    "{requirement_text!r}. Decide a verdict of PASS (the evidence shows the "
    "requirement is satisfied), FAIL (the evidence shows the requirement is "
    "actively violated), or INSUFFICIENT_EVIDENCE (the evidence does not "
    "let you tell either way -- this is different from FAIL). Agreement "
    "should be judged on the verdict field matching; differences in "
    "reasoning wording are fine."
)

# timeouts, in seconds (ARCHITECTURE.md S6: "every non-final state has a
# hard timeout")
DECOMPOSITION_TIMEOUT_SECONDS = 24 * 3600
MAPPING_TIMEOUT_SECONDS = 24 * 3600
JUDGMENT_TIMEOUT_SECONDS = 24 * 3600
CHALLENGE_WINDOW_SECONDS = 48 * 3600

# Cap on how much of an excerpt's content is shown to the leader during
# evidence mapping (S11) -- enough to judge plausibility, bounded so one
# large file doesn't blow up the prompt. Judgment itself (S12) still uses
# each excerpt's full content_text, never truncated.
MAPPING_EXCERPT_CONTENT_LIMIT = 2000

# ARCHITECTURE.md S16 calls for the challenge re-judgment to use a larger
# validator set than the original round. That is NOT implemented here: the
# GenLayer SDK surface this contract calls (gl.eq_principle.*) has no
# contract-side parameter for validator count -- validator set size appears
# to be a network/transaction-level property set by the caller (e.g. a
# genlayer-js write option), not something contract code controls. Rather
# than fabricate a keyword argument that would silently do nothing (which
# is exactly what an earlier draft of this file did), a challenge here runs
# at the same validator count as the original judgment. If GenVM does
# expose a real per-call validator-count control, this is the one place to
# wire it in once confirmed.


# ---------------------------------------------------------------------------
# Data model (ARCHITECTURE.md S7)
# ---------------------------------------------------------------------------

@allow_storage
@dataclass
class EvidenceExcerpt:
    excerpt_id: str
    file_path: str
    line_start: u256
    line_end: u256
    content_hash: str
    content_text: str


@allow_storage
@dataclass
class Specification:
    spec_id: str
    submitter: Address
    repository_url: str
    ref: str
    requirements_text: str
    spec_hash: str
    created_at: str


@allow_storage
@dataclass
class EvidenceSnapshot:
    spec_id: str
    commit_sha: str
    diff_hash: str
    excerpt_ids: DynArray[str]
    frozen_at: str


@allow_storage
@dataclass
class Requirement:
    requirement_id: str
    spec_id: str
    text: str
    status: str
    evidence_refs: DynArray[str]  # excerpt_ids, subset of the snapshot's
    verdict: str
    reason: str
    cited_evidence: DynArray[str]
    round: u256
    challenge_count: u256


@allow_storage
@dataclass
class Verification:
    spec_id: str
    status: str
    final_verdict: str
    decomposition_hash: str
    mapping_hash: str
    requirement_ids: DynArray[str]
    created_at: str
    decomposition_deadline: str
    mapping_deadline: str
    judgment_deadline: str
    challenge_deadline: str
    attestation_json: str


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------

class SpecProof(gl.Contract):
    specifications: TreeMap[str, Specification]
    evidence_snapshots: TreeMap[str, EvidenceSnapshot]
    evidence_excerpts: TreeMap[str, EvidenceExcerpt]
    requirements: TreeMap[str, Requirement]
    verifications: TreeMap[str, Verification]

    spec_counter: u256
    requirement_counter: u256
    excerpt_counter: u256

    def __init__(self):
        # TreeMap fields above (specifications, evidence_snapshots,
        # evidence_excerpts, requirements, verifications) are already
        # zero-initialized (empty) by GenVM the moment the contract is
        # declared -- do NOT assign them here. A real deploy crashed on
        # exactly this with:
        #   AssertionError: Is right the same storage type? `TreeMap` <- `dict`
        # A plain `{}` is a dict, not a TreeMap, and GenVM does not
        # auto-convert it on assignment (unlike some scalar/DynArray cases).
        self.spec_counter = u256(0)
        self.requirement_counter = u256(0)
        self.excerpt_counter = u256(0)

    # -- internal id helpers ------------------------------------------------

    def _next_spec_id(self) -> str:
        n = self.spec_counter
        self.spec_counter = u256(int(n) + 1)
        return f"spec_{int(n)}"

    def _next_requirement_id(self, spec_id: str) -> str:
        n = self.requirement_counter
        self.requirement_counter = u256(int(n) + 1)
        return f"{spec_id}_req_{int(n)}"

    def _next_excerpt_id(self, spec_id: str) -> str:
        n = self.excerpt_counter
        self.excerpt_counter = u256(int(n) + 1)
        return f"{spec_id}_ex_{int(n)}"

    def _get_verification(self, spec_id: str) -> Verification:
        v = self.verifications.get(spec_id)
        if v is None:
            raise Exception(f"unknown spec_id: {spec_id}")
        return v

    def _require_status(self, v: Verification, *allowed: str) -> None:
        if v.status not in allowed:
            raise Exception(
                f"invalid state: spec {v.spec_id} is {v.status}, expected one of {allowed}"
            )

    # -- step 1: submit_specification (S8) ----------------------------------

    @gl.public.write
    def submit_specification(self, repository_url: str, ref: str, requirements_text: str) -> str:
        if not repository_url.strip():
            raise Exception("repository_url must not be empty")
        if not ref.strip():
            raise Exception("ref must not be empty")
        if not requirements_text.strip():
            raise Exception("requirements_text must not be empty")

        spec_id = self._next_spec_id()
        now = _now_iso()
        spec_hash = _sha256(requirements_text)

        self.specifications[spec_id] = Specification(
            spec_id=spec_id,
            submitter=gl.message.sender_address,
            repository_url=repository_url,
            ref=ref,
            requirements_text=requirements_text,
            spec_hash=spec_hash,
            created_at=now,
        )
        self.verifications[spec_id] = Verification(
            spec_id=spec_id,
            status=STATUS_SPEC_REGISTERED,
            final_verdict="",
            decomposition_hash="",
            mapping_hash="",
            requirement_ids=[],
            created_at=now,
            decomposition_deadline="",
            mapping_deadline="",
            judgment_deadline="",
            challenge_deadline="",
            attestation_json="",
        )
        return spec_id

    # -- step 2: request_verification (S5, S10, S17) -------------------------

    @gl.public.write
    def request_verification(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_SPEC_REGISTERED)
        spec = self.specifications[spec_id]

        diff_url = self._resolve_diff_url(spec.repository_url, spec.ref)

        # ARCHITECTURE.md S19: "GitHub artifact unreachable at freeze time ->
        # request_verification() reverts; nothing is frozen, submitter may
        # retry." _fetch_nondet already raises on failed consensus/fetch, so
        # letting the exception propagate is the correct behavior here --
        # nothing below this point has been written yet.
        diff_text = _fetch_nondet(diff_url)
        if not diff_text.strip():
            raise Exception(f"empty diff fetched from {diff_url}; nothing to verify")

        # Resolve BEFORE writing any excerpts, so a PR whose head sha can't
        # be resolved leaves nothing frozen either (same invariant as an
        # unreachable diff).
        commit_sha = self._resolve_commit_sha(spec.repository_url, spec.ref)

        excerpts = self._split_diff_into_excerpts(spec_id, diff_text)
        if not excerpts:
            raise Exception("diff could not be split into any evidence excerpts")

        excerpt_ids = []
        for ex in excerpts:
            self.evidence_excerpts[ex.excerpt_id] = ex
            excerpt_ids.append(ex.excerpt_id)

        now = _now_iso()
        self.evidence_snapshots[spec_id] = EvidenceSnapshot(
            spec_id=spec_id,
            commit_sha=commit_sha,
            diff_hash=_sha256(diff_text),
            excerpt_ids=excerpt_ids,
            frozen_at=now,
        )

        v.status = STATUS_EVIDENCE_FROZEN
        v.decomposition_deadline = _iso_plus_seconds(now, DECOMPOSITION_TIMEOUT_SECONDS)

    def _resolve_diff_url(self, repository_url: str, ref: str) -> str:
        repo = repository_url.rstrip("/")
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        if self._is_pr_ref(ref):
            number = "".join(ch for ch in ref if ch.isdigit())
            return f"{repo}/pull/{number}.diff"
        return f"{repo}/commit/{ref}.diff"

    @staticmethod
    def _is_pr_ref(ref: str) -> bool:
        lowered = ref.lower()
        return lowered.startswith("pr#") or lowered.startswith("pull/")

    def _resolve_commit_sha(self, repository_url: str, ref: str) -> str:
        # ARCHITECTURE.md S7: commit_sha must be a "resolved, immutable Git
        # ref -- never 'latest'". A plain commit ref already IS that. A PR
        # ref is NOT -- "PR#42" doesn't pin anything (the branch can be
        # force-pushed), so it must be resolved to the PR's actual head
        # commit sha via the GitHub API before it's allowed into the
        # EvidenceSnapshot or the final attestation.
        if not self._is_pr_ref(ref):
            return ref

        number = "".join(ch for ch in ref if ch.isdigit())
        api_url = self._pr_api_url(repository_url, number)

        def fetch_fn() -> str:
            payload = gl.nondet.web.render(api_url)
            data = json.loads(payload)
            sha = (data.get("head") or {}).get("sha")
            if not sha:
                raise Exception(f"GitHub PR API response for {ref} had no head.sha")
            return sha

        return _run_strict_eq(fetch_fn)

    @staticmethod
    def _pr_api_url(repository_url: str, number: str) -> str:
        repo = repository_url.rstrip("/")
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        owner_repo = repo.split("github.com/")[-1]
        return f"https://api.github.com/repos/{owner_repo}/pulls/{number}"

    def _split_diff_into_excerpts(self, spec_id: str, diff_text: str) -> list:
        # ARCHITECTURE.md S10: evidence is never "the whole repository" --
        # split the unified diff per file into bounded excerpts.
        lines = diff_text.splitlines()
        excerpts = []
        current_path = None
        current_lines = []

        def flush():
            if current_path is not None and current_lines:
                text = "\n".join(current_lines)
                excerpts.append(
                    EvidenceExcerpt(
                        excerpt_id=self._next_excerpt_id(spec_id),
                        file_path=current_path,
                        line_start=u256(0),
                        line_end=u256(len(current_lines) - 1),
                        content_hash=_sha256(text),
                        content_text=text,
                    )
                )

        for line in lines:
            if line.startswith("diff --git "):
                flush()
                parts = line.split(" ")
                # "diff --git a/path b/path"
                current_path = parts[-1][2:] if len(parts) >= 4 else line
                current_lines = [line]
            else:
                if current_path is None:
                    current_path = "(preamble)"
                    current_lines = []
                current_lines.append(line)
        flush()
        return excerpts

    # -- step 4: propose_decomposition (S9) ----------------------------------

    @gl.public.write
    def propose_decomposition(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_EVIDENCE_FROZEN)
        spec = self.specifications[spec_id]
        requirements_text = spec.requirements_text  # plain copy before nondet

        v.status = STATUS_DECOMPOSITION_PENDING

        def leader_fn() -> str:
            prompt = (
                "Decompose the following specification into independent, "
                "judgeable requirement strings. Return ONLY a JSON object "
                'of the exact form {"requirements": ["requirement one", '
                '"requirement two", ...]}.\n\n'
                f"Specification:\n{requirements_text}"
            )
            return gl.nondet.exec_prompt(prompt, response_format="json")

        try:
            raw = _consensus_categorical(leader_fn, DECOMPOSITION_CRITERIA)
            texts = self._unwrap_json_list(raw)
            if not texts:
                raise RuntimeError("decomposition produced no requirements")
        except RuntimeError:
            v.status = STATUS_DECOMPOSITION_FAILED
            return

        requirement_ids = []
        for text in texts:
            rid = self._next_requirement_id(spec_id)
            self.requirements[rid] = Requirement(
                requirement_id=rid,
                spec_id=spec_id,
                text=text,
                status=REQ_PENDING,
                evidence_refs=[],
                verdict="",
                reason="",
                cited_evidence=[],
                round=u256(0),
                challenge_count=u256(0),
            )
            requirement_ids.append(rid)

        v.requirement_ids = requirement_ids
        v.decomposition_hash = _sha256(json.dumps(sorted(texts)))
        v.status = STATUS_DECOMPOSITION_AGREED
        now = _now_iso()
        v.mapping_deadline = _iso_plus_seconds(now, MAPPING_TIMEOUT_SECONDS)

    @staticmethod
    def _unwrap_json_list(data) -> list:
        # CONFIRMED LIVE: gl.nondet.exec_prompt(..., response_format="json")
        # returns an ALREADY-PARSED Python object, not a JSON string -- a
        # real deploy crashed with AttributeError: 'dict' object has no
        # attribute 'strip' from calling .strip()/json.loads() on it. JSON
        # mode also seems to require a top-level object rather than a bare
        # array (the model wrapped our requested array as
        # {"requirements": [...]}), which is exactly why the prompt above
        # asks for that shape explicitly. The dict-scan below is a
        # defensive fallback in case a future prompt tweak or provider uses
        # a different wrapper key.
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    return [str(x).strip() for x in value if str(x).strip()]
            raise RuntimeError(f"expected an object containing a list, got keys {list(data.keys())}")
        raise RuntimeError(f"expected a JSON array or object, got {type(data).__name__}")

    # -- step 6: propose_evidence_mapping (S11) ------------------------------

    @gl.public.write
    def propose_evidence_mapping(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_DECOMPOSITION_AGREED)

        snapshot = self.evidence_snapshots[spec_id]
        valid_excerpt_ids = set(snapshot.excerpt_ids)
        # Give the leader actual excerpt content, not just file_path -- a
        # mapping proposed from paths alone is a guess, not evidence-based
        # (this is exactly the gap flagged before deploy: §11 requires the
        # mapping to be judged on whether the cited evidence "plausibly
        # bears on this requirement", which is unanswerable from a path
        # string). Content is capped defensively so one oversized file
        # can't blow up the prompt.
        excerpt_summaries = [
            {
                "excerpt_id": eid,
                "file_path": self.evidence_excerpts[eid].file_path,
                "content": self._truncate(
                    self.evidence_excerpts[eid].content_text, MAPPING_EXCERPT_CONTENT_LIMIT
                ),
            }
            for eid in snapshot.excerpt_ids
        ]
        requirement_texts = {
            rid: self.requirements[rid].text for rid in v.requirement_ids
        }

        v.status = STATUS_MAPPING_PENDING

        def leader_fn() -> str:
            prompt = (
                "For each requirement below, list which of the given "
                "evidence excerpt_ids are relevant to judging it. Return "
                "ONLY a JSON object mapping requirement_id -> array of "
                "excerpt_id strings, using only excerpt_ids from the "
                "provided list.\n\n"
                f"Requirements: {json.dumps(requirement_texts)}\n\n"
                f"Evidence excerpts: {json.dumps(excerpt_summaries)}"
            )
            return gl.nondet.exec_prompt(prompt, response_format="json")

        try:
            raw = _consensus_categorical(leader_fn, MAPPING_CRITERIA)
            mapping = self._parse_mapping(raw, set(requirement_texts.keys()), valid_excerpt_ids)
        except RuntimeError:
            v.status = STATUS_MAPPING_FAILED
            return

        for rid, excerpt_ids in mapping.items():
            req = self.requirements[rid]
            req.evidence_refs = excerpt_ids

        v.mapping_hash = _sha256(json.dumps(mapping, sort_keys=True))
        v.status = STATUS_MAPPING_AGREED
        now = _now_iso()
        v.judgment_deadline = _iso_plus_seconds(now, JUDGMENT_TIMEOUT_SECONDS)

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "...[truncated]"

    @staticmethod
    def _parse_mapping(data, valid_requirement_ids: set, valid_excerpt_ids: set) -> dict:
        # See _unwrap_json_list: gl.nondet.exec_prompt(..., response_format=
        # "json") returns an already-parsed object, never a JSON string.
        if not isinstance(data, dict):
            raise RuntimeError(f"expected a JSON object, got {type(data).__name__}")

        result = {}
        for rid, excerpt_ids in data.items():
            if rid not in valid_requirement_ids:
                # Defensive validation (S11/S18): a leader citing a
                # nonexistent requirement is a malformed proposal, rejected
                # deterministically -- not something to send to a consensus
                # vote.
                raise RuntimeError(f"mapping references unknown requirement_id {rid}")
            if not isinstance(excerpt_ids, list):
                raise RuntimeError(f"mapping for {rid} is not a list")
            clean_ids = [str(x) for x in excerpt_ids]
            for eid in clean_ids:
                if eid not in valid_excerpt_ids:
                    raise RuntimeError(
                        f"mapping for {rid} cites unknown excerpt_id {eid} (leader hallucination guard)"
                    )
            result[rid] = clean_ids

        for rid in valid_requirement_ids:
            if rid not in result:
                raise RuntimeError(f"mapping is missing requirement {rid}")
        return result

    # -- step 8: judge_requirements (S12, S13, S17) --------------------------

    @gl.public.write
    def judge_requirements(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_MAPPING_AGREED)

        for rid in v.requirement_ids:
            self._judge_one_requirement(rid, round_number=0)

        v.status = STATUS_JUDGED

    def _judge_one_requirement(self, requirement_id: str, round_number: int) -> None:
        req = self.requirements[requirement_id]

        # Copy plain values out of storage BEFORE entering the nondet
        # closure. Passing a storage-backed object (or a bound method that
        # captures `self`) into gl.vm.run_nondet crashes GenVM's pickling of
        # the leader/validator closures -- this cost real debugging time on
        # ModAppeal and must not be repeated here.
        requirement_text = req.text
        excerpt_texts = [
            {
                "excerpt_id": eid,
                "file_path": self.evidence_excerpts[eid].file_path,
                "content": self.evidence_excerpts[eid].content_text,
            }
            for eid in req.evidence_refs
        ]
        valid_excerpt_ids = set(req.evidence_refs)

        def leader_fn() -> str:
            prompt = (
                "Judge this single requirement using ONLY the evidence "
                "excerpts given. Return ONLY a JSON object: "
                '{"verdict": "PASS"|"FAIL"|"INSUFFICIENT_EVIDENCE", '
                '"reason": "...", "cited_evidence": ["excerpt_id", ...]}. '
                "cited_evidence must be a subset of the given excerpt_ids.\n\n"
                f"Requirement: {requirement_text}\n\n"
                f"Evidence excerpts: {json.dumps(excerpt_texts)}"
            )
            return gl.nondet.exec_prompt(prompt, response_format="json")

        criteria = JUDGMENT_CRITERIA_TEMPLATE.format(requirement_text=requirement_text)

        try:
            raw = _consensus_categorical(leader_fn, criteria)
            verdict, reason, cited = self._parse_judgment(raw, valid_excerpt_ids)
        except RuntimeError as e:
            # A requirement whose judgment round cannot reach consensus, or
            # whose evidence is genuinely absent, resolves to
            # INSUFFICIENT_EVIDENCE rather than blocking the whole
            # verification (ARCHITECTURE.md S19).
            verdict, reason, cited = VERDICT_INSUFFICIENT, f"judgment round failed: {e}", []

        req.verdict = verdict
        req.reason = reason
        req.cited_evidence = cited
        req.round = u256(round_number)
        req.status = REQ_JUDGED

    @staticmethod
    def _parse_judgment(data, valid_excerpt_ids: set):
        # See _unwrap_json_list: gl.nondet.exec_prompt(..., response_format=
        # "json") returns an already-parsed object, never a JSON string.
        if not isinstance(data, dict):
            raise RuntimeError(f"expected a JSON object, got {type(data).__name__}")

        verdict = str(data.get("verdict", "")).strip()
        if verdict not in VALID_VERDICTS:
            raise RuntimeError(f"invalid verdict {verdict!r}")

        reason = str(data.get("reason", "")).strip()
        cited = [str(x) for x in data.get("cited_evidence", [])]
        for eid in cited:
            if eid not in valid_excerpt_ids:
                # S12: "a judgment citing evidence outside its own mapping
                # is rejected as malformed" -- deterministic validation, not
                # a consensus round.
                raise RuntimeError(f"judgment cites out-of-mapping evidence {eid}")

        return verdict, reason, cited

    # -- step 9: aggregate (S14) ---------------------------------------------

    @gl.public.write
    def aggregate(self, spec_id: str) -> str:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_JUDGED, STATUS_VERIFIED, STATUS_FAILED, STATUS_INSUFFICIENT_EVIDENCE)

        verdicts = [self.requirements[rid].verdict for rid in v.requirement_ids]
        final = self._aggregate_verdicts(verdicts)

        v.final_verdict = final
        v.status = final
        now = _now_iso()
        v.challenge_deadline = _iso_plus_seconds(now, CHALLENGE_WINDOW_SECONDS)
        return final

    @staticmethod
    def _aggregate_verdicts(verdicts: list) -> str:
        # ARCHITECTURE.md S14, strict, no threshold, no weighting:
        #   ALL PASS               -> VERIFIED
        #   ANY FAIL                -> FAILED         (highest priority)
        #   ANY unresolved/INSUFF   -> INSUFFICIENT_EVIDENCE
        if not verdicts:
            return VERDICT_INSUFFICIENT
        if any(v == VERDICT_FAIL for v in verdicts):
            return STATUS_FAILED
        if any(v != VERDICT_PASS for v in verdicts):
            return STATUS_INSUFFICIENT_EVIDENCE
        return STATUS_VERIFIED

    # -- step 11: challenge (S16) ---------------------------------------------

    @gl.public.write
    def challenge(self, spec_id: str, requirement_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_VERIFIED, STATUS_FAILED, STATUS_INSUFFICIENT_EVIDENCE)

        if _is_past(v.challenge_deadline):
            raise Exception("challenge window has closed for this spec_id")

        if requirement_id not in v.requirement_ids:
            raise Exception("requirement_id does not belong to this spec_id")

        req = self.requirements[requirement_id]
        if int(req.challenge_count) >= 1:
            # ARCHITECTURE.md S16: "Capped at one challenge per requirement."
            raise Exception("this requirement has already used its single challenge round")

        req.status = REQ_CHALLENGED
        req.challenge_count = u256(int(req.challenge_count) + 1)

        # Re-judgment against the already-locked evidence mapping only --
        # a challenge disputes the judgment, never the mapping/decomposition
        # (S16).
        self._judge_one_requirement(requirement_id, round_number=1)

        # Re-aggregate using the new result for this requirement plus the
        # untouched results for every other requirement.
        verdicts = [self.requirements[rid].verdict for rid in v.requirement_ids]
        v.final_verdict = self._aggregate_verdicts(verdicts)
        v.status = v.final_verdict
        now = _now_iso()
        v.challenge_deadline = _iso_plus_seconds(now, CHALLENGE_WINDOW_SECONDS)

    # -- step 12: finalize + attestation (S15) -------------------------------

    @gl.public.write
    def finalize(self, spec_id: str) -> str:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_VERIFIED, STATUS_FAILED, STATUS_INSUFFICIENT_EVIDENCE)

        if not _is_past(v.challenge_deadline):
            raise Exception("challenge window is still open")

        spec = self.specifications[spec_id]
        snapshot = self.evidence_snapshots[spec_id]

        requirement_results = []
        for rid in v.requirement_ids:
            req = self.requirements[rid]
            requirement_results.append(
                {"requirement_id": rid, "verdict": req.verdict, "reason": req.reason}
            )

        challenged = any(int(self.requirements[rid].challenge_count) > 0 for rid in v.requirement_ids)

        attestation = {
            "spec_hash": spec.spec_hash,
            "repository_url": spec.repository_url,
            "commit_sha": snapshot.commit_sha,
            "evidence_root": snapshot.diff_hash,
            "decomposition_hash": v.decomposition_hash,
            "mapping_hash": v.mapping_hash,
            "requirement_results": requirement_results,
            "final_verdict": v.final_verdict,
            "consensus_metadata": {
                "requirement_count": len(v.requirement_ids),
                "finalized_at": _now_iso(),
            },
            "challenge_status": "RESOLVED" if challenged else "NONE",
        }

        v.attestation_json = json.dumps(attestation, sort_keys=True)
        v.status = STATUS_FINALIZED
        return v.attestation_json

    # -- timeouts (S6: "an expired pending state resolves to its failure branch") --

    @gl.public.write
    def expire_if_timed_out(self, spec_id: str) -> str:
        v = self._get_verification(spec_id)

        if v.status == STATUS_EVIDENCE_FROZEN and v.decomposition_deadline and _is_past(v.decomposition_deadline):
            v.status = STATUS_DECOMPOSITION_FAILED
            return v.status
        if v.status == STATUS_DECOMPOSITION_AGREED and v.mapping_deadline and _is_past(v.mapping_deadline):
            v.status = STATUS_MAPPING_FAILED
            return v.status
        if v.status == STATUS_MAPPING_AGREED and v.judgment_deadline and _is_past(v.judgment_deadline):
            verdicts = [VERDICT_INSUFFICIENT for _ in v.requirement_ids]
            v.final_verdict = self._aggregate_verdicts(verdicts)
            v.status = v.final_verdict
            v.challenge_deadline = _iso_plus_seconds(_now_iso(), CHALLENGE_WINDOW_SECONDS)
            return v.status
        return v.status

    # -- views ----------------------------------------------------------------

    @gl.public.view
    def get_verification(self, spec_id: str) -> dict:
        v = self._get_verification(spec_id)
        return {
            "spec_id": v.spec_id,
            "status": v.status,
            "final_verdict": v.final_verdict,
            "decomposition_hash": v.decomposition_hash,
            "mapping_hash": v.mapping_hash,
            "requirement_ids": list(v.requirement_ids),
            "challenge_deadline": v.challenge_deadline,
        }

    @gl.public.view
    def get_requirement(self, requirement_id: str) -> dict:
        req = self.requirements.get(requirement_id)
        if req is None:
            raise Exception(f"unknown requirement_id: {requirement_id}")
        return {
            "requirement_id": req.requirement_id,
            "text": req.text,
            "status": req.status,
            "evidence_refs": list(req.evidence_refs),
            "verdict": req.verdict,
            "reason": req.reason,
            "cited_evidence": list(req.cited_evidence),
            "round": int(req.round),
            "challenge_count": int(req.challenge_count),
        }

    @gl.public.view
    def get_attestation(self, spec_id: str) -> str:
        v = self._get_verification(spec_id)
        if v.status != STATUS_FINALIZED:
            raise Exception("verification is not finalized yet")
        return v.attestation_json
