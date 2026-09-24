# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
import hashlib
import json
import datetime
from genlayer import *
from dataclasses import dataclass                                        
_NONDET_FAILURE_MARKER = "\x00SPECPROOF_NONDET_FAILED\x00"
def _run_strict_eq(fn):
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
    return _run_prompt_comparative(leader_fn, criteria)
def _fetch_nondet(url: str) -> str:
    def fetch_fn() -> str:
        return gl.nondet.web.render(url)
    return _run_strict_eq(fetch_fn)
def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
def _iso_plus_seconds(iso: str, seconds: int) -> str:
    dt = datetime.datetime.fromisoformat(iso)
    return (dt + datetime.timedelta(seconds=seconds)).isoformat()
def _is_past(deadline_iso: str) -> bool:
    return datetime.datetime.fromisoformat(_now_iso()) > datetime.datetime.fromisoformat(deadline_iso)
def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
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
TERMINAL_STATUSES = {STATUS_DECOMPOSITION_FAILED, STATUS_MAPPING_FAILED, STATUS_FINALIZED}
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
DECOMPOSITION_TIMEOUT_SECONDS = 24 * 3600
MAPPING_TIMEOUT_SECONDS = 24 * 3600
JUDGMENT_TIMEOUT_SECONDS = 24 * 3600
CHALLENGE_WINDOW_SECONDS = 48 * 3600
MAPPING_EXCERPT_CONTENT_LIMIT = 2000
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
    evidence_refs: DynArray[str]                                         
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
        self.spec_counter = u256(0)
        self.requirement_counter = u256(0)
        self.excerpt_counter = u256(0)
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
    @gl.public.write
    def request_verification(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_SPEC_REGISTERED)
        spec = self.specifications[spec_id]
        diff_url = self._resolve_diff_url(spec.repository_url, spec.ref)
        diff_text = _fetch_nondet(diff_url)
        if not diff_text.strip():
            raise Exception(f"empty diff fetched from {diff_url}; nothing to verify")
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
                current_path = parts[-1][2:] if len(parts) >= 4 else line
                current_lines = [line]
            else:
                if current_path is None:
                    current_path = "(preamble)"
                    current_lines = []
                current_lines.append(line)
        flush()
        return excerpts
    @gl.public.write
    def propose_decomposition(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_EVIDENCE_FROZEN)
        spec = self.specifications[spec_id]
        requirements_text = spec.requirements_text                            
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
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    return [str(x).strip() for x in value if str(x).strip()]
            raise RuntimeError(f"expected an object containing a list, got keys {list(data.keys())}")
        raise RuntimeError(f"expected a JSON array or object, got {type(data).__name__}")
    @gl.public.write
    def propose_evidence_mapping(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_DECOMPOSITION_AGREED)
        snapshot = self.evidence_snapshots[spec_id]
        valid_excerpt_ids = set(snapshot.excerpt_ids)
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
        if not isinstance(data, dict):
            raise RuntimeError(f"expected a JSON object, got {type(data).__name__}")
        result = {}
        for rid, excerpt_ids in data.items():
            if rid not in valid_requirement_ids:
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
    @gl.public.write
    def judge_requirements(self, spec_id: str) -> None:
        v = self._get_verification(spec_id)
        self._require_status(v, STATUS_MAPPING_AGREED)
        for rid in v.requirement_ids:
            self._judge_one_requirement(rid, round_number=0)
        v.status = STATUS_JUDGED
    def _judge_one_requirement(self, requirement_id: str, round_number: int) -> None:
        req = self.requirements[requirement_id]
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
            verdict, reason, cited = VERDICT_INSUFFICIENT, f"judgment round failed: {e}", []
        req.verdict = verdict
        req.reason = reason
        req.cited_evidence = cited
        req.round = u256(round_number)
        req.status = REQ_JUDGED
    @staticmethod
    def _parse_judgment(data, valid_excerpt_ids: set):
        if not isinstance(data, dict):
            raise RuntimeError(f"expected a JSON object, got {type(data).__name__}")
        verdict = str(data.get("verdict", "")).strip()
        if verdict not in VALID_VERDICTS:
            raise RuntimeError(f"invalid verdict {verdict!r}")
        reason = str(data.get("reason", "")).strip()
        cited = [str(x) for x in data.get("cited_evidence", [])]
        for eid in cited:
            if eid not in valid_excerpt_ids:
                raise RuntimeError(f"judgment cites out-of-mapping evidence {eid}")
        return verdict, reason, cited
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
        if not verdicts:
            return VERDICT_INSUFFICIENT
        if any(v == VERDICT_FAIL for v in verdicts):
            return STATUS_FAILED
        if any(v != VERDICT_PASS for v in verdicts):
            return STATUS_INSUFFICIENT_EVIDENCE
        return STATUS_VERIFIED
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
            raise Exception("this requirement has already used its single challenge round")
        req.status = REQ_CHALLENGED
        req.challenge_count = u256(int(req.challenge_count) + 1)
        self._judge_one_requirement(requirement_id, round_number=1)
        verdicts = [self.requirements[rid].verdict for rid in v.requirement_ids]
        v.final_verdict = self._aggregate_verdicts(verdicts)
        v.status = v.final_verdict
        now = _now_iso()
        v.challenge_deadline = _iso_plus_seconds(now, CHALLENGE_WINDOW_SECONDS)
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
