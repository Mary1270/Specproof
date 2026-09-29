"""
A minimal, offline stub of the GenLayer SDK (`genlayer`), just enough
surface area for contracts/specproof.py to import and run against. This is
NOT a GenVM emulator -- it does not execute real LLM prompts or reach real
network consensus. It gives tests full manual control over:

  - who the calling address is (gl.message.sender_address)
  - what each nondet LLM call returns, for the leader (gl.nondet.responses)
    and, separately, for validators (gl.nondet.validator_responses)
  - what each nondet web fetch returns, per URL
  - validator disagreement: gl.vm.run_nondet_unsafe really runs the
    contract's own validator_fn against the leader's result and raises
    NondetConsensusError when it does not return True, which models real
    GenVM refusing to accept the transaction

Install with `install()` before importing contracts/specproof.py, and call
`reset()` between tests so canned responses/pages from one test don't leak
into the next.
"""
import sys
import types
import dataclasses


# ---------------------------------------------------------------------------
# storage / typing primitives
# ---------------------------------------------------------------------------

class Address(str):
    pass


class u256(int):
    pass


class TreeMap(dict):
    def __class_getitem__(cls, item):
        return cls


class DynArray(list):
    def __class_getitem__(cls, item):
        return cls


def allow_storage(cls):
    return cls


dataclass = dataclasses.dataclass


class Contract:
    """
    Mimics one real GenVM behavior that matters for this fix: class-level
    TreeMap/DynArray-annotated fields are zero-initialized (empty)
    automatically, before the subclass's own __init__ runs -- a contract
    must NOT (and, per a real deploy, cannot) assign a plain {} to them.
    Without this, the offline stub would never have caught the exact bug
    a live Studio deploy did (assigning `self.specifications = {}` crashed
    with "Is right the same storage type? TreeMap <- dict").
    """

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        for klass in reversed(cls.__mro__):
            for name, annotation in getattr(klass, "__annotations__", {}).items():
                if annotation is TreeMap:
                    object.__setattr__(instance, name, TreeMap())
                elif annotation is DynArray:
                    object.__setattr__(instance, name, DynArray())
        return instance


# ---------------------------------------------------------------------------
# gl.message
# ---------------------------------------------------------------------------

class _Message:
    def __init__(self):
        self.sender_address = Address("0x000000000000000000000000000000000000A1")


# ---------------------------------------------------------------------------
# gl.vm -- used by specproof.py for decomposition, mapping and judgment
# (custom validators: propose-and-review and exact-verdict).
# ---------------------------------------------------------------------------

class NondetConsensusError(Exception):
    pass


class _Return:
    """What a validator_fn receives for a successful leader run on real
    GenVM: the leader's value is on `.calldata` (confirmed live on
    ModAppeal; using any other attribute silently disagreed)."""

    def __init__(self, calldata):
        self.calldata = calldata


class _VM:
    NondetConsensusError = NondetConsensusError
    Return = _Return

    def __init__(self):
        self.validator_runs = 0

    def run_nondet(self, leader_fn, validator_fn):
        return self.run_nondet_unsafe(leader_fn, validator_fn)

    def run_nondet_unsafe(self, leader_fn, validator_fn):
        """Runs the leader, then one validator against the leader's result.
        The validator's own exec_prompt() calls get either the responses a
        test queued in gl.nondet.validator_responses (to simulate a
        validator that sees things differently) or, by default, a replay of
        exactly what the leader got (an honest, agreeing validator).
        If the validator disagrees this raises NondetConsensusError, which
        models real GenVM refusing to accept the transaction."""
        nd = gl.nondet
        nd._recording = []
        nd._mode = "leader"
        try:
            leader_result = leader_fn()
        finally:
            nd._mode = None
        leader_calls = list(nd._recording)
        nd._replay = leader_calls if not nd.validator_responses else None
        nd._mode = "validator"
        try:
            agreed = validator_fn(_Return(leader_result))
        finally:
            nd._mode = None
            nd._replay = None
        self.validator_runs += 1
        if agreed is not True:
            raise NondetConsensusError("validator disagreed with leader (test)")
        return leader_result


# ---------------------------------------------------------------------------
# gl.eq_principle -- specproof.py uses only strict_eq (evidence fetches).
#
# Real signatures (sdk.genlayer.com/main/api/genlayer.html):
#   gl.eq_principle.strict_eq(fn) -> T
#   gl.eq_principle.prompt_comparative(fn, principle) -> T
# These ARE the consensus call -- not values passed into gl.vm.run_nondet.
# The stub calls fn() once and lets test code force a disagreement via
# force_fail_next(). prompt_comparative/prompt_non_comparative are kept only
# so the stub mirrors the SDK surface; the contract no longer calls them.
# ---------------------------------------------------------------------------

class _EqPrinciple:
    def __init__(self):
        self._force_fail_once = False

    def force_fail_next(self):
        """Test hook: makes the *next* eq_principle call raise, simulating a
        validator disagreement (used to exercise *_FAILED paths)."""
        self._force_fail_once = True

    def _maybe_fail(self):
        if self._force_fail_once:
            self._force_fail_once = False
            raise NondetConsensusError("forced disagreement (test)")

    def strict_eq(self, fn):
        self._maybe_fail()
        return fn()

    def prompt_comparative(self, fn, principle=None):
        self._maybe_fail()
        return fn()

    def prompt_non_comparative(self, fn, *, task=None, criteria=None):
        self._maybe_fail()
        return fn()


# ---------------------------------------------------------------------------
# gl.nondet  (web fetch + LLM prompt exec)
# ---------------------------------------------------------------------------

class _Response:
    def __init__(self, status, body):
        self.status = status
        self.body = body


class _Web:
    """pages: url -> str (served by both render and get).
    statuses: url -> HTTP status for get (default 200).
    raw: url -> bytes served by get instead of pages[url].encode().

    render() reproduces what was observed live on StudioNet (v1.5 probe):
    rendered page text, with runs of spaces collapsed to one and trailing
    spaces removed on every line. get() returns the exact bytes."""

    def __init__(self):
        self.pages = {}
        self.statuses = {}
        self.raw = {}

    def render(self, url, mode="text"):
        if url not in self.pages:
            raise Exception(f"[stub] no page registered for url: {url}")
        text = self.pages[url]
        if mode != "text":
            return text
        out = []
        for line in text.split("\n"):
            while "  " in line:
                line = line.replace("  ", " ")
            out.append(line.rstrip(" "))
        return "\n".join(out)

    def get(self, url, headers=None):
        if url not in self.pages and url not in self.raw:
            raise Exception(f"[stub] no page registered for url: {url}")
        body = self.raw[url] if url in self.raw else self.pages[url].encode("utf-8")
        return _Response(self.statuses.get(url, 200), body)


class _Nondet:
    def __init__(self):
        self.web = _Web()
        self.responses = []  # queue of canned exec_prompt() return values, popped in order
        self.validator_responses = []  # optional: what a validator sees instead of a replay
        self.last_prompt = None  # records the most recent prompt, for tests to inspect
        self.prompts = []
        self._mode = None
        self._recording = []
        self._replay = None

    def exec_prompt(self, prompt, response_format=None, images=None):
        self.last_prompt = prompt
        self.prompts.append(prompt)
        if self._mode == "validator":
            if self._replay is not None:
                if not self._replay:
                    raise Exception("[stub] validator made more LLM calls than the leader")
                return self._replay.pop(0)
            if not self.validator_responses:
                raise Exception("[stub] no validator response queued")
            return self.validator_responses.pop(0)
        if not self.responses:
            raise Exception("[stub] exec_prompt called with no canned response queued")
        value = self.responses.pop(0)
        if self._mode == "leader":
            self._recording.append(value)
        return value


# ---------------------------------------------------------------------------
# gl.public
# ---------------------------------------------------------------------------

def _write(fn):
    return fn


def _view(fn):
    return fn


class _Public:
    write = staticmethod(_write)
    view = staticmethod(_view)


# ---------------------------------------------------------------------------
# gl namespace
# ---------------------------------------------------------------------------

class _GL:
    def __init__(self):
        self.Contract = Contract
        self.message = _Message()
        self.vm = _VM()
        self.eq_principle = _EqPrinciple()
        self.nondet = _Nondet()
        self.public = _Public()


gl = _GL()


def install():
    """Registers a fake `genlayer` module in sys.modules so that
    `from genlayer import *` inside contracts/specproof.py resolves to this
    stub instead of failing on import."""
    module = types.ModuleType("genlayer")
    module.gl = gl
    module.Address = Address
    module.u256 = u256
    module.TreeMap = TreeMap
    module.DynArray = DynArray
    module.allow_storage = allow_storage
    module.dataclass = dataclass
    module.Contract = Contract
    module.__all__ = [
        "gl", "Address", "u256", "TreeMap", "DynArray",
        "allow_storage", "dataclass", "Contract",
    ]
    sys.modules["genlayer"] = module
    return module


def reset():
    """Clears all test-controlled state between tests. Does NOT reset
    contract storage -- instantiate a fresh SpecProof() for that."""
    gl.message.sender_address = Address("0x000000000000000000000000000000000000A1")
    gl.eq_principle._force_fail_once = False
    gl.nondet.web.pages.clear()
    gl.nondet.web.statuses.clear()
    gl.nondet.web.raw.clear()
    gl.nondet.responses.clear()
    gl.nondet.validator_responses.clear()
    gl.nondet.prompts.clear()
    gl.nondet.last_prompt = None
    gl.vm.validator_runs = 0
