"""
A minimal, offline stub of the GenLayer SDK (`genlayer`), just enough
surface area for contracts/specproof.py to import and run against. This is
NOT a GenVM emulator -- it does not execute real LLM prompts or reach real
network consensus. It gives tests full manual control over:

  - who the calling address is (gl.message.sender_address)
  - what each nondet LLM call ("leader_fn") returns, in call order
  - what each nondet web fetch returns, per URL
  - whether the next consensus round should fail (simulating a validator
    disagreement), for exercising DECOMPOSITION_FAILED / MAPPING_FAILED /
    challenge paths

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
# gl.vm  (kept for completeness -- NOT used by specproof.py's own consensus
# calls, which go through gl.eq_principle directly per the real SDK docs.
# A contract could still reach for gl.vm.run_nondet/run_nondet_unsafe
# directly for a fully custom validator, so the stub keeps a minimal one.)
# ---------------------------------------------------------------------------

class NondetConsensusError(Exception):
    pass


class _VM:
    NondetConsensusError = NondetConsensusError

    def run_nondet(self, leader_fn, validator_fn):
        return leader_fn()

    def run_nondet_unsafe(self, leader_fn, validator_fn):
        return leader_fn()


# ---------------------------------------------------------------------------
# gl.eq_principle
#
# Real signatures (sdk.genlayer.com/main/api/genlayer.html):
#   gl.eq_principle.strict_eq(fn) -> T
#   gl.eq_principle.prompt_comparative(fn, principle) -> T
# These ARE the consensus call -- not values passed into gl.vm.run_nondet.
# The stub calls fn() once (single "leader") and lets test code force a
# disagreement via force_fail_next(), simulating what a real validator
# split would raise.
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

class _Web:
    def __init__(self):
        self.pages = {}

    def render(self, url):
        if url not in self.pages:
            raise Exception(f"[stub] no page registered for url: {url}")
        return self.pages[url]


class _Nondet:
    def __init__(self):
        self.web = _Web()
        self.responses = []  # queue of canned exec_prompt() return values, popped in order
        self.last_prompt = None  # records the most recent prompt, for tests to inspect

    def exec_prompt(self, prompt, response_format=None, images=None):
        self.last_prompt = prompt
        if not self.responses:
            raise Exception("[stub] exec_prompt called with no canned response queued")
        return self.responses.pop(0)


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
    gl.nondet.responses.clear()
