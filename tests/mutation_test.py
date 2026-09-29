"""
Mutation test: checks that the test suites actually detect security bugs.

    python3 tests/mutation_test.py

Each mutant re-introduces one known vulnerability into a temporary copy of
contracts/specproof.py (one line changed), then runs the unit suite and the
invariant fuzzer against it. Every mutant must be CAUGHT by both; a mutant
that survives means a guarantee is not really being tested.
"""
import os, shutil, subprocess, sys, tempfile
SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
W = os.path.join(tempfile.mkdtemp(prefix="specproof-mut-"), "repo")
survivors = []
mutants = {
    "M1 drop PASS-withheld guard": ("if verdict == VERDICT_PASS and truncated_files:", "if False:"),
    "M2 challenge re-roll (no reproduce-or-downgrade)": ("if new_origin == ORIGIN_CONSENSUS and new_verdict == original_verdict:", "if True:"),
    "M3 aggregate callable again": ("self._require_status(v, STATUS_JUDGED)", "self._require_status(v, STATUS_JUDGED, STATUS_VERIFIED, STATUS_FAILED, STATUS_INSUFFICIENT_EVIDENCE)"),
    "M4 finalize inside window": ("if not _is_past(v.challenge_deadline):", "if False:"),
    "M5 anyone can freeze": ("if str(gl.message.sender_address).lower() != str(spec.submitter).lower():", "if False:"),
    "M6 validator skips canonical judgment check": ('if (leader["verdict"], leader["reason"], leader["cited_evidence"]) != canonical:', "if False:"),
    "M7 validator skips canonical proposal check": ("if canonicalize(value) != value:", "if False:"),
    "M8 window re-opens on every challenge": ("if first_challenge_on_spec:", "if True:"),
    "M9 unlimited challenges": ("if count >= 1 and not second_allowed:", "if False:"),
    "M10 splitlines again": ('lines = diff_text.split("\\n")', "lines = diff_text.splitlines()"),
    "M12 diff fetched with render() again": ("diff_text = _fetch_raw_nondet(diff_url)", "diff_text = _run_strict_eq(lambda: gl.nondet.web.render(diff_url))"),
    "M13 HTTP status ignored": ("        if status != 200:\n", "        if False:\n"),
    "M11 abbreviated shas accepted": ('_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")', '_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")'),
}
for name, (a, b) in mutants.items():
    shutil.rmtree(W, ignore_errors=True)
    shutil.copytree(SRC, W, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    p = os.path.join(W, "contracts/specproof.py")
    s = open(p).read()
    assert s.count(a) == 1, name
    open(p, "w").write(s.replace(a, b))
    unit = subprocess.run([sys.executable, "tests/test_specproof.py"], cwd=W, capture_output=True, text=True)
    fz = subprocess.run([sys.executable, "tests/test_fuzz.py"], cwd=W, capture_output=True, text=True, env={**os.environ, "FUZZ_RUNS": "400"})
    first = next((l for l in fz.stdout.splitlines() if "violated" in l or "unexpected" in l or "coverage" in l), "-")
    if not (unit.returncode and fz.returncode):
        survivors.append(name)
    print(f"{name:50s} unit={'CAUGHT' if unit.returncode else 'missed'}  fuzz={'CAUGHT' if fz.returncode else 'missed'}  {first[:80]}")
shutil.rmtree(os.path.dirname(W), ignore_errors=True)
print(f"{len(mutants) - len(survivors)}/{len(mutants)} mutants caught by both suites")
sys.exit(1 if survivors else 0)
