"""
Builds contracts/specproof_deploy.py from contracts/specproof.py and proves
the two are the same program.

    python3 tools/build_deploy.py           # rebuild the deploy file
    python3 tools/build_deploy.py --check   # fail if the committed file differs

The deploy build only removes comments, docstrings and blank lines, using
Python's own tokenizer and parser (never regular expressions), and keeps the
two GenVM header lines. It then verifies that the syntax tree of the build
equals the syntax tree of the source with docstrings removed, so no
statement, expression or string literal can differ between what was
reviewed and what is deployed.
"""
import ast
import io
import os
import sys
import tokenize

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "contracts", "specproof.py")
OUT = os.path.join(ROOT, "contracts", "specproof_deploy.py")
DOC_NODES = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def docstring_positions(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, DOC_NODES) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                out.add((first.lineno, first.col_offset))
    return out


def without_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, DOC_NODES) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                node.body = node.body[1:] or [ast.Pass()]
    return ast.dump(tree, include_attributes=False)


def strip_body(body_without_pass):
    # a block left empty by removing its docstring gets `pass`; a `pass`
    # added that way is dropped again wherever the block has other statements
    tree = ast.parse(body_without_pass)
    drop = set()
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if isinstance(block, list) and len(block) > 1:
                drop.update(st.lineno for st in block if isinstance(st, ast.Pass))
    return "\n".join(l for i, l in enumerate(body_without_pass.splitlines(), 1) if i not in drop) + "\n"


def build(src):
    lines = src.splitlines(keepends=True)
    header = lines[:2]
    if not (header[0].startswith("# v") and '"Depends"' in header[1]):
        raise SystemExit("the first two lines must be the GenVM version and Depends header")
    docs = docstring_positions(ast.parse(src))
    kept = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and tok.start in docs:
            tok = tokenize.TokenInfo(tokenize.NAME, "pass", tok.start, tok.end, tok.line)
        kept.append(tok)
    code = tokenize.untokenize(kept)
    code = "\n".join(l.rstrip() for l in code.splitlines() if l.strip()) + "\n"
    out = "".join(header) + strip_body(code)
    if without_docstrings(ast.parse(out)) != without_docstrings(ast.parse(src)):
        raise SystemExit("deploy build is NOT equivalent to the source; refusing to write it")
    if not out.isascii():
        # GenLayer Studio has failed to load contract schemas for files with
        # non-ASCII characters; the deploy file must be plain ASCII.
        raise SystemExit("deploy build contains non-ASCII characters; use escapes in string literals")
    return out


def main():
    src = open(SRC, encoding="utf-8").read()
    out = build(src)
    if "--check" in sys.argv:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if current != out:
            raise SystemExit("contracts/specproof_deploy.py is out of date; run python3 tools/build_deploy.py")
        print(f"ok: contracts/specproof_deploy.py is the current, equivalent build ({len(out)} bytes)")
        return
    open(OUT, "w", encoding="utf-8").write(out)
    print(f"built contracts/specproof_deploy.py ({len(src)} -> {len(out)} bytes); syntax tree identical to source")


if __name__ == "__main__":
    main()
