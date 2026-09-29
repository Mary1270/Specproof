# v0.2.16
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
import hashlib
import json

from genlayer import *

_FAIL = "\x00PROBE_FAILED\x00"


def _report(text) -> str:
    if not isinstance(text, str):
        return f"not a string: {type(text).__name__}"
    lines = text.split("\n")
    wanted = [l for l in lines if "margin" in l or "Hello World" in l][:4]
    return json.dumps({
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "starts_with_diff": text.startswith("diff --git "),
        "double_space_lines": sum(1 for l in lines if "  " in l),
        "sample_spaces_as_underscores": [l.replace(" ", "_") for l in wanted],
    })


def _strict(fn) -> str:
    def safe():
        try:
            return fn()
        except Exception as e:
            return _FAIL + f"{type(e).__name__}: {e}"[:500]
    return gl.eq_principle.strict_eq(safe)


class FetchProbe(gl.Contract):
    last: str

    def __init__(self):
        self.last = ""

    @gl.public.view
    def web_api(self) -> str:
        return json.dumps(sorted(n for n in dir(gl.nondet.web) if not n.startswith("_")))

    @gl.public.write
    def probe_render_text(self, url: str) -> str:
        def fn():
            return _report(gl.nondet.web.render(url, mode="text"))
        self.last = "render_text " + _strict(fn)
        return self.last

    @gl.public.write
    def probe_render_html(self, url: str) -> str:
        def fn():
            html = gl.nondet.web.render(url, mode="html")
            return json.dumps({"head": html[:300].replace(" ", "_"), "report": _report(html)})
        self.last = "render_html " + _strict(fn)
        return self.last

    @gl.public.write
    def probe_get(self, url: str) -> str:
        def fn():
            resp = gl.nondet.web.get(url)
            body = getattr(resp, "body", resp)
            status = getattr(resp, "status", None)
            if isinstance(body, (bytes, bytearray)):
                body = bytes(body).decode("utf-8")
            return json.dumps({"status": status, "report": _report(body)})
        self.last = "get " + _strict(fn)
        return self.last
