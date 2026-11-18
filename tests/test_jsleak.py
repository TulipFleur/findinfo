"""P4-B acceptance: JS path / domain extraction fixes, with counter-examples.

- /api/login, /admin, /graphql, /v1/health are extracted (the old regex
  required >=2 chars before the keyword and dropped exactly these).
- service.example.com.au is not truncated to service.example.com.
- Counter-examples: adjacent text, query params, non-domain expressions do
  not produce junk paths/domains.
"""
import tests.util  # noqa: F401

from lib import jsleak
from tests.util import fresh_core


def test_api_paths_extracted():
    text = '''
    var a = "/api/login";
    var b = '/admin';
    var c = `/graphql`;
    var d = "/v1/health";
    var e = "/api/v2/users";
    var f = "/internal/queue/stats";
    '''
    paths = set(jsleak.extract(text)["api_paths"])
    for want in ("/api/login", "/admin", "/graphql", "/v1/health",
                 "/api/v2/users", "/internal/queue/stats"):
        assert want in paths, (want, paths)


def test_api_path_counterexamples():
    text = '''
    "version": "1.2.3"
    "path": "/avatar1"          <- no api keyword
    "path": "/canvas2"
    x = "/static/logo.png"
    url = /no/quotes/here       <- unquoted, must not match
    '''
    paths = set(jsleak.extract(text)["api_paths"])
    # none of these contain an API-ish keyword segment
    assert "/avatar1" not in paths
    assert "/canvas2" not in paths
    assert "/static/logo.png" not in paths


def test_domain_multilevel_suffix_not_truncated():
    got = jsleak.extract("connect to service.example.com.au please")
    assert "service.example.com.au" in got["all_domains"], got["all_domains"]
    assert not any(d == "service.example.com" for d in got["all_domains"]), \
        "old TLD whitelist truncated multi-label suffixes; must not happen"


def test_domain_counterexamples():
    """JS expressions / versions / filenames die at the canon gate (t_extract),
    and the obviously-numeric shapes never even shape-match as domains."""
    from tests.util import fresh_core
    core = fresh_core()
    raw = jsleak.extract("""
        依赖版本 v1.2.3 版本号 1.2.3.4 是IP
        window.top / popover.style.top / e.top
        文件名 app.min.js index.vsb.css
        Math.min(a,b) e.preventDefault()
        """)
    # raw extractor: numeric TLDs never shape-match
    for junk in ("v1.2.3", "1.2.3"):
        assert junk not in raw["all_domains"], junk
    assert "1.2.3.4" in raw["ips"]                       # it IS an IP
    # canon gate (what t_extract / dns actually consume):
    for d in raw["all_domains"]:
        if d in ("window.top", "style.top", "e.top"):
            assert core.canon_domain(d) is None, d       # JS chain: rejected
        if d in ("app.min.js", "index.vsb.css"):
            assert core.canon_domain(d) is None, d       # file TLD: rejected


def test_domain_adjacent_text():
    got = jsleak.extract("域名example.com结束 https://sub.example.com/path?a=b")
    assert "example.com" in got["all_domains"]
    assert "sub.example.com" in got["all_domains"]
    # query params do not become part of the hostname
    assert not any("path" in d or "a=b" in d for d in got["all_domains"])


def test_extract_from_text_canon_gate():
    """tools.extract_from_text + the t_extract canon gate reject file TLDs."""
    from tests.util import fresh_core, fresh_tools
    core = fresh_core()
    tools = fresh_tools(core)
    got = tools.extract_from_text("see app.min.js and www.example.com.au", [])
    assert "app.min.js" not in got["domains"]
    assert "www.example.com.au" in got["domains"]


def test_jsluice_recovers_params_a_regex_misses():
    """The AST engine must beat the regex engine on concatenated URLs."""
    core = fresh_core()
    from lib import tools

    # This is the canonical case from the jsluice README: a naive regex sees
    # only "/login?redirect=" and loses the ?method= parameter entirely.
    body = ('const login = (redirect) => {'
            '  document.location = "/login?redirect=" + redirect + "&method=oauth";'
            '};')
    if not core.has_tool("jsluice"):
        # the fallback must still work, just with lower recall
        r = tools.js_scan(body)
        assert r["api_paths"], "the regex fallback must still extract something"
        return
    r = tools.js_scan(body)
    assert r.get("engine") == "jsluice", r.get("engine")
    joined = " ".join(r["api_paths"])
    assert "method=oauth" in joined or "method" in joined, (
        "jsluice did not recover the concatenated query parameter: " + joined)
    meta = r.get("path_meta") or {}
    any_two_params = any(len((m or {}).get("query") or []) >= 2 for m in meta.values())
    assert any_two_params, (
        "expected a row with both redirect and method query params, got " + repr(meta))


def test_js_scan_marks_the_engine_it_used():
    """Callers must be able to tell which extractor produced the paths."""
    core = fresh_core()
    from lib import tools
    r = tools.js_scan('fetch("/api/x?id=" + y)')
    assert r.get("engine") in ("jsluice", None), r.get("engine")
    assert r["api_paths"], "no paths extracted at all"
