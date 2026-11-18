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


