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




def test_version_strings_are_not_ips():
    """`03.06.03.118` matches the permissive regex but is not an address.

    A real target (南开大学) collected 36 such strings -- version numbers and
    dates from JS bundles -- into the asset graph because this module returned
    regex hits verbatim. Every hit now goes through core.canon_ip, which
    rejects a leading-zero octet (and anything ipaddress refuses).
    """
    import lib.jsleak as js
    got = js.extract("var v='03.06.03.118'; var d='06.118.206.148';", [])
    assert got["ips"] == [], got["ips"]


def test_a_real_ip_is_still_kept():
    import lib.jsleak as js
    got = js.extract("const api='http://93.184.216.34:8080/x'", [])
    assert got["ips"] == ["93.184.216.34"], got["ips"]


def test_internal_addresses_are_evidence_not_assets():
    """127.0.0.1 in a bundle proves a leak; it is not a host to scan.

    Kept in the report as `internal_ips`, excluded from `ips` so probe/ports
    never treat the operator's own machine or a private range as target.
    """
    from lib import tools
    got = tools.extract_from_text(
        "a 127.0.0.1 b 10.2.2.2 c 93.184.216.34 d 03.06.03.118", [])
    assert got["ips"] == ["93.184.216.34"], got
    assert sorted(got["internal_ips"]) == ["10.2.2.2", "127.0.0.1"], got


def test_js_concatenation_fragments_are_not_endpoints():
    """katana reports `'/_upload/tpl/' + tecUrl + '/x'` pieces as paths.

    A real target produced 25,510 such fragments against 492 real API
    endpoints. They can never be requested, so they are dropped before
    storage rather than after triage fails.
    """
    from lib import core
    assert core.is_junk_path("/_upload/tpl/{n}/template1/js/'+tecUrl+'")
    assert core.is_junk_path("/a%27+%20x")
    assert not core.is_junk_path("/api/cas/login")
    assert not core.is_junk_path("/api/user/{n}")
    assert not core.is_junk_path("/")
