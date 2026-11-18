"""Regression: JS/HTML artifacts must not become assets (canon_domain guard).

Real run evidence: extracting JS from a crawled site produced thousands of
"domains" that were actually property chains -- arguments.length,
action.preserve, avalon.router.go -- because any two lowercase words joined by
a dot satisfy the hostname grammar. A hostname needs a REAL public suffix.
"""
import tests.util  # noqa: F401
from tests.util import fresh_core


def test_js_property_chains_are_not_domains():
    core = fresh_core()
    junk = ["arguments.length", "e.env.need", "action.preserve",
            "authcontro.prototype", "removeclass.children", "tolowercase.push",
            "dximagetransform.microsoft.alphaimageloader", "window.top",
            "ajax.js", "index.vsb.css", "t.top"]
    for value in junk:
        assert core.canon_domain(value) is None, "junk accepted as domain: " + value


def test_real_hosts_still_accepted():
    core = fresh_core()
    good = ["example.com", "ehall.example.com", "authserver.example.com",
            "www.example.com", "api.example.io", "x.co.uk",
            "hr.lh.rendd.cn", "a1.b2.example.org", "sub.domain.tech"]
    for value in good:
        assert core.canon_domain(value) == value, "real host rejected: " + value


def test_common_cctld_and_gtld_coverage():
    """Two-letter ccTLDs and common gTLDs are all accepted."""
    core = fresh_core()
    for tld in ("cn", "com", "net", "org", "io", "co", "ai", "jp", "de", "uk"):
        host = "host." + tld
        assert core.canon_domain(host) == host, "rejected " + host
