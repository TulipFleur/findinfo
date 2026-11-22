"""An ICP reverse lookup must keep WHICH filing answered.

The third collection pass is filings: a filing number reverse-looks-up the
domains registered under it. `store_results` wrote those domains with no
parent, so the report could not say which filing a host came from -- the answer
looked like a direct statement about the seed domain.
"""
import tests.util  # noqa: F401
from tests.util import fresh_core

from lib import mapdispatch, mapping


def _store():
    s = fresh_core().Store()
    mapping.ensure_schema(s)
    return s


def test_a_domain_answered_by_a_filing_keeps_its_filing():
    s = _store()
    ctx = {"engine": "fofa", "kind": "icp", "asked": "京ICP备00000001号"}
    try:
        stored = mapdispatch.store_results(
            s, [("domain", "a.mt-a.example.com", ctx),
                ("domain", "b.mt-a.example.com", ctx),
                ("ip", "203.0.113.10", ctx)])
        rows = {a["canonical"]: a for a in s.get_assets(kind="domain")}
        ips = {a["canonical"]: a for a in s.get_assets(kind="ip")}
    finally:
        s.close()
    assert stored == {"domain": 2, "ip": 1}, stored
    assert rows["a.mt-a.example.com"]["parent"] == "京ICP备00000001号", rows
    assert ips["203.0.113.10"]["parent"] == "京ICP备00000001号", ips
    # the provenance names the question type, so a filing answer cannot be
    # mistaken for a direct domain search
    assert "icp" in rows["a.mt-a.example.com"]["sources"], rows


def test_a_domain_answer_has_no_filing_parent():
    s = _store()
    ctx = {"engine": "fofa", "kind": "domain", "asked": "mt-a.example.com"}
    try:
        mapdispatch.store_results(s, [("domain", "x.mt-a.example.com", ctx)])
        row = {a["canonical"]: a for a in s.get_assets(kind="domain")}[
            "x.mt-a.example.com"]
    finally:
        s.close()
    assert row.get("parent") in (None, ""), row
    assert "mapping:domain" in row["sources"], row


def test_rows_without_context_still_store():
    """A legacy 2-tuple row (no context) must not crash the writer."""
    s = _store()
    try:
        stored = mapdispatch.store_results(s, [("domain", "y.mt-a.example.com")])
    finally:
        s.close()
    assert stored == {"domain": 1, "ip": 0}, stored
