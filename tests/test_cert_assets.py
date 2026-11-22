"""Certificates are an asset, not just names to harvest.

The three-pass collection the operator asked for is: domains (uncover), then
certificates (CT), then filings (ICP). The certificate pass used to keep only
the NAMES inside a certificate and throw the certificate itself away, so the
middle pass produced no artefact of its own.
"""
import json
import unittest.mock as mock

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools


def test_a_certificate_becomes_an_asset():
    core = fresh_core()
    tools = fresh_tools(core)
    payload = [{
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "a.mt-a.example.com",
        "name_value": "a.mt-a.example.com\nb.mt-a.example.com",
        "serial_number": "03:1f:2e",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "entry_timestamp": "2026-01-02T03:04:05",
        "dns_names": ["a.mt-a.example.com", "b.mt-a.example.com"],
    }]
    store = core.Store()
    try:
        with mock.patch.object(core, "curl_json", lambda *a, **kw: payload):
            res = tools.t_certs(store, "mt-a.example.com")
        certs = store.get_assets(kind="cert")
        domains = sorted(a["canonical"] for a in store.get_assets(kind="domain"))
    finally:
        store.close()
    assert res["certs"] == 1, res
    assert domains == ["a.mt-a.example.com", "b.mt-a.example.com"], domains
    assert len(certs) == 1, certs
    attrs = certs[0].get("attrs") or {}
    assert attrs.get("issuer", "").startswith("C=US"), attrs
    assert attrs.get("serial") == "03:1f:2e", attrs
    assert attrs.get("not_after") == "2026-04-01T00:00:00", attrs
    assert "b.mt-a.example.com" in (attrs.get("san") or []), attrs
    assert certs[0]["parent"] == "mt-a.example.com", certs[0]


def test_certspotter_spelling_is_read_too():
    """CertSpotter uses `id` / `issuer.name` where crt.sh uses serial/issuer_name."""
    core = fresh_core()
    tools = fresh_tools(core)
    payload = [{
        "id": "998877",
        "issuer": {"name": "C=US, O=Test CA", "O": "Test CA"},
        "dns_names": ["c.mt-a.example.com"],
        "not_before": "2026-02-02T00:00:00Z",
        "not_after": "2026-05-02T00:00:00Z",
    }]
    store = core.Store()
    try:
        with mock.patch.object(core, "curl_json", lambda *a, **kw: payload):
            res = tools.t_certs(store, "mt-a.example.com")
        certs = store.get_assets(kind="cert")
    finally:
        store.close()
    assert res["certs"] == 1, res
    attrs = certs[0].get("attrs") or {}
    assert attrs.get("issuer") == "C=US, O=Test CA", attrs
    assert attrs.get("serial") == "998877", attrs
