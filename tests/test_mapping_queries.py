"""Query-syntax contracts: configurable templates, explicit limit, self-check.

Batch 3 acceptance, all offline. Pinned:

* each engine's template is data (config `mapping.queries.<kind>.<engine>`),
  overridable, and a template without `{value}` is rejected loudly;
* an engine with no template is never dispatched (a guessed syntax yields a
  silent zero that reads as "no assets");
* uncover always gets an explicit -limit (its default of 100 is a silent cap)
  and a full page is reported as possible truncation;
* the self-check reports per engine whether the KEY and the SYNTAX were
  accepted, and runs unattended (an agent cannot answer a consent prompt).
"""
import json

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, mapdispatch, mapping, metered
from tests.util import fresh_core


def _key(engine, value="test-key"):
    core.CFG.setdefault("apis", {}).setdefault(engine, {})["key"] = value
    if engine == "fofa":
        core.CFG["apis"]["fofa"]["email"] = "probe@example.com"


def _store():
    s = fresh_core().Store()
    mapping.ensure_schema(s)
    return s


# ---------------------------------------------------------------- templates
def test_default_templates_are_per_engine():
    """No engine inherits another engine's syntax."""
    fo = core.uncover_query("domain", "fofa", "x.example.com")
    qu = core.uncover_query("domain", "quake", "x.example.com")
    sh = core.uncover_query("domain", "shodan", "x.example.com")
    assert fo == 'domain="x.example.com"', fo
    assert qu == 'domain:"x.example.com"', qu
    assert sh == 'hostname:"x.example.com"', sh
    assert len({fo, qu, sh}) == 3


def test_a_template_is_overridable_from_config():
    core.CFG["mapping"] = {"queries": {"domain": {"fofa": 'host="{value}"'}}}
    try:
        assert core.uncover_query("domain", "fofa", "x.example.com") == \
            'host="x.example.com"'
        # an engine with no override keeps its default
        assert core.uncover_query("domain", "quake", "x.example.com") == \
            'domain:"x.example.com"'
    finally:
        core.CFG.pop("mapping", None)


def test_a_template_without_the_placeholder_is_rejected():
    core.CFG["mapping"] = {"queries": {"domain": {"fofa": 'host="fixed"'}}}
    try:
        raised = False
        try:
            core.uncover_query("domain", "fofa", "x.example.com")
        except core.FindInfoError as exc:
            raised = True
            assert "{value}" in str(exc), exc
        assert raised, "a template that drops the value must be refused"
    finally:
        core.CFG.pop("mapping", None)


def test_an_engine_with_no_template_is_never_asked():
    """censys has no domain template here: it must not be dispatched.

    zoomeye/daydaymap DO have one now (docs/MAPPING-SYNTAX.md); censys keeps
    being the example of "syntax not verified, so never ask".
    """
    assert core.uncover_query("domain", "censys", "x.example.com") is None
    usable, skipped = mapdispatch.engines_for("domain", "censys")
    assert usable == [], usable
    assert all("syntax" in s["reason"] for s in skipped), skipped


def test_query_value_cannot_escape_its_quoted_term():
    got = core.uncover_query("domain", "fofa", 'ev"il' + chr(92) + "x")
    assert got == 'domain="evilx"', got


# ---------------------------------------------------------------- limit
def test_uncover_is_always_given_an_explicit_limit():
    s = _store()
    calls = []

    def fake(cmd, **kw):
        calls.append(list(cmd))
        return 0, "", ""
    orig = core.run
    core.run = fake
    try:
        _key("fofa")
        mapdispatch.ask(s, "R", "fofa", "domain", "x.example.com")
    finally:
        core.run = orig
        s.close()
    cmd = calls[0]
    assert "-limit" in cmd, ("uncover default 100 is a silent cap", cmd)
    assert int(cmd[cmd.index("-limit") + 1]) >= 1


def test_a_full_page_is_marked_truncated():
    s = _store()
    rows = [{"host": "h%d.x.example.com" % i} for i in range(2)]
    orig = core.run
    core.run = lambda cmd, **kw: (0, "".join(json.dumps(r) + chr(10)
                                             for r in rows), "")
    try:
        _key("fofa")
        r = mapdispatch.ask(s, "R", "fofa", "domain", "x.example.com", limit=2)
    finally:
        core.run = orig
        s.close()
    assert r["truncated"] is True, r


# ---------------------------------------------------------------- self-check
def test_self_check_reports_key_and_syntax_per_engine():
    calls = []

    def fake(cmd, **kw):
        eng = cmd[cmd.index("-e") + 1]
        calls.append(eng)
        if eng == "hunter":
            return 1, "", "401 unauthorized: invalid key"
        if eng == "shodan":
            return 1, "", "invalid query syntax near 'hostname:'"
        return 0, json.dumps({"host": "a.example.com"}) + chr(10), ""
    orig = core.run
    core.run = fake
    try:
        for e in ("fofa", "hunter", "shodan"):
            _key(e)
        res = mapdispatch.check_engines("example.com", "fofa,hunter,shodan")
    finally:
        core.run = orig
    by = {c["engine"]: c for c in res["checked"]}
    assert by["fofa"]["key_accepted"] and by["fofa"]["syntax_accepted"], by
    assert by["hunter"]["key_accepted"] is False, by
    assert by["shodan"]["syntax_accepted"] is False, by
    # one minimal query each, nothing cached as task mapping
    assert sorted(calls) == ["fofa", "hunter", "shodan"], calls


def test_self_check_is_limit_one():
    seen = []
    orig = core.run
    core.run = lambda cmd, **kw: (seen.append(list(cmd)), (0, "", ""))[1]
    try:
        _key("fofa")
        mapdispatch.check_engines("example.com", "fofa")
    finally:
        core.run = orig
    cmd = seen[0]
    assert cmd[cmd.index("-limit") + 1] == "1", cmd

# --------------------------------------------------- self-check runs unattended
def test_self_check_needs_no_consent_flag():
    """The skill is driven by an agent; a consent prompt would just block it.

    The cost is bounded by construction (one -limit 1 query per engine), so
    `doctor --check-mapping --domain X` runs directly. `--yes-spend-quota` is
    still accepted so an existing command line keeps working.
    """
    import io
    import contextlib
    import unittest.mock as mock
    import tests.util  # noqa: F401
    from tests.util import fresh_tools, import_findinfo

    core_ = fresh_core()
    fresh_tools(core_)
    _key("fofa")
    fi = import_findinfo()
    seen = []
    fake = lambda cmd, **kw: (seen.append(list(cmd)), (0, "", ""))[1]
    buf = io.StringIO()
    with mock.patch.object(fi.mapdispatch, "check_engines",
                           lambda d, e=None, timeout=0: {"domain": d,
                                                         "checked": [], "skipped": []}),             contextlib.redirect_stdout(buf):
        rc = fi.main(["doctor", "--check-mapping", "--domain", "example.com"])
    assert rc == 0, buf.getvalue()
    payload = json.loads([l for l in buf.getvalue().splitlines()
                          if l.startswith("{")][-1])
    assert payload["check_mapping"]["domain"] == "example.com", payload
    assert fake is not None

# ------------------------------------------------- gateway credentials (real run)
def test_a_relay_key_is_never_handed_to_uncover():
    """A gateway AK is valid only at the relay and needs no email.

    Found on a real run (南开大学): fofa was configured as base+key with no
    email. uncover speaks the OFFICIAL API and demanded FOFA_EMAIL, so every
    dispatch died with "agents [fofa] requires keys but no keys were found"
    and was recorded as `failed` (never retried). The gateway protocol is
    POST /api/v1/query with an X-Ak header -- a different protocol entirely.
    """
    core_ = fresh_core()
    s = core_.Store()
    mapping.ensure_schema(s)
    core_.CFG.setdefault("apis", {})["fofa"] = {
        "email": "", "key": "test-relay-ak", "base": "http://relay.example.test:1"}
    uncovered, gateway = [], []

    def fake_run(cmd, **kw):
        uncovered.append(list(cmd))
        return 0, "", ""

    def fake_gateway(query, **kw):
        gateway.append(query)
        return {"ok": True, "results": [{"host": "a.mt-a.example.com",
                                         "ip": "203.0.113.10"}]}

    orig_run, orig_gw = core.run, core.fofa_query
    core.run, core.fofa_query = fake_run, fake_gateway
    try:
        r = mapdispatch.ask(s, "R", "fofa", "domain", "mt-a.example.com")
    finally:
        core.run, core.fofa_query = orig_run, orig_gw
        s.close()
    assert uncovered == [], ("uncover must not be used for a relay", uncovered)
    assert gateway == ['domain="mt-a.example.com"'], gateway
    assert r["status"] == metered.ST_OK and r["rows"] >= 2, r


def test_a_deleted_key_is_an_auth_skip_not_a_transport_failure():
    """A provider saying "key does not exist" must not look like a crash.

    The real answer was `密钥不存在或已被删除`; recorded as `failed` it made
    the stage look broken AND stayed retryable, so every later question
    re-sent the same dead key. It is `auth`: skip, name as a gap, never retry.
    """
    assert metered.status_of("", rc=1, count=0,
                             error="密钥不存在或已被删除") == metered.ST_AUTH
    assert metered.status_of(
        "", rc=1, count=0,
        error="[uncover:RUNTIME] agents [fofa] requires keys but no keys "
              "were found") == metered.ST_AUTH
    # a genuine transport failure stays retryable
    assert metered.status_of("", rc=124, count=0, error="timeout") == metered.ST_FAILED


def test_an_engine_with_a_dead_key_is_skipped_without_dispatching_again():
    fresh_core()                     # its own home: no ledger row from another test
    s = core.Store()
    mapping.ensure_schema(s)
    core.CFG.setdefault("apis", {}).setdefault("fofa", {})["key"] = "test-dead-key"
    core.CFG["apis"]["fofa"].pop("base", None)
    calls = []
    orig = core.run
    core.run = lambda cmd, **kw: (calls.append(list(cmd)),
                                  (1, "", "401 unauthorized: invalid key"))[1]
    try:
        first = mapdispatch.ask(s, "R", "fofa", "domain", "mt-a.example.com")
        assert first["status"] == metered.ST_AUTH, first
        assert len(calls) == 1, calls
        # a SECOND question must not spend another request on the dead key
        second = mapdispatch.ask(s, "R", "fofa", "domain", "other.example.com")
    finally:
        core.run = orig
        s.close()
    assert second["status"] == "skipped", second
    assert "auth" in second["reason"], second
    assert len(calls) == 1, ("a dead key must not be retried", calls)

# -------------------------------------- entitlement refusal (real run, 南开大学)
def test_a_plan_without_search_is_auth_not_empty():
    """Shodan's free `oss` plan answers every query with zero rows.

    Found on a real run: `hostname:"nankai.edu.cn"` returned 0 rows and the
    ledger recorded `empty`, which publishes a paid-plan limitation as "this
    target has no assets". uncover reports the refusal as rc=0 with no rows AND
    no message, so the only way to tell is to ask the provider. `/api-info`
    answers without spending a query credit.
    """
    core_ = fresh_core()
    s = core_.Store()
    mapping.ensure_schema(s)
    core_.CFG.setdefault("apis", {})["shodan"] = {"key": "test-oss-key"}
    orig_run, orig_curl = core.run, core.curl
    core.run = lambda cmd, **kw: (0, "", "")
    probe_calls = []

    def fake_curl(args, timeout=None):
        probe_calls.append(list(args))
        return 0, json.dumps({"plan": "oss", "query_credits": 0}), ""

    core.curl = fake_curl
    try:
        r = mapdispatch.ask(s, "R", "shodan", "domain", "mt-a.example.com")
    finally:
        core.run, core.curl = orig_run, orig_curl
        s.close()
    assert r["status"] == metered.ST_AUTH, r
    assert "membership" in r["reason"] or "credits" in r["reason"], r
    assert probe_calls and "api-info" in probe_calls[0][-1], probe_calls


def test_a_plan_with_credits_stays_empty():
    """A zero from a key that MAY search is a real empty answer."""
    core_ = fresh_core()
    s = core_.Store()
    mapping.ensure_schema(s)
    core_.CFG.setdefault("apis", {})["shodan"] = {"key": "test-paid-key"}
    orig_run, orig_curl = core.run, core.curl
    core.run = lambda cmd, **kw: (0, "", "")
    core.curl = lambda args, timeout=None: (
        0, json.dumps({"plan": "dev", "query_credits": 100}), "")
    try:
        r = mapdispatch.ask(s, "R", "shodan", "domain", "mt-a.example.com")
    finally:
        core.run, core.curl = orig_run, orig_curl
        s.close()
    assert r["status"] == metered.ST_EMPTY, r

def test_a_free_hunter_account_is_auth_not_empty():
    """A free Hunter account answers code=400 "账号无 API 访问权限".

    Same defect class as the Shodan `oss` plan: uncover passes the refusal
    through as rc=0 with no rows. It is a billing limitation, so it is `auth`
    (skip, report as a gap), never `empty`.
    """
    core_ = fresh_core()
    s = core_.Store()
    mapping.ensure_schema(s)
    core_.CFG.setdefault("apis", {})["hunter"] = {"key": "test-free-hunter"}
    orig_run, orig_curl = core.run, core.curl
    core.run = lambda cmd, **kw: (0, "", "")
    core.curl = lambda args, timeout=None: (
        0, json.dumps({"code": 400,
                       "message": "账号无 API 访问权限，需升级为付费账号"}), "")
    try:
        r = mapdispatch.ask(s, "R", "hunter", "domain", "mt-a.example.com")
    finally:
        core.run, core.curl = orig_run, orig_curl
        s.close()
    assert r["status"] == metered.ST_AUTH, r
    assert "API" in r["reason"] or "auth" in r["reason"], r


def test_a_paid_hunter_account_stays_empty():
    core_ = fresh_core()
    s = core_.Store()
    mapping.ensure_schema(s)
    core_.CFG.setdefault("apis", {})["hunter"] = {"key": "test-paid-hunter"}
    orig_run, orig_curl = core.run, core.curl
    core.run = lambda cmd, **kw: (0, "", "")
    core.curl = lambda args, timeout=None: (
        0, json.dumps({"code": 200, "message": "success",
                       "data": {"total": 0, "arr": []}}), "")
    try:
        r = mapdispatch.ask(s, "R", "hunter", "domain", "mt-a.example.com")
    finally:
        core.run, core.curl = orig_run, orig_curl
        s.close()
    assert r["status"] == metered.ST_EMPTY, r


def test_brief_carries_the_mapping_ledger_summary():
    """A run whose engines were all refused must not read as "no assets".

    Found on the 南开大学 run: the run summary had `coverage.mapping` but the
    brief dropped it, so an agent saw zero findings and no reason for them.
    """
    from lib import report
    cov = {"unavailable": {}, "mapping": {"questions": 3, "by_engine": {
               "shodan": {"asked": 1, "auth": 1, "total": 1}}},
           "metered": {"by_engine": {"quake": {"requests": 1}}}}
    out = report._brief_coverage(coverage=cov)
    assert out["mapping"]["questions"] == 3, out
    assert out["metered"]["by_engine"]["quake"]["requests"] == 1, out

# ------------------------------------------- pagination is a spend ceiling
def test_each_engine_gets_its_own_row_ceiling():
    """One global number cannot be right for every engine.

    Every engine pages at 100 rows per request (verified in the bundled uncover
    sources: quake Size=100, fofa Size=100, shodan page=..., hunter Size=100,
    zoomeye pagesize=100), so `-limit` is a PAGE BUDGET. But what one page
    COSTS differs: fofa bills the query, quake bills 100 credits a page and its
    whole free month is 3000. A single default therefore either underspends on
    one engine or drains another, so each engine carries its own ceiling.
    """
    fresh_core()
    assert "mapping_rows" not in (core.CFG.get("limits") or {}), (
        "a global default would override every engine's own ceiling")
    assert mapdispatch.mapping_limit("quake") == 3000      # one free month
    assert mapdispatch.mapping_limit("fofa") == 1000
    assert mapdispatch.mapping_limit("shodan") == 1000
    assert mapdispatch.mapping_limit("hunter") == 1000


def test_a_per_engine_page_budget_can_be_raised_on_request():
    """`limits.mapping_rows_<engine>` overrides that engine only."""
    fresh_core()
    core.CFG.setdefault("limits", {})["mapping_rows_quake"] = 500
    assert mapdispatch.mapping_limit("quake") == 500
    # every other engine keeps its own ceiling: not global
    assert mapdispatch.mapping_limit("fofa") == 1000


def test_a_global_cap_still_wins_when_the_operator_sets_one():
    """An operator who wants ONE cap for all engines can still say so."""
    fresh_core()
    core.CFG.setdefault("limits", {})["mapping_rows"] = 200
    assert mapdispatch.mapping_limit("quake") == 200
    assert mapdispatch.mapping_limit("fofa") == 200


def test_billed_pages_are_counted_for_every_paginating_engine():
    """One dispatch of N pages must not be recorded as one request.

    uncover pages on ALL of these engines at 100 rows a page (verified in the
    bundled sources), so a 3000-row quake question is 30 billed round trips.
    """
    assert mapdispatch.pages_spent("quake", 50, 100) == 1
    assert mapdispatch.pages_spent("quake", 250, 500) == 5
    assert mapdispatch.pages_spent("quake", 0, 3000) == 30
    assert mapdispatch.pages_spent("fofa", 0, 1000) == 10
    assert mapdispatch.pages_spent("shodan", 0, 1000) == 10
    assert mapdispatch.pages_spent("hunter", 0, 1000) == 10
    # asking for less than one page is still one page
    assert mapdispatch.pages_spent("quake", 10, 10) == 1


# ------------------------------------------------- name as a search value
def test_a_company_name_can_be_searched_when_no_domain_exists():
    """ENScan can anchor a subject and file no domain; the name IS the query.

    A name must not pass through canon_user_domain (that drops every Chinese
    company name and would empty the search), and the quoted-term guard is what
    keeps it safe.
    """
    s = fresh_core().Store()
    mapping.ensure_schema(s)
    for e in ("fofa", "quake"):
        core.CFG.setdefault("apis", {}).setdefault(e, {})["key"] = "test-key"
    core.CFG["apis"]["fofa"]["base"] = ""
    seen = []
    orig = core.run
    core.run = lambda cmd, **kw: (seen.append(list(cmd)), (0, "", ""))[1]
    try:
        r = mapdispatch.ask(s, "R", "fofa", "domain", "南开大学")
    finally:
        core.run = orig
        s.close()
    assert r["status"] == metered.ST_EMPTY, r
    q = seen[0][seen[0].index("-q") + 1]
    assert "南开大学" in q, q


def test_a_name_cannot_break_out_of_the_quoted_term():
    s = fresh_core().Store()
    mapping.ensure_schema(s)
    core.CFG.setdefault("apis", {}).setdefault("fofa", {})["key"] = "test-key"
    core.CFG["apis"]["fofa"]["base"] = ""
    seen = []
    orig = core.run
    core.run = lambda cmd, **kw: (seen.append(list(cmd)), (0, "", ""))[1]
    try:
        mapdispatch.ask(s, "R", "fofa", "domain", 'a" OR b:"c')
    finally:
        core.run = orig
        s.close()
    q = seen[0][seen[0].index("-q") + 1]
    assert q.count('"') == 2, ("exactly the two template quotes", q)


# ---------------------------------------------------- the platform syntax table
def test_zoomeye_and_daydaymap_have_their_own_syntax():
    """docs/MAPPING-SYNTAX.md is the field matrix; these two were missing.

    Each platform spells the same field differently (fofa `domain="x"`, quake
    `domain:"x"`, shodan `hostname:x`). An engine with no template is never
    dispatched, so adding the syntax is what makes it usable at all.
    """
    fresh_core()
    assert core.uncover_query("domain", "zoomeye", "example.com") == \
        'domain="example.com"'
    assert core.uncover_query("domain", "daydaymap", "example.com") == \
        'domain="example.com"'
    assert core.uncover_query("icp", "daydaymap", "京ICP备1号") == \
        'icp.number="京ICP备1号"'
    # an engine with no ICP field must still answer None, not a bad query
    assert core.uncover_query("icp", "shodan", "京ICP备1号") is None


def test_a_provider_file_engine_is_not_trusted_from_an_env_var():
    """uncover reads daydaymap's key from provider-config.yaml, not the env.

    Reporting "has key" from an environment variable would dispatch a query
    that cannot authenticate, and uncover reports that as rc=0/no rows -- a
    silent zero that reads as "no assets".
    """
    core_ = fresh_core()
    assert "daydaymap" in core_.PROVIDER_FILE_ENGINES
    # no provider file -> no key, even if an env var is present
    core_.CFG.setdefault("apis", {}).setdefault("daydaymap", {})["key"] = "env-key"
    assert core_.engine_has_key("daydaymap") is False
    # a provider file with the engine listed -> usable
    p = core_.provider_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("daydaymap:\n  - file-key\n", encoding="utf-8")
    try:
        assert core_.engine_has_key("daydaymap") is True
    finally:
        p.unlink()
