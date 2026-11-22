"""Mapping dispatch: ask once per task, always explicit -limit, keyless rest.

Batch 1 dispatch acceptance. ``core.run`` is faked in every test here, so no
socket, DNS lookup or bundled binary is ever started. The defects pinned:

* one seed was sent to the same engine twice inside one run (onepass + subs +
  subs' uncover loop), and every standalone command paid again;
* uncover's ``-limit`` was never set, so a query silently capped at 100 rows;
* API keys reached children that never use them.
"""
import json

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, mapdispatch, mapping, metered
from tests.util import fresh_core


def _store():
    s = fresh_core().Store()
    mapping.ensure_schema(s)
    return s


class _Run:
    """A stand-in for core.run that records invocations and answers."""

    def __init__(self, rows=None, rc=0, err=""):
        self.calls = []
        self.rows = rows or []
        self.rc = rc
        self.err = err

    def __call__(self, cmd, **kw):
        self.calls.append({"cmd": list(cmd), "env": dict(kw.get("env") or {})})
        body = "".join(json.dumps(r) + chr(10) for r in self.rows)
        return self.rc, body, self.err

    def engines(self):
        out = []
        for c in self.calls:
            try:
                out.append(c["cmd"][c["cmd"].index("-e") + 1])
            except (ValueError, IndexError):
                continue
        return out

    def uncover(self):
        """Only the uncover invocations (a dispatch also polls a credit balance)."""
        return [c for c in self.calls if "-q" in c["cmd"] and "-e" in c["cmd"]]


def _key(cfg_mod, engine, value: str) -> None:
    """Set one engine's credential to a TEST value and nothing else.

    The ambient config on a developer machine may hold a real key; a test that
    reads or asserts it would both leak the value into a log and pass for the
    wrong reason. Every test here sets exactly what it expects.
    """
    apis = cfg_mod.CFG.setdefault("apis", {})
    apis.setdefault(engine, {})["key"] = value
    if engine == "fofa":
        apis["fofa"]["email"] = "probe@example.com"
        # No relay: a configured base routes fofa to the gateway protocol
        # (POST /api/v1/query + X-Ak) instead of uncover, and a test that then
        # asserts on uncover's argv would be asserting about the wrong path.
        apis["fofa"]["base"] = ""


def _patch_run(monkey, fake):
    monkey.setattr(core, "run", fake)


# ------------------------------------------------------------ ask once
def test_the_same_question_is_paid_for_once():
    """The second ask of one (engine, seed) is a cache hit, not a new request."""
    s = _store()
    fake = _Run([{"host": "a.mt-a.example.com", "ip": "203.0.113.10"}])
    real = core.run
    core.run = fake
    try:
        _key(core, "fofa", "test-fofa-key")
        r1 = mapdispatch.ask(s, "RUN1", "fofa", "domain", "mt-a.example.com")
        assert r1["status"] == metered.ST_OK and r1["rows"] >= 1, r1
        assert len(fake.calls) == 1, fake.calls
        r2 = mapdispatch.ask(s, "RUN1", "fofa", "domain", "mt-a.example.com")
        assert r2["reused"] is True, r2
        assert len(fake.calls) == 1, ("a second ask must not hit the wire", fake.calls)
        # the reused answer still carries the evidence
        assert ("domain", "a.mt-a.example.com") in r2["results"], r2
    finally:
        core.run = real
        s.close()


def test_remap_is_the_explicit_opt_in_to_ask_again():
    s = _store()
    fake = _Run([{"host": "a.mt-a.example.com"}])
    real = core.run
    core.run = fake
    try:
        _key(core, "fofa", "test-fofa-key")
        mapdispatch.ask(s, "RUN1", "fofa", "domain", "mt-a.example.com")
        r = mapdispatch.ask(s, "RUN1", "fofa", "domain", "mt-a.example.com",
                            remap=True)
        assert r["reused"] is False
        assert len(fake.uncover()) == 2
        assert mapping.lookup(s, mapping.question(
            "fofa", "domain", "mt-a.example.com",
            core.uncover_query("domain", "fofa", "mt-a.example.com")))["attempts"] == 2
    finally:
        core.run = real
        s.close()


def test_each_engine_is_asked_in_its_own_syntax_once():
    """One dispatch per engine, each with that engine's own query text."""
    s = _store()
    fake = _Run([{"host": "a.mt-a.example.com"}])
    real = core.run
    core.run = fake
    try:
        for eng in ("fofa", "quake"):
            _key(core, eng, "test-" + eng + "-key")
        res = mapdispatch.ask_all(s, "RUN1", "domain", ["mt-a.example.com"],
                                  engines="fofa,quake")
        assert sorted(fake.engines()) == ["fofa", "quake"], fake.engines()
        assert res["dispatched"] == 2, res
        # the query text differs per engine (uncover does not translate)
        qs = [c["cmd"][c["cmd"].index("-q") + 1] for c in fake.uncover()]
        assert len(set(qs)) == 2, qs
    finally:
        core.run = real
        s.close()


# ------------------------------------------------------------ limit
def test_every_dispatch_sets_an_explicit_limit():
    s = _store()
    fake = _Run([])
    real = core.run
    core.run = fake
    try:
        _key(core, "fofa", "test-fofa-key")
        mapdispatch.ask(s, "RUN1", "fofa", "domain", "mt-a.example.com")
        cmd = fake.calls[0]["cmd"]
        assert "-limit" in cmd, ("uncover default (100) is a silent cap", cmd)
        assert int(cmd[cmd.index("-limit") + 1]) >= 1
    finally:
        core.run = real
        s.close()


def test_a_full_page_is_reported_as_possible_truncation():
    s = _store()
    # exactly `limit` rows -> the page may hide more
    rows = [{"host": "h%d.mt-a.example.com" % i} for i in range(3)]
    fake = _Run(rows)
    real = core.run
    core.run = fake
    try:
        _key(core, "fofa", "test-fofa-key")
        r = mapdispatch.ask(s, "RUN1", "fofa", "domain", "mt-a.example.com",
                            limit=3)
        assert r["truncated"] is True, r
        assert "uncover:fofa" in [
            "uncover:" + x for x in []] or r["truncated"]
        row = mapping.lookup(s, mapping.question(
            "fofa", "domain", "mt-a.example.com",
            core.uncover_query("domain", "fofa", "mt-a.example.com")))
        assert row["truncated"] == 1, row
    finally:
        core.run = real
        s.close()


# ------------------------------------------------------------ keyless
def test_a_mapping_dispatch_passes_only_the_called_tools_keys():
    s = _store()
    # configure BOTH so "not asked -> key absent" is a real assertion
    _key(core, "hunter", "test-hunter-key")
    fake = _Run([])
    real = core.run
    core.run = fake
    try:
        _key(core, "fofa", "test-fofa-key")
        core.CFG.setdefault("apis", {}).setdefault("hunter", {})["key"] = "h"
        mapdispatch.ask(s, "RUN1", "fofa", "domain", "mt-a.example.com")
        env = fake.calls[0]["env"]
        assert env.get("FOFA_KEY") == "test-fofa-key", env
        assert env.get("FOFA_EMAIL") == "probe@example.com", env
        # an engine we are not asking must not carry its key
        assert "HUNTER_API_KEY" not in env, env
    finally:
        core.run = real
        s.close()


def test_engine_without_key_is_skipped_with_a_reason():
    s = _store()
    # no key and no gateway configured for either engine (never inherit the
    # host's real credentials: the ambient config may hold a live key)
    _key(core, "fofa", "")
    core.CFG["apis"]["fofa"]["base"] = ""
    _key(core, "quake", "")
    usable, skipped = mapdispatch.engines_for("domain", "fofa,quake")
    assert usable == []
    reasons = {x["engine"]: x["reason"] for x in skipped}
    assert reasons.get("fofa") == "no api key", reasons
    s.close()


def test_engine_without_query_syntax_is_never_dispatched():
    s = _store()
    _key(core, "zoomeye", "test-zoomeye-key")
    usable, skipped = mapdispatch.engines_for("domain", "zoomeye")
    assert usable == [], ("no domain syntax known -> must not be asked", usable)
    assert any("syntax" in x["reason"] for x in skipped), skipped
    s.close()


# ------------------------------------------------------------ isolation
def test_two_tasks_share_no_mapping_ledger():
    s = _store()
    qa = mapping.question("fofa", "domain", "mt-a.example.com", "q", task="A")
    qb = mapping.question("fofa", "domain", "mt-a.example.com", "q", task="B")
    mapping.record(s, qa, metered.ST_OK, rows=1)
    assert mapping.lookup(s, qb) is None, "a ledger row must not cross tasks"
    s.close()


# ---------------------------------------------------- rejected keys are skipped
def test_a_rejected_key_is_skipped_for_the_rest_of_the_task():
    """The operator's rule: no key OR a dead key -> skip, never retry.

    A provider that answers 403 is saying the credential is dead. Asking again
    burns time and (on metered plans) quota, so the engine is dropped from
    dispatch for the rest of the task and reported as a capability gap.
    """
    s = _store()
    fake = _Run([])
    real = core.run
    core.run = fake
    try:
        _key(core, "fofa", "test-fofa-key")
        _key(core, "quake", "test-quake-key")
        # fofa's key is refused
        def refuse_fofa(cmd, **kw):
            # a dispatch also polls a credit balance; only uncover has -e
            if "-e" not in cmd:
                return 0, "", ""
            eng = cmd[cmd.index("-e") + 1]
            if eng == "fofa":
                return 1, "", "401 unauthorized: invalid key"
            return 0, json.dumps({"host": "a.mt-a.example.com"}) + chr(10), ""
        core.run = refuse_fofa
        mapdispatch.ask_all(s, "RUNQ", "domain", ["mt-a.example.com"],
                            engines="fofa,quake")
        assert mapping.blocked_engines(s) == ["fofa"], mapping.blocked_engines(s)
        calls_before = len(fake.calls)
        # a SECOND question must not touch fofa again
        core.run = fake
        r = mapdispatch.ask_all(s, "RUNQ", "domain", ["second.example.com"],
                                engines="fofa,quake")
        engines_asked = [c["cmd"][c["cmd"].index("-e") + 1]
                         for c in fake.calls if "-e" in c["cmd"]]
        assert "fofa" not in engines_asked, (
            "a rejected key must not be retried", engines_asked)
        assert any(x["engine"] == "fofa" and "rejected" in x["reason"]
                   for x in r["skipped_engines"]), r["skipped_engines"]
        assert "quake" in engines_asked, engines_asked
    finally:
        core.run = real
        s.close()


def test_an_engine_without_a_key_is_skipped_not_failed():
    """No credential at all is a skip; the other engines still run."""
    s = _store()
    _key(core, "fofa", "test-fofa-key")
    _key(core, "quake", "")
    usable, skipped = mapdispatch.engines_for_task(s, "domain", "fofa,quake")
    assert usable == ["fofa"], usable
    assert {"engine": "quake", "reason": "no api key"} in skipped, skipped
    s.close()
