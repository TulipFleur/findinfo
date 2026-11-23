"""A provider's rate limit is a wait, not a lost question.

The FOFA relay used in a real run answers "请求过于频繁，当前限额 10 次/分钟"
when asked faster than ten questions a minute. That answer was classified as
a failure; the task ledger reuses every recorded question, so the seeds that
hit the limit were never asked again unless the operator knew to --remap.
Everything here is faked: no socket, no binary, no real sleep.
"""
from unittest import mock

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)
from lib import mapdispatch, mapping, metered
from tests.util import fresh_core

RATE_ZH = "请求过于频繁，当前限额 10 次/分钟"


def _store():
    s = fresh_core().Store()
    mapping.ensure_schema(s)
    return s


class _Gateway:
    """core.fofa_query stand-in: answers from a script, records each call."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.sizes = []

    def __call__(self, query, fields="", size=100, page=1, timeout=60):
        self.sizes.append(size)
        if len(self.answers) > 1:
            return self.answers.pop(0)
        return self.answers[0]


OK = {"ok": True, "total": 1, "count": 1,
      "results": [{"host": "a.example-go.com", "ip": "", "domain": "example-go.com",
                   "link": "", "title": ""}]}
LIMITED = {"ok": False, "error": RATE_ZH, "results": []}


def _ask(store, gateway, waits, throttle=lambda name: None):
    with mock.patch.object(mapdispatch, "_gateway_available", lambda e: True), \
            mock.patch.object(mapdispatch.core, "fofa_query", gateway), \
            mock.patch.object(mapdispatch.core, "throttle", throttle), \
            mock.patch.object(mapdispatch.core, "mapping_wait", lambda: None), \
            mock.patch.object(mapdispatch, "_rate_wait", waits.append):
        return mapdispatch.ask(store, "run-1", "fofa", "domain", "example-go.com")


def test_a_rate_limit_answer_has_its_own_status():
    assert metered.status_of("", rc=1, error=RATE_ZH) == metered.ST_RATE
    assert metered.status_of("", rc=1, error="HTTP 429 Too Many Requests") == metered.ST_RATE
    assert metered.status_of("", rc=1, error="rate limit exceeded") == metered.ST_RATE
    # neither a spent quota nor an oversized request is a rate limit
    assert metered.status_of("", rc=1, error="quota exhausted") == metered.ST_QUOTA
    assert metered.status_of("", rc=1, error="超过最大值2000") == metered.ST_FAILED


def test_a_rate_limited_question_waits_once_and_asks_again():
    store = _store()
    gw = _Gateway(LIMITED, OK)
    waits = []
    r = _ask(store, gw, waits)
    store.close()
    assert r["status"] == metered.ST_OK, r
    assert len(gw.sizes) == 2 and len(waits) == 1, (gw.sizes, waits)
    assert ("domain", "example-go.com") in r["results"] or r["rows"] == 1, r


def test_a_question_still_rate_limited_is_asked_again_next_run():
    store = _store()
    gw = _Gateway(LIMITED)
    waits = []
    first = _ask(store, gw, waits)
    assert first["status"] == metered.ST_RATE, first
    asked = len(gw.sizes)
    second = _ask(store, gw, waits)
    store.close()
    # not "already asked in this task": a rate limit answers nothing
    assert second["reused"] is False, second
    assert len(gw.sizes) > asked, gw.sizes


def test_the_relay_is_paced_and_never_asked_past_its_row_ceiling():
    core = fresh_core()
    core.CFG.setdefault("limits", {})["mapping_rows_fofa"] = 10000
    store = core.Store()
    mapping.ensure_schema(store)
    gw = _Gateway(OK)
    names = []
    _ask(store, gw, [], throttle=names.append)
    store.close()
    assert gw.sizes and max(gw.sizes) <= 2000, gw.sizes
    assert "fofa-gateway" in names, names
