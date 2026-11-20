"""Batch F acceptance: billed-request ledger (T22-T27, T34).

Synthetic Meituan fixture; no provider, socket or credential is touched: the
tests hand the ledger observed outcomes directly.
"""

import json
import tempfile

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import metered

RUN = "20261120-210000-mt-a.example.com"


def _ledger():
    return metered.MeteredLedger(buffer=[])


def test_t22_one_append_per_request_not_per_row():
    led = _ledger()
    # one request returning 5000 rows = ONE ledger append
    assert led.record(RUN, "quake", metered.hash_input({"d": "mt-a.example.com"}),
                      status=metered.ST_OK, requested=1, returned=5000)
    assert led.totals(RUN)["requests"] == 1
    assert led.totals(RUN)["returned_rows"] == 5000
    # a genuine SECOND dispatch of the same query is a second row: the paid
    # call happened twice and must be visible (F08). Only an explicit replay
    # of the SAME log event is deduplicated.
    assert led.record(RUN, "quake", metered.hash_input({"d": "mt-a.example.com"}),
                      status=metered.ST_OK, requested=1, returned=5000) is True
    assert led.totals(RUN)["requests"] == 2
    # the SAME event logged twice (replay=True) is not a second charge
    assert led.record(RUN, "quake", metered.hash_input({"d": "mt-a.example.com"}),
                      status=metered.ST_OK, requested=1, returned=5000,
                      replay=True) is False
    assert led.totals(RUN)["requests"] == 2
    # a changed status IS a new record (retry after failure)
    assert led.record(RUN, "quake", metered.hash_input({"d": "mt-a.example.com"}),
                      status=metered.ST_FAILED, requested=1, returned=0,
                      error="timeout")
    assert led.totals(RUN)["requests"] == 3


def test_t23_status_vocabulary_is_typed():
    # raw outcome strings map to typed statuses, never re-guessed downstream
    assert metered.status_of("ok") == metered.ST_OK
    assert metered.status_of("", count=0) == metered.ST_EMPTY
    assert metered.status_of("", error="quota exceeded") == metered.ST_QUOTA
    assert metered.status_of("", rc=403) == metered.ST_AUTH
    assert metered.status_of("", rc=124) == metered.ST_FAILED
    assert metered.status_of("truncated") == metered.ST_TRUNCATED


def test_t24_quota_fields_recorded_and_summarised():
    led = _ledger()
    # fofa-gateway shape (remaining/maxQueries) normalises unchanged
    led.record(RUN, "fofa-gateway", "h1", status=metered.ST_OK,
              returned=120, quota={"remaining": 880, "maxQueries": 1000})
    assert led.quota_remaining("fofa-gateway") == 880
    # a fresher answer replaces the older ceiling
    led.record(RUN, "fofa-gateway", "h2", status=metered.ST_OK,
              returned=3, quota={"remaining": 797, "maxQueries": 1000})
    assert led.quota_remaining("fofa-gateway") == 797
    # an engine that never answered a quota field is UNKNOWN, not infinite
    led.record(RUN, "quake", "h3", status=metered.ST_OK, returned=5)
    assert led.quota_remaining("quake") is None


def test_t25_partial_then_full_counts_rows_and_status_once():
    led = _ledger()
    # a truncated page (provider cut at 100) then the completing page
    led.record(RUN, "hunter", "page1", status=metered.ST_TRUNCATED,
              requested=1, returned=100)
    led.record(RUN, "hunter", "page2", status=metered.ST_OK,
              requested=1, returned=100)
    tot = led.totals(RUN)
    assert tot["requests"] == 2 and tot["returned_rows"] == 200
    by = led.by_engine(RUN)["hunter"]
    assert by["statuses"][metered.ST_TRUNCATED] == 1
    assert by["statuses"][metered.ST_OK] == 1


def test_t26_auth_failure_is_not_retried_blind():
    led = _ledger()
    led.record(RUN, "shodan", "k1", status=metered.ST_AUTH, rc=403,
              error="unauthorized")
    # the engine is blocked: further spend is known-useless
    assert "shodan" in led.blocked_engines(RUN)
    # a transport failure is NOT blocked -- a retry may succeed
    led.record(RUN, "censys", "k2", status=metered.ST_FAILED, rc=124)
    assert "censys" not in led.blocked_engines(RUN)
    # quota-blocked engines are listed too
    led.record(RUN, "fofa-gateway", "k3", status=metered.ST_QUOTA,
              error="quota limit reached")
    assert "fofa-gateway" in led.blocked_engines(RUN)


def test_t27_ledger_file_is_jsonl_and_reloadable():
    with tempfile.TemporaryDirectory(prefix="fi-meter-") as td:
        p = td + "/metered.jsonl"
        led = metered.MeteredLedger(path=p)
        led.record(RUN, "quake", "h1", status=metered.ST_OK, returned=42)
        led.record(RUN, "fofa-gateway", "h2", status=metered.ST_QUOTA,
                  quota={"remaining": 0, "maxQueries": 1000})
        rows = [json.loads(l) for l in open(p, encoding="utf-8")]
        assert len(rows) == 2
        assert rows[0]["engine"] == "quake" and rows[0]["returned"] == 42
        assert rows[1]["status"] == metered.ST_QUOTA
        assert rows[1]["quota"]["remaining"] == 0
        # reload: a second ledger over the same file keeps history
        led2 = metered.MeteredLedger(path=p)
        led2.record(RUN, "quake", "h9", status=metered.ST_OK, returned=1)
        rows2 = [json.loads(l) for l in open(p, encoding="utf-8")]
        assert len(rows2) == 3


def test_t34_failed_request_is_cost_incurred():
    led = _ledger()
    # a request that died: recorded with zero rows -- spend with no data,
    # never silently absent from the spend summary
    assert led.record(RUN, "quake", "h-fail", status=metered.ST_FAILED,
                      requested=1, returned=0, error="connection reset")
    tot = led.totals(RUN)
    assert tot["requests"] == 1
    assert tot["by_status"][metered.ST_FAILED] == 1
    assert tot["returned_rows"] == 0
