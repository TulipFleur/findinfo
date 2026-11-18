"""Regression: streaming collectors must not write to SQLite off-thread.

Live finding: `dns --from-store` logged
  stream line skipped: ProgrammingError(SQLite objects created in a thread can
  only be used in that same thread ...)
for EVERY resolved host of a 7373-host scope. The stage still reported success,
so the run looked complete while storing zero resolved domains -- silent data
loss. Cause: run_stream delivers lines from a reader thread and the handlers
called store.upsert_* directly. Handlers now only parse; the caller's thread
writes.
"""
import json
import sqlite3
import threading

import tests.util  # noqa: F401
from tests.util import fresh_core


def test_store_write_from_reader_thread_would_raise():
    """Shows the trap this module guards against (so the fix is not folklore)."""
    core = fresh_core()
    store = core.Store()
    box = {}

    def worker():
        try:
            store.upsert_asset("domain", "off-thread.example.com", source="t")
        except Exception as exc:          # pragma: no cover - platform dependent
            box["err"] = exc
    t = threading.Thread(target=worker)
    t.start()
    t.join()
    store.close()
    err = box.get("err")
    if err is not None:
        assert "thread" in str(err).lower(), err


def test_dns_handler_parses_off_thread_and_stores_on_caller_thread():
    """t_dns must give the store every resolved host even though it streams."""
    core = fresh_core()
    from lib import tools

    names = ["a%d.example.com" % i for i in range(50)]
    lines = [json.dumps({"host": n, "a": ["10.0.0.%d" % (i + 1)]})
             for i, n in enumerate(names)]

    def fake_run_stream(cmd, on_line, timeout=0, **kw):
        # the real run_stream calls on_line from a helper thread
        def feed():
            for ln in lines:
                on_line(ln)
        th = threading.Thread(target=feed)
        th.start()
        th.join()
        return 0, len(lines), ""

    orig_stream = core.run_stream
    orig_has = core.has_tool
    orig_run = core.run
    core.run_stream = fake_run_stream
    core.has_tool = lambda name: False       # skip the wildcard probe
    core.run = lambda *a, **k: (0, "", "")
    store = core.Store()
    try:
        res = tools.t_dns(store, names)
        stored = store.get_assets(kind="domain", min_conf=0.7)
    finally:
        core.run_stream = orig_stream
        core.has_tool = orig_has
        core.run = orig_run
        store.close()
    got = {a["canonical"] for a in stored} & set(names)
    assert len(got) == len(names), (
        "the streaming collector stored %d/%d resolved hosts: " % (len(got), len(names)) +
        "a reader-thread write to SQLite fails silently")
    assert res["count"] == len(names), res


def test_crawl_handler_parses_off_thread_and_stores_on_caller_thread():
    """t_crawl must persist every in-scope URL it streams (P18, second site)."""
    core = fresh_core()
    from lib import tools

    urls = ["https://h%d.example.com/a%d.png" % (i % 5, i) for i in range(40)]
    lines = [json.dumps({"request": {"endpoint": u, "method": "GET"}})
             for u in urls]
    lines.append(json.dumps({"request": {"endpoint":
                                   "https://out.example.org/x", "method": "GET"}}))

    def fake_run_stream(cmd, on_line, timeout=0, **kw):
        def feed():
            for ln in lines:
                on_line(ln)
        th = threading.Thread(target=feed)
        th.start()
        th.join()
        return 0, len(lines), ""

    orig = core.run_stream
    core.run_stream = fake_run_stream
    store = core.Store()
    try:
        res = tools.t_crawl(store, ["https://a.example.com/"], depth=1,
                            scope_domains=["example.com"])
        stored = [a["canonical"] for a in store.get_assets(kind="url", min_conf=0.0)]
    finally:
        core.run_stream = orig
        store.close()
    got = {u for u in stored if "example.com" in u}
    assert len(got) == len(urls), (
        "t_crawl stored %d/%d streamed URLs: a reader-thread write to SQLite " % (
            len(got), len(urls)) + "fails silently")
    assert res["count"] == len(urls), res
    assert res["dropped_out_of_scope"] == 1, res
