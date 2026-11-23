"""A dead CT upstream costs a couple of attempts, not an hour.

Real run: crt.sh and CertSpotter were unreachable. With --tool-timeout 0 each
curl got `--max-time 0` (no limit) while the process was killed after 0 + 15 s,
so every slow-but-alive answer was lost too; and each seed retried both
upstreams three times, so 24 seeds took about 70 minutes before the stage
could report the gap. Nothing here touches the network.
"""
from types import SimpleNamespace
from unittest import mock

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)
from tests.util import fresh_core, fresh_tools


def test_a_zero_timeout_means_the_default_not_a_15_second_kill():
    core = fresh_core()
    seen = {}

    def _run(cmd, timeout=0, **kw):
        seen["cmd"] = list(cmd)
        seen["timeout"] = timeout
        return (0, "{}", "")

    with mock.patch.object(core, "run", _run):
        core.curl(["https://ct.example.org/"], timeout=0)
    cmd = seen["cmd"]
    max_time = int(cmd[cmd.index("--max-time") + 1])
    assert max_time >= 30, cmd
    assert seen["timeout"] > max_time, seen      # the process outlives one transfer
    assert "--connect-timeout" in cmd, cmd       # a black-holed host fails fast


def test_the_certs_stage_stops_asking_an_upstream_that_keeps_failing():
    core = fresh_core()
    tools = fresh_tools(core)
    from lib import pipeline
    asked = []

    def _fetch(fn, url, **kw):
        asked.append(url.split("/")[2])
        return None

    store = core.Store()
    try:
        rd = core.new_run_dir("certs-breaker")
        summary = {"stages": [], "_run_public_id": rd.name, "attempt": 1}
        seeds = ["s%d.example-go.com" % i for i in range(5)]
        ctx = pipeline.RunContext(
            args=SimpleNamespace(), store=store, run_id=None, run_dir=rd,
            summary=summary, active=False, attempt=1, target_label="t",
            planned=["certs"], ledger=None, rounds=1, time_budget=0.0,
            tool_timeout=0, max_seed=0, t_start=0.0, seeds=seeds)
        with mock.patch.object(tools.core, "fetch_with_retry", _fetch), \
                mock.patch.object(tools.core, "throttle", lambda name: None):
            pipeline._stage_certs(ctx)
    finally:
        store.close()
    # two seeds in a row failed on an upstream: the rest of the stage skips it
    assert asked.count("crt.sh") == 2, asked
    assert asked.count("api.certspotter.com") == 2, asked
    entry = summary["stages"][-1]
    # still a visible, retryable gap that names every seed it did not cover
    assert entry["stage"] == "certs" and entry.get("failed") is True, entry
    assert "s4.example-go.com" in entry.get("error", ""), entry
