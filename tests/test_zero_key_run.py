"""Zero-key behaviour: a missing API key is a coverage gap, not a failure.

README promises "不配 key 也能跑 80%", but a fresh install used to end the very
first passive run as `partial/stage_failed` with
`coverage.failed_stages = [{"stage": "subs", ...}]`, which sends an agent into
a --resume loop that retrying can never fix: the key is still missing.

These tests pin the three rules that make the promise true:
  1. uncover is never handed an engine without a key
  2. a source we never configured is `unavailable`, and does not outrank a
     real success when outcomes are merged
  3. once a key appears, the stage re-runs instead of hitting the old checkpoint
"""
import contextlib
import os
import unittest.mock as mock

import tests.util  # noqa: F401
from tests.util import fresh_core, fresh_tools


@contextlib.contextmanager
def _keyless(core, extra=None):
    """Make the whole process look keyless (no engine credentials at all)."""
    patches = [
        mock.patch.object(core, "api_key", lambda n: ""),
        mock.patch.object(core, "api_base", lambda n: ""),
    ]
    if extra:
        patches.extend(extra)
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        yield


def test_split_engines_separates_configured_from_missing():
    core = fresh_core()
    with mock.patch.object(core, "api_key", lambda n: ""), \
            mock.patch.object(core, "api_base", lambda n: ""):
        usable, missing = core.split_engines("fofa,quake,hunter")
    assert usable == [], usable
    assert missing == ["fofa", "quake", "hunter"], missing


def test_split_engines_keeps_configured_ones():
    core = fresh_core()
    with mock.patch.object(core, "api_key",
                           lambda n: "k" if n == "quake" else ""), \
            mock.patch.object(core, "api_base", lambda n: ""):
        usable, missing = core.split_engines("fofa,quake")
    assert usable == ["quake"], usable
    assert missing == ["fofa"], missing


def test_uncover_is_not_run_without_any_key():
    """No key: the passive stage asks nothing, and mapping says why.

    subs is keyless now, so it never produces an `uncover` source entry; the
    "no api key" reason belongs to the mapping dispatch's skipped-engine list.
    """
    from lib import mapdispatch
    core = fresh_core()
    core.CFG.setdefault("apis", {}).setdefault("fofa", {})["key"] = ""
    core.CFG["apis"]["fofa"]["base"] = ""
    core.CFG.setdefault("apis", {}).setdefault("quake", {})["key"] = ""
    usable, skipped = mapdispatch.engines_for("domain", "fofa,quake")
    assert usable == [], usable
    assert all(x["reason"] == "no api key" for x in skipped), skipped
def test_subs_with_no_key_reports_empty_not_failed():
    """subfinder succeeded with nothing; uncover was never asked -> not failed."""
    core = fresh_core()
    tools = fresh_tools(core)
    with _keyless(core, [
        mock.patch.object(core, "has_tool",
                          lambda n: n in ("subfinder", "uncover")),
        mock.patch.object(core, "run", lambda *a, **kw: (0, "", "")),
    ]):
        out = tools.t_subs(core.Store(), "example.com")
    assert out["outcome"] in (core.OUTCOME_EMPTY, core.OUTCOME_OK), out
    assert out["ok"] is True, out


def test_keyed_engine_failure_is_still_failed():
    """A configured engine that really dies must not be washed into a gap."""
    core = fresh_core()
    tools = fresh_tools(core)
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(
            core, "has_tool", lambda n: n in ("subfinder", "uncover")))
        stack.enter_context(mock.patch.object(
            core, "api_key", lambda n: "k" if n == "quake" else ""))
        stack.enter_context(mock.patch.object(core, "api_base", lambda n: ""))
        stack.enter_context(mock.patch.object(
            core, "run", lambda *a, **kw: (1, "", "boom")))
        out = tools.t_subs(core.Store(), "example.com")
    assert out["outcome"] == core.OUTCOME_FAILED, out
    assert out["ok"] is False, out


def test_unavailable_does_not_outrank_a_success_when_merging():
    core = fresh_core()
    c = core.combine_outcome
    assert c(core.OUTCOME_OK, core.OUTCOME_UNAVAILABLE) == core.OUTCOME_OK
    assert c(core.OUTCOME_EMPTY, core.OUTCOME_UNAVAILABLE) == core.OUTCOME_EMPTY
    assert c(core.OUTCOME_FAILED, core.OUTCOME_UNAVAILABLE) == core.OUTCOME_FAILED
    assert c(core.OUTCOME_UNAVAILABLE) == core.OUTCOME_UNAVAILABLE


def test_subs_checkpoint_hash_includes_the_usable_engine_set():
    """Adding a key must re-run subs instead of hitting the keyless checkpoint."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "findinfo.py"), encoding="utf-8").read()
    assert "usable_engines" in text, (
        "subs checkpoint does not hash the usable engine set: adding a key would "
        "hit a stale checkpoint")