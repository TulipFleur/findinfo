"""Run the findinfo test suite (function-style tests): python -m tests

Supports BOTH bare unittest-style functions and pytest-style signatures
(monkeypatch / tmp_path fixtures) so mixed-generation test modules all run.
"""
import importlib
import inspect
import sys
import traceback
import unittest.mock as _mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

MODULES = [
    "tests.test_scope_and_tasks",
    "tests.test_provenance",
    "tests.test_stages_and_dns",
    "tests.test_jsleak",
    "tests.test_report_and_clean",
    "tests.test_jobs",
    "tests.test_run_flow",
    "tests.test_docs_commands",
    "tests.test_source_outcomes",
    "tests.test_cancel_outcome",
    "tests.test_selfcheck",
    "tests.test_entity_anchor",
    "tests.test_domain_guard",
    "tests.test_scale_regressions",
    "tests.test_crawl_scope",
    "tests.test_crawl_timeout",
    "tests.test_stream_deadline",
    "tests.test_thread_store",
    "tests.test_resume_after_failure",
    "tests.test_worker_e2e",
    "tests.test_worker_survives_launcher",
    "tests.test_p0_regressions",
    "tests.test_js_queue",
    "tests.test_job_reliability",
    "tests.test_outcome_and_evidence",
    "tests.test_coverage_states",
    "tests.test_docs_flow",
    "tests.test_integration_e2e",
    "tests.test_tool_resolution",
    "tests.test_tool_inventory",
    "tests.test_host_reap",
    "tests.test_env_selfcheck",
    "tests.test_zero_key_run",
    "tests.test_version_parsing",
    "tests.test_report_brief",
    "tests.test_brief_command",
    "tests.test_coverage_semantics",
    "tests.test_release_bundle",
    "tests.test_shipped_manifest",
    "tests.test_extract_scope_split",
    "tests.test_fake_ip_guard",
    "tests.test_js_property_chains",
    "tests.test_dns_wildcard_probe",
    "tests.test_asset_timestamps",
]


class _TmpPathFactory:
    """Minimal pytest tmp_path stand-in: a fresh temp dir per test."""

    def __init__(self, root: Path):
        self._root = root
        self._n = 0

    def __call__(self) -> Path:
        self._n += 1
        d = self._root / ("t%d" % self._n)
        d.mkdir(parents=True, exist_ok=True)
        return d


def _run_with_fixtures(fn, tmp_root: Path):
    """Invoke a test function, injecting the pytest fixtures it asks for."""
    params = list(inspect.signature(fn).parameters)
    if not params:
        fn()
        return
    import tempfile
    fixtures = []
    kwargs = {}
    for p in params:
        if p == "monkeypatch":
            mp = _mock._patch
            fx = _mock.patch  # lightweight: use a context-capable patcher bundle
            mp_obj = _MonkeyPatch()
            fixtures.append(mp_obj)
            kwargs[p] = mp_obj
        elif p == "tmp_path":
            kwargs[p] = _TmpPathFactory(tmp_root)()
        else:
            raise TypeError("unsupported fixture: %s (add to _run_with_fixtures)" % p)
    try:
        fn(**kwargs)
    finally:
        for f in fixtures:
            undo = getattr(f, "undo", None)
            if callable(undo):
                undo()


class _MonkeyPatch:
    """The subset of pytest's MonkeyPatch these tests use: setattr/setenv/undo."""

    def __init__(self):
        import os
        self._os = os
        self._undo = []

    def setattr(self, target, name, value=...):
        if value is ...:
            # monkeypatch.setattr("pkg.mod.attr", value) string form
            raise TypeError("string-form setattr not supported; use (obj, name, value)")
        old = getattr(target, name)
        self._undo.append((target, name, old))
        setattr(target, name, value)

    def setenv(self, name, value):
        old = self._os.environ.get(name)
        self._undo.append((self._os.environ, name, old, True))
        self._os.environ[name] = value

    def delattr(self, target, name):
        old = getattr(target, name)
        self._undo.append((target, name, old))
        delattr(target, name)

    def undo(self):
        import os
        while self._undo:
            entry = self._undo.pop()
            if len(entry) == 4:                     # env entry: value may be None
                target, name, old, _env = entry
                if old is None:
                    target.pop(name, None)
                else:
                    target[name] = old
            else:
                target, name, old = entry
                try:
                    setattr(target, name, old)
                except Exception:
                    pass


def main() -> int:
    import tempfile
    failed = []
    for name in MODULES:
        mod = importlib.import_module(name)
        fns = [(n, getattr(mod, n)) for n in dir(mod)
               if n.startswith("test_") and callable(getattr(mod, n))]
        for fname, fn in sorted(fns):
            with tempfile.TemporaryDirectory(prefix="fit-fx-") as td:
                try:
                    _run_with_fixtures(fn, Path(td))
                    print("PASS  %s:%s" % (name.split(".")[-1], fname))
                except Exception:
                    failed.append((name, fname))
                    print("FAIL  %s:%s" % (name.split(".")[-1], fname))
                    traceback.print_exc()
    print("-" * 60)
    print("%d failed, suite done" % len(failed))
    import tests.util
    tests.util.cleanup()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
