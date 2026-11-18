"""Run the findinfo test suite (function-style tests): python -m tests"""
import importlib
import sys
import traceback
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
]


def main() -> int:
    failed = []
    for name in MODULES:
        mod = importlib.import_module(name)
        fns = [(n, getattr(mod, n)) for n in dir(mod)
               if n.startswith("test_") and callable(getattr(mod, n))]
        for fname, fn in fns:
            try:
                fn()
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
