"""findinfo.py is the CLI; the run pipeline lives in lib/pipeline.py.

The CLI re-exports the pipeline's names so `findinfo.<name>` keeps meaning the
SAME object the run executes: a second copy left in findinfo.py would let a
caller (or a test patch) talk to code the run never calls.
"""
import re

import tests.util as util
from tests.util import fresh_core, fresh_tools, import_findinfo

REEXPORTED = ("ENGAGEMENT", "_run_pipeline", "_stage", "_write_status",
              "_plan_stages", "_round_plan", "_active_enabled", "_attach",
              "_adopt_membership", "_not_run_stages", "_coverage_unavailable",
              "_fold_runtime_unavailable", "_subs_stage_inputs", "_input_hash")


def test_cli_reexports_the_pipeline_objects_themselves():
    core = fresh_core()
    fresh_tools(core)
    fi = import_findinfo()
    from lib import pipeline
    assert fi.pipeline is pipeline
    for name in REEXPORTED:
        assert getattr(fi, name) is getattr(pipeline, name), name


def test_pipeline_reaches_core_through_the_module_only():
    """lib.core resolves HOME/DB at import time and the tests reload it in
    place: a value bound out of core when the pipeline is imported would keep
    pointing at the previous home."""
    src = (util.ROOT / "lib" / "pipeline.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*from\s+(\.|lib\.)core\s+import", src, re.M)
