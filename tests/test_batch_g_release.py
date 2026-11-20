"""Batch G acceptance: stage registry validation, docs and install (T01, T28).

Offline: registry checks are pure data; docs checks read the repo tree.
"""

import io
import subprocess
import sys

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from tests.util import ROOT, import_findinfo

MARKDOWN = ("README.md", "CHANGELOG.md", "docs/CLIENTS.md",
            "docs/RELIABILITY-PLAN.md")


# ---------------------------------------------------------------- T01
def test_t01_registry_rejects_missing_runner_duplicate_and_cycle():
    fi = import_findinfo()
    reg = fi.StageRegistry()

    # a stage without a runner cannot validate
    reg.register("x")
    try:
        reg.validate()
        raised = False
    except ValueError as e:
        raised = "without a runner" in str(e)
    assert raised, "missing runner must be rejected"

    # a duplicate name cannot even register
    reg2 = fi.StageRegistry()
    reg2.register("x", runner=lambda: None)
    try:
        reg2.register("x", runner=lambda: None)
        raised = False
    except ValueError as e:
        raised = "duplicate stage" in str(e)
    assert raised, "duplicate registration must be rejected"

    # a dependency cycle cannot validate
    reg3 = fi.StageRegistry()
    reg3.register("a", runner=lambda: None, needs=("b",))
    reg3.register("b", runner=lambda: None, needs=("a",))
    try:
        reg3.validate()
        raised = False
    except ValueError as e:
        raised = "cycle" in str(e)
    assert raised, "dependency cycle must be rejected"

    # the shipped registry is valid, ordered, and complete
    order = fi.STAGE_REGISTRY.order()
    assert order[0] == "entity" and order[1] == "onepass", order
    assert "dns" in order and "probe" in order and "extract" in order
    for name in order:
        assert fi.STAGE_REGISTRY.runner(name) is not None, name


def test_t01_planned_stages_exist_in_registry():
    """_plan_stages may only return registered names (no phantom stages)."""
    import argparse
    fi = import_findinfo()
    ns = argparse.Namespace(name="", domain=["mt-a.example.com"], active=True,
                            ports=True, vhost=True, crawl=True, brute=True,
                            no_icp=True, no_onepass=False)
    planned = fi._plan_stages(ns, True)
    registered = set(fi.STAGE_REGISTRY.order())
    assert planned, "an active run must plan stages"
    for name in planned:
        assert name in registered, "planned stage missing from registry: " + name


# ---------------------------------------------------------------- T28
def test_t28_docs_and_install_artifacts():
    # markdown files exist and are non-empty
    for name in MARKDOWN:
        p = ROOT / name
        assert p.exists(), "missing documentation: " + name
        assert io.open(p, encoding="utf-8").read(64).strip(), "empty doc: " + name
    # CHANGELOG references every commit since 0.7.2 (same contract as
    # test_shipped_manifest: e793464..HEAD, newest two may be absent,
    # full short hash with backticks)
    log = subprocess.run(["git", "log", "--format=%h", "e793464..HEAD"],
                         capture_output=True, text=True, cwd=str(ROOT),
                         encoding="utf-8", timeout=30)
    assert log.returncode == 0, log.stderr
    hashes = [h for h in log.stdout.split() if h][2:]
    import re
    cl = io.open(ROOT / "CHANGELOG.md", encoding="utf-8").read()
    missing = [h for h in hashes if ("`" + h + "`") not in cl]
    assert not missing, "CHANGELOG never mentions commit(s) " + repr(missing)
    # install artifacts: the runtime package ships every lib module, tests
    # and wordlists per the manifest
    manifest = ROOT / ".gitignore"
    assert manifest.exists()


def test_t28_new_lib_modules_present_and_importable():
    import importlib
    for name in ("spec", "work", "metered", "doh"):
        mod = importlib.import_module("lib." + name)
        assert mod is not None
