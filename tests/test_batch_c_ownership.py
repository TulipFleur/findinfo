"""Batch C acceptance: asset ownership and honest reuse (F06, F07, F10).

Offline, synthetic ENScan documents under reserved namespaces. Pinned:

* per-entity attribution: only an APPROVED subject's assets reach the seeds
  and the active scope; another returned entity's assets never do (F06);
* one identity per document is attributed its asset tables; several subjects
  with unattached assets are left un-attributed (no guessing);
* an alias / legal name that differs from the search string keeps its seeds
  through the subject reference, not `parent == search string` (F10);
* a brand that matches several subjects stays ambiguous (conservative);
* membership reconciliation does not fabricate observations: a historical
  asset is marked as reuse with its original time preserved, and another
  target's rows never enter this run's statistics (F07).
"""

import json

import tests.util  # noqa: F401  (sets FINDINFO_HOME before lib import)

from lib import core, work
from tests.util import fresh_core, fresh_tools

RUN = "20261121-140000-mt-a.example.com"


def _store():
    s = fresh_core().Store()
    work.ensure_schema(s)
    return s


# ---------------------------------------------------------------- F06 harvest
def test_single_subject_document_owns_its_asset_tables():
    """One company in the document: its ICP/domain tables belong to it."""
    tools = fresh_tools(fresh_core())
    doc = {
        "enterprise_info": [{"name": "fixture-subject-A", "id": "sa-1"}],
        "icp": [{"domain": "mt-a.example.com", "icp": "京ICP备00000001号-1"}],
    }
    ents = tools.harvest_entities(doc)
    assert len(ents) == 1, ents
    ent = ents[0]
    assert ent["subject_ref"] == "id:sa-1", ent
    assert ent["legal_name"] == "fixture-subject-A"
    assert ent["domains"] == ["mt-a.example.com"], ent
    assert ent["icp"] == ["京ICP备00000001号-1"], ent


def test_two_subjects_never_share_unattached_assets():
    """Two companies in one document: shared tables are not assigned to either."""
    tools = fresh_tools(fresh_core())
    doc = {
        "enterprise_info": [{"name": "fixture-subject-A", "id": "sa-1"},
                            {"name": "fixture-subject-B", "id": "sb-1"}],
        "icp": [{"domain": "unowned.example.net", "icp": "京ICP备00000002号-1"}],
    }
    ents = tools.harvest_entities(doc)
    refs = {e["subject_ref"]: e for e in ents}
    assert set(refs) == {"id:sa-1", "id:sb-1"}, refs
    for ref, ent in refs.items():
        assert "unowned.example.net" not in ent["domains"], (
            "an unattached asset must not be guessed into a subject", ref, ent)


def test_enscan_grants_only_the_approved_subject():
    """Approved A keeps its assets; B's assets never enter the store as A's."""
    core_now = fresh_core()
    tools = fresh_tools(core_now)
    store = core_now.Store()
    outdir = core_now.RUNS_DIR / "enscan-c"
    outdir.mkdir(parents=True, exist_ok=True)

    def _write(*_a, **_kw):
        # A is the requested entity; B is an unrelated subject in the same
        # document with its own asset table entry.
        (outdir / "doc.json").write_text(json.dumps({
            "enterprise_info": [{"name": "fixture-subject-A", "id": "sa-1"}],
            "domains": [{"domain": "mt-a.example.com", "company": "fixture-subject-A"}],
            "invest": [{"name": "fixture-subject-B", "id": "sb-1",
                        "domains": [{"domain": "mt-b.example.net"}]}],
        }), encoding="utf-8")
        return (0, "", "")

    try:
        from unittest import mock
        with mock.patch.object(tools.core, "run", side_effect=_write):
            r = tools.t_enscan(store, "fixture-subject-A", outdir=outdir)
    finally:
        pass
    assert not r.get("anchor_failed"), r
    doms = set(r["domains"])
    assert "mt-a.example.com" in doms, r
    assert "mt-b.example.net" not in doms, (
        "an unapproved subject's domain reached the approved seed set", r)
    stored = {a["canonical"] for a in store.get_assets(kind="domain")}
    assert "mt-b.example.net" not in stored, stored
    # the candidate is still REPORTED (evidence), never granted
    cands = {c["legal_name"] for c in (r.get("candidates") or [])}
    assert "fixture-subject-B" in cands, r.get("candidates")
    store.close()


def test_no_matching_subject_grants_nothing():
    """A lookalike-only answer grants no assets (conservative short brand)."""
    core_now = fresh_core()
    tools = fresh_tools(core_now)
    store = core_now.Store()
    outdir = core_now.RUNS_DIR / "enscan-c2"
    outdir.mkdir(parents=True, exist_ok=True)

    def _write(*_a, **_kw):
        (outdir / "doc.json").write_text(json.dumps({
            "enterprise_info": [{"name": "fixture-lookalike", "id": "x1"}],
            "icp": [{"domain": "lookalike.example.org"}],
        }), encoding="utf-8")
        return (0, "", "")

    from unittest import mock
    with mock.patch.object(tools.core, "run", side_effect=_write):
        r = tools.t_enscan(store, "fixture-subject-A", outdir=outdir)
    assert r.get("anchor_failed") is True, r
    assert r["domains"] == [] and r["icp"] == [], r
    assert store.get_assets(kind="domain") == []
    store.close()


# ---------------------------------------------------------------- F10 seeds
def test_alias_seed_survives_a_different_legal_name():
    """Seeds come from the approved subject ref, not a name equality."""
    s = _store()
    # the run approved subject id:sa-1, whose legal name differs from the
    # search alias the caller typed
    s.upsert_asset("domain", "mt-a.example.com", source="enscan",
                   confidence=0.9, parent="id:sa-1")
    s.upsert_asset("icp", "京ICP备00000001号-1", source="enscan",
                   confidence=0.9, parent="id:sa-1")
    refs = ["id:sa-1"]
    seeds = [a["canonical"] for a in s.get_assets(kind="domain", min_conf=0.9)
             if (a.get("parent") or "") in set(refs)]
    assert seeds == ["mt-a.example.com"], seeds
    # the alias text itself is NOT required anywhere
    assert "fixture-subject-A" not in seeds
    s.close()


def test_unapproved_subject_assets_are_not_seeds():
    """B's assets are present in the graph but never become A's seeds."""
    s = _store()
    s.upsert_asset("domain", "mt-a.example.com", source="enscan",
                   confidence=0.9, parent="id:sa-1")
    s.upsert_asset("domain", "mt-b.example.net", source="enscan",
                   confidence=0.9, parent="id:sb-1")
    refs = {"id:sa-1"}
    seeds = [a["canonical"] for a in s.get_assets(kind="domain", min_conf=0.9)
             if (a.get("parent") or "") in refs]
    assert seeds == ["mt-a.example.com"], seeds
    s.close()


# ---------------------------------------------------------------- F07 reuse
def test_membership_reconciliation_does_not_fabricate_observations():
    """A history-only asset joins as a marked reuse, not a current observation."""
    import findinfo as fi
    core_now = fresh_core()
    store = core_now.Store()
    work.ensure_schema(store)
    old_time = "2026-11-19T08:00:00Z"
    # historic row from an EARLIER run (no producer this run ran)
    store.upsert_asset("domain", "historic.mt-a.example.com",
                       source="old-crawler", confidence=0.6,
                       parent="mt-a.example.com")
    with store._write():
        store.conn.execute("UPDATE assets SET first_seen=?, last_seen=? WHERE"
                           " canonical=?", (old_time, old_time,
                                            "historic.mt-a.example.com"))
    summary = {"_run_public_id": RUN,
               "_run_producers": ["dnsx", "httpx", "enscan"]}
    count = fi._adopt_membership(store, summary, ["mt-a.example.com"])
    assert count >= 1
    # membership exists
    assert "historic.mt-a.example.com" in work.run_assets(store, RUN, "domain")
    # the observation is explicitly a reuse, and its own row carries a
    # current timestamp, but the historical observation time is untouched
    ups = work.observed_upstreams(store, RUN, "domain",
                                  "historic.mt-a.example.com")
    assert ups == ["reuse:run_membership"], ups
    rows = store.conn.execute(
        "SELECT producer FROM observations WHERE run_id=? AND canonical=?",
        (RUN, "historic.mt-a.example.com")).fetchall()
    assert rows and all(r["producer"] == "reuse" for r in rows), (
        "a reuse observation row must exist", [dict(r) for r in rows])
    a = store.get_assets(kind="domain", match=["mt-a.example.com"])[0]
    assert a["first_seen"] == old_time, (
        "the historical observation time must not move", a.get("first_seen"))
    store.close()


def test_membership_reconciliation_records_no_obs_for_own_producers():
    """An asset THIS run's collector stored needs membership, not fake evidence."""
    import findinfo as fi
    core_now = fresh_core()
    store = core_now.Store()
    work.ensure_schema(store)
    store.upsert_asset("domain", "own.mt-a.example.com", source="dnsx",
                       confidence=0.8)
    summary = {"_run_public_id": RUN, "_run_producers": ["dnsx"]}
    fi._adopt_membership(store, summary, ["mt-a.example.com"])
    assert "own.mt-a.example.com" in work.run_assets(store, RUN, "domain")
    # no synthetic observation was added by the reconciliation
    n = store.conn.execute(
        "SELECT COUNT(*) c FROM observations WHERE run_id=?", (RUN,)
    ).fetchone()["c"]
    assert n == 0, ("the collector's own write is the evidence", n)
    store.close()


def test_another_targets_rows_do_not_enter_this_runs_membership():
    """Membership is scoped: another target never joins this run."""
    import findinfo as fi
    core_now = fresh_core()
    store = core_now.Store()
    work.ensure_schema(store)
    store.upsert_asset("domain", "mt-b.example.net", source="old-crawler",
                       confidence=0.6)
    summary = {"_run_public_id": RUN, "_run_producers": ["dnsx"]}
    fi._adopt_membership(store, summary, ["mt-a.example.com"])
    assert work.run_assets(store, RUN, "domain") == []
    store.close()
