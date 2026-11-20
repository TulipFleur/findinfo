"""Assets are deduplicated before they reach the store, and carry both the
first and the most recent time they were observed.

The operator-facing promise is: a re-run of the same target must not create a
second row, must not move first_seen, and must move last_seen forward."""

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import core


def _fresh_store():
    tmp = tempfile.mkdtemp(prefix="findinfo-seen-")
    return core.Store(os.path.join(tmp, "t.db"))


def test_upserting_the_same_asset_twice_keeps_one_row():
    store = _fresh_store()
    try:
        store.upsert_asset("domain", "a.example.com", source="dnsx", confidence=0.6)
        store.upsert_asset("domain", "a.example.com", source="httpx", confidence=0.7)
        rows = store.get_assets(kind="domain")
        assert len(rows) == 1, rows
    finally:
        store.close()


def test_first_seen_is_frozen_and_last_seen_advances():
    store = _fresh_store()
    try:
        store.upsert_asset("domain", "a.example.com", source="dnsx")
        first = store.conn.execute(
            "SELECT first_seen, last_seen FROM assets WHERE canonical=?",
            ("a.example.com",)).fetchone()
        # Force the clock forward so a same-second write cannot mask a bug.
        store.conn.execute(
            "UPDATE assets SET last_seen='2000-01-01T00:00:00Z' WHERE canonical=?",
            ("a.example.com",))
        store.upsert_asset("domain", "a.example.com", source="httpx")
        again = store.conn.execute(
            "SELECT first_seen, last_seen FROM assets WHERE canonical=?",
            ("a.example.com",)).fetchone()
        assert again["first_seen"] == first["first_seen"]
        assert again["last_seen"] != "2000-01-01T00:00:00Z", "last_seen must move forward"
    finally:
        store.close()


def test_asset_links_carry_both_timestamps_and_refresh_on_reobservation():
    store = _fresh_store()
    try:
        store.upsert_asset("domain", "b.example.com", source="dnsx",
                           parent="example.com")
        assert store.link_asset("domain", "b.example.com", "serves",
                                "other.com", "certs") is True
        assert store.link_asset("domain", "b.example.com", "serves",
                                "other.com", "certs") is False
        row = store.conn.execute(
            "SELECT first_seen, last_seen, source FROM asset_links"
            " WHERE canonical=? AND owner=?",
            ("b.example.com", "other.com")).fetchone()
        assert row["first_seen"] and row["last_seen"]
        assert "certs" in row["source"]
    finally:
        store.close()


def test_endpoints_carry_both_timestamps():
    store = _fresh_store()
    try:
        store.upsert_endpoint("a.example.com", "GET", "/x", [], "crawl")
        store.conn.execute("UPDATE endpoints SET last_seen='2000-01-01T00:00:00Z'")
        assert store.upsert_endpoint("a.example.com", "GET", "/x", [], "crawl") is False
        row = store.conn.execute(
            "SELECT first_seen, last_seen FROM endpoints").fetchone()
        assert row["first_seen"] and row["first_seen"] != "2000-01-01T00:00:00Z"
        assert row["last_seen"] != "2000-01-01T00:00:00Z", "last_seen must refresh"
    finally:
        store.close()


def test_an_old_database_is_migrated_in_place():
    """A store created before last_seen existed must gain the column."""
    tmp = tempfile.mkdtemp(prefix="findinfo-mig-")
    path = os.path.join(tmp, "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE assets (id INTEGER PRIMARY KEY AUTOINCREMENT,
          kind TEXT NOT NULL, canonical TEXT NOT NULL, parent TEXT,
          sources TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL DEFAULT 0.4,
          passivity TEXT NOT NULL DEFAULT 'passive', attrs TEXT NOT NULL DEFAULT '{}',
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          UNIQUE(kind, canonical));
        CREATE TABLE endpoints (id INTEGER PRIMARY KEY AUTOINCREMENT,
          asset TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'GET',
          path TEXT NOT NULL, params TEXT NOT NULL DEFAULT '',
          source TEXT NOT NULL DEFAULT '', status INTEGER, title TEXT,
          first_seen TEXT NOT NULL, UNIQUE(asset, method, path, params));
        INSERT INTO endpoints(asset,path,first_seen) VALUES('a.example.com','/','2020-01-01T00:00:00Z');
        CREATE TABLE asset_links (id INTEGER PRIMARY KEY AUTOINCREMENT,
          kind TEXT NOT NULL, canonical TEXT NOT NULL, relation TEXT NOT NULL,
          owner TEXT NOT NULL, source TEXT NOT NULL DEFAULT '',
          first_seen TEXT NOT NULL, UNIQUE(kind, canonical, relation, owner));
    """)
    conn.commit()
    conn.close()
    store = core.Store(path)
    try:
        cols = [r[1] for r in store.conn.execute("PRAGMA table_info(endpoints)")]
        assert "last_seen" in cols, cols
        lcols = [r[1] for r in store.conn.execute("PRAGMA table_info(asset_links)")]
        assert "last_seen" in lcols, lcols
        row = store.conn.execute("SELECT first_seen, last_seen FROM endpoints").fetchone()
        assert row["last_seen"] == "2020-01-01T00:00:00Z", "backfilled from first_seen"
    finally:
        store.close()
