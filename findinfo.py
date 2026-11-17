#!/usr/bin/env python
"""findinfo - asset reconnaissance skill CLI.

Every subcommand prints one JSON object to stdout (machine-readable for the agent)
and human-readable progress to stderr.

    python findinfo.py doctor
    python findinfo.py entity --name 美团
    python findinfo.py subs   --domain example.com
    python findinfo.py probe  --from-store
    python findinfo.py run    --name 美团 --active
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib import core, tools


def out(obj) -> None:
    core.emit(obj)


# ---------------------------------------------------------------- commands
def cmd_doctor(args) -> None:
    out(tools.doctor())


def cmd_scope(args) -> None:
    sc = core.Scope.load()
    if args.check:
        ok, rule = sc.check(args.check)
        out({"host": args.check, "allowed": ok, "rule": rule})
        return
    out(sc.summary())


def cmd_entity(args) -> None:
    store = core.Store()
    try:
        res = tools.t_enscan(store, args.name, invest=args.invest, deep=args.deep,
                            outdir=Path(args.out) if args.out else None)
        out(res)
    finally:
        store.close()


def cmd_certs(args) -> None:
    store = core.Store()
    try:
        out(tools.t_certs(store, args.domain))
    finally:
        store.close()


def cmd_passive(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store or not domains:
            domains = [a["canonical"] for a in store.get_assets(kind="domain", min_conf=0.7)]
        srcs = [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else None
        merged = []
        for d in domains:
            merged.append(tools.t_onepass(store, d, sources=srcs,
                                          min_confidence=args.min_conf))
        out({"domains": merged, "total": sum(m.get("count", 0) for m in merged)})
    finally:
        store.close()


def cmd_brute(args) -> None:
    store = core.Store()
    try:
        out(tools.t_brute(store, args.domain, wordlist=args.wordlist,
                          bandwidth=args.bandwidth, wildcard=args.wildcard))
    finally:
        store.close()


def cmd_icp(args) -> None:
    store = core.Store()
    try:
        codes = args.code or []
        if args.from_store:
            codes = [a["canonical"] for a in store.get_assets(kind="icp")]
        out(tools.t_icp(store, codes, engines=args.engines))
    finally:
        store.close()


def cmd_subs(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store:
            domains = [a["canonical"] for a in store.get_assets(kind="domain", min_conf=0.7)]
        merged = []
        for d in domains:
            r = tools.t_subs(store, d, engines=args.engines)
            merged.append(r)
        out({"domains": merged, "total": sum(m.get("count", 0) for m in merged)})
    finally:
        store.close()


def _domains_from_store(store, min_conf: float) -> list[str]:
    return [a["canonical"] for a in store.get_assets(kind="domain", min_conf=min_conf)]


def _vhost_bases(store) -> list[str]:
    """Base domains used to qualify bare vhost wordlist labels."""
    bases: list[str] = []
    sc = core.Scope.load()
    bases.extend(sc.domains)
    for a in store.get_assets(kind="domain", min_conf=0.4):
        parent = core.canon_domain(a.get("parent") or "")
        if parent:
            bases.append(parent)
    out: list[str] = []
    for b in bases:
        cd = core.canon_domain(b)
        if cd and cd not in out:
            out.append(cd)
    return out


def _active_enabled(args) -> bool:
    """--ports/--vhost/--crawl/--brute imply --active, as --help documents."""
    return bool(args.active or args.ports or args.vhost or args.crawl or args.brute)


def cmd_dns(args) -> None:
    store = core.Store()
    try:
        domains = args.domain or []
        if args.from_store or not domains:
            domains = _domains_from_store(store, args.min_conf)
        out(tools.t_dns(store, domains))
    finally:
        store.close()


def cmd_probe(args) -> None:
    store = core.Store()
    try:
        hosts = args.host or []
        if args.from_store or not hosts:
            hosts = _domains_from_store(store, args.min_conf)
        out(tools.t_httpx(store, hosts))
    finally:
        store.close()


def cmd_ipagg(args) -> None:
    store = core.Store()
    try:
        out(tools.t_ipagg(store, args.ip))
    finally:
        store.close()


def cmd_ports(args) -> None:
    store = core.Store()
    try:
        ips = args.ip or [a["canonical"] for a in store.get_assets(kind="ip")]
        out(tools.t_ports(store, ips, top_ports=args.top_ports))
    finally:
        store.close()


def cmd_vhost(args) -> None:
    store = core.Store()
    try:
        hosts = args.host or []
        if args.from_store or not hosts:
            hosts = _domains_from_store(store, 0.4)
        if args.wordlist:
            raw = [w.strip() for w in
                   Path(args.wordlist).read_text(encoding="utf-8").splitlines() if w.strip()]
            bases = args.domain or _vhost_bases(store)
            extra = tools.expand_host_words(raw, bases)
            core.log("vhost wordlist: " + str(len(raw)) + " words -> " +
                     str(len(extra)) + " hosts from " + str(len(bases)) + " base domain(s)")
            hosts = hosts + extra
        ports = [int(p) for p in (args.ports or "80,443").split(",") if p.strip()]
        out(tools.t_vhost(store, args.ip, hosts, ports=ports, threads=args.threads))
    finally:
        store.close()


def cmd_crawl(args) -> None:
    store = core.Store()
    try:
        urls = args.url or []
        if args.from_store or not urls:
            for a in store.get_assets(kind="domain", min_conf=0.7):
                attrs = a.get("attrs") or {}
                if attrs.get("url"):
                    urls.append(attrs["url"])
        out(tools.t_crawl(store, urls, depth=args.depth))
    finally:
        store.close()


def cmd_extract(args) -> None:
    store = core.Store()
    try:
        rows = []
        if args.from_run:
            p = Path(args.from_run)
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            rows.append(json.loads(line))
                        except Exception:
                            pass
        out(tools.t_extract(store, rows, urls=args.url))
    finally:
        store.close()


def cmd_assets(args) -> None:
    store = core.Store()
    try:
        if args.export:
            kind = None if args.kind == "all" else args.kind
            rows = store.get_assets(kind=kind, min_conf=args.min_conf)
            path = Path(args.export)
            n = core.write_jsonl(path, rows)
            out({"exported": n, "path": str(path),
                 "counts": store.count_assets()})
            return
        rows = store.get_assets(kind=None if args.kind == "all" else args.kind,
                                min_conf=args.min_conf, limit=args.limit)
        out({"counts": store.count_assets(), "total": len(rows),
             "endpoints": len(store.get_endpoints()), "rows": rows})
    finally:
        store.close()


# ---------------------------------------------------------------- full pipeline
def cmd_run(args) -> None:
    store = core.Store()
    scope = core.Scope.load()
    active = _active_enabled(args)
    summary: dict = {"engagement": scope.engagement, "active": active, "stages": []}
    target_label = args.name or (",".join(args.domain) if args.domain else "?")
    run_id = store.start_run(scope.engagement, target_label)
    run_dir = core.new_run_dir(target_label)
    summary["run_dir"] = str(run_dir)
    try:
        # 1. entity
        domains: list[str] = []
        icp_codes: list[str] = []
        if args.name:
            core.log("stage 1/6 entity")
            r = tools.t_enscan(store, args.name, invest=args.invest, deep=args.deep,
                              outdir=run_dir / "enscan")
            domains += r.get("domains", [])
            icp_codes += r.get("icp", [])
            summary["stages"].append({"stage": "entity", "companies": len(r.get("companies", [])),
                                      "icp": len(icp_codes), "domains": len(domains)})
        if args.domain:
            for d in args.domain:
                cd = core.canon_domain(d)
                if not cd:
                    raise core.FindInfoError("invalid domain: " + str(d))
                domains.append(cd)
        domains = [d for d in dict.fromkeys([core.canon_domain(d) for d in domains if core.canon_domain(d)])]
        summary["seed_domains"] = domains
        if not domains:
            raise core.FindInfoError("no seed domain; give --domain or check ENScan output")

        # 1.5 onepass (15-source passive aggregation, Rust binary)
        if not getattr(args, "no_onepass", False):
            core.log("stage 1.5/6 onepass passive aggregation")
            op_total = 0
            for d in domains[: args.max_seed]:
                r = tools.t_onepass(store, d)
                op_total += r["count"]
            summary["stages"].append({"stage": "onepass", "found": op_total})

        # 2. certificate transparency
        core.log("stage 2/6 certificate transparency")
        cert_total = 0
        for d in domains[: args.max_seed]:
            r = tools.t_certs(store, d)
            cert_total += r["count"]
        summary["stages"].append({"stage": "certs", "found": cert_total})

        # 3. passive subdomains
        core.log("stage 3/6 passive subdomains")
        sub_total = 0
        for d in domains[: args.max_seed]:
            r = tools.t_subs(store, d, engines=args.engines)
            sub_total += r["count"]
        summary["stages"].append({"stage": "subs", "found": sub_total})

        # 3.5 brute force (active, raw socket)
        if active and args.brute:
            core.log("stage 3.5/6 dns brute force")
            brute_total = 0
            for d in domains[: args.max_seed]:
                try:
                    br = tools.t_brute(store, d, wordlist=args.brute_wordlist,
                                       bandwidth=args.brute_bandwidth)
                    brute_total += br["count"]
                except core.ScopeError as exc:
                    core.log("brute skipped: " + str(exc))
            summary["stages"].append({"stage": "brute", "found": brute_total})

        # 4. icp reverse
        if icp_codes and not args.no_icp:
            core.log("stage 4/6 icp reverse lookup")
            r = tools.t_icp(store, icp_codes, engines=args.engines)
            summary["stages"].append({"stage": "icp", "domains": len(r.get("domains", []))})

        # 5. dns
        core.log("stage 5/6 dns resolve")
        all_domains = _domains_from_store(store, 0.4)
        r = tools.t_dns(store, all_domains)
        summary["stages"].append({"stage": "dns", "resolved": r["count"],
                                  "wildcard": len(r.get("wildcard", []))})

        # 6. probe (active)
        if active:
            core.log("stage 6/6 httpx probe")
            hosts = [x["domain"] for x in r["domains"]]
            p = tools.t_httpx(store, hosts)
            summary["stages"].append({"stage": "probe", "live": p["count"]})
            ipa = tools.t_ipagg(store)
            summary["stages"].append({"stage": "ipagg",
                                      "candidates": ipa["count_candidates"]})
            if args.ports:
                cand_ips = [c["ip"] for c in ipa["candidates"]] or \
                           [a["canonical"] for a in store.get_assets(kind="ip")]
                try:
                    pr = tools.t_ports(store, cand_ips, top_ports=args.top_ports)
                    summary["stages"].append({"stage": "ports", "open": pr["count"]})
                except core.ScopeError as exc:
                    summary["stages"].append({"stage": "ports", "skipped": str(exc)})
            if args.vhost:
                hits = 0
                for cand in ipa["candidates"][: args.max_vhost_ips]:
                    try:
                        vr = tools.t_vhost(store, cand["ip"], cand["domains"] + all_domains,
                                           ports=[80, 443, 8080, 8443])
                        hits += vr["hits"]
                    except core.ScopeError as exc:
                        core.log("vhost skipped: " + str(exc))
                summary["stages"].append({"stage": "vhost", "hits": hits})
            if args.crawl:
                urls = []
                for a in store.get_assets(kind="domain", min_conf=0.7):
                    attrs = a.get("attrs") or {}
                    if attrs.get("url"):
                        urls.append(attrs["url"])
                try:
                    cr = tools.t_crawl(store, urls, depth=args.depth)
                    summary["stages"].append({"stage": "crawl", "urls": cr["count"]})
                    ex = tools.t_extract(store, cr["rows"], urls=[x["url"] for x in cr["rows"]])
                    summary["stages"].append({"stage": "extract",
                                              "new_domains": ex["count_domains"],
                                              "new_ips": ex["count_ips"]})
                except core.ScopeError as exc:
                    summary["stages"].append({"stage": "crawl", "skipped": str(exc)})
        summary["counts"] = store.count_assets()
        summary["endpoints"] = len(store.get_endpoints())
        core.write_jsonl(run_dir / "summary.jsonl", [summary])
        store.finish_run(run_id, summary)
        out(summary)
    finally:
        store.close()


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="findinfo",
                                description="asset reconnaissance skill for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="check bundled tools, api keys, scope")
    d.set_defaults(func=cmd_doctor)

    s = sub.add_parser("scope", help="show or test authorization scope")
    s.add_argument("--check", help="host to test")
    s.set_defaults(func=cmd_scope)

    e = sub.add_parser("entity", help="brand/company name -> subsidiaries, ICP, domains")
    e.add_argument("--name", required=True)
    e.add_argument("--invest", type=int, default=51)
    e.add_argument("--deep", type=int, default=2)
    e.add_argument("--out", default="")
    e.set_defaults(func=cmd_entity)

    c = sub.add_parser("certs", help="certificate transparency expansion")
    c.add_argument("--domain", required=True)
    c.set_defaults(func=cmd_certs)

    i = sub.add_parser("icp", help="ICP record -> domains (fofa/quake/hunter)")
    i.add_argument("--code", action="append", help="repeatable")
    i.add_argument("--from-store", action="store_true")
    i.add_argument("--engines", default="fofa,quake,hunter")
    i.set_defaults(func=cmd_icp)

    pa = sub.add_parser("passive", help="14-source passive collection via bundled Rust onepass")
    pa.add_argument("--domain", action="append")
    pa.add_argument("--from-store", action="store_true")
    pa.add_argument("--sources", default="", help="comma separated source ids (see: onepass sources)")
    pa.add_argument("--min-conf", type=float, default=0.0)
    pa.set_defaults(func=cmd_passive)

    br = sub.add_parser("brute", help="DNS brute force via ksubdomain (ACTIVE, needs Npcap)")
    br.add_argument("--domain", required=True)
    br.add_argument("--wordlist", default="wordlists/sub.txt")
    br.add_argument("--bandwidth", default="3m", help="3m/5m/10m, lower = politer")
    br.add_argument("--wildcard", default="basic", choices=["basic", "advanced", "none"])
    br.set_defaults(func=cmd_brute)

    sb = sub.add_parser("subs", help="passive subdomain enumeration")
    sb.add_argument("--domain", action="append")
    sb.add_argument("--from-store", action="store_true")
    sb.add_argument("--engines", default="fofa,quake,hunter,shodan,censys")
    sb.set_defaults(func=cmd_subs)

    dn = sub.add_parser("dns", help="resolve + wildcard filtering")
    dn.add_argument("--domain", action="append")
    dn.add_argument("--from-store", action="store_true")
    dn.add_argument("--min-conf", type=float, default=0.4)
    dn.set_defaults(func=cmd_dns)

    pr = sub.add_parser("probe", help="httpx liveness / tech / ip mapping (ACTIVE)")
    pr.add_argument("--host", action="append")
    pr.add_argument("--from-store", action="store_true")
    pr.add_argument("--min-conf", type=float, default=0.7)
    pr.set_defaults(func=cmd_probe)

    ia = sub.add_parser("ipagg", help="group domains by ip, drop CDN")
    ia.add_argument("--ip", action="append")
    ia.set_defaults(func=cmd_ipagg)

    po = sub.add_parser("ports", help="naabu port scan (ACTIVE)")
    po.add_argument("--ip", action="append")
    po.add_argument("--top-ports", type=int, default=1000)
    po.set_defaults(func=cmd_ports)

    vh = sub.add_parser("vhost", help="Host header collision -> internal services (ACTIVE)")
    vh.add_argument("--ip", required=True)
    vh.add_argument("--host", action="append")
    vh.add_argument("--from-store", action="store_true")
    vh.add_argument("--domain", action="append",
                    help="base domain for bare wordlist labels (repeatable; "
                         "defaults to scope domains + parents in the store)")
    vh.add_argument("--wordlist", default="",
                    help="prefix list; bare labels are qualified with --domain")
    vh.add_argument("--ports", default="80,443")
    vh.add_argument("--threads", type=int, default=20)
    vh.set_defaults(func=cmd_vhost)

    cr = sub.add_parser("crawl", help="katana crawl (ACTIVE)")
    cr.add_argument("--url", action="append")
    cr.add_argument("--from-store", action="store_true")
    cr.add_argument("--depth", type=int, default=3)
    cr.set_defaults(func=cmd_crawl)

    ex = sub.add_parser("extract", help="leaked domains/IPs from crawl output")
    ex.add_argument("--from-run", default="")
    ex.add_argument("--url", action="append")
    ex.set_defaults(func=cmd_extract)

    as_ = sub.add_parser("assets", help="list / export asset graph")
    as_.add_argument("--kind", default="all",
                     choices=["all", "company", "icp", "domain", "ip", "url", "endpoint"])
    as_.add_argument("--min-conf", type=float, default=0.0)
    as_.add_argument("--limit", type=int, default=500)
    as_.add_argument("--export", default="")
    as_.set_defaults(func=cmd_assets)

    rn = sub.add_parser("run", help="full pipeline: entity -> certs -> subs -> dns -> probe")
    rn.add_argument("--name", default="")
    rn.add_argument("--domain", action="append")
    rn.add_argument("--active", action="store_true", help="enable traffic-generating stages")
    rn.add_argument("--ports", action="store_true", help="naabu scan (implies --active)")
    rn.add_argument("--vhost", action="store_true", help="host collision (implies --active)")
    rn.add_argument("--crawl", action="store_true", help="katana crawl (implies --active)")
    rn.add_argument("--brute", action="store_true", help="ksubdomain DNS brute force (implies --active, needs Npcap)")
    rn.add_argument("--brute-wordlist", default="wordlists/sub.txt")
    rn.add_argument("--brute-bandwidth", default="3m")
    rn.add_argument("--depth", type=int, default=3)
    rn.add_argument("--invest", type=int, default=51)
    rn.add_argument("--deep", type=int, default=2)
    rn.add_argument("--engines", default="fofa,quake,hunter,shodan,censys")
    rn.add_argument("--no-icp", action="store_true")
    rn.add_argument("--no-onepass", action="store_true", help="skip the onepass stage")
    rn.add_argument("--top-ports", type=int, default=1000)
    rn.add_argument("--max-seed", type=int, default=5)
    rn.add_argument("--max-vhost-ips", type=int, default=10)
    rn.set_defaults(func=cmd_run)

    return p


def main(argv: list[str]) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
        return 0
    except core.ScopeError as exc:
        out({"error": "scope_denied", "message": str(exc)})
        return 3
    except core.ToolMissing as exc:
        out({"error": "tool_missing", "message": str(exc)})
        return 4
    except core.FindInfoError as exc:
        out({"error": "error", "message": str(exc)})
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        out({"error": "unexpected", "message": repr(exc)})
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
