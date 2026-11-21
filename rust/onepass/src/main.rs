//! onepass - passive subdomain collector designed for AI agents.
//!
//! Contract:
//!   stdout = exactly one JSON object
//!   stderr = human progress only (agents must not parse it)
//!   exit 0 ok / 2 bad usage / 3 nothing usable (all sources failed or skipped)

mod http;
mod paging;
mod sources;
mod util;

use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

fn out_json(v: &Value) {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{}", s);
}

fn log(msg: &str) {
    eprintln!("[onepass] {}", msg);
}

fn env_val(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

struct Args {
    domain: String,
    only: Vec<String>,
    concurrency: usize,
    timeout: u64,
    retries: u32,
    min_reliability: f32,
    /// page budget for the free cursor APIs (VirusTotal, urlscan). Default 4
    /// fits VirusTotal's free tier (4 requests/minute). Billed engines are
    /// never paged; their cap is reported instead.
    max_pages: u32,
}

fn parse_query_args(argv: &[String]) -> Result<Args, String> {
    let mut domain = String::new();
    let mut only: Vec<String> = Vec::new();
    let mut concurrency = 6usize;
    let mut timeout = 20u64;
    let mut retries = 1u32;
    let mut min_reliability = 0.0f32;
    let mut max_pages = 4u32;

    let mut i = 0usize;
    while i < argv.len() {
        let flag = argv[i].as_str();
        let value = |i: usize| -> Result<String, String> {
            argv.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("missing value for {}", flag))
        };
        match flag {
            "--domain" | "-d" => {
                domain = value(i)?;
                i += 1;
            }
            "--sources" | "-s" => {
                only = value(i)?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                i += 1;
            }
            "--concurrency" | "-c" => {
                concurrency = value(i)?.parse().map_err(|_| "bad concurrency".to_string())?;
                i += 1;
            }
            "--timeout" | "-t" => {
                timeout = value(i)?.parse().map_err(|_| "bad timeout".to_string())?;
                i += 1;
            }
            "--retries" => {
                retries = value(i)?.parse().map_err(|_| "bad retries".to_string())?;
                i += 1;
            }
            "--min-reliability" => {
                min_reliability = value(i)?
                    .parse()
                    .map_err(|_| "bad min-reliability".to_string())?;
                i += 1;
            }
            "--max-pages" => {
                max_pages = value(i)?.parse().map_err(|_| "bad max-pages".to_string())?;
                i += 1;
            }
            other => return Err(format!("unknown flag: {}", other)),
        }
        i += 1;
    }
    if domain.trim().is_empty() {
        return Err("--domain is required".to_string());
    }
    let d = util::canon_domain(&domain).ok_or_else(|| format!("invalid domain: {}", domain))?;
    Ok(Args {
        domain: d,
        only,
        concurrency: concurrency.clamp(1, 16),
        timeout: timeout.clamp(3, 120),
        retries: retries.min(3),
        min_reliability,
        max_pages: max_pages.clamp(1, 20),
    })
}

/// The report entry of a source that answered.
fn ok_report(id: &str, pages: &paging::Pages, found: usize, ms: u64) -> Value {
    let mut r = json!({
        "id": id, "status": "ok", "found": found, "ms": ms, "http": pages.status,
        "pages": pages.pages, "truncated": pages.truncated, "total": pages.total,
    });
    if let Some(e) = &pages.page_error {
        r["page_error"] = json!(e);
    }
    r
}

/// Sources whose upstream holds rows that were not fetched.
fn truncated_ids(rep: &[Value]) -> Vec<String> {
    let mut ids: Vec<String> = rep
        .iter()
        .filter(|v| v["truncated"] == json!(true))
        .filter_map(|v| v["id"].as_str().map(str::to_string))
        .collect();
    ids.sort();
    ids
}

fn cmd_sources() {
    let mut arr: Vec<Value> = Vec::new();
    for s in sources::SOURCES {
        let env_name = sources::env_for(&s.auth);
        let ready = match env_name {
            None => true,
            Some(e) => env_val(e).is_some(),
        };
        arr.push(json!({
            "id": s.id,
            "name": s.name,
            "url_template": s.url,
            "requires_key": env_name.is_some(),
            "env": env_name,
            "ready": ready,
            "reliability": s.reliability,
            "note": s.note,
            "paging": paging::label(s.paging),
        }));
    }
    let ready_count = arr.iter().filter(|v| v["ready"] == json!(true)).count();
    out_json(&json!({
        "ok": true,
        "total": arr.len(),
        "ready": ready_count,
        "sources": arr,
        "hint": "pass --sources id1,id2 to restrict, or omit to use every ready source",
    }));
}

fn cmd_doctor() {
    let mut arr: Vec<Value> = Vec::new();
    for s in sources::SOURCES {
        let env_name = sources::env_for(&s.auth);
        let status = match &s.auth {
            sources::Auth::Fofa => {
                if env_val("FOFA_EMAIL").is_some() && env_val("FOFA_KEY").is_some() {
                    "ready"
                } else {
                    "missing_key"
                }
            }
            _ => match env_name {
                None => "ready",
                Some(e) => {
                    if env_val(e).is_some() {
                        "ready"
                    } else {
                        "missing_key"
                    }
                }
            },
        };
        arr.push(json!({"id": s.id, "status": status, "env": env_name}));
    }
    let ready = arr.iter().filter(|v| v["status"] == json!("ready")).count();
    out_json(&json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "sources_ready": ready,
        "sources_total": arr.len(),
        "sources": arr,
    }));
}

fn cmd_query(args: Args) -> i32 {
    let started = Instant::now();
    let root = args.domain.clone();

    // pick the sources this agent can actually use right now
    let mut picked: Vec<&'static sources::Source> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    for s in sources::SOURCES {
        if !args.only.is_empty() && !args.only.iter().any(|x| x.as_str() == s.id) {
            continue;
        }
        if s.reliability < args.min_reliability {
            skipped.push(json!({
                "id": s.id, "status": "skipped", "reason": "below_min_reliability",
                "reliability": s.reliability,
            }));
            continue;
        }
        let mut missing_env: Option<&'static str> = None;
        match s.auth {
            sources::Auth::None => {}
            sources::Auth::Header(_, e) | sources::Auth::Query(_, e) => {
                if env_val(e).is_none() {
                    missing_env = Some(e);
                }
            }
            sources::Auth::Fofa => {
                if env_val("FOFA_EMAIL").is_none() {
                    missing_env = Some("FOFA_EMAIL");
                } else if env_val("FOFA_KEY").is_none() {
                    missing_env = Some("FOFA_KEY");
                }
            }
        }
        if let Some(e) = missing_env {
            skipped.push(json!({
                "id": s.id, "status": "skipped", "reason": "missing_key", "env": e,
            }));
            continue;
        }
        picked.push(s);
    }

    if picked.is_empty() {
        out_json(&json!({
            "ok": false,
            "error": "no_usable_sources",
            "message": "all sources were skipped; check the doctor command",
            "skipped": skipped,
        }));
        return 3;
    }
    log(&format!(
        "querying {} sources for {} (concurrency {})",
        picked.len(),
        root,
        args.concurrency
    ));

    let acc: Arc<Mutex<HashMap<String, (Vec<String>, f32)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let report: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let total = picked.len();
    let list: Arc<Vec<&'static sources::Source>> = Arc::new(picked);
    let idx = Arc::new(Mutex::new(0usize));

    let mut handles = Vec::new();
    for _ in 0..args.concurrency.min(total) {
        let acc = Arc::clone(&acc);
        let report = Arc::clone(&report);
        let list = Arc::clone(&list);
        let idx = Arc::clone(&idx);
        let root = root.clone();
        let timeout = args.timeout;
        let retries = args.retries;
        let max_pages = args.max_pages;
        handles.push(std::thread::spawn(move || loop {
            let i = {
                let mut g = idx.lock().unwrap();
                if *g >= list.len() {
                    break;
                }
                *g += 1;
                *g - 1
            };
            let src = list[i];
            let t0 = Instant::now();
            let mut headers: Vec<(String, String)> = Vec::new();
            let mut url = src.url.replace("{domain}", &root);
            let mut missing: Option<&'static str> = None;
            match src.auth {
                sources::Auth::None => {}
                sources::Auth::Header(name, env_name) => match env_val(env_name) {
                    Some(v) => headers.push((name.to_string(), v)),
                    None => missing = Some(env_name),
                },
                sources::Auth::Query(name, env_name) => match env_val(env_name) {
                    Some(v) => url = format!("{}&{}={}", url, name, v),
                    None => missing = Some(env_name),
                },
                sources::Auth::Fofa => {
                    let email = env_val("FOFA_EMAIL");
                    let key = env_val("FOFA_KEY");
                    match (email, key) {
                        (Some(mail), Some(k)) => {
                            let q = format!("domain=\"{}\"", root);
                            url = format!(
                                "{}?email={}&key={}&qbase64={}&size=200&fields=host",
                                src.url,
                                mail,
                                k,
                                util::b64(&q)
                            );
                        }
                        (None, _) => missing = Some("FOFA_EMAIL"),
                        (_, None) => missing = Some("FOFA_KEY"),
                    }
                }
            }
            if let Some(env_name) = missing {
                report.lock().unwrap().push(json!({
                    "id": src.id, "status": "skipped", "reason": "missing_key",
                    "env": env_name, "ms": t0.elapsed().as_millis() as u64, "found": 0,
                }));
                continue;
            }
            let fetched = paging::collect(
                src.paging, &url, max_pages,
                |u: &str| http::fetch(u, &headers, timeout, retries).map(|r| (r.body, r.status)),
                |e: &http::FetchError| http::err_code(e).to_string(),
            );
            match fetched {
                Ok(pages) => {
                    let ms = t0.elapsed().as_millis() as u64;
                    if pages.bodies.iter().all(|b| b.trim().is_empty()) {
                        report.lock().unwrap().push(json!({
                            "id": src.id, "status": "empty", "found": 0, "ms": ms,
                            "http": pages.status, "pages": pages.pages,
                            "truncated": false, "total": pages.total,
                        }));
                        continue;
                    }
                    let mut all: Vec<String> = Vec::new();
                    for body in &pages.bodies {
                        all.extend(util::extract_hosts(body, &root));
                    }
                    let hosts = util::dedupe(all);
                    let n = hosts.len();
                    {
                        let mut a = acc.lock().unwrap();
                        for h in &hosts {
                            let e = a.entry(h.clone()).or_insert_with(|| (Vec::new(), 0.0));
                            if !e.0.iter().any(|x| x == src.id) {
                                e.0.push(src.id.to_string());
                            }
                            if src.reliability > e.1 {
                                e.1 = src.reliability;
                            }
                        }
                    }
                    report.lock().unwrap().push(ok_report(src.id, &pages, n, ms));
                }
                Err(e) => {
                    let ms = t0.elapsed().as_millis() as u64;
                    report.lock().unwrap().push(json!({
                        "id": src.id, "status": "error",
                        "code": http::err_code(&e), "detail": http::err_detail(&e),
                        "found": 0, "ms": ms,
                    }));
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    let map = acc.lock().unwrap().clone();
    let mut records: Vec<Value> = map
        .iter()
        .map(|(host, (srcs, rel))| {
            let n = srcs.len() as f32;
            let conf = match n {
                1.0 => (rel * 0.6).min(0.6),
                2.0 => rel.max(0.7),
                _ => (rel + 0.1).min(0.95),
            };
            json!({
                "domain": host,
                "sources": srcs,
                "confidence": (conf * 100.0).round() / 100.0,
            })
        })
        .collect();
    records.sort_by(|a, b| {
        b["confidence"]
            .as_f64()
            .partial_cmp(&a["confidence"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut rep = report.lock().unwrap().clone();
    rep.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    rep.extend(skipped);
    let ok_count = rep.iter().filter(|v| v["status"] == json!("ok")).count();
    let err_count = rep.iter().filter(|v| v["status"] == json!("error")).count();

    let ret = if records.is_empty() && ok_count == 0 { 3 } else { 0 };
    out_json(&json!({
        "ok": ret == 0,
        "domain": root,
        "elapsed_ms": started.elapsed().as_millis() as u64,
        "sources_used": total,
        "sources_ok": ok_count,
        "sources_error": err_count,
        "found": records.len(),
        "records": records,
        // the upstream holds rows these sources did not return (page budget
        // spent, billed engine capped, or a later page failed)
        "truncated_sources": truncated_ids(&rep),
        "sources": rep,
        "hint": "confidence derives from how many independent sources confirmed the host",
    }));
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn max_pages_defaults_to_four_and_is_clamped() {
        assert_eq!(parse_query_args(&argv(&["--domain", "x.com"])).unwrap().max_pages, 4);
        assert_eq!(parse_query_args(&argv(&["--domain", "x.com", "--max-pages", "99"]))
                       .unwrap().max_pages, 20);
        assert_eq!(parse_query_args(&argv(&["--domain", "x.com", "--max-pages", "0"]))
                       .unwrap().max_pages, 1);
    }

    #[test]
    fn a_source_report_says_whether_its_answer_was_cut() {
        let pages = paging::Pages { pages: 2, truncated: true, total: Some(900),
                                    status: 200, ..paging::Pages::default() };
        let r = ok_report("virustotal", &pages, 80, 12);
        assert_eq!(r["status"], json!("ok"));
        assert_eq!(r["found"], json!(80));
        assert_eq!(r["pages"], json!(2));
        assert_eq!(r["truncated"], json!(true));
        assert_eq!(r["total"], json!(900));
        let rep = vec![r, json!({"id": "crtsh", "status": "ok", "truncated": false})];
        assert_eq!(truncated_ids(&rep), vec!["virustotal".to_string()]);
    }
}

fn main() {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.is_empty() {
        out_json(&json!({
            "ok": false,
            "error": "no_command",
            "commands": ["sources", "doctor", "query --domain X"],
            "example": "onepass query --domain example.com",
        }));
        std::process::exit(2);
    }
    let code = match argv[0].as_str() {
        "sources" => {
            cmd_sources();
            0
        }
        "doctor" => {
            cmd_doctor();
            0
        }
        "query" | "q" => match parse_query_args(&argv[1..]) {
            Ok(a) => cmd_query(a),
            Err(e) => {
                out_json(&json!({"ok": false, "error": "bad_usage", "message": e}));
                2
            }
        },
        "version" | "-v" | "--version" => {
            out_json(&json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}));
            0
        }
        other => {
            out_json(&json!({
                "ok": false, "error": "unknown_command", "command": other,
                "commands": ["sources", "doctor", "query"],
            }));
            2
        }
    };
    std::process::exit(code);
}
