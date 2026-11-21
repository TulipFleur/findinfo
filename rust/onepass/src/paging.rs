//! Pagination: what one page says about the rest of the answer.
//!
//! A source used to be ONE GET. VirusTotal, urlscan, FOFA, Quake and Hunter
//! all cap a response (100-200 rows), so on a large target everything past
//! the first page was dropped without a word. `inspect` reads a page and
//! says whether the upstream holds more and, for the two free cursor APIs,
//! where the next page is. The billed engines (FOFA/Quake/Hunter) are never
//! paged automatically -- every page spends quota -- so their cap is
//! REPORTED instead (truncated + total), and the caller decides.

use serde_json::Value;

/// How a source pages its answer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Paging {
    /// one response is the whole answer (or no paging contract is known)
    None,
    /// VirusTotal v3 collections: follow `links.next`, same origin only
    VtCursor,
    /// urlscan search: `has_more` + `search_after=<sort of the last result>`
    UrlscanSearchAfter,
    /// FOFA search/all: `size` is the total match count (one page only)
    FofaTotal,
    /// Quake quake_service: `meta.pagination.total` (one page only)
    QuakeTotal,
    /// Hunter openApi/search: `data.total` (one page only)
    HunterTotal,
}

pub const VT_ORIGIN: &str = "https://www.virustotal.com/";

/// What one page says about the answer it belongs to.
#[derive(Debug, Default, PartialEq)]
pub struct PageInfo {
    /// rows on this page, when the response shape is known
    pub rows: Option<u64>,
    /// the upstream's total match count, when it states one
    pub total: Option<u64>,
    /// the upstream says rows exist beyond this page
    pub more: bool,
    /// where the next page is, when this source can be paged safely
    pub next: Option<String>,
}

/// Everything collected for one source.
#[derive(Debug, Default, PartialEq)]
pub struct Pages {
    pub bodies: Vec<String>,
    pub status: u16,
    pub pages: u32,
    /// the upstream holds rows that were NOT fetched
    pub truncated: bool,
    pub total: Option<u64>,
    /// why paging stopped early, when a later page failed
    pub page_error: Option<String>,
}

/// The paging mode as emitted by the `sources` command.
pub fn label(p: Paging) -> &'static str {
    match p {
        Paging::None => "none",
        Paging::VtCursor => "cursor",
        Paging::UrlscanSearchAfter => "search_after",
        Paging::FofaTotal | Paging::QuakeTotal | Paging::HunterTotal => "total_only",
    }
}

fn arr_len(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Array(a)) => Some(a.len() as u64),
        // Hunter answers `"arr": null` for an empty page
        Some(Value::Null) => Some(0),
        _ => None,
    }
}

/// Percent-encode everything but RFC 3986 unreserved characters.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn sort_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Read one page. A body whose shape is unknown (or not JSON) claims
/// nothing: a wrong guess about a response must never invent a truncation.
pub fn inspect(paging: Paging, first_url: &str, body: &str) -> PageInfo {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return PageInfo::default(),
    };
    let capped = |rows: Option<u64>, total: Option<u64>| PageInfo {
        rows,
        total,
        more: matches!((rows, total), (Some(r), Some(t)) if t > r),
        next: None,
    };
    match paging {
        Paging::None => PageInfo::default(),
        Paging::VtCursor => {
            let link = v.pointer("/links/next").and_then(|n| n.as_str())
                .filter(|s| !s.is_empty());
            PageInfo {
                rows: arr_len(v.get("data")),
                total: v.pointer("/meta/count").and_then(|c| c.as_u64()),
                more: link.is_some(),
                // the API key travels in a header: never hand it to another host
                next: link.filter(|s| s.starts_with(VT_ORIGIN)).map(str::to_string),
            }
        }
        Paging::UrlscanSearchAfter => {
            let results = v.get("results").and_then(|r| r.as_array());
            let more = v.get("has_more").and_then(|h| h.as_bool()).unwrap_or(false);
            let next = if more {
                results.and_then(|a| a.last())
                    .and_then(|last| last.get("sort"))
                    .and_then(|s| s.as_array())
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        let parts: Vec<String> = s.iter().map(|x| pct(&sort_value(x))).collect();
                        format!("{}&search_after={}", first_url, parts.join(","))
                    })
            } else {
                None
            };
            PageInfo {
                rows: results.map(|a| a.len() as u64),
                total: v.get("total").and_then(|t| t.as_u64()),
                more,
                next,
            }
        }
        Paging::FofaTotal => capped(arr_len(v.get("results")),
                                    v.get("size").and_then(|t| t.as_u64())),
        Paging::QuakeTotal => capped(arr_len(v.get("data")),
                                     v.pointer("/meta/pagination/total").and_then(|t| t.as_u64())),
        Paging::HunterTotal => capped(arr_len(v.pointer("/data/arr")),
                                      v.pointer("/data/total").and_then(|t| t.as_u64())),
    }
}

/// Fetch a source page by page (at most `max_pages`).
///
/// `fetch` performs one GET and returns (body, http status). A failed FIRST
/// page is the source's error; a failed later page keeps what was collected
/// and marks the answer truncated (`code_of` names the failure).
pub fn collect<E, F, C>(paging: Paging, first_url: &str, max_pages: u32,
                        mut fetch: F, code_of: C) -> Result<Pages, E>
where
    F: FnMut(&str) -> Result<(String, u16), E>,
    C: Fn(&E) -> String,
{
    let mut out = Pages::default();
    let mut url = first_url.to_string();
    let mut rows: u64 = 0;
    let mut rows_known = true;
    loop {
        match fetch(&url) {
            Ok((body, status)) => {
                out.pages += 1;
                out.status = status;
                let info = inspect(paging, first_url, &body);
                match info.rows {
                    Some(r) => rows += r,
                    None => rows_known = false,
                }
                if info.total.is_some() {
                    out.total = info.total;
                }
                out.bodies.push(body);
                if !info.more {
                    break;
                }
                match info.next {
                    Some(n) if out.pages < max_pages.max(1) => url = n,
                    // more exists, but the budget is spent or the source is
                    // never paged (billed) or the next page is unsafe to follow
                    _ => {
                        out.truncated = true;
                        break;
                    }
                }
            }
            Err(e) => {
                if out.pages == 0 {
                    return Err(e);
                }
                out.truncated = true;
                out.page_error = Some(code_of(&e));
                break;
            }
        }
    }
    if let (Some(t), true) = (out.total, rows_known) {
        if t > rows {
            out.truncated = true;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const VT1: &str = "https://www.virustotal.com/api/v3/domains/x.com/subdomains?limit=100";

    fn vt_page(n: usize, next: Option<&str>) -> String {
        let data: Vec<String> = (0..n).map(|i| format!("{{\"id\":\"h{}.x.com\"}}", i)).collect();
        match next {
            Some(u) => format!("{{\"data\":[{}],\"links\":{{\"next\":\"{}\"}}}}", data.join(","), u),
            None => format!("{{\"data\":[{}],\"links\":{{}}}}", data.join(",")),
        }
    }

    fn fake(pages: HashMap<String, String>)
            -> impl FnMut(&str) -> Result<(String, u16), String> {
        move |u: &str| pages.get(u).cloned().map(|b| (b, 200)).ok_or_else(|| "http_error".to_string())
    }

    fn code(e: &String) -> String {
        e.clone()
    }

    #[test]
    fn vt_follows_next_links_to_the_end() {
        let p2 = "https://www.virustotal.com/api/v3/domains/x.com/subdomains?cursor=B";
        let p3 = "https://www.virustotal.com/api/v3/domains/x.com/subdomains?cursor=C";
        let mut m = HashMap::new();
        m.insert(VT1.to_string(), vt_page(2, Some(p2)));
        m.insert(p2.to_string(), vt_page(2, Some(p3)));
        m.insert(p3.to_string(), vt_page(1, None));
        let got = collect(Paging::VtCursor, VT1, 5, fake(m), code).unwrap();
        assert_eq!(got.pages, 3);
        assert_eq!(got.bodies.len(), 3);
        assert!(!got.truncated);
    }

    #[test]
    fn vt_page_budget_marks_the_answer_truncated() {
        let p2 = "https://www.virustotal.com/api/v3/domains/x.com/subdomains?cursor=B";
        let p3 = "https://www.virustotal.com/api/v3/domains/x.com/subdomains?cursor=C";
        let mut m = HashMap::new();
        m.insert(VT1.to_string(), vt_page(2, Some(p2)));
        m.insert(p2.to_string(), vt_page(2, Some(p3)));
        let got = collect(Paging::VtCursor, VT1, 2, fake(m), code).unwrap();
        assert_eq!(got.pages, 2);
        assert!(got.truncated);
    }

    #[test]
    fn vt_next_link_to_another_origin_is_never_followed() {
        // the API key travels in a header: never hand it to another host
        let mut m = HashMap::new();
        m.insert(VT1.to_string(), vt_page(2, Some("https://evil.example/steal?cursor=B")));
        let got = collect(Paging::VtCursor, VT1, 5, fake(m), code).unwrap();
        assert_eq!(got.pages, 1);
        assert!(got.truncated);
    }

    #[test]
    fn urlscan_pages_with_search_after_from_the_last_result() {
        let first = "https://urlscan.io/api/v1/search/?q=domain:x.com&size=200";
        let body1 = r#"{"results":[{"sort":[1700000000002,"a"]},{"sort":[1700000000001,"b c"]}],"total":3,"has_more":true}"#;
        let info = inspect(Paging::UrlscanSearchAfter, first, body1);
        assert_eq!(info.rows, Some(2));
        assert!(info.more);
        let next = info.next.clone().unwrap();
        assert_eq!(next, format!("{}&search_after=1700000000001,b%20c", first));
        let body2 = r#"{"results":[{"sort":[1700000000000,"z"]}],"total":3,"has_more":false}"#;
        let mut m = HashMap::new();
        m.insert(first.to_string(), body1.to_string());
        m.insert(next, body2.to_string());
        let got = collect(Paging::UrlscanSearchAfter, first, 5, fake(m), code).unwrap();
        assert_eq!(got.pages, 2);
        assert!(!got.truncated);
        assert_eq!(got.total, Some(3));
    }

    #[test]
    fn billed_engines_report_their_cap_without_paging() {
        let fofa = r#"{"error":false,"size":1000,"page":1,"results":["a.x.com","b.x.com"]}"#;
        let quake = r#"{"code":0,"data":[{},{}],"meta":{"pagination":{"total":500}}}"#;
        let hunter = r#"{"code":200,"data":{"total":300,"arr":[{},{},{}]}}"#;
        for (paging, body, total) in [(Paging::FofaTotal, fofa, 1000u64),
                                      (Paging::QuakeTotal, quake, 500),
                                      (Paging::HunterTotal, hunter, 300)] {
            let mut calls = 0;
            let got = collect(paging, "https://api.example/q", 5, |_u: &str| {
                calls += 1;
                Ok::<_, String>((body.to_string(), 200))
            }, code).unwrap();
            assert_eq!(calls, 1, "{:?} must never be paged (each page costs quota)", paging);
            assert!(got.truncated, "{:?}", paging);
            assert_eq!(got.total, Some(total), "{:?}", paging);
        }
    }

    #[test]
    fn a_complete_billed_answer_is_not_truncated() {
        let hunter = r#"{"code":200,"data":{"total":2,"arr":[{},{}]}}"#;
        let got = collect(Paging::HunterTotal, "https://api.example/q", 5,
                          |_u: &str| Ok::<_, String>((hunter.to_string(), 200)), code).unwrap();
        assert!(!got.truncated);
        let empty = r#"{"code":200,"data":{"total":0,"arr":null}}"#;
        assert_eq!(inspect(Paging::HunterTotal, "u", empty).rows, Some(0));
    }

    #[test]
    fn a_failed_later_page_keeps_what_was_collected() {
        let p2 = "https://www.virustotal.com/api/v3/domains/x.com/subdomains?cursor=B";
        let mut m = HashMap::new();
        m.insert(VT1.to_string(), vt_page(2, Some(p2)));
        let got = collect(Paging::VtCursor, VT1, 5, fake(m), code).unwrap();
        assert_eq!(got.pages, 1);
        assert!(got.truncated);
        assert_eq!(got.page_error.as_deref(), Some("http_error"));
    }

    #[test]
    fn a_failed_first_page_is_the_source_error() {
        let got = collect(Paging::VtCursor, VT1, 5, fake(HashMap::new()), code);
        assert!(got.is_err());
    }

    #[test]
    fn unknown_or_non_json_bodies_claim_nothing() {
        assert_eq!(inspect(Paging::None, "u", r#"{"has_more":true}"#), PageInfo::default());
        assert_eq!(inspect(Paging::QuakeTotal, "u", "<html>"), PageInfo::default());
        assert_eq!(label(Paging::VtCursor), "cursor");
        assert_eq!(label(Paging::HunterTotal), "total_only");
    }
}
