//! Source registry.
//!
//! Design note (for AI agents reading this code):
//! a source is DATA, not code. Adding a source = adding a struct literal.
//! Every field is emitted by the "sources" command as JSON, so an agent can
//! decide which sources it is able to use without reading this file.

use crate::paging::Paging;

#[derive(Clone, Copy)]
pub enum Auth {
    /// No credentials required.
    None,
    /// Header name + env var name holding the value.
    Header(&'static str, &'static str),
    /// Query parameter name + env var name.
    Query(&'static str, &'static str),
    /// FOFA needs two env vars (FOFA_EMAIL + FOFA_KEY) and a base64 query.
    Fofa,
}

pub struct Source {
    /// stable id, used in --sources filter and in every record
    pub id: &'static str,
    /// human readable name
    pub name: &'static str,
    /// URL template; {domain} is substituted
    pub url: &'static str,
    pub auth: Auth,
    /// 0.0-1.0 trust level, mirrored into record confidence
    pub reliability: f32,
    /// one line describing what it returns / caveats
    pub note: &'static str,
    /// how the source pages its answer (see paging.rs): free cursor APIs
    /// are followed, billed engines only report their cap
    pub paging: Paging,
}

pub const SOURCES: &[Source] = &[
    Source {
        id: "crtsh",
        name: "crt.sh (certificate transparency)",
        url: "https://crt.sh/?q=%25.{domain}&output=json",
        auth: Auth::None,
        reliability: 0.85,
        note: "Best free source. May 502 under load; retried automatically.",
        paging: Paging::None,
    },
    Source {
        id: "certspotter",
        name: "CertSpotter",
        url: "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        auth: Auth::None,
        reliability: 0.80,
        note: "Certificate transparency mirror, free tier rate limited.",
        paging: Paging::None,
    },
    Source {
        id: "hackertarget",
        name: "HackerTarget hostsearch",
        url: "https://api.hackertarget.com/hostsearch/?q={domain}",
        auth: Auth::None,
        reliability: 0.60,
        note: "Plain text CSV. Free tier capped around 50/day.",
        paging: Paging::None,
    },
    Source {
        id: "rapiddns",
        name: "RapidDNS",
        url: "https://rapiddns.io/subdomain/{domain}?full=1",
        auth: Auth::None,
        reliability: 0.60,
        note: "HTML page, scraped. Keep concurrency low.",
        paging: Paging::None,
    },
    Source {
        id: "anubis",
        name: "Anubis (jldc.me)",
        url: "https://jldc.me/anubis/subdomains/{domain}",
        auth: Auth::None,
        reliability: 0.60,
        note: "JSON array. Sometimes slow or offline.",
        paging: Paging::None,
    },
    Source {
        id: "alienvault",
        name: "AlienVault OTX passive DNS",
        url: "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        auth: Auth::None,
        reliability: 0.75,
        note: "JSON. No key required for the public endpoint.",
        paging: Paging::None,
    },
    Source {
        id: "threatminer",
        name: "ThreatMiner",
        url: "https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
        auth: Auth::None,
        reliability: 0.65,
        note: "JSON. Free, occasionally erroring.",
        paging: Paging::None,
    },
    Source {
        id: "subdomain_center",
        name: "subdomain.center",
        url: "https://api.subdomain.center/?domain={domain}",
        auth: Auth::None,
        reliability: 0.60,
        note: "JSON array aggregator.",
        paging: Paging::None,
    },
    Source {
        id: "urlscan",
        name: "urlscan.io",
        url: "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
        auth: Auth::Header("api-key", "URLSCAN_KEY"),
        reliability: 0.80,
        note: "Works without key at low rate; key raises quota.",
        paging: Paging::UrlscanSearchAfter,
    },
    Source {
        id: "virustotal",
        name: "VirusTotal",
        url: "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100",
        auth: Auth::Header("x-apikey", "VIRUSTOTAL_KEY"),
        reliability: 0.80,
        note: "Requires VIRUSTOTAL_KEY. Free tier 4 req/min.",
        paging: Paging::VtCursor,
    },
    Source {
        id: "securitytrails",
        name: "SecurityTrails",
        url: "https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        auth: Auth::Header("APIKEY", "SECURITYTRAILS_KEY"),
        reliability: 0.85,
        note: "Requires SECURITYTRAILS_KEY. Free tier 50/month.",
        paging: Paging::None,
    },
    Source {
        id: "chaos",
        name: "ProjectDiscovery Chaos",
        url: "https://chaos-data.projectdiscovery.io/?domain={domain}",
        auth: Auth::Header("Authorization", "CHAOS_KEY"),
        reliability: 0.85,
        note: "Requires CHAOS_KEY. Enterprise subdomain dataset.",
        paging: Paging::None,
    },
    Source {
        id: "fofa",
        name: "FOFA",
        url: "https://fofa.info/api/v1/search/all",
        auth: Auth::Fofa,
        reliability: 0.80,
        note: "Needs FOFA_EMAIL + FOFA_KEY. Strong CN coverage, query is domain=...",
        paging: Paging::FofaTotal,
    },
    Source {
        id: "quake",
        name: "360 Quake",
        url: "https://quake.360.net/api/v3/search/quake_service?query=domain%3A%22{domain}%22&size=200",
        auth: Auth::Header("X-QuakeToken", "QUAKE_TOKEN"),
        reliability: 0.75,
        note: "Requires QUAKE_TOKEN. Best coverage in CN.",
        paging: Paging::QuakeTotal,
    },
    Source {
        id: "hunter",
        name: "Qianxin Hunter",
        url: "https://hunter.qianxin.com/openApi/search?search=domain%3D%22{domain}%22&page_size=100",
        auth: Auth::Query("api-key", "HUNTER_KEY"),
        reliability: 0.75,
        note: "Requires HUNTER_KEY. Strong CN coverage.",
        paging: Paging::HunterTotal,
    },
];

pub fn env_for(auth: &Auth) -> Option<&'static str> {
    match auth {
        Auth::None => None,
        Auth::Header(_, env) => Some(env),
        Auth::Query(_, env) => Some(env),
        Auth::Fofa => Some("FOFA_KEY"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::Paging;

    fn mode(id: &str) -> Paging {
        SOURCES.iter().find(|s| s.id == id).map(|s| s.paging).unwrap()
    }

    #[test]
    fn capped_sources_declare_how_they_page() {
        assert_eq!(mode("virustotal"), Paging::VtCursor);
        assert_eq!(mode("urlscan"), Paging::UrlscanSearchAfter);
        assert_eq!(mode("fofa"), Paging::FofaTotal);
        assert_eq!(mode("quake"), Paging::QuakeTotal);
        assert_eq!(mode("hunter"), Paging::HunterTotal);
        assert_eq!(mode("crtsh"), Paging::None);
    }
}
