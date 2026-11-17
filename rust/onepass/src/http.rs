//! HTTP layer: bounded retries, per-request timeout, JSON-vs-text agnostic.

use std::time::Duration;

pub enum FetchError {
    MissingKey(&'static str),
    Http(u16),
    Transport(String),
    Timeout,
}

pub struct Resp {
    pub body: String,
    pub status: u16,
}

pub fn fetch(
    url: &str,
    headers: &[(String, String)],
    timeout_secs: u64,
    retries: u32,
) -> Result<Resp, FetchError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("onepass/0.1 (+asset-recon)")
        .build();

    let mut last_err = FetchError::Transport("no attempt".into());
    for attempt in 0..=retries {
        let mut req = agent.get(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(r) => {
                let status = r.status();
                let body = r.into_string().unwrap_or_default();
                return Ok(Resp { body, status });
            }
            Err(ureq::Error::Status(code, r)) => {
                // 404/403 are auth/quota problems: do not retry, it burns quota
                if code == 404 || code == 401 || code == 403 {
                    return Err(FetchError::Http(code));
                }
                if code == 429 {
                    last_err = FetchError::Http(code);
                    if attempt < retries {
                        std::thread::sleep(Duration::from_millis(800 * (attempt as u64 + 1)));
                        continue;
                    }
                    return Err(FetchError::Http(code));
                }
                last_err = FetchError::Http(code);
                let _ = r.into_string();
            }
            Err(ureq::Error::Transport(t)) => {
                let msg = t.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    last_err = FetchError::Timeout;
                } else {
                    last_err = FetchError::Transport(msg);
                }
            }
        }
        if attempt < retries {
            std::thread::sleep(Duration::from_millis(500 * (attempt as u64 + 1)));
        }
    }
    Err(last_err)
}

pub fn err_code(e: &FetchError) -> &'static str {
    match e {
        FetchError::MissingKey(_) => "missing_key",
        FetchError::Http(401) | FetchError::Http(403) => "forbidden",
        FetchError::Http(404) => "not_found",
        FetchError::Http(429) => "rate_limited",
        FetchError::Http(_) => "http_error",
        FetchError::Transport(_) => "transport_error",
        FetchError::Timeout => "timeout",
    }
}

pub fn err_detail(e: &FetchError) -> String {
    match e {
        FetchError::MissingKey(env) => format!("set {} to enable this source", env),
        FetchError::Http(c) => format!("http status {}", c),
        FetchError::Transport(m) => m.clone(),
        FetchError::Timeout => "request timed out".to_string(),
    }
}
