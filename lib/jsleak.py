"""Pure-python JS/HTML leak extractor (replaces the cgo-dependent jsluice binary).

Extracts from a page or JS bundle:
  - absolute / relative API paths
  - hostnames and IPv4 addresses
  - common secret patterns (AK/SK, tokens, private keys)
  - sourcemap references
No external dependency, runs on any platform.
"""
from __future__ import annotations

import re

from . import core

# Generic alpha TLD: an explicit whitelist (com|cn|net|...) both missed real
# multi-label suffixes (.com.au) and TRUNCATED matches -- "service.example.com.au"
# was captured as "service.example.com". Consumers must still validate with a
# hostname gate (core.canon_domain); this regex only shapes the token.
# Boundaries are character classes, not \b: \b never fires between a Chinese
# char and a letter (both are \w in unicode mode), so a CJK-flanked host was
# invisible. Excluding "." at the END prevents mid-hostname truncation
# (example.com.evil.io must not be captured as example.com.evil).
DOMAIN = re.compile(
    r"(?<![A-Za-z0-9.\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})"
    r"(?![A-Za-z0-9.\-])", re.I)
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# A path is any quoted string starting with "/" that contains an API-ish
# segment. The keyword may sit at the VERY START of the path (/api/login,
# /admin, /graphql, /v1/health) -- the old regex required >=2 chars before it
# and silently dropped exactly those. "/v\d" is anchored with a leading slash
# so "version numbers" inside words (/avatar1) do not match.
_API_KEYWORD = (r"api|internal|admin|auth|login|logout|sso|oauth|token|user|"
                 r"order|pay|upload|download|graphql|rest|gateway|health|"
                 r"console|dashboard|manage")
API_PATH = re.compile(
    r"""["'\`](/[\w\-./{}$:]*(?:""" + _API_KEYWORD + r"""|/v\d)[\w\-./{}$:]*)["'\`]""",
    re.I)
SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
SECRETS = {
    "aws_ak": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "aws_sk": re.compile(r"(?i)aws.{0,20}?['\"]([0-9a-zA-Z/+=]{40})['\"]"),
    "aliyun_ak": re.compile(r"\b(LTAI[0-9A-Za-z]{12,20})\b"),
    "tencent_ak": re.compile(r"\b(AKID[0-9A-Za-z]{13,30})\b"),
    "google_api": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    "github_token": re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{20,60})\b"),
    "slack_token": re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,80})\b"),
    "jwt": re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "inner_ip": re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
}


def extract(text: str, root_domains: list[str] | None = None) -> dict:
    text = text or ""
    root_domains = [d.lower().lstrip(".") for d in (root_domains or [])]

    def keep_domain(d: str) -> bool:
        d = d.lower()
        if not root_domains:
            return True
        return any(d == r or d.endswith("." + r) for r in root_domains)

    domains = sorted({m.group(1).lower() for m in DOMAIN.finditer(text)})
    # The regex is deliberately permissive (it also matches `03.06.03.118`,
    # which is a version string, not an address). canonicalise every hit and
    # drop what ipaddress rejects: a leading-zero "address" is not routable and
    # storing it put 36 version strings into the asset graph of a real target.
    ips = sorted({core.canon_ip(m.group(0)) for m in IPV4.finditer(text)}
                 - {None})
    paths = sorted({m.group(1) for m in API_PATH.finditer(text)})
    smaps = sorted({m.group(1) for m in SOURCEMAP.finditer(text)})
    secrets = {}
    for name, rx in SECRETS.items():
        hits = sorted({(m.group(1) if m.groups() else m.group(0)) for m in rx.finditer(text)})
        if hits:
            secrets[name] = hits[:20]
    return {
        "domains": [d for d in domains if keep_domain(d)],
        "all_domains": domains,
        "ips": ips,
        "api_paths": paths[:300],
        "sourcemaps": smaps[:20],
        "secrets": secrets,
    }
