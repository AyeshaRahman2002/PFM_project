# app/threat_intel.py
from __future__ import annotations
from typing import Dict, Any, Optional, Set, Tuple
import os
import ipaddress
from functools import lru_cache
import time

# Config
TI_IP_REPUTATION_PATH = os.getenv("TI_IP_REPUTATION_PATH", "")     # plain text, one CIDR/IP per line
TI_TOR_LIST_PATH      = os.getenv("TI_TOR_LIST_PATH", "")          # plain text, one CIDR/IP per line
TI_BAD_ASN_PATH       = os.getenv("TI_BAD_ASN_PATH", "")           # plain text, one ASN per line (e.g., AS12345)
TI_BAD_EMAIL_DOMAINS  = os.getenv("TI_BAD_EMAIL_DOMAINS", "")      # comma-separated disposable domains
TI_ENABLE             = os.getenv("TI_ENABLE", "1") not in ("0", "false", "False")
TI_DEFAULT_SCORE_BUMPS = {
    "ti_bad_ip": 30,
    "ti_tor_exit": 25,
    "ti_bad_asn": 15,
    "ti_disposable_email": 15,
    # breached cred is intentionally 0 here (don’t infer), leave to future hook:
    "ti_breached_cred": 0,
}

# In-memory state
_STATE: Dict[str, Any] = {
    "loaded_at": 0.0,
    "ip_bad": [],     # list of ipaddress.IPv4Network/IPv6Network
    "ip_tor": [],
    "asn_bad": set(), # set of strings like "AS12345"
    "bad_domains": set(),  # disposable domains
    "counts": {"bad_ip": 0, "tor": 0, "bad_asn": 0, "bad_domains": 0},
}

def _now() -> float:
    return time.time()

def _read_lines(path: str) -> Set[str]:
    out: Set[str] = set()
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.add(s)
    return out

def _parse_cidrs(lines: Set[str]):
    nets = []
    for s in lines:
        try:
            # Accept bare IPs and CIDRs
            if "/" in s:
                nets.append(ipaddress.ip_network(s, strict=False))
            else:
                ip = ipaddress.ip_address(s)
                # /32 or /128 depending on family
                if isinstance(ip, ipaddress.IPv4Address):
                    nets.append(ipaddress.ip_network(f"{s}/32"))
                else:
                    nets.append(ipaddress.ip_network(f"{s}/128"))
        except Exception:
            continue
    return nets

def _parse_asn(lines: Set[str]) -> Set[str]:
    out = set()
    for s in lines:
        s = s.upper().replace(" ", "")
        if s.startswith("AS") and s[2:].isdigit():
            out.add(s)
    return out

def _parse_domains(csv: str) -> Set[str]:
    out = set()
    for piece in (csv or "").split(","):
        d = piece.strip().lower()
        if d:
            out.add(d)
    return out

def _asn_for_ip(_: str) -> Optional[str]:
    return None  # placeholder. the flag will be False unless a resolver is added

def reload() -> Dict[str, Any]:
    """(Re)load feeds from disk/env. Idempotent and fast."""
    if not TI_ENABLE:
        # Clear state if disabled
        _STATE.update({
            "loaded_at": _now(),
            "ip_bad": [], "ip_tor": [],
            "asn_bad": set(), "bad_domains": set(),
            "counts": {"bad_ip": 0, "tor": 0, "bad_asn": 0, "bad_domains": 0},
        })
        return status()

    bad_ip_lines = _read_lines(TI_IP_REPUTATION_PATH)
    tor_lines    = _read_lines(TI_TOR_LIST_PATH)
    asn_lines    = _read_lines(TI_BAD_ASN_PATH)

    _STATE["ip_bad"] = _parse_cidrs(bad_ip_lines)
    _STATE["ip_tor"] = _parse_cidrs(tor_lines)
    _STATE["asn_bad"] = _parse_asn(asn_lines)
    _STATE["bad_domains"] = _parse_domains(TI_BAD_EMAIL_DOMAINS)

    _STATE["counts"] = {
        "bad_ip": len(_STATE["ip_bad"]),
        "tor": len(_STATE["ip_tor"]),
        "bad_asn": len(_STATE["asn_bad"]),
        "bad_domains": len(_STATE["bad_domains"]),
    }
    _STATE["loaded_at"] = _now()
    return status()

def status() -> Dict[str, Any]:
    return {
        "enabled": TI_ENABLE,
        "loaded_at": _STATE["loaded_at"],
        "counts": dict(_STATE["counts"]),
        "sources": {
            "bad_ip": TI_IP_REPUTATION_PATH or "(env/none)",
            "tor": TI_TOR_LIST_PATH or "(env/none)",
            "bad_asn": TI_BAD_ASN_PATH or "(env/none)",
            "bad_domains": TI_BAD_EMAIL_DOMAINS or "(env/none)",
        },
        "score_bumps": TI_DEFAULT_SCORE_BUMPS,
    }

def _ip_in(nets, ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for n in nets:
        if ip_obj in n:
            return True
    return False

@lru_cache(maxsize=10000)
def lookup_ip(ip: str) -> Dict[str, Any]:
    # Return TI flags for an IP. Cached aggressively and invalid IPs return safe defaults.
    out = {
        "ti_bad_ip": False,
        "ti_tor_exit": False,
        "ti_bad_asn": False,
        "ti_asn": None,
        "ti_labels": [],
        "ti_score_bump_suggest": 0,
    }
    if not TI_ENABLE:
        return out
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return out

    if _ip_in(_STATE["ip_bad"], ip):
        out["ti_bad_ip"] = True
        out["ti_labels"].append("bad_ip")
        out["ti_score_bump_suggest"] += TI_DEFAULT_SCORE_BUMPS["ti_bad_ip"]

    if _ip_in(_STATE["ip_tor"], ip):
        out["ti_tor_exit"] = True
        out["ti_labels"].append("tor_exit")
        out["ti_score_bump_suggest"] += TI_DEFAULT_SCORE_BUMPS["ti_tor_exit"]

    asn = _asn_for_ip(ip)
    if asn:
        out["ti_asn"] = asn
        if asn in _STATE["asn_bad"]:
            out["ti_bad_asn"] = True
            out["ti_labels"].append(f"bad_asn:{asn}")
            out["ti_score_bump_suggest"] += TI_DEFAULT_SCORE_BUMPS["ti_bad_asn"]

    return out

def check_email_domain(email: str) -> Dict[str, Any]:
    """
    Flag disposable domains; never logs the full email. (Basic TI.)
    """
    out = {"ti_disposable_email": False, "domain": None}
    if not TI_ENABLE or not email or "@" not in email:
        return out
    domain = email.split("@", 1)[1].strip().lower()
    out["domain"] = domain
    if domain in _STATE["bad_domains"]:
        out["ti_disposable_email"] = True
    return out

def check_breached_cred(_: str) -> Dict[str, Any]:
    """
    Placeholder for k-Anonymity/hibp-style check. Always returns False here.
    DO NOT send raw passwords to any service.
    """
    return {"ti_breached_cred": False}
