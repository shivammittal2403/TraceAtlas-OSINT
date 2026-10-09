#!/usr/bin/env python3

"""

TRACEATLAS BRANDINT — Short safe starter



Defensive brand-abuse / impersonation intelligence only.



Hard boundaries:

- Does NOT create impersonation assets, phishing sites, fake support pages,

  fake social accounts, fake apps, deceptive logos, or typosquat domains.

- Does NOT submit credentials, interact with malicious forms, execute artifacts,

  attempt domain/subdomain takeover, hack, DDoS, deface, harass, or dox.

- Does NOT autonomously file takedown/legal notices.

- Treats candidate websites/social/app/marketplace/ad text as untrusted data.

"""



from __future__ import annotations



import argparse

import hashlib

import json

import re

import sys

import unicodedata

from collections import defaultdict

from datetime import datetime, timezone

from pathlib import Path

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from urllib.parse import urlparse



VERSION = "0.1.0-brandint-short-safe-starter"



ALLOWED_SCOPES = {

    "public_and_authorized_records",

    "authorized_case_evidence",

    "provided_records_only",

}



PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [

    (re.compile(r"(?i)\b(create|build|make|generate|deploy)\s+(phishing|fake|spoof|impersonation)\s+(site|website|page|social|account|app|logo|domain)\b"), "IMPERSONATION_CREATION"),

    (re.compile(r"(?i)\b(register|buy|purchase)\s+(typosquat|lookalike|deceptive|homoglyph)\s+domain\b"), "DECEPTIVE_DOMAIN_REGISTRATION"),

    (re.compile(r"(?i)\b(submit|enter|send|use)\s+(credentials|password|otp|mfa|token|recovery code)\b.*\b(candidate|phishing|fake|login|support)\b"), "CREDENTIAL_SUBMISSION_REQUEST"),

    (re.compile(r"(?i)\b(domain|subdomain)\s+takeover\b"), "TAKEOVER_REQUEST"),

    (re.compile(r"(?i)\b(hack|breach|ddos|deface|take over)\b.*\b(account|domain|site|infrastructure|social)\b"), "ATTACK_OR_TAKEOVER"),

    (re.compile(r"(?i)\b(automatically|autonomously|auto|without review)\s+(submit|file|send)\s+(takedown|abuse|legal|dmca)\b"), "AUTONOMOUS_TAKEDOWN"),

    (re.compile(r"(?i)\b(harass|dox|doxx|publish private|home address|personal phone)\b"), "HARASSMENT_OR_DOXXING"),

    (re.compile(r"(?i)\b(purchase|buy)\s+counterfeit\b.*\b(illicit|resell|fraud)\b"), "COUNTERFEIT_TRAFFICKING"),

]



ASSET_TYPES = {

    "DOMAIN", "URL", "WEBSITE", "EMAIL", "SOCIAL_ACCOUNT", "APP",

    "BROWSER_EXTENSION", "MARKETPLACE_LISTING", "ADVERTISEMENT",

    "PHONE", "PAYMENT_PAGE", "SUPPORT_CHANNEL", "OTHER", "UNKNOWN",

}



TAKEDOWN_STATES = {

    "OBSERVED", "ACTIVE_CANDIDATE", "ACTIVE_SUPPORTED", "INACTIVE",

    "PARKED", "SUSPENDED", "TAKEN_DOWN_REPORTED", "TAKEN_DOWN_VERIFIED",

    "SEIZED", "EXPIRED", "REASSIGNED", "UNKNOWN",

}



SOURCE_RELIABILITY: Dict[str, float] = {

    "official_brand_source": 0.92,

    "official_corporate_source": 0.90,

    "trademark_registry": 0.88,

    "government_warning": 0.86,

    "regulator": 0.86,

    "authorized_brand_protection": 0.82,

    "official_app_store": 0.80,

    "public_website": 0.65,

    "commercial_provider": 0.62,

    "consumer_complaint": 0.50,

    "social_post": 0.35,

    "anonymous_report": 0.20,

    "unknown": 0.30,

}



HOMOGLYPH_MAP = {

    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",

    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X",

    "ο": "o", "α": "a", "ε": "e", "ν": "v", "κ": "k", "ρ": "p", "τ": "t",

    "і": "i", "ј": "j", "ӏ": "l", "ԁ": "d", "ԝ": "w",

}



COUNTRY_SECOND = {

    "uk", "au", "nz", "za", "in", "br", "jp", "kr", "mx", "ar",

    "tr", "il", "sg", "my", "th", "id", "ph", "vn", "pk", "bd",

    "lk", "np", "ng", "ke", "eg", "ma", "tn", "sa", "ae", "qa",

}



SECOND_LEVEL = {

    "co", "com", "net", "org", "gov", "edu", "ac", "sch", "me",

    "ne", "or", "res", "gen", "nom", "info", "biz", "ltd", "plc",

}





# --------------------------------------------------------------------

# Helpers

# --------------------------------------------------------------------



def utc_now() -> str:

    return datetime.now(timezone.utc).isoformat()





def stable_id(prefix: str, *parts: Any) -> str:

    raw = "|".join(str(json_safe(p)) for p in parts)

    return f"{prefix}-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"





def json_safe(obj: Any) -> Any:

    if isinstance(obj, dict):

        return {str(k): json_safe(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set)):

        return [json_safe(x) for x in obj]

    if isinstance(obj, datetime):

        return obj.isoformat()

    if isinstance(obj, bytes):

        return obj.hex()

    if isinstance(obj, (str, int, float, bool, type(None))):

        return obj

    return str(obj)





def normalize_text(value: Any) -> str:

    if value is None:

        return ""

    s = unicodedata.normalize("NFKC", str(value))

    s = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", s)

    return s.strip()





def parse_time(value: Any) -> Optional[datetime]:

    s = normalize_text(value)

    if not s:

        return None

    if s.endswith("Z"):

        s = s[:-1] + "+00:00"

    try:

        dt = datetime.fromisoformat(s)

        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    except Exception:

        pass

    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):

        try:

            dt = datetime.strptime(s, fmt)

            return dt.replace(tzinfo=timezone.utc)

        except Exception:

            continue

    return None





def source_list(*items: Any) -> List[str]:

    out: List[str] = []

    for it in items:

        if it is None:

            continue

        if isinstance(it, list):

            out.extend(normalize_text(x) for x in it if normalize_text(x))

        else:

            s = normalize_text(it)

            if s:

                out.append(s)

    return list(dict.fromkeys(out))





def unique_preserve(items: Iterable[Any]) -> List[Any]:

    seen: Set[str] = set()

    out = []

    for item in items:

        key = json.dumps(json_safe(item), sort_keys=True, ensure_ascii=False)

        if key not in seen:

            seen.add(key)

            out.append(item)

    return out





def add_unique(lst: List[Any], item: Any) -> None:

    if item is None:

        return

    key = json.dumps(json_safe(item), sort_keys=True, ensure_ascii=False)

    for existing in lst:

        if json.dumps(json_safe(existing), sort_keys=True, ensure_ascii=False) == key:

            return

    lst.append(item)





def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:

    return max(lo, min(hi, value))





def norm_enum(value: Any, allowed: Set[str], default: str = "UNKNOWN") -> str:

    s = normalize_text(value).upper().replace("-", "_").replace(" ", "_")

    return s if s in allowed else default





def mask_value(value: Any, keep: int = 2) -> str:

    s = normalize_text(value)

    if not s:

        return ""

    if len(s) <= keep * 2:

        return "*" * len(s)

    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]





# --------------------------------------------------------------------

# Domain / similarity utilities

# --------------------------------------------------------------------



def extract_host(value: Any) -> str:

    s = normalize_text(value)

    if not s:

        return ""

    if "@" in s and "." in s.rsplit("@", 1)[-1] and "://" not in s:

        s = s.rsplit("@", 1)[-1]

    parsed = urlparse(s if "://" in s else "//" + s)

    host = (parsed.hostname or "").strip().lower().rstrip(".")

    if not host and "@" in s:

        host = s.rsplit("@", 1)[-1].split(":")[0].strip().lower()

    return host.split(":")[0]





def ascii_domain(host: str) -> str:

    host = normalize_text(host).lower().rstrip(".")

    try:

        return host.encode("idna").decode("ascii")

    except Exception:

        return host





def registrable_domain(host: str) -> str:

    host = ascii_domain(extract_host(host) or host)

    parts = [p for p in host.split(".") if p]

    if len(parts) <= 2:

        return host

    if parts[-1] in COUNTRY_SECOND and len(parts) >= 3 and parts[-2] in SECOND_LEVEL:

        return ".".join(parts[-3:])

    return ".".join(parts[-2:])





def homoglyph_normalize(s: str) -> str:

    out = []

    for ch in normalize_text(s):

        out.append(HOMOGLYPH_MAP.get(ch, ch))

    return unicodedata.normalize("NFKD", "".join(out)).encode("ascii", "ignore").decode("ascii").lower()





def normalized_compare(s: Any) -> str:

    return re.sub(r"[^a-z0-9]", "", homoglyph_normalize(s))





def token_set(s: Any) -> Set[str]:

    return set(re.findall(r"[a-z0-9]+", homoglyph_normalize(s)))





def levenshtein(a: str, b: str) -> int:

    if a == b:

        return 0

    if not a:

        return len(b)

    if not b:

        return len(a)

    prev = list(range(len(b) + 1))

    for i, ca in enumerate(a, 1):

        cur = [i]

        for j, cb in enumerate(b, 1):

            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))

        prev = cur

    return prev[-1]





def lexical_similarity(candidate: Any, brands: List[str]) -> Tuple[str, float, Optional[str]]:

    cand = normalized_compare(candidate)

    best_score = 0.0

    best_brand = None

    exact = False

    for brand in brands:

        bn = normalized_compare(brand)

        if not bn:

            continue

        if cand == bn:

            exact = True

            score = 1.0

        else:

            dist = levenshtein(cand, bn)

            score = 1.0 - dist / float(max(len(cand), len(bn), 1))

            tc, tb = token_set(cand), token_set(bn)

            if tc and tb:

                score = max(score, len(tc & tb) / float(len(tc | tb)))

        if score > best_score:

            best_score = score

            best_brand = brand

    if exact:

        state = "EXACT_BRAND_MATCH"

    elif best_score >= 0.85:

        state = "HIGH_LEXICAL_SIMILARITY"

    elif best_score >= 0.65:

        state = "MODERATE_SIMILARITY"

    elif best_score >= 0.40:

        state = "LOW_SIMILARITY"

    else:

        state = "NO_MEANINGFUL_SIMILARITY"

    return state, round(best_score, 4), best_brand





# --------------------------------------------------------------------

# Policy / authorization

# --------------------------------------------------------------------



def collect_intent_text(manifest: Dict[str, Any]) -> str:

    parts = [

        normalize_text(manifest.get("objective", "")),

        " ".join(normalize_text(q) for q in manifest.get("questions", []) or []),

        " ".join(normalize_text(x) for x in manifest.get("requested_actions", []) or []),

    ]

    return " ".join(parts)





def policy_screen(manifest: Dict[str, Any]) -> List[str]:

    blob = collect_intent_text(manifest)

    blocked = []

    for pat, label in PROHIBITED_PATTERNS:

        if pat.search(blob):

            blocked.append(label)

    return list(dict.fromkeys(blocked))





def authorization_check(manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:

    auth = manifest.get("authorization") or {}

    reasons: List[str] = []

    if not auth.get("approved"):

        reasons.append("AUTHORIZATION_MISSING_OR_NOT_APPROVED")

    if auth.get("scope", "provided_records_only") not in ALLOWED_SCOPES:

        reasons.append("UNSUPPORTED_SCOPE")

    mode = auth.get("model_mode", "LOCAL_ONLY")

    if mode not in {"LOCAL_ONLY", "HYBRID", "CLOUD"}:

        reasons.append("UNKNOWN_MODEL_MODE")

    if mode == "CLOUD" and not auth.get("cloud_approved"):

        reasons.append("CLOUD_PROCESSING_NOT_APPROVED")

    return len(reasons) == 0, reasons





# --------------------------------------------------------------------

# Sources / independence

# --------------------------------------------------------------------



def collect_referenced_source_ids(obj: Any) -> Set[str]:

    ids: Set[str] = set()



    def walk(x: Any) -> None:

        if isinstance(x, dict):

            for k, v in x.items():

                if k in ("source_id", "source_ids"):

                    if isinstance(v, list):

                        ids.update(normalize_text(i) for i in v if normalize_text(i))

                    else:

                        s = normalize_text(v)

                        if s:

                            ids.add(s)

                walk(v)

        elif isinstance(x, list):

            for i in x:

                walk(i)



    walk(obj)

    return ids





def ingest_sources(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:

    sources: Dict[str, Dict[str, Any]] = {}

    for s in manifest.get("sources", []) or []:

        sid = normalize_text(s.get("source_id"))

        if not sid:

            continue

        stype = normalize_text(s.get("source_type", "unknown")).lower()

        rel = s.get("reliability", SOURCE_RELIABILITY.get(stype, SOURCE_RELIABILITY["unknown"]))

        sources[sid] = {

            "source_id": sid,

            "source_type": stype,

            "upstream_source_id": normalize_text(s.get("upstream_source_id")) or None,

            "reliability": clamp(float(rel)),

            "limitations": list(s.get("limitations", []) or []),

        }

    for sid in collect_referenced_source_ids(manifest):

        if sid not in sources:

            sources[sid] = {

                "source_id": sid,

                "source_type": "unknown",

                "upstream_source_id": None,

                "reliability": SOURCE_RELIABILITY["unknown"],

                "limitations": ["Source referenced but not defined."],

            }

    return sources





def resolve_source_root(sid: str, sources: Dict[str, Dict[str, Any]], memo: Dict[str, str], visiting: Set[str]) -> str:

    if sid in memo:

        return memo[sid]

    if sid in visiting:

        return sid

    visiting.add(sid)

    src = sources.get(sid)

    if not src or not src.get("upstream_source_id"):

        memo[sid] = sid

    else:

        memo[sid] = resolve_source_root(src["upstream_source_id"], sources, memo, visiting)

    visiting.discard(sid)

    return memo[sid]





def build_source_roots(sources: Dict[str, Dict[str, Any]]) -> Dict[str, str]:

    memo: Dict[str, str] = {}

    for sid in sources:

        resolve_source_root(sid, sources, memo, set())

    return memo





def source_family_ids(source_ids: List[str], roots: Dict[str, str]) -> List[str]:

    return list(dict.fromkeys(roots.get(sid, sid) for sid in source_ids))





def source_quality(source_ids: List[str], sources: Dict[str, Dict[str, Any]]) -> Tuple[float, float]:

    vals = [float(sources.get(sid, {}).get("reliability", SOURCE_RELIABILITY["unknown"])) for sid in source_ids]

    if not vals:

        return SOURCE_RELIABILITY["unknown"], SOURCE_RELIABILITY["unknown"]

    return max(vals), sum(vals) / len(vals)





def independence_state(families: List[str], sources: Dict[str, Dict[str, Any]], source_ids: List[str]) -> str:

    if not source_ids:

        return "UNKNOWN"

    if len(families) <= 1:

        return "DEPENDENT"

    rels = [sources.get(sid, {}).get("reliability", 0.3) for sid in source_ids]

    types = {sources.get(sid, {}).get("source_type", "unknown") for sid in source_ids}

    if len(types) == 1 and max(rels) < 0.70:

        return "PARTIALLY_DEPENDENT"

    if max(rels) >= 0.70:

        return "INDEPENDENT"

    return "PARTIALLY_DEPENDENT"





# --------------------------------------------------------------------

# Brands / candidates

# --------------------------------------------------------------------



def ingest_brands(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:

    brands: Dict[str, Dict[str, Any]] = {}

    for idx, b in enumerate(manifest.get("brands", []) or []):

        bid = normalize_text(b.get("brand_id") or b.get("id") or b.get("name") or f"BRAND-{idx}")

        name = normalize_text(b.get("name") or bid)

        aliases = source_list(b.get("aliases"), name)

        official_domains_raw = source_list(b.get("official_domains"))

        official_urls_raw = source_list(b.get("official_urls"))

        brands[bid] = {

            "brand_id": bid,

            "name": name,

            "aliases": aliases,

            "all_names": list(dict.fromkeys([name] + aliases)),

            "legal_owner": normalize_text(b.get("legal_owner")) or None,

            "operator_entities": source_list(b.get("operator_entities")),

            "licensed_entities": source_list(b.get("licensed_entities")),

            "official_domains": [registrable_domain(extract_host(d)) for d in official_domains_raw if extract_host(d)],

            "official_hosts": [extract_host(d) for d in official_domains_raw + official_urls_raw if extract_host(d)],

            "official_social_accounts": [normalize_text(s).lstrip("@").lower() for s in source_list(b.get("official_social_accounts"))],

            "official_apps": [normalize_text(a).lower() for a in source_list(b.get("official_apps"))],

            "official_support_channels": source_list(b.get("official_support_channels")),

            "official_phone_numbers": [normalize_text(p) for p in source_list(b.get("official_phone_numbers"))],

            "official_email_domains": [extract_host(e) or normalize_text(e).lower() for e in source_list(b.get("official_email_domains"))],

            "authorized_resellers": source_list(b.get("authorized_resellers")),

            "authorized_partners": source_list(b.get("authorized_partners")),

            "licensees": source_list(b.get("licensees")),

            "historical_domains": [registrable_domain(extract_host(d)) for d in source_list(b.get("historical_domains")) if extract_host(d)],

            "trademarks": b.get("trademarks", []) or [],

            "source_ids": source_list(b.get("source_ids"), b.get("source_id")),

            "limitations": [

                "Brand is not legal entity, product, domain, or trademark automatically.",

                "Official baseline must be maintained over time; historical assets may expire or migrate.",

            ],

        }

    return brands





def matches_list(asset: Dict[str, Any], items: List[str]) -> bool:

    v = normalize_text(asset.get("value")).lower()

    r = normalize_text(asset.get("registrable_domain")).lower()

    h = normalize_text(asset.get("host")).lower()

    for item in items or []:

        it = normalize_text(item).lower()

        if not it:

            continue

        ih = extract_host(it)

        ir = registrable_domain(ih) if ih else it

        if it in (v, r, h):

            return True

        if ih and ih == h:

            return True

        if ir and ir == r:

            return True

        if len(it) > 4 and (it in v or it in r):

            return True

    return False





def ingest_candidates(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:

    assets: List[Dict[str, Any]] = []

    raw_assets = manifest.get("candidate_assets") or manifest.get("candidates") or []

    for idx, c in enumerate(raw_assets):

        value = normalize_text(c.get("value") or c.get("url") or c.get("domain") or c.get("handle") or c.get("package") or c.get("phone") or c.get("email") or "")

        host = extract_host(value)

        reg = registrable_domain(host) if host else ""

        ind = c.get("indicators", {}) or {}

        display = normalize_text(c.get("display_name") or c.get("title") or "")

        claims = bool(ind.get("claims_official")) or bool(re.search(r"(?i)\b(official|authorized|support|secure login|customer service)\b", display or value))

        assets.append({

            "asset_id": normalize_text(c.get("asset_id") or c.get("id") or f"ASSET-{idx}"),

            "brand_id": normalize_text(c.get("brand_id")) or None,

            "asset_type": norm_enum(c.get("asset_type"), ASSET_TYPES),

            "value": value,

            "display_name": display or None,

            "host": host,

            "registrable_domain": reg,

            "ascii_domain": ascii_domain(host),

            "unicode_domain": host,

            "indicators": {

                "presents_login_form": bool(ind.get("presents_login_form")),

                "requests_credentials": bool(ind.get("requests_credentials")),

                "requests_payment": bool(ind.get("requests_payment")),

                "uses_brand_logo": bool(ind.get("uses_brand_logo")),

                "copies_official_content": bool(ind.get("copies_official_content")),

                "claims_official": bool(ind.get("claims_official", claims)),

                "redirect_chain": bool(ind.get("redirect_chain")),

                "malware_artifact": bool(ind.get("malware_artifact")),

            },

            "features": {

                "registrar": normalize_text(c.get("registrar")) or None,

                "hosting_ip": normalize_text(c.get("hosting_ip")) or None,

                "asn": normalize_text(c.get("asn")) or None,

                "cert_fingerprint": normalize_text(c.get("cert_fingerprint")) or None,

                "payment_account": normalize_text(c.get("payment_account")) or None,

                "phone": normalize_text(c.get("phone")) or None,

                "email": normalize_text(c.get("email")) or None,

                "logo_hash": normalize_text(c.get("logo_hash")) or None,

                "favicon_hash": normalize_text(c.get("favicon_hash")) or None,

                "template_hash": normalize_text(c.get("template_hash")) or None,

                "analytics_id": normalize_text(c.get("analytics_id")) or None,

            },

            "timestamps": {

                "registered_at": normalize_text(c.get("registered_at")) or None,

                "first_seen": normalize_text(c.get("first_seen")) or None,

                "observed_at": normalize_text(c.get("observed_at")) or None,

            },

            "takedown_status": norm_enum(c.get("takedown_status"), TAKEDOWN_STATES),

            "current_activity": c.get("current_activity"),

            "source_ids": source_list(c.get("source_ids"), c.get("source_id")),

            "limitations": list(c.get("limitations", []) or []) + [

                "Candidate content is untrusted. No credentials submitted, no forms interacted, no artifacts executed.",

                "Similarity alone is not impersonation; authorization and behavior must be checked.",

            ],

        })

    return assets





# --------------------------------------------------------------------

# Analysis

# --------------------------------------------------------------------



def analyze_assets(

    assets: List[Dict[str, Any]],

    brands: Dict[str, Dict[str, Any]],

    sources: Dict[str, Dict[str, Any]],

    roots: Dict[str, str],

) -> List[Dict[str, Any]]:

    results = []

    official_auth = {"OFFICIAL_VERIFIED", "AUTHORIZED_RESELLER", "AUTHORIZED_PARTNER", "AUTHORIZED_LICENSEE"}



    for a in assets:

        brand = brands.get(a.get("brand_id") or "", {})

        names = brand.get("all_names") or []



        if not brand and brands:

            probe = a.get("registrable_domain") or a.get("display_name") or a.get("value") or ""

            best = None

            for bid, b in brands.items():

                st, sc, _ = lexical_similarity(probe, b.get("all_names", []))

                if sc >= 0.65 and (best is None or sc > best[1]):

                    best = (bid, sc, st)

            if best:

                a["brand_id"] = best[0]

                brand = brands[best[0]]

                names = brand.get("all_names", [])



        if not names and a.get("brand_id"):

            names = [a["brand_id"]]



        probe = a.get("registrable_domain") or a.get("display_name") or a.get("value") or ""

        sim_state, sim_score, sim_brand = lexical_similarity(probe, names)



        auth = "UNKNOWN"

        if a.get("registrable_domain") in brand.get("official_domains", []) or a.get("host") in brand.get("official_hosts", []):

            auth = "OFFICIAL_VERIFIED"

        elif matches_list(a, brand.get("official_social_accounts", [])) or matches_list(a, brand.get("official_apps", [])):

            auth = "OFFICIAL_VERIFIED"

        elif matches_list(a, brand.get("authorized_resellers", [])):

            auth = "AUTHORIZED_RESELLER"

        elif matches_list(a, brand.get("authorized_partners", [])):

            auth = "AUTHORIZED_PARTNER"

        elif matches_list(a, brand.get("licensees", [])):

            auth = "AUTHORIZED_LICENSEE"

        elif sim_state in {"EXACT_BRAND_MATCH", "HIGH_LEXICAL_SIMILARITY"}:

            auth = "UNAFFILIATED"



        ind = a["indicators"]

        cred = ind["presents_login_form"] or ind["requests_credentials"]

        pay = ind["requests_payment"]

        brandish = ind["uses_brand_logo"] or ind["copies_official_content"] or ind["claims_official"] or sim_state in {"EXACT_BRAND_MATCH", "HIGH_LEXICAL_SIMILARITY"}



        fams = source_family_ids(a.get("source_ids", []), roots)

        indep = independence_state(fams, sources, a.get("source_ids", []))

        max_rel, avg_rel = source_quality(a.get("source_ids", []), sources)

        independent_reliable = indep == "INDEPENDENT" and max_rel >= 0.70 and len(fams) >= 2



        if auth in official_auth:

            abuse = "NO_ABUSE_EVIDENCE"

        elif cred and pay and brandish and sim_state in {"EXACT_BRAND_MATCH", "HIGH_LEXICAL_SIMILARITY"}:

            abuse = "ABUSE_SUPPORTED" if independent_reliable else "ABUSE_CANDIDATE"

        elif cred and brandish and sim_state in {"EXACT_BRAND_MATCH", "HIGH_LEXICAL_SIMILARITY", "MODERATE_SIMILARITY"}:

            abuse = "IMPERSONATION_SUPPORTED" if independent_reliable else "IMPERSONATION_CANDIDATE"

        elif pay and brandish and sim_state in {"EXACT_BRAND_MATCH", "HIGH_LEXICAL_SIMILARITY"}:

            abuse = "ABUSE_CANDIDATE"

        elif ind["claims_official"] and auth not in official_auth:

            abuse = "IMPERSONATION_CANDIDATE"

        elif brandish and sim_state in {"EXACT_BRAND_MATCH", "HIGH_LEXICAL_SIMILARITY"}:

            abuse = "IMPERSONATION_CANDIDATE"

        elif sim_state in {"HIGH_LEXICAL_SIMILARITY", "MODERATE_SIMILARITY"}:

            abuse = "SIMILARITY_ONLY"

        elif auth == "UNAFFILIATED":

            abuse = "UNAFFILIATED"

        else:

            abuse = "UNKNOWN"



        a.update({

            "brand_resolution": {

                "brand_id": a.get("brand_id"),

                "matched_brand_name": sim_brand,

                "similarity_state": sim_state,

                "similarity_score": sim_score,

            },

            "authorization_state": auth,

            "abuse_state": abuse,

            "source_independence": {

                "state": indep,

                "families": fams,

                "max_reliability": round(max_rel, 4),

                "avg_reliability": round(avg_rel, 4),

            },

            "risk_indicators": {

                "credential_solicitation": cred,

                "payment_solicitation": pay,

                "brand_impersonation_indicators": brandish,

                "malware_artifact": ind["malware_artifact"],

            },

        })

        results.append(a)

    return results





def cluster_campaigns(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    buckets: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))

    sensitive = {"payment_account", "phone", "email"}

    for a in assets:

        for k, v in (a.get("features") or {}).items():

            if v:

                buckets[k][normalize_text(v).lower()].add(a["asset_id"])

    clusters = []

    for feat, vals in buckets.items():

        for val, ids in vals.items():

            if len(ids) > 1:

                clusters.append({

                    "cluster_id": stable_id("CLUSTER", feat, val),

                    "shared_feature": feat,

                    "shared_value": mask_value(val) if feat in sensitive else val,

                    "asset_ids": sorted(ids),

                    "state": "POSSIBLE_CLUSTER",

                    "limitations": [

                        "Shared template/hosting/payment/DNS/certificate can be legitimate or abused.",

                        "Cluster is not real-world actor attribution.",

                    ],

                })

    return clusters





def detect_contradictions(assets: List[Dict[str, Any]], brands: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:

    contr = []

    official_auth = {"OFFICIAL_VERIFIED", "AUTHORIZED_RESELLER", "AUTHORIZED_PARTNER", "AUTHORIZED_LICENSEE"}

    for a in assets:

        brand = brands.get(a.get("brand_id") or "", {})

        if a["indicators"]["claims_official"] and a["authorization_state"] not in official_auth:

            contr.append({

                "contradiction_id": stable_id("CTR", "claim_official", a["asset_id"]),

                "type": "CLAIMED_OFFICIAL_NOT_BASELINED",

                "severity": "MATERIAL",

                "asset_id": a["asset_id"],

                "detail": "Asset claims official/authorized status but is not in current official baseline.",

                "possible_causes": ["outdated baseline", "new regional partner", "impersonation", "reseller not recorded"],

            })

        if a["authorization_state"] == "AUTHORIZED_RESELLER" and (a["risk_indicators"]["credential_solicitation"] or a["risk_indicators"]["payment_solicitation"]):

            contr.append({

                "contradiction_id": stable_id("CTR", "reseller_risk", a["asset_id"]),

                "type": "AUTHORIZED_RESELLER_WITH_HIGH_RISK_BEHAVIOR",

                "severity": "MATERIAL",

                "asset_id": a["asset_id"],

                "detail": "Asset appears authorized but solicits credentials/payment; requires review before action.",

                "possible_causes": ["legitimate login/payment", "compromised partner", "scope creep", "misclassification"],

            })

        if a["abuse_state"] in {"IMPERSONATION_SUPPORTED", "ABUSE_SUPPORTED"} and a["source_independence"]["state"] != "INDEPENDENT":

            contr.append({

                "contradiction_id": stable_id("CTR", "source_dep", a["asset_id"]),

                "type": "SUPPORTED_ABUSE_WITH_DEPENDENT_SOURCES",

                "severity": "MATERIAL",

                "asset_id": a["asset_id"],

                "detail": "Abuse marked supported but sources are not independent.",

                "possible_causes": ["syndicated complaint", "same screenshot", "one provider feed"],

            })

        if a.get("takedown_status") in {"TAKEN_DOWN_VERIFIED", "SUSPENDED"} and a.get("current_activity") in (True, "ACTIVE", "active"):

            contr.append({

                "contradiction_id": stable_id("CTR", "takedown_active", a["asset_id"]),

                "type": "CURRENT_ACTIVITY_AFTER_TAKEDOWN",

                "severity": "MATERIAL",

                "asset_id": a["asset_id"],

                "detail": "Asset reported takedown/suspended but current activity is indicated.",

                "possible_causes": ["re-registration", "redirect", "new infrastructure", "stale takedown status"],

            })

        if a.get("registrable_domain") in brand.get("historical_domains", []) and a["authorization_state"] != "OFFICIAL_VERIFIED":

            contr.append({

                "contradiction_id": stable_id("CTR", "historical", a["asset_id"]),

                "type": "HISTORICAL_OFFICIAL_ASSET_CANDIDATE",

                "severity": "LOW",

                "asset_id": a["asset_id"],

                "detail": "Asset matches historical official domain; current control era must be resolved.",

                "possible_causes": ["domain migration", "expiry", "reassignment", "historical abuse"],

            })

    return unique_preserve(contr)





def build_hypotheses(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    hyp = []

    for a in assets:

        aid = a["asset_id"]



        def add(category: str, statement: str, support: List[str], opposition: List[str], unknowns: List[str], falsify: List[str]) -> None:

            hyp.append({

                "hypothesis_id": stable_id("HYP", aid, category),

                "asset_id": aid,

                "category": category,

                "statement": statement,

                "support": support,

                "opposition": opposition,

                "unknowns": unknowns,

                "falsification_conditions": falsify,

                "status": "CANDIDATE",

            })



        add("MALICIOUS_IMPERSONATION",

            "Candidate may be malicious brand impersonation.",

            [f"authorization={a['authorization_state']}", f"abuse={a['abuse_state']}", f"similarity={a['brand_resolution']['similarity_state']}"],

            ["Authorized reseller/partner/fan use possible.", "Dependent sources may overstate corroboration."],

            ["Operator identity", "current control era", "authorization scope"],

            ["Official baseline or authorized partner record confirms legitimacy."])

        add("AUTHORIZED_RESELLER_OR_PARTNER",

            "Candidate may be authorized reseller, partner, franchisee, or licensee.",

            [f"authorization={a['authorization_state']}"],

            ["Claims official but absent from baseline.", "Credential/payment behavior unusual."],

            ["Reseller directory completeness", "regional license scope"],

            ["No authorization evidence and independent abuse indicators remain."])

        add("FAN_COMMUNITY_PARODY",

            "Candidate may be fan, community, review, parody, or news use.",

            ["Unofficial but non-commercial use is common."],

            ["Credential/payment solicitation or logo misuse weakens this hypothesis."],

            ["Declared purpose", "platform policy"],

            ["Behavior solicits credentials/payment or impersonates support."])

        add("HISTORICAL_CONTROL_CHANGE",

            "Candidate may have changed control since historical abuse/official use.",

            ["Domain/account lifecycle can change."],

            ["Current indicators suggest active abuse."],

            ["Registration history", "DNS history", "certificate history"],

            ["Control-era evidence shows same operator and continuous abuse."])

        add("UNRELATED_SIMILARITY",

            "Candidate may be unrelated despite lexical similarity.",

            ["Similar names can be coincidental or linguistic."],

            ["Strong brand/content/behavior indicators exist."],

            ["Brand context", "market overlap"],

            ["Content/infrastructure/behavior links to brand abuse."])

    return hyp[:1000]





def build_gaps(assets: List[Dict[str, Any]], brands: Dict[str, Dict[str, Any]], contradictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    gaps = []

    for bid, b in brands.items():

        if not b.get("official_domains") and not b.get("official_social_accounts") and not b.get("official_apps"):

            gaps.append({

                "gap_id": stable_id("GAP", "baseline", bid),

                "type": "OFFICIAL_BASELINE_INCOMPLETE",

                "importance": "HIGH",

                "brand_id": bid,

                "recommended_source": "Official brand site, corporate filings, app-store developer page, official social links.",

                "specialist": "BRANDINT",

                "expected_information_value": "Prevent similarity-only false positives.",

            })

    for a in assets:

        if a["authorization_state"] == "UNKNOWN":

            gaps.append({

                "gap_id": stable_id("GAP", "auth", a["asset_id"]),

                "type": "AUTHORIZATION_UNRESOLVED",

                "importance": "HIGH",

                "asset_id": a["asset_id"],

                "recommended_source": "Authorized reseller/partner directory, brand statement, licensee record.",

                "specialist": "BRANDINT / CORPINT",

                "expected_information_value": "Distinguish abuse from authorized commercial use.",

            })

        if not a.get("timestamps", {}).get("registered_at") and not a.get("timestamps", {}).get("first_seen"):

            gaps.append({

                "gap_id": stable_id("GAP", "lifecycle", a["asset_id"]),

                "type": "DOMAIN_CONTROL_ERA_UNRESOLVED",

                "importance": "MEDIUM",

                "asset_id": a["asset_id"],

                "recommended_source": "RDAP/WHOIS history, DNS history, certificate transparency, web archive.",

                "specialist": "DOMAININT / CERTINT / WEBINT",

                "expected_information_value": "Avoid historical-to-current contamination.",

            })

        if a["risk_indicators"]["credential_solicitation"] or a["risk_indicators"]["payment_solicitation"]:

            gaps.append({

                "gap_id": stable_id("GAP", "fraud", a["asset_id"]),

                "type": "FRAUD_OR_CREDENTIAL_RISK_CONTEXT",

                "importance": "HIGH",

                "asset_id": a["asset_id"],

                "recommended_source": "Authorized fraud telemetry, payment intelligence, victim report correlation.",

                "specialist": "FRAUDINT / FININT / CREDINT",

                "expected_information_value": "Assess consumer harm without interacting.",

            })

        if a["indicators"]["malware_artifact"]:

            gaps.append({

                "gap_id": stable_id("GAP", "malware", a["asset_id"]),

                "type": "MALWARE_ARTIFACT_HANDOFF_REQUIRED",

                "importance": "HIGH",

                "asset_id": a["asset_id"],

                "recommended_source": "Sandboxed malware analysis, app/package analysis.",

                "specialist": "MALINT / APPINT",

                "expected_information_value": "Do not execute or install candidate artifacts.",

            })

    for c in contradictions:

        gaps.append({

            "gap_id": stable_id("GAP", "ctr", c["contradiction_id"]),

            "type": "BRAND_CONTRADICTION_UNRESOLVED",

            "importance": "HIGH" if c.get("severity") == "MATERIAL" else "MEDIUM",

            "contradiction_id": c["contradiction_id"],

            "recommended_source": "Official baseline, control-era evidence, independent source pedigree.",

            "specialist": "BRANDINT / HUMAN_REVIEW",

            "expected_information_value": "Resolve conflict before consequential action.",

        })

    return gaps[:1000]





def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

    actions = []

    prio = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    for g in gaps:

        t = g.get("type")

        if t == "OFFICIAL_BASELINE_INCOMPLETE":

            action = "Expand official brand baseline from authorized/public sources before classifying abuse."

        elif t == "AUTHORIZATION_UNRESOLVED":

            action = "Check reseller/partner/licensee directory and brand authorization scope."

        elif t == "DOMAIN_CONTROL_ERA_UNRESOLVED":

            action = "Retrieve passive domain/DNS/certificate/archive history; do not perform intrusive validation."

        elif t == "FRAUD_OR_CREDENTIAL_RISK_CONTEXT":

            action = "Preserve evidence and hand credential/payment risk to FRAUDINT/FININT; do not submit credentials."

        elif t == "MALWARE_ARTIFACT_HANDOFF_REQUIRED":

            action = "Hash and hand artifact to MALINT/APPINT; do not execute, install, or open."

        elif t == "BRAND_CONTRADICTION_UNRESOLVED":

            action = "Resolve contradiction with independent authoritative sources before takedown/legal recommendation."

        else:

            action = "Gather additional authorized defensive evidence."

        actions.append({

            "action": action,

            "gap_id": g.get("gap_id"),

            "priority": g.get("importance", "MEDIUM"),

            "expected_information_value": g.get("expected_information_value"),

            "prohibited_alternatives": [

                "Do not create impersonation/phishing/fake assets.",

                "Do not submit credentials or interact with forms.",

                "Do not attempt domain/subdomain takeover or hack infrastructure.",

                "Do not autonomously file takedown/legal notices.",

                "Do not harass or dox suspected operators.",

            ],

        })

    actions.sort(key=lambda x: prio.get(x.get("priority", "LOW"), 9))

    return actions[:300]





def build_handoffs(assets: List[Dict[str, Any]], brands: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:

    hands = []

    seen = set()



    def add(spec: str, reason: str, payload: Dict[str, Any]) -> None:

        key = (spec, json.dumps(json_safe(payload), sort_keys=True, ensure_ascii=False))

        if key not in seen:

            seen.add(key)

            hands.append({"specialist": spec, "reason": reason, "payload": payload})



    if brands:

        add("CORPINT", "Brand/legal entity/ownership resolution may be required.", {"brand_ids": list(brands.keys())[:100]})

    if any(a.get("registrable_domain") for a in assets):

        add("DOMAININT / DNSINT / CERTINT", "Domain lifecycle, DNS, and certificate context required for control-era analysis.", {"asset_ids": [a["asset_id"] for a in assets if a.get("registrable_domain")][:100]})

    if any(a.get("asset_type") in {"URL", "WEBSITE"} for a in assets):

        add("WEBINT", "Safe website preservation/content analysis required.", {"asset_ids": [a["asset_id"] for a in assets if a.get("asset_type") in {"URL", "WEBSITE"}][:100]})

    if any(a.get("asset_type") == "SOCIAL_ACCOUNT" for a in assets):

        add("SOCMINT", "Social account history/network context required.", {"asset_ids": [a["asset_id"] for a in assets if a.get("asset_type") == "SOCIAL_ACCOUNT"][:100]})

    if any(a.get("asset_type") in {"APP", "BROWSER_EXTENSION"} for a in assets):

        add("APPINT / MOBILEINT", "App/extension package, publisher, permissions, and behavior analysis required.", {"asset_ids": [a["asset_id"] for a in assets if a.get("asset_type") in {"APP", "BROWSER_EXTENSION"}][:100]})

    if any(a.get("asset_type") == "MARKETPLACE_LISTING" for a in assets):

        add("MARKETPLACEINT / TECHINT", "Seller/listing/authenticity context required.", {"asset_ids": [a["asset_id"] for a in assets if a.get("asset_type") == "MARKETPLACE_LISTING"][:100]})

    if any(a.get("asset_type") == "ADVERTISEMENT" for a in assets):

        add("ADINT", "Advertiser/destination/campaign context required.", {"asset_ids": [a["asset_id"] for a in assets if a.get("asset_type") == "ADVERTISEMENT"][:100]})

    if any(a["risk_indicators"]["credential_solicitation"] or a["risk_indicators"]["payment_solicitation"] for a in assets):

        add("FRAUDINT / FININT / CREDINT", "Credential/payment fraud context requires fraud/financial specialist.", {"asset_ids": [a["asset_id"] for a in assets if a["risk_indicators"]["credential_solicitation"] or a["risk_indicators"]["payment_solicitation"]][:100]})

    if any(a["indicators"]["malware_artifact"] for a in assets):

        add("MALINT", "Malware artifact handoff required; do not execute.", {"asset_ids": [a["asset_id"] for a in assets if a["indicators"]["malware_artifact"]][:100]})

    if any(b.get("trademarks") for b in brands.values()):

        add("LEGALINT", "Trademark/legal infringement determinations require human legal review.", {"brand_ids": [bid for bid, b in brands.items() if b.get("trademarks")][:100]})

    return hands





class GraphMemory:

    def __init__(self) -> None:

        self.nodes: List[Dict[str, Any]] = []

        self.edges: List[Dict[str, Any]] = []

        self.ids: Set[str] = set()



    def node(self, ntype: str, nid: str, props: Optional[Dict[str, Any]] = None) -> None:

        if nid and nid not in self.ids:

            self.ids.add(nid)

            self.nodes.append({"type": ntype, "id": nid, "properties": props or {}})



    def edge(self, frm: str, to: str, etype: str, props: Optional[Dict[str, Any]] = None) -> None:

        if frm and to:

            self.edges.append({"from": frm, "to": to, "type": etype, "properties": props or {}})



    def to_dict(self) -> Dict[str, Any]:

        return {

            "nodes": self.nodes[:2000],

            "edges": self.edges[:4000],

            "note": "Brand graph preserves baseline, candidate relationships, uncertainty, and source dependence. It does not prove operator identity or authorize takedown.",

        }





def build_graph(assets: List[Dict[str, Any]], brands: Dict[str, Dict[str, Any]], clusters: List[Dict[str, Any]], contradictions: List[Dict[str, Any]], hypotheses: List[Dict[str, Any]], gaps: List[Dict[str, Any]], sources: Dict[str, Dict[str, Any]]) -> GraphMemory:

    g = GraphMemory()

    for bid, b in brands.items():

        g.node("Brand", bid, {"name": b.get("name"), "legal_owner": b.get("legal_owner")})

        for d in b.get("official_domains", []):

            g.node("Domain", d, {"official": True})

            g.edge(bid, d, "OFFICIAL_DOMAIN_OF", {})

    for a in assets:

        g.node("CandidateAsset", a["asset_id"], {

            "asset_type": a.get("asset_type"),

            "value_masked": mask_value(a.get("value"), 4),

            "authorization_state": a.get("authorization_state"),

            "abuse_state": a.get("abuse_state"),

        })

        if a.get("brand_id"):

            g.edge(a["asset_id"], a["brand_id"], "RELATED_TO_BRAND_CANDIDATE", {"similarity": a.get("brand_resolution", {}).get("similarity_state")})

        if a.get("registrable_domain"):

            g.node("Domain", a["registrable_domain"], {"official": False})

            g.edge(a["asset_id"], a["registrable_domain"], "RESOLVES_TO_DOMAIN", {})

        for sid in a.get("source_ids", []):

            g.node("Source", sid, {"source_type": sources.get(sid, {}).get("source_type")})

            g.edge(a["asset_id"], sid, "SUPPORTED_BY_SOURCE", {})

    for c in clusters:

        g.node("CampaignCluster", c["cluster_id"], {"shared_feature": c.get("shared_feature"), "state": c.get("state")})

        for aid in c.get("asset_ids", []):

            g.edge(aid, c["cluster_id"], "RELATED_TO_CAMPAIGN_CANDIDATE", {})

    for c in contradictions:

        g.node("Contradiction", c["contradiction_id"], {"type": c.get("type"), "severity": c.get("severity")})

    for h in hypotheses:

        g.node("Hypothesis", h["hypothesis_id"], {"category": h.get("category"), "asset_id": h.get("asset_id")})

    for gap in gaps:

        g.node("Gap", gap["gap_id"], {"type": gap.get("type"), "importance": gap.get("importance")})

    return g





def dual_ai_review_stub(assets: List[Dict[str, Any]], contradictions: List[Dict[str, Any]], gaps: List[Dict[str, Any]]) -> Dict[str, Any]:

    review = {

        "status": "INSUFFICIENT_EVIDENCE",

        "primary_conclusions": [],

        "skeptic_challenges": [],

        "comparison": "NO_SECOND_MODEL_CONFIGURED",

        "notes": [

            "Starter does not call an independent second model.",

            "AI agreement is not independent evidence.",

            "Human/legal review required for takedown, trademark infringement, operator attribution, or public accusation.",

        ],

    }

    if any(a["abuse_state"] in {"IMPERSONATION_SUPPORTED", "ABUSE_SUPPORTED"} for a in assets):

        review["primary_conclusions"].append("Some assets reach supported impersonation/abuse state under current evidence rules.")

        review["skeptic_challenges"].append("Check official baseline completeness, reseller/partner scope, control-era changes, and source dependence.")

    if contradictions:

        review["primary_conclusions"].append(f"{len(contradictions)} brand-intelligence contradiction candidate(s) detected.")

        review["skeptic_challenges"].append("Contradictions may reflect rebrand, migration, outdated baseline, compromise, or dependent complaints.")

    if any(g["type"] == "OFFICIAL_BASELINE_INCOMPLETE" for g in gaps):

        review["primary_conclusions"].append("Official baseline is incomplete; similarity-only conclusions are unsafe.")

        review["skeptic_challenges"].append("Do not classify abuse until official/authorized assets are baselined.")

    if review["primary_conclusions"]:

        review["status"] = "PARTIAL_AGREEMENT"

    return review





# --------------------------------------------------------------------

# Result / report

# --------------------------------------------------------------------



def empty_result(manifest: Dict[str, Any]) -> Dict[str, Any]:

    return {

        "case_id": manifest.get("case_id", "CASE-UNKNOWN"),

        "task_id": manifest.get("task_id", "TASK-UNKNOWN"),

        "objective": manifest.get("objective", ""),

        "questions": manifest.get("questions", []) or [],

        "generated_at": utc_now(),

        "version": VERSION,

        "source_ids": [],

        "evidence_ids": [],

        "brands": [],

        "official_baseline": {},

        "candidate_assets": [],

        "similarity_dimensions": [],

        "authorization_states": [],

        "abuse_states": [],

        "campaign_clusters": [],

        "contradictions": [],

        "hypotheses": [],

        "falsification_results": [],

        "source_reliability": [],

        "source_independence": [],

        "privacy_flags": [

            "No private-person identification attempted.",

            "Sensitive payment/phone/email values masked in report.",

        ],

        "legal_flags": [

            "BRANDINT does not make final trademark infringement or criminal determinations.",

        ],

        "unknowns": [],

        "knowledge_gaps": [],

        "recommended_next_actions": [],

        "specialist_handoffs": [],

        "limitations": [],

        "dual_ai_review": {},

        "graph_memory": {},

        "status": "PARTIAL",

    }





def finalize_status(policy_blocked: List[str], auth_ok: bool, brands: Dict[str, Any], assets: List[Dict[str, Any]], gaps: List[Dict[str, Any]]) -> str:

    if policy_blocked:

        return "POLICY_BLOCKED"

    if not auth_ok:

        return "BLOCKED_PERMISSION"

    if not brands:

        return "BRAND_UNRESOLVED"

    if not assets:

        return "INSUFFICIENT_INPUT"

    if any(g.get("importance") == "HIGH" for g in gaps):

        return "PARTIAL"

    return "SUCCEEDED"





def analyze_brandint_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:

    result = empty_result(manifest)



    policy_blocked = policy_screen(manifest)

    if policy_blocked:

        result["status"] = "POLICY_BLOCKED"

        result["violations"] = policy_blocked

        result["limitations"] = ["BRANDINT does not create impersonation assets, submit credentials, take over infrastructure, harass operators, or autonomously file takedown notices."]

        return result



    auth_ok, auth_reasons = authorization_check(manifest)

    if not auth_ok:

        result["status"] = "BLOCKED_PERMISSION"

        result["limitations"] = auth_reasons

        return result



    sources = ingest_sources(manifest)

    roots = build_source_roots(sources)

    brands = ingest_brands(manifest)

    assets = ingest_candidates(manifest)

    assets = analyze_assets(assets, brands, sources, roots)

    clusters = cluster_campaigns(assets)

    contradictions = detect_contradictions(assets, brands)

    hypotheses = build_hypotheses(assets)

    gaps = build_gaps(assets, brands, contradictions)

    actions = build_next_actions(gaps)

    handoffs = build_handoffs(assets, brands)

    graph = build_graph(assets, brands, clusters, contradictions, hypotheses, gaps, sources)

    review = dual_ai_review_stub(assets, contradictions, gaps)



    result["brands"] = list(brands.values())

    result["official_baseline"] = {

        bid: {

            "official_domains": b.get("official_domains", []),

            "official_social_accounts": b.get("official_social_accounts", []),

            "official_apps": b.get("official_apps", []),

            "authorized_resellers": b.get("authorized_resellers", []),

            "authorized_partners": b.get("authorized_partners", []),

            "licensees": b.get("licensees", []),

            "historical_domains": b.get("historical_domains", []),

        }

        for bid, b in brands.items()

    }

    result["candidate_assets"] = assets

    result["similarity_dimensions"] = [

        {

            "asset_id": a["asset_id"],

            "lexical_similarity": a["brand_resolution"]["similarity_state"],

            "score": a["brand_resolution"]["similarity_score"],

        }

        for a in assets

    ]

    result["authorization_states"] = [{"asset_id": a["asset_id"], "state": a["authorization_state"]} for a in assets]

    result["abuse_states"] = [{"asset_id": a["asset_id"], "state": a["abuse_state"]} for a in assets]

    result["campaign_clusters"] = clusters

    result["contradictions"] = contradictions

    result["hypotheses"] = hypotheses

    result["falsification_results"] = [

        {"hypothesis_id": h["hypothesis_id"], "falsification_conditions": h.get("falsification_conditions", [])}

        for h in hypotheses

    ]

    result["source_independence"] = [

        {"asset_id": a["asset_id"], **a["source_independence"]}

        for a in assets

    ]

    result["knowledge_gaps"] = gaps

    result["recommended_next_actions"] = actions

    result["specialist_handoffs"] = handoffs

    result["dual_ai_review"] = review

    result["graph_memory"] = graph.to_dict()



    for sid, src in sources.items():

        result["source_ids"].append(sid)

        result["source_reliability"].append({"source_id": sid, "source_type": src.get("source_type"), "reliability": src.get("reliability")})



    unknowns = []

    for a in assets:

        if a["authorization_state"] == "UNKNOWN":

            unknowns.append(f"Authorization unresolved for {a['asset_id']}.")

        if a["abuse_state"] in {"UNKNOWN", "INCONCLUSIVE"}:

            unknowns.append(f"Abuse state unresolved for {a['asset_id']}.")

    unknowns.append("Real-world operator identity is not inferred from domain/phone/email/social/payment alone.")

    unknowns.append("Historical abuse does not automatically contaminate current control era.")

    result["unknowns"] = list(dict.fromkeys(unknowns))[:300]



    result["limitations"] = list(dict.fromkeys([

        "BRANDINT starter uses only provided/local authorized records; no network fetching, form interaction, credential submission, or artifact execution was performed.",

        "Official baseline must be established before abuse classification.",

        "Similarity is not impersonation; logo use is not fraud; domain privacy is not maliciousness; HTTPS is not legitimacy.",

        "Authorized resellers, partners, licensees, franchises, fan/community/parody accounts may legitimately resemble a brand.",

        "Campaign clustering is not actor attribution.",

        "Takedown/legal notices require human authorization and independent verification.",

        "Trademark infringement and counterfeit determinations require legal/technical specialist review.",

    ] + auth_reasons))



    result["status"] = finalize_status(policy_blocked, auth_ok, brands, assets, gaps)

    return result





def generate_report(result: Dict[str, Any]) -> str:

    lines = ["# BRANDINT Defensive Brand-Abuse Report", ""]

    lines += [

        f"- Case ID: `{result.get('case_id')}`",

        f"- Task ID: `{result.get('task_id')}`",

        f"- Generated: `{result.get('generated_at')}`",

        f"- Status: `{result.get('status')}`",

        "",

    ]

    if result.get("status") == "POLICY_BLOCKED":

        lines += ["## POLICY BLOCKED", "Violations:", *[f"- `{v}`" for v in result.get("violations", [])], ""]

        return "\n".join(lines)



    lines += ["## Objective", str(result.get("objective", "")), ""]

    lines += ["## Boundaries",

              "- Defensive analysis only.",

              "- No impersonation creation, phishing deployment, credential submission, takeover, hacking, harassment, doxxing, or autonomous takedown.",

              "- Candidate content treated as untrusted data.", ""]



    lines += ["## Official Baseline"]

    for bid, base in (result.get("official_baseline") or {}).items():

        lines.append(f"### `{bid}`")

        lines.append(f"- Official domains: {', '.join(base.get('official_domains', [])[:30]) or 'None'}")

        lines.append(f"- Official social: {', '.join(base.get('official_social_accounts', [])[:30]) or 'None'}")

        lines.append(f"- Official apps: {', '.join(base.get('official_apps', [])[:30]) or 'None'}")

        lines.append(f"- Authorized resellers: {', '.join(base.get('authorized_resellers', [])[:30]) or 'None'}")

        lines.append(f"- Historical domains: {', '.join(base.get('historical_domains', [])[:30]) or 'None'}")

    lines.append("")



    lines += ["## Candidate Assets"]

    for a in result.get("candidate_assets", [])[:300]:

        lines.append(f"### `{a.get('asset_id')}`")

        lines.append(f"- Type: `{a.get('asset_type')}` value=`{mask_value(a.get('value'), 6)}`")

        lines.append(f"- Brand: `{a.get('brand_id')}` similarity=`{a.get('brand_resolution', {}).get('similarity_state')}` score=`{a.get('brand_resolution', {}).get('similarity_score')}`")

        lines.append(f"- Authorization: `{a.get('authorization_state')}` abuse: `{a.get('abuse_state')}`")

        lines.append(f"- Indicators: {json.dumps(a.get('risk_indicators', {}), ensure_ascii=False)}")

        lines.append(f"- Source independence: `{a.get('source_independence', {}).get('state')}` families={a.get('source_independence', {}).get('families', [])}")

        lines.append(f"- Takedown/current: `{a.get('takedown_status')}` / `{a.get('current_activity')}`")

        lines.append("")



    lines += ["## Campaign Clusters"]

    for c in result.get("campaign_clusters", [])[:200]:

        lines.append(f"- `{c.get('cluster_id')}` feature=`{c.get('shared_feature')}` value=`{c.get('shared_value')}` assets={c.get('asset_ids', [])[:20]} state=`{c.get('state')}`")

    lines.append("")



    lines += ["## Contradictions"]

    for c in result.get("contradictions", [])[:300]:

        lines.append(f"- `{c.get('contradiction_id')}` [{c.get('severity')}] {c.get('type')}: {c.get('detail')}")

    lines.append("")



    lines += ["## Hypotheses / Falsification"]

    for h in result.get("hypotheses", [])[:500]:

        lines.append(f"- `{h.get('hypothesis_id')}` [{h.get('category')}] {h.get('statement')}")

        if h.get("falsification_conditions"):

            lines.append(f"  - falsify if: {'; '.join(map(str, h['falsification_conditions'][:5]))}")

    lines.append("")



    lines += ["## Knowledge Gaps"]

    for g in result.get("knowledge_gaps", [])[:500]:

        lines.append(f"- `{g.get('gap_id')}` [{g.get('importance')}] {g.get('type')}: {g.get('recommended_source')}")

    lines.append("")



    lines += ["## Recommended Safe Next Actions"]

    for a in result.get("recommended_next_actions", [])[:500]:

        lines.append(f"- [{a.get('priority')}] {a.get('action')}")

    lines.append("")



    lines += ["## Specialist Handoffs"]

    for h in result.get("specialist_handoffs", []):

        lines.append(f"- {h.get('specialist')}: {h.get('reason')}")

    lines.append("")



    lines += ["## Limitations"]

    for lim in result.get("limitations", []):

        lines.append(f"- {lim}")

    return "\n".join(lines)





def main() -> int:

    p = argparse.ArgumentParser(description="TRACEATLAS BRANDINT short safe starter")

    p.add_argument("--manifest", required=True)

    p.add_argument("--output", default="brandint_result.json")

    p.add_argument("--report", default="brandint_report.md")

    args = p.parse_args()



    try:

        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))

    except Exception as exc:

        print(f"ERROR reading manifest: {exc}", file=sys.stderr)

        return 2



    result = analyze_brandint_manifest(manifest)

    Path(args.output).write_text(json.dumps(json_safe(result), ensure_ascii=False, indent=2), encoding="utf-8")

    Path(args.report).write_text(generate_report(result), encoding="utf-8")

    print(f"Wrote: {args.output}")

    print(f"Wrote: {args.report}")

    return 0





if __name__ == "__main__":

    raise SystemExit(main())
