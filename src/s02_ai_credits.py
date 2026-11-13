"""Step 2: Identify CVEs whose credits name an AI system or an AI-native organisation.

Input : data/processed/cve_records.csv.gz, data/curated/ai_credit_lexicon.csv,
        data/curated/ai_credit_exclusions.csv
Output: data/processed/cve_ai_flags.csv.gz   (one row per published CVE, slim)
        data/processed/ai_credited_cves.csv   (AI-credited subset, full detail)

Tier 1 = an AI model, agent or tool is named as finder or co-finder.
Tier 2 = credit names an AI-native security organisation or AI lab but no model.
Because many large vendors (Microsoft, Google Chrome, Apple, Oracle, the Linux
kernel CNA) publish no credits in CVE records, all counts are lower bounds.
"""
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "data" / "processed"
C = ROOT / "data" / "curated"

# Software-domain map applied to vendor + product + assigner (first match wins).
DOMAINS = [
    ("Cryptography, TLS & PKI", r"bouncy ?castle|legion of the bouncy|wolfssl|openssl|gnutls|mbed ?tls|libssh|openssh|\bnss\b|botan|libgcrypt|boringssl|libsodium|pkcs|\bcrypto"),
    ("Browsers & JS engines", r"mozilla|firefox|thunderbird|chrome|chromium|quickjs|webkit|\bv8\b|safari"),
    ("OS kernels & system", r"\blinux\b|kernel|x\.org|xorg|freebsd|openbsd|netbsd|windows|\bmicrosoft\b|apple|macos|\bios\b|android|systemd|glibc|busybox"),
    ("Network & security appliances", r"palo alto|\bf5\b|fortinet|forti|cisco|watchguard|juniper|sonicwall|citrix|ivanti|zyxel|check ?point|sophos|netgear|tp-?link|d-?link"),
    ("Office & document software", r"foxit|libreoffice|document foundation|adobe|acrobat|\bpdf\b|office"),
    ("Virtualisation & language runtimes", r"\bxen\b|qemu|kvm|virtualbox|erlang|python|ruby|golang|\bgo\b|openjdk|\bjava\b|wasm|webassembly|\.net"),
    ("Databases & data stores", r"sqlite|postgres|mysql|mariadb|redis|mongodb|cassandra|elasticsearch|clickhouse|duckdb"),
    ("Media & file parsers", r"ffmpeg|imagemagick|libpng|libtiff|libjpeg|libxml|expat|poppler|ghostscript|libarchive|zlib|7-?zip|libav"),
    ("Network libraries & tools", r"\bcurl\b|libcurl|wget|openvpn|wireguard|dnsmasq|\bbind\b|unbound|nlnet|nginx|haproxy|squid|rejetto|samba"),
    ("Java & web middleware", r"apache|pac4j|tomcat|jetty|spring|struts|camel|kafka|activemq|jfrog|jenkins|netty|node\.?js|express|django|rails|laravel|php"),
    ("Business & collaboration apps", r"mattermost|misp|cerebrate|obsidian|gitlab|gitea|nextcloud|owncloud|confluence|jira|zimbra|roundcube|\bsap\b|oracle|odoo|openbankproject|flowintel|dolibarr|frappe|erpnext|limesurvey|vulnerability-lookup|backblaze"),
    ("CMS, plugins & small web apps", r"wordpress|plugin|theme|drupal|joomla|\bphp\b|code-projects|sourcecodester|itsourcecode|campcodes|phpgurukul|projectworlds|\bcms\b"),
]


def load_lexicon():
    lex = pd.read_csv(C / "ai_credit_lexicon.csv")
    lex["rx"] = lex["pattern"].apply(lambda p: re.compile(p, re.I))
    exc = pd.read_csv(C / "ai_credit_exclusions.csv")
    exc_rx = [re.compile(p, re.I) for p in exc["pattern"]]
    return lex, exc_rx


def classify_credit(text, lex, exc_rx):
    if not text:
        return 0, "", ""
    for rx in exc_rx:
        text = rx.sub(" ", text)
    hits = [(int(r.tier), r.label, r.developer) for r in lex.itertuples() if r.rx.search(text)]
    if not hits:
        return 0, "", ""
    hits.sort(key=lambda h: h[0])  # tier 1 dominates
    best_tier = hits[0][0]
    labels = sorted({h[1] for h in hits if h[0] == best_tier})
    devs = sorted({h[2] for h in hits if h[0] == best_tier})
    return best_tier, "; ".join(labels), "; ".join(devs)


def domain_of(vendor, product, assigner):
    s = f"{vendor} {product} {assigner}".lower()
    for name, pat in DOMAINS:
        if re.search(pat, s):
            return name
    return "Other software"


def main():
    df = pd.read_csv(P / "cve_records.csv.gz", dtype=str, keep_default_na=False)
    df = df[df["state"] == "PUBLISHED"].copy()
    lex, exc_rx = load_lexicon()
    res = [classify_credit(t, lex, exc_rx) for t in df["credits"].tolist()]
    df["ai_tier"] = [r[0] for r in res]
    df["ai_label"] = [r[1] for r in res]
    df["ai_developer"] = [r[2] for r in res]
    df["domain"] = [domain_of(v, p, a) for v, p, a in zip(df["vendor"], df["product"], df["assigner"])]
    df["has_credit"] = (df["credits"] != "").astype(int)
    slim = df[["cve_id", "assigner", "date_reserved", "date_published", "vendor", "product",
               "cwe", "cvss_max", "ssvc_exploitation", "has_credit", "ai_tier", "ai_label",
               "ai_developer", "domain"]]
    slim.to_csv(P / "cve_ai_flags.csv.gz", index=False, compression="gzip")
    ai = df[df["ai_tier"] > 0].sort_values("date_published")
    ai.to_csv(P / "ai_credited_cves.csv", index=False)
    print(f"published CVEs: {len(df):,}; AI-credited: {len(ai):,} "
          f"(tier1 {int((ai.ai_tier == 1).sum()):,}, tier2 {int((ai.ai_tier == 2).sum()):,})")
    print(ai.groupby(ai.date_published.str[:4])["ai_tier"].value_counts().unstack(fill_value=0))


if __name__ == "__main__":
    main()
