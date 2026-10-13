"""CVE research library generated from validated CISA KEV records.

Purpose: a browsable, source-traceable vulnerability reference, NOT invented
severity ratings, affected-version matches, vendor fixes, or exploit claims.
Existing pages remain stable and get refreshed when new KEV data arrives.
No paid API, AI service, cookies, or new dependency.
"""
import datetime as dt
import json
import re
from pathlib import Path
from urllib.parse import quote

CISA_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}\Z")


def _article(row, esc, updated, origin):
    cve = row["cveID"]
    vendor = row.get("vendorProject", "").strip() or "Vendor not specified"
    product = row.get("product", "").strip() or "Product not specified"
    name = row.get("vulnerabilityName", "").strip() or "Known exploited vulnerability"
    summary = row.get("shortDescription", "").strip() or "Consult the linked CISA and NVD records for the current description."
    action = row.get("requiredAction", "").strip() or "Follow the vendor's current remediation guidance after confirming the affected systems."
    noted = row.get("notes", "").strip()
    ransom = row.get("knownRansomwareCampaignUse", "").strip() or "Not specified"
    date = row.get("dateAdded", "").strip() or "Not specified"
    deadline = row.get("dueDate", "").strip() or "Not specified"
    nvd = "https://nvd.nist.gov/vuln/detail/" + quote(cve)
    url = origin + "/cve/" + cve + ".html"
    product_label = vendor if vendor.casefold() == product.casefold() else f"{vendor} {product}"
    title = f"{cve}: {product_label} | Known exploited vulnerability"
    description = (f"{cve} CISA KEV entry for {product_label}: catalog information, action, and a practical evidence-based triage checklist.")[:155]
    schema = {
        "@context": "https://schema.org",
        "@type": "TechArticle",
        "headline": f"{cve} — {name}",
        "description": description,
        "mainEntityOfPage": {"@type": "WebPage", "@id": url},
        "about": {"@type": "Thing", "name": cve, "sameAs": nvd},
        "author": {"@type": "Organization", "name": "CalculatedIT Threat Pulse", "url": origin},
        "publisher": {"@type": "Organization", "name": "Calculated Ventures, LLC", "url": "https://calculatedit.com/"},
        "dateModified": updated,
        "isBasedOn": [CISA_CATALOG, nvd],
    }
    # Escape characters that could terminate a JSON script element in source data.
    structured = json.dumps(schema, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    note = f'<p><strong>Additional CISA notes:</strong> {esc(noted)}</p>' if noted else ""
    body = f'''<section class="simple-hero"><div class="wrap">
<div class="eyebrow">CISA KEV · SOURCE-BASED CVE RESEARCH</div><h1>{esc(cve)}</h1>
<p class="lead">{esc(name)}</p><p class="cve-subhead">{esc(vendor)} · {esc(product)}</p>
<p class="cve-breadcrumb"><a href="/cve/index.html">← CVE research library</a> · <a href="/alerts.html">Full KEV tracker</a></p>
</div></section>
<section class="wrap section cve-article">
<div class="cve-article-grid"><article class="cve-content prose">
<h2>What the official KEV catalog reports</h2>
<p>{esc(summary)}</p>
<div class="cve-facts">
<div><small>Catalog addition date</small><strong>{esc(date)}</strong></div>
<div><small>Product and vendor</small><strong>{esc(vendor)} / {esc(product)}</strong></div>
<div><small>CISA agency due date</small><strong>{esc(deadline)}</strong></div>
<div><small>Ransomware campaign use (CISA field)</small><strong>{esc(ransom)}</strong></div>
</div>
<h2>Action in the CISA catalog</h2>
<div class="resource-callout"><p>{esc(action)}</p></div>{note}
<p class="source-note">The CISA due date refers to covered federal-agency obligations where applicable; it is not automatically a private-sector deadline. Catalog inclusion documents known exploitation, not whether your own system is vulnerable. Check official sources before acting.</p>
<h2>How to decide whether your systems are affected</h2>
<ol>
<li><strong>Check your software inventory.</strong> Look for {esc(vendor)} {esc(product)} across managed computers, servers, appliances, and cloud services where applicable. Record the asset IDs and deployed versions. A matching product name alone is not proof of exposure.</li>
<li><strong>Validate affected versions and mitigations.</strong> Read the current vendor advisory and <a href="{esc(nvd)}" target="_blank" rel="noopener">NVD entry for {esc(cve)}</a>. Compare the affected configuration, version, and prerequisites to each asset before marking it exposed.</li>
<li><strong>Plan and verify an authorized response.</strong> Follow current vendor guidance, test changes, document the owner and remediation date, and confirm the issue is resolved with a targeted check or rescan. Escalate uncertainty rather than guessing.</li>
</ol>
<h2>Evidence to keep for a defensible decision</h2>
<p>For assets that need remediation, retain a record of the CVE, affected asset, discovery source, advisory reference, approval, action taken, and validation result. For assets found not to be affected, retain the version or configuration evidence supporting that decision.</p>
<p><a href="/kev-triage-checklist.html">Use the free KEV triage worksheet →</a> · <a href="/nessus-to-poam-guide.html">Learn about scan-to-POA&amp;M evidence →</a></p>
</article>
<aside class="cve-sources"><h3>Verify with primary sources</h3>
<p>These references let you check updates, product applicability, and recommendations independently.</p>
<a href="{esc(CISA_CATALOG)}" target="_blank" rel="noopener">CISA KEV catalog ↗</a>
<a href="{esc(nvd)}" target="_blank" rel="noopener">NVD: {esc(cve)} ↗</a>
<p class="cve-disclaimer">CalculatedIT adds a triage workflow but does not issue vulnerability scores or claim your environment is affected. Vendor instructions and your organization's policies govern remediation.</p>
</aside></div></section>
<script type="application/ld+json">{structured}</script>'''
    return title, description, body


def build_cve_library(cfg, rows, public, chrome, esc, initial_limit=24):
    """Build a curated initial batch, then preserve prior URLs on each refresh.

    Avoid publishing thousands of nearly identical pages at launch; existing CVE
    pages are regenerated from current source data, not left to go stale.
    """
    if not rows:
        return []
    origin = cfg.get("site_url", "").rstrip("/")
    if not origin.startswith("https://"):
        return []
    directory = Path(public) / "cve"
    directory.mkdir(parents=True, exist_ok=True)
    by_id = {r["cveID"]: r for r in rows if CVE_PATTERN.fullmatch(r.get("cveID", "")) and r.get("shortDescription", "").strip()}
    initial = [r["cveID"] for r in rows if r["cveID"] in by_id][:initial_limit]
    previous = [p.stem for p in directory.glob("CVE-*.html") if CVE_PATTERN.fullmatch(p.stem)]
    selected = set(initial + previous)
    build_day = dt.datetime.now(dt.timezone.utc).date().isoformat()
    published = []
    for cve in selected:
        row = by_id.get(cve)
        if not row:
            continue
        title, description, body = _article(row, esc, build_day, origin)
        path = "/cve/" + cve + ".html"
        (directory / (cve + ".html")).write_text(chrome(cfg, title, description, body, path), encoding="utf-8")
        published.append(row)
    published.sort(key=lambda r: (r["dateAdded"], r["cveID"]), reverse=True)
    if not published:
        return []
    items = []
    for r in published:
        cve, vendor, product = r["cveID"], r["vendorProject"], r["product"]
        short = r["shortDescription"]
        items.append(f'<li><a href="/cve/{esc(cve)}.html"><strong>{esc(cve)}</strong> — {esc(vendor)} / {esc(product)}</a><p>{esc(short)}</p><small>CISA catalog addition: {esc(r["dateAdded"])}</small></li>')
    index = ('<section class="simple-hero"><div class="wrap"><div class="eyebrow">CVE RESEARCH LIBRARY</div>'
             '<h1>Known exploited vulnerabilities, explained</h1>'
             '<p class="lead">Explore source-traceable CISA KEV records and a practical triage checklist for each. '
             'Check vendor advisories before changing a system.</p></div></section>'
             '<section class="wrap section cve-library"><div class="resource-callout"><strong>How to use these pages</strong>'
             '<p>Search the CVE identifier or product in your browser. The records come from the official CISA KEV catalog; '
             'our checklists explain the decision process, not your individual exposure. '
             '<a href="/alerts.html">See the latest 200 catalog entries →</a></p></div>'
             '<ol class="cve-list">' + "".join(items) + '</ol></section>')
    (directory / "index.html").write_text(chrome(cfg, "Known exploited vulnerability research library",
                                                    "CISA KEV CVE reference pages with evidence-based triage guidance.",
                                                    index, "/cve/index.html"), encoding="utf-8")
    return ["/cve/index.html"] + ["/cve/" + r["cveID"] + ".html" for r in published]
