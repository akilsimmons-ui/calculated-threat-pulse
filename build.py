#!/usr/bin/env python3
"""Build a low-maintenance, source-traceable security-information website.
No third-party Python packages or paid APIs required.
The daily feed refresh also republishes tools after their scheduled release gates.
"""
import argparse
import datetime as dt
import html
import json
import re
import shutil
import urllib.request
from pathlib import Path
from urllib.parse import quote
from site_rollups import build_weekly, build_rss

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / 'public'
DATA = ROOT / 'data' / 'kev.json'
CISA_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


def esc(x):
    return html.escape(str(x or ''), quote=True)


def fetch_kev():
    """Load CISA's publicly available KEV JSON. Fail closed, keeping previous data."""
    request = urllib.request.Request(CISA_URL, headers={'User-Agent': 'CalculatedIT Threat Pulse/1.0 (+public security information site)'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(8_000_000)
            new = json.loads(raw)
        assert isinstance(new.get('vulnerabilities'), list)
        assert len(new['vulnerabilities']) > 100
        assert all('cveID' in entry and 'dateAdded' in entry for entry in new['vulnerabilities'][:20])
        DATA.parent.mkdir(parents=True, exist_ok=True)
        DATA.write_text(json.dumps(new, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        print(f"Downloaded {len(new['vulnerabilities'])} CISA KEV records")
    except Exception as error:
        print(f'Unable to refresh CISA feed: {error}; using last cached feed, if present.')


def load_data():
    if not DATA.exists():
        return [], '', ''
    data = json.loads(DATA.read_text(encoding='utf-8'))
    rows = data.get('vulnerabilities', [])
    clean = []
    for r in rows:
        cve = str(r.get('cveID', ''))
        day = str(r.get('dateAdded', ''))
        if re.fullmatch(r'CVE-\d{4}-\d{4,}', cve) and re.fullmatch(r'\d{4}-\d\d-\d\d', day):
            clean.append({k: str(r.get(k, '')) for k in [
                'cveID', 'dateAdded', 'vendorProject', 'product', 'vulnerabilityName',
                'shortDescription', 'requiredAction', 'dueDate', 'knownRansomwareCampaignUse', 'notes']})
    clean.sort(key=lambda r: (r['dateAdded'], r['cveID']), reverse=True)
    return clean, str(data.get('dateReleased', '')), str(data.get('catalogVersion', ''))


def poam_tool_release_ready(now=None):
    """Release only on/after the next 06:21 UTC scheduled KEV refresh."""
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError('Release gate requires a timezone-aware datetime')
    return now >= dt.datetime(2026, 10, 12, 6, 20, tzinfo=dt.timezone.utc)


def chrome(cfg, title, description, content, path='/'):
    name = cfg['site_name']
    origin = cfg.get('site_url', '').rstrip('/')
    canonical = f'<link rel="canonical" href="{esc(origin + path)}">' if origin.startswith('https://') else ''
    full_title = f'{title} | {name}'
    social = (f'<meta property="og:type" content="website">'
              f'<meta property="og:site_name" content="{esc(name)}">'
              f'<meta property="og:title" content="{esc(full_title)}">'
              f'<meta property="og:description" content="{esc(description)}">'
              f'<meta name="twitter:card" content="summary">'
              f'<meta name="twitter:title" content="{esc(full_title)}">'
              f'<meta name="twitter:description" content="{esc(description)}">')
    if origin.startswith('https://'):
        social += f'<meta property="og:url" content="{esc(origin + path)}">'
    if poam_tool_release_ready():
        calculator_link = '<a href="/poam-aging-calculator.html">POA&amp;M deadline calculator</a>'
    else:
        calculator_link = ''
    ads_id = cfg.get('adsense_publisher_id', '')
    script = ''
    meta = f'<meta name="google-adsense-account" content="{esc(ads_id)}">' if re.fullmatch(r'ca-pub-\d{16}', ads_id) else ''
    if re.fullmatch(r'ca-pub-\d{16}', ads_id) and cfg.get('ads_enabled') is True:
        script = f'<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={esc(ads_id)}" crossorigin="anonymous"></script>'
    return f'''<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{esc(description)}"><meta name="theme-color" content="#0b1630">
<title>{esc(title)} | {esc(name)}</title>{canonical}{social}{meta}{script}
<link rel="alternate" type="application/rss+xml" title="CalculatedIT security updates RSS" href="/feed.xml"><link rel="stylesheet" href="/assets/style.css"><link rel="stylesheet" href="/assets/brand.css"></head><body>
<header class="header"><div class="wrap nav"><a href="/" class="logo"><span class="logo-plate"><img class="logo-graphic" src="https://calculatedit.com/wp-content/uploads/2023/05/cropped-output-onlinejpgtools-1.png" alt="Calculated Ventures" width="250" height="83"></span><span class="brand-copy"><small>THREAT PULSE</small></span></a><nav aria-label="Main navigation"><a href="/">Home</a><a href="/alerts.html">Threat feed</a><a href="/tools.html">Free tools</a><a href="/guides.html">Guides</a></nav><span class="navpill"><span class="live"></span> Official sources</span></div></header>
<main>{content}</main>
<footer><div class="wrap footer"><div><a href="https://calculatedit.com/" class="parent-identity"><img class="corporate-logo" src="https://calculatedit.com/wp-content/uploads/2023/05/cropped-output-onlinejpgtools-1.png" alt="Calculated Ventures logo" width="650" height="305" loading="lazy"><span><strong>{esc(name)}</strong><small>A Calculated Ventures, LLC publication</small></span></a><p>Security intelligence and practical tools. Information, not security guarantees.</p><p class="fine">Source data: CISA. Not affiliated with or endorsed by CISA or the U.S. government.</p><p class="fine">© {dt.datetime.now(dt.timezone.utc).year} Calculated Ventures, LLC</p></div><div class="footerlinks"><a href="/about.html">About</a><a href="/privacy.html">Privacy</a><a href="/contact.html">Contact</a><a href="/weekly-briefing.html">Seven-day briefing</a><a href="/feed.xml">RSS updates</a><a href="/rmf-evidence-pilot.html">RMF pilot offer</a><a href="/kev-triage-checklist.html">Free KEV checklist</a><a href="/nessus-to-poam-guide.html">Scan-to-POA&amp;M guide</a>{calculator_link}<a href="https://app.calculatedit.com/" rel="noopener" target="_blank">RMF Accelerator ↗</a><a href="https://calculatedit.com/" rel="noopener" target="_blank">Calculated Ventures ↗</a></div></div></footer>
</body></html>'''


def ad(cfg):
    publisher = cfg.get('adsense_publisher_id', '')
    slot = str(cfg.get('adsense_slot_id', ''))
    if cfg.get('ads_enabled') is True and re.fullmatch(r'ca-pub-\d{16}', publisher) and re.fullmatch(r'\d{8,12}', slot):
        return f'''<div class="ad-wrap"><span class="ad-label">Advertisement</span><ins class="adsbygoogle" style="display:block" data-ad-client="{esc(publisher)}" data-ad-slot="{esc(slot)}" data-ad-format="auto" data-full-width-responsive="true"></ins><script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script></div>'''
    return ''  # No fake advertisement placeholders before approval.


def ads_txt_line(cfg):
    """Authorized AdSense seller entry; do not invent or publish an account ID."""
    publisher = cfg.get('adsense_publisher_id', '')
    if re.fullmatch(r'ca-pub-\d{16}', publisher):
        return 'google.com, ' + publisher[3:] + ', DIRECT, f08c47fec0942fa0\n'
    return ''


def accelerator_cta(compact=False):
    """An optional commercial next step after the free security content."""
    lead = 'Need a faster path from security findings to reviewable RMF evidence?'
    if compact:
        lead = 'Ready to turn findings into an RMF evidence package?'
    return f'''<section class="accelerator-section"><div class="wrap">
<div class="accelerator-panel"><div class="accelerator-copy">
<span class="accelerator-eyebrow">CALCULATEDIT RMF ACCELERATOR · PROFESSIONAL SERVICES</span>
<h2>{esc(lead)}</h2>
<p>Convert customer-provided Nessus / ACAS scan findings into structured draft POA&amp;M materials, remediation recommendations, and review-ready RMF outputs with expert quality assurance. Every output requires human validation.</p>
<div class="accelerator-actions">
<a class="accelerator-button" href="https://app.calculatedit.com/" target="_blank" rel="noopener">Explore RMF Accelerator ↗</a>
<a class="accelerator-link" href="/rmf-evidence-pilot.html">See the $2,500 pilot details →</a></div>
<p class="accelerator-note">Optional paid service by Calculated Ventures, LLC. The free security feed and tools remain available without a purchase.</p>
</div></div></div></section>'''


def write_page(cfg, file, title, description, body):
    path = '/' if file == 'index.html' else '/' + file
    (PUBLIC / file).write_text(chrome(cfg, title, description, body, path), encoding='utf-8')


def alert_card(r):
    cve = r['cveID']
    cve_url = 'https://nvd.nist.gov/vuln/detail/' + quote(cve)
    action = r['requiredAction'] or 'Review the vendor advisory and assess exposure.'
    return f'''<article id="{esc(cve)}" class="threat-card" data-search="{esc(' '.join([r['cveID'], r['vendorProject'], r['product'], r['vulnerabilityName']]).lower())}">
<div class="threat-top"><span class="cve">{esc(cve)}</span><span class="date">Added {esc(r['dateAdded'])}</span></div>
<h3>{esc(r['vulnerabilityName'] or r['vendorProject'] + ' ' + r['product'])}</h3>
<p class="muted">{esc(r['vendorProject'])} · {esc(r['product'])}</p>
<p>{esc(r['shortDescription'])}</p><div class="action"><strong>CISA-required action:</strong> {esc(action)}</div>
<div class="threat-bottom"><span>Agency due date: {esc(r['dueDate'] or 'Not specified')}</span><a href="{esc(cve_url)}" rel="noopener" target="_blank">NVD details ↗</a></div></article>'''


def build():
    cfg = json.loads((ROOT / 'config.json').read_text(encoding='utf-8'))
    PUBLIC.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / 'assets', PUBLIC / 'assets', dirs_exist_ok=True)
    rows, released, version = load_data()
    (PUBLIC / 'data').mkdir(exist_ok=True)
    (PUBLIC / 'data' / 'kev.json').write_text(json.dumps({'source': CISA_URL, 'dateReleased': released, 'catalogVersion': version, 'vulnerabilities': rows[:200]}, ensure_ascii=False), encoding='utf-8')
    cards = ''.join(alert_card(r) for r in rows[:6]) if rows else '<div class="empty">Threat data hasn’t been downloaded yet. Run <code>python build.py --fetch</code> when connected to the internet, or enable the daily GitHub Actions workflow.</div>'
    today = dt.datetime.now(dt.timezone.utc).strftime('%B %d, %Y')
    body = f'''<section class="hero hero-refresh"><div class="wrap hero-grid"><div class="hero-intro"><div class="eyebrow"><span class="hero-live-dot" aria-hidden="true"></span> FREE TOOLS · VERIFIED SOURCES · DAILY UPDATES</div><h1>Security signals.<br><em>Clearer decisions.</em></h1><p class="lead">Cut through the noise with actively exploited vulnerability intelligence, practical security checklists, and free tools built for busy IT teams.</p><div class="hero-highlights"><span>Official CISA data</span><span>No registration</span><span>Useful, not alarmist</span></div><div class="buttons"><a class="btn" href="/alerts.html">Explore live threat feed <span>↗</span></a><a class="btn-secondary" href="/tools.html">Use free tools →</a></div><div class="subline"><span class="live"></span> CISA KEV official source <span class="separator">•</span> No sign-up required</div></div><div class="hero-panel threat-console"><div class="panel-head"><span>THREAT INTELLIGENCE · LIVE CATALOG</span><span class="signal">SOURCE: CISA</span></div><div class="bigstat">{len(rows):,}<span>tracked</span></div><p>Known exploited vulnerabilities in source feed</p><div class="panel-divider"></div><div class="statsrow"><div><small>Latest addition</small><b>{esc(rows[0]['dateAdded'] if rows else 'Not loaded')}</b></div><div><small>Feed edition</small><b>{esc(version or 'Not loaded')}</b></div></div><div class="panel-note">Catalog records show observed exploitation, not proof that your systems are affected.</div></div><div class="hero-sidecar"><div class="sidecar-art" aria-hidden="true"><span></span><span></span><span></span><span></span></div><div><strong>Know what changed</strong><p>Follow the seven-day briefing for a quick, source-based view.</p><a href="/weekly-briefing.html">View this week’s briefing →</a></div></div></div></div></section>
<section class="explore-band"><div class="wrap explore-grid"><a href="/alerts.html" class="explore-tile"><span class="explore-symbol explore-red" aria-hidden="true">!</span><span><strong>Track exploited vulnerabilities</strong><small>Search recent CVEs and product names</small></span><span class="explore-arrow" aria-hidden="true">↗</span></a><a href="/tools.html" class="explore-tile"><span class="explore-symbol explore-blue" aria-hidden="true">⌁</span><span><strong>Use free security tools</strong><small>Quick calculations, private by design</small></span><span class="explore-arrow" aria-hidden="true">↗</span></a><a href="/kev-triage-checklist.html" class="explore-tile"><span class="explore-symbol explore-green" aria-hidden="true">✓</span><span><strong>Get actionable checklists</strong><small>Practical steps and free worksheets</small></span><span class="explore-arrow" aria-hidden="true">↗</span></a></div></section>
<section class="section wrap"><div class="section-top"><div><div class="eyebrow dark">THE LATEST</div><h2>Recently added advisories</h2><p class="muted">Automatically pulled from the public CISA Known Exploited Vulnerabilities catalog. <a href="/alerts.html">Browse more →</a> · <a href="/weekly-briefing.html">7-day briefing →</a> · <a href="/feed.xml">RSS updates →</a></p></div></div><div class="cardgrid">{cards}</div><div class="source-note">Source: CISA Known Exploited Vulnerabilities catalog. Feed release: {esc(released or 'Not available')}. Page built {esc(today)} UTC. See CISA for authoritative updates.</div></section>
<section class="section pale"><div class="wrap"><div class="eyebrow dark">FREE, PRACTICAL, PRIVATE</div><h2>Try a tool. Leave with a next step.</h2><p class="muted intro">Practical tools to turn security questions into actionable decisions.</p><div class="featuregrid"><a class="feature" href="/tools.html#downtime"><div class="feature-icon">⌁</div><h3>Downtime cost calculator</h3><p>Estimate operational losses from a service interruption using your own assumptions.</p><span>Open calculator →</span></a><a class="feature" href="/tools.html#password"><div class="feature-icon">✳</div><h3>Passphrase strength planner</h3><p>Compare lengths and character set sizes without entering your actual password.</p><span>Open calculator →</span></a><a class="feature" href="/guides.html"><div class="feature-icon">✓</div><h3>Risk response guides</h3><p>Understand prioritization, MFA rollout, and the first hour of an incident.</p><span>Read the guides →</span></a></div></div></section>
<section class="wrap section"><div class="eyebrow dark">NEXT STEPS, MADE SIMPLE</div><h2>Free checklists for work that matters</h2><p class="muted intro">Go beyond an alert: document an exposure decision and trace scan findings to a reviewed action plan.</p><div class="featuregrid"><a class="feature" href="/kev-triage-checklist.html"><div class="feature-icon">✓</div><h3>KEV triage checklist + CSV</h3><p>Seven evidence-based checks and a blank spreadsheet for assigning, tracking, and verifying a vulnerability response.</p><span>Download the worksheet →</span></a><a class="feature" href="/nessus-to-poam-guide.html"><div class="feature-icon">↗</div><h3>Nessus / ACAS to POA&amp;M</h3><p>Keep scan evidence traceable, handle uncertain mappings, and verify remediation without invented findings.</p><span>Read the evidence guide →</span></a></div></section>
{accelerator_cta()}<section class="wrap section">{ad(cfg)}<div class="editorial"><div><div class="eyebrow dark">BUILT FOR THE WORK YOU DO</div><h2>Practical advice, grounded in public evidence.</h2></div><p>We link back to primary sources rather than inventing vulnerability severity scores or pretending automated summaries are expert assessments. Verify applicability to your environment before acting.</p></div></section>'''
    if poam_tool_release_ready():
        # Reveal the tool as part of the scheduled KEV refresh, never during tonight's build.
        old = '<span>Read the evidence guide →</span></a></div></section>'
        new = ('<span>Read the evidence guide →</span></a>'
               '<a class="feature" href="/poam-aging-calculator.html">'
               '<div class="feature-icon">◷</div><h3>POA&amp;M aging calculator</h3>'
               '<p>Check how long a finding has been open and how close your target milestone is.'
               ' No uploads or accounts.</p><span>Open free calculator →</span></a></div></section>')
        if old not in body:
            raise RuntimeError('Home feature anchor not found; refusing to build a broken release')
        body = body.replace(old, new, 1)
    write_page(cfg, 'index.html', 'Daily security intelligence & free tools', 'Practical free security tools and automatically refreshed CISA KEV alerts for small IT teams.', body)

    alerts = ''.join(alert_card(r) for r in rows[:200]) if rows else '<p class="empty">No official feed was cached. Contact the operator or check CISA directly for the latest updates.</p>'
    body = f'''<section class="simple-hero"><div class="wrap"><div class="eyebrow">SOURCE-TRACEABLE INTELLIGENCE</div><h1>Known exploited vulnerabilities</h1><p class="lead">Browse recently added records in CISA's KEV catalog. Search below for a CVE, vendor, or product. Data is not a complete inventory of vulnerabilities.</p></div></section><section class="wrap section"><div class="filterline"><label for="search">Filter advisories</label><input id="search" placeholder="Try a CVE, vendor, or product..." aria-label="Filter advisories"><span id="count" aria-live="polite"></span></div><div class="cardgrid" id="alerts">{alerts}</div><p class="source-note">Displaying up to 200 most recent catalog records. Date added to catalog is not the date of initial exploitation. Source: <a href="{esc(CISA_URL)}">CISA JSON</a>. Catalog edition {esc(version or 'not loaded')}. <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">Read CISA's guidance</a>.</p>{ad(cfg)}</section><script src="/assets/app.js" defer></script>'''
    write_page(cfg, 'alerts.html', 'CISA known exploited vulnerabilities', 'Search up to 200 recent CISA known exploited vulnerability records by CVE, product or vendor.', body)

    tools = '''<section class="simple-hero"><div class="wrap"><div class="eyebrow">USEFUL · PRIVATE · FREE</div><h1>Security planning tools</h1><p class="lead">Fast, transparent estimates you can use without submitting personal information. Calculations run in your browser.</p></div></section><section class="wrap section tool-layout"><article id="downtime" class="tool"><div class="eyebrow dark">OPERATIONS</div><h2>Downtime cost estimator</h2><p class="muted">For planning only. Enter your own assumptions; this is not a predictive model.</p><div class="fieldgrid"><label>Employees affected<input id="workers" type="number" min="0" max="100000" value="15"></label><label>Fully loaded hourly cost ($)<input id="hourly" type="number" min="0" max="100000" value="65"></label><label>Downtime (hours)<input id="hours" type="number" min="0" max="10000" step="0.5" value="4"></label><label>Estimated lost revenue per hour ($)<input id="revenue" type="number" min="0" max="10000000" value="500"></label></div><div class="result"><small>Illustrative total interruption impact</small><strong id="downtime-result">—</strong><span>Labor cost + revenue impact; may overstate losses when the same activity is counted twice.</span></div></article><article id="password" class="tool"><div class="eyebrow dark">ACCOUNT HYGIENE</div><h2>Passphrase length planner</h2><p class="muted">Never enter a real password here. This is a theoretical search-space comparison, not an estimate of actual resistance to attacks.</p><div class="fieldgrid"><label>Hypothetical random characters<input id="chars" type="number" min="1" max="100" value="16"></label><label>Hypothetical character set<select id="charset"><option value="26">Lowercase letters (26)</option><option value="52">Mixed-case letters (52)</option><option value="62" selected>Letters + digits (62)</option><option value="94">Letters + digits + symbols (94)</option></select></label></div><div class="result"><small>Theoretical entropy, only if uniformly random</small><strong id="password-result">—</strong><span>Real human-chosen passwords have less entropy. Use unique passphrases, a password manager, and MFA.</span></div></article></section><section class="wrap section"><div class="callout"><h3>Where to go after the estimate</h3><p>For account defenses, consult <a href="https://www.cisa.gov/secure-our-world/use-strong-passwords" target="_blank" rel="noopener">CISA guidance on passwords</a>. For incident preparedness, see the <a href="https://www.cisa.gov/resources-tools/resources/incident-response-plan-irp-basics" target="_blank" rel="noopener">CISA incident response planning guide</a>.</p></div></section><script src="/assets/app.js" defer></script>'''
    if poam_tool_release_ready():
        tool_card = ('<section class="wrap section"><div class="resource-callout">'
                     '<h2>POA&amp;M deadline &amp; aging calculator</h2>'
                     '<p>Track the calendar-day age of an open finding and count days until'
                     ' your chosen remediation target date. Entirely in-browser;'
                     ' no uploads, stored data, or accounts.</p>'
                     '<p><a href="/poam-aging-calculator.html">Open the free POA&amp;M calculator →</a></p>'
                     '</div></section>')
        anchor = '<section class="wrap section"><div class="callout">'
        if anchor not in tools:
            raise RuntimeError('Tools anchor not found; refusing broken release')
        tools = tools.replace(anchor, tool_card + anchor, 1)
        source = ROOT / 'content' / 'poam-aging-calculator.html'
        if not source.is_file():
            raise FileNotFoundError(f'Missing staged tool: {source}')
        write_page(cfg, 'poam-aging-calculator.html',
                   'Free POA&M deadline and finding aging calculator',
                   'Calculate days open and days until your POA&M milestone target, privately in your browser with no account or uploads.',
                   source.read_text(encoding='utf-8') + accelerator_cta(compact=True))
    else:
        # A delayed or manually invoked earlier build must not publish the staged page.
        (PUBLIC / 'poam-aging-calculator.html').unlink(missing_ok=True)
    write_page(cfg, 'tools.html', 'Free security calculators', 'Downtime costs, passphrase planning and POA&M milestone aging calculators that run in the browser.', tools)

    guides = '''<section class="simple-hero"><div class="wrap"><div class="eyebrow">PRACTICAL LEARNING</div><h1>Security guides for small teams</h1><p class="lead">A starting point for better decisions. These guides are general educational material, not incident-specific professional advice.</p></div></section><section class="wrap section"><div class="eyebrow dark">FREE FIELD RESOURCES</div><h2>Start with a usable checklist</h2><div class="featuregrid"><a class="feature" href="/kev-triage-checklist.html"><h3>KEV triage checklist</h3><p>Seven steps, worked example, and downloadable blank CSV.</p><span>Open checklist →</span></a><a class="feature" href="/nessus-to-poam-guide.html"><h3>Scan findings to POA&amp;M</h3><p>Documentation quality, source traceability, and human review.</p><span>Open guide →</span></a></div></section><section class="wrap section prose"><article><div class="eyebrow dark">GUIDE 01</div><h2>Prioritize vulnerabilities by exposure and exploitation</h2><p>Not every vulnerability is equally urgent. Start with software you actually operate, then determine whether a vulnerable version is present and reachable. An entry in the CISA Known Exploited Vulnerabilities catalog is evidence that exploitation has been observed in the wild, so it is a practical input into prioritization rather than merely a theoretical score.</p><p>Build a simple triage record that includes the asset owner, version, network accessibility, vulnerability reference, compensating controls, remediation owner, and verification date. Compare available vendor remediation guidance to the CISA required action; don't automatically assume a patch is suitable for your environment.</p><p>Federal agencies have specific CISA deadlines. Private businesses can use the dates as useful signals, but should set their own risk-based commitments. Test mitigations in an appropriate environment and track exceptions. Primary source: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV catalog</a>.</p></article><article><div class="eyebrow dark">GUIDE 02</div><h2>Roll out multifactor authentication without causing chaos</h2><p>Start with privileged accounts, email, VPN, and critical business systems. Identify any service accounts or legacy applications that cannot support MFA before enforcing policies broadly. Prefer phishing-resistant MFA when your platforms support it.</p><p>Prepare recovery procedures before deployment: backup factors, help-desk identity verification, and a clear process for lost devices. Test with a small group, monitor lockouts, then expand. MFA reduces account compromise risks but is not a substitute for patching, device protection, and good access management.</p><p>Primary sources: <a href="https://www.cisa.gov/secure-our-world/turn-mfa">CISA MFA guidance</a> and <a href="https://pages.nist.gov/800-63-4/sp800-63b.html">NIST digital identity guidance</a>.</p></article><article><div class="eyebrow dark">GUIDE 03</div><h2>The first hour after a suspected security incident</h2><p>Keep people safe, assess what is happening, preserve evidence, and activate your organization's incident response procedures. Record the time and source of each observation. Isolate affected systems when appropriate, but consider operational consequences and evidence preservation before altering or powering them off.</p><p>Notify the responsible incident commander, IT/security leadership, and legal or compliance teams as required by your organization. Don't promise that a system is clean until there is evidence. Maintain a single decision log covering hypotheses, actions, and owners.</p><p>Reporting duties differ by sector and jurisdiction. Your actual plan and applicable law govern. Primary source: <a href="https://www.cisa.gov/resources-tools/resources/incident-response-plan-irp-basics">CISA incident response plan basics</a>.</p></article><article><div class="eyebrow dark">OPERATIONAL PLAYBOOK</div><h2>Turn a CISA KEV alert into a patch decision you can defend</h2>
<p>Receiving a vulnerability alert is not the same as knowing whether your organization is exposed. Here is a repeatable seven-step approach for a small IT team that lacks a dedicated threat intelligence function. The objective is a documented decision and verified action, not a dashboard full of red numbers.</p>
<h3>1. Verify the source and the affected product</h3><p>Open the official CISA record and vendor advisory. Record the CVE identifier, affected product family, known conditions, vendor-recommended fixed version or mitigation, and source date. Confirm whether the version in your environment is actually affected. Similar product names do not prove applicability. Record uncertainty as an open question, not as a confirmed finding.</p>
<h3>2. Identify the assets you really operate</h3><p>Check your asset inventory, software discovery, configuration management records, and cloud service ownership. Ask the accountable system owner whether the affected component is installed and used. If the inventory is incomplete, create a limited discovery task with a named owner and completion date; do not label every device vulnerable by default. Document which data sources were checked and what remains unknown.</p>
<h3>3. Assess reachability and business impact</h3><p>Distinguish internet-facing systems from internal workloads, and production from isolated test systems. Determine authentication requirements, segmentation, compensating safeguards, maintenance windows, and mission importance. Evidence of real-world exploitation should increase urgency, but exposure and consequence still require local analysis. A software version match by itself does not establish exploitability in your specific configuration.</p>
<h3>4. Choose an authorized response</h3><p>Compare patching, configuration change, disabling a feature, isolation, vendor-approved mitigation, and retiring unsupported products. Verify that the proposed measure actually addresses the identified vulnerability. Some changes can interrupt essential services or violate application support requirements. Get the required change approval and a tested rollback plan before executing. If no feasible mitigation exists, document the accountable risk-acceptance process rather than silently closing the finding.</p>
<h3>5. Assign and schedule accountable work</h3><p>Create a task or POA&amp;M entry stating the system, vulnerability, evidence, owner, action, target date, and dependency. Federal agencies subject to CISA directives must follow applicable federal requirements; private businesses should establish their own documented deadlines based on risk and contractual obligations. Avoid copying a federal deadline into an unrelated commercial policy without explanation.</p>
<h3>6. Verify effectiveness, not just change completion</h3><p>After the change, check the vendor version or relevant configuration, rerun an appropriate assessment, and retain a small record showing that the affected condition was resolved. A successful patch installation log is evidence of change, not necessarily proof that exposure ended. Consider whether other assets or duplicate instances were missed, then have an independent reviewer examine exceptions when appropriate.</p>
<h3>7. Measure whether the process is improving</h3><p>Track time from notice to asset confirmation, time to approved remediation, percentage of actions with verification evidence, and overdue exceptions. A useful weekly review asks: Which exploited vulnerabilities affect exposed business systems, who owns the response, and what is blocking closure? These measures help management prioritize work without pretending that every CVE has an objective single-number business risk score.</p>
<h3>Example: a one-line decision record</h3><p><strong>Illustrative only:</strong> CVE-YYYY-NNNN; affected application confirmed on one externally reachable staging server; production unaffected based on inventory review; owner: IT Operations; mitigation: vendor-approved version upgrade after staging test; scheduled change: next authorized window; verification: version query and targeted rescan; remaining uncertainty: external exposure validation. Replace every illustrative value with evidence collected in your environment.</p>
<p>Primary references: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noopener" target="_blank">CISA Known Exploited Vulnerabilities catalog</a> and <a href="https://csrc.nist.gov/pubs/sp/800/40/r4/final" rel="noopener" target="_blank">NIST SP 800-40 Rev. 4, Enterprise Patch Management Planning</a>. Always review the current vendor advisory before modifying a system.</p></article></section>{accelerator_cta(compact=True)}<section class="wrap section prose">{ad_here}</section>'''.replace('{ad_here}', ad(cfg))
    write_page(cfg, 'guides.html', 'Small-business security guides', 'Original guides to vulnerability prioritization, MFA adoption, and incident response with primary-source links.', guides)

    write_page(cfg, 'weekly-briefing.html', 'Seven-day CISA KEV briefing',
               'Automatically refreshed seven-day CISA KEV additions plus a responsible vulnerability response checklist.',
               build_weekly(rows, version, released) + accelerator_cta(compact=True))
    feed_xml = build_rss(rows, cfg.get('site_url', ''))
    if feed_xml:
        (PUBLIC / 'feed.xml').write_text(feed_xml, encoding='utf-8')

    for filename, title, description in (
        ('rmf-evidence-pilot.html', 'RMF Evidence Acceleration Pilot — $2,500',
         'A scoped $2,500 human-reviewed RMF Evidence Acceleration Pilot using Nessus and ACAS exports to draft POA&M artifacts.'),
        ('kev-triage-checklist.html', 'CISA KEV triage checklist and free CSV', 'A seven-step KEV exposure response checklist with a downloadable vulnerability triage spreadsheet for small IT teams.'),
        ('nessus-to-poam-guide.html', 'Nessus and ACAS to POA&M evidence guide', 'A practical, source-backed RMF workflow for translating scan findings into traceable draft POA&M evidence and reviewable remediation.'),
    ):
        source = ROOT / 'content' / filename
        if not source.is_file():
            raise FileNotFoundError(f'Missing editorial resource: {source}')
        write_page(cfg, filename, title, description, source.read_text(encoding='utf-8') + accelerator_cta(compact=True))

    about = '''<section class="simple-hero"><div class="wrap"><div class="eyebrow">ABOUT</div><h1>Built to reduce security noise</h1><p class="lead">CalculatedIT Threat Pulse is a security-information publication of Calculated Ventures, LLC. It brings together public-source threat intelligence, free tools, and practical security guidance. Our RMF Accelerator and professional services are separate offerings.</p></div></section><section class="wrap section prose"><h2>Editorial standards</h2><p>We use primary sources where possible, distinguish advisory data from interpretation, and avoid invented risk scores. The feed is automatically sourced from the CISA Known Exploited Vulnerabilities catalog; entries are displayed with source links, and any data outage should be treated as a reason to consult CISA directly.</p><p>Calculator outputs are estimates, not guarantees or expert assessments. This publication is not affiliated with or endorsed by NASA, CISA, NIST, or any U.S. government agency. See <a href="https://calculatedit.com/">CalculatedIT and Calculated Ventures</a> for the parent company and commercial services.</p></section>'''
    write_page(cfg, 'about.html', 'About', 'About CalculatedIT Threat Pulse, a Calculated Ventures security-information publication.', about)

    email = cfg.get('contact_email', '')
    contact = ('<p>Questions or corrections? Email <a href="mailto:' + esc(email) + '">' + esc(email) + '</a>.</p>') if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) else '<p>Contact details will be provided by the site operator before public launch. No contact form currently collects user data.</p>'
    write_page(cfg, 'contact.html', 'Contact', 'Contact the CalculatedIT Threat Pulse editorial team.', f'<section class="simple-hero"><div class="wrap"><h1>Contact</h1></div></section><section class="wrap section prose">{contact}</section>')
    privacy = f'''<section class="simple-hero"><div class="wrap"><h1>Privacy policy</h1><p class="lead">Last updated: {esc(today)}</p></div></section><section class="wrap section prose"><h2>What this website does</h2><p>The tools operate locally in your browser. The current site does not include account registration or an email collection form. Hosting providers may process request logs such as IP addresses and user agents under their own policies.</p><h2>Advertising</h2><p>{'The site currently includes a Google AdSense publisher verification tag and an ads.txt authorization entry. Advertising scripts and ad units are not active while the account is being reviewed. If ads are activated later, Google and its advertising partners may use cookies, IP addresses, or other identifiers as described in the applicable consent notice and the Google advertising policy.' if re.fullmatch(r'ca-pub-\d{16}', cfg.get('adsense_publisher_id', '')) else 'Advertising has not been configured. If third-party advertising is enabled, this policy must be reviewed and updated to reflect the actual providers, cookie and consent practices.'}</p><p>Before enabling ads, we will review this policy and implement legally required consent controls. Learn about <a href="https://policies.google.com/technologies/ads">Google advertising technologies</a> and <a href="https://policies.google.com/technologies/partner-sites">how Google uses information from sites and apps that use its services</a>. Depending on a visitor's location and choices, users may be able to limit personalized ads.</p><h2>Outbound links</h2><p>Links to CISA, NIST, and other external websites take you to third parties governed by their respective policies.</p><h2>Questions</h2><p>See the <a href="/contact.html">contact page</a>.</p><p class="muted">Review this disclosure against the site's actual hosting, analytics, advertising and consent setup before enabling advertising. This page is not legal advice.</p></section>'''
    write_page(cfg, 'privacy.html', 'Privacy policy', 'Privacy and third-party advertising disclosure.', privacy)

    (PUBLIC / 'robots.txt').write_text('User-agent: *\nAllow: /\n' + (f'Sitemap: {cfg["site_url"].rstrip("/")}/sitemap.xml\n' if cfg.get('site_url', '').startswith('https://') else ''), encoding='utf-8')
    if cfg.get('site_url', '').startswith('https://'):
        url = cfg['site_url'].rstrip('/')
        pages = ['/', '/alerts.html', '/tools.html', '/guides.html', '/kev-triage-checklist.html', '/nessus-to-poam-guide.html', '/weekly-briefing.html', '/rmf-evidence-pilot.html', '/about.html', '/contact.html', '/privacy.html']
        if poam_tool_release_ready():
            pages.append('/poam-aging-calculator.html')
        (PUBLIC / 'sitemap.xml').write_text('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + ''.join(f'<url><loc>{esc(url+p)}</loc></url>' for p in pages) + '</urlset>', encoding='utf-8')
    ads_line = ads_txt_line(cfg)
    if ads_line:
        (PUBLIC / 'ads.txt').write_text(ads_line, encoding='utf-8')
    else:
        (PUBLIC / 'ads.txt').unlink(missing_ok=True)
    print(f'Built {len(list(PUBLIC.glob("*.html")))} pages. Cached vulnerabilities: {len(rows)}. AdSense: {"configured" if cfg.get("adsense_publisher_id") else "disabled"}.')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--fetch', action='store_true', help='Fetch official CISA KEV source before building')
    args = p.parse_args()
    if args.fetch:
        fetch_kev()
    build()
