"""Deterministic, source-traceable briefing and RSS builder for public CISA KEV entries.

Never generate fabricated impact, severity, exploitability, or customer findings.
"""
import datetime as dt
import html
from urllib.parse import quote


def esc(value):
    return html.escape(str(value or ''), quote=True)


def build_weekly(rows, version, released, today=None):
    today = today or dt.datetime.now(dt.timezone.utc).date()
    start = today - dt.timedelta(days=6)
    recent = [r for r in rows if start.isoformat() <= r['dateAdded'] <= today.isoformat()]
    if recent:
        summary = f'{len(recent)} KEV catalog entries were added during this seven-day window.'
    else:
        summary = 'No new entries were added to the cached catalog in this seven-day window.'
    items = []
    for r in recent[:25]:
        url = '/alerts.html#' + quote(r['cveID'])
        items.append(
            f'<li><a href="{esc(url)}"><strong>{esc(r["cveID"])}</strong></a>'
            f' — {esc(r["vendorProject"])} / {esc(r["product"])} '
            f'<small>(catalog addition {esc(r["dateAdded"])})</small>'
            f'<div>{esc(r["vulnerabilityName"])}</div></li>'
        )
    if not items:
        items = ['<li>No new records in the reporting window. Existing unresolved exposure still matters.</li>']
    return (
        '<section class="simple-hero"><div class="wrap"><div class="eyebrow">'
        'FACTUAL CISA SOURCE BRIEFING</div><h1>Seven-day KEV watchlist</h1>'
        '<p class="lead">An automatically refreshed list of newly cataloged vulnerabilities,'
        ' paired with an evergreen response checklist. It does not assess your environment.</p>'
        '</div></section><section class="wrap section prose editorial-article">'
        f'<p class="resource-meta">Window: {esc(start.isoformat())} – {esc(today.isoformat())} (UTC)'
        f' · CISA catalog edition: {esc(version or "unknown")}'
        f' · Feed release: {esc(released or "not provided")}</p>'
        f'<div class="resource-callout"><strong>{esc(summary)}</strong>'
        '<p>The catalog addition date is not the date exploitation began. A KEV listing is'
        ' not proof a particular device is affected, nor a substitute for vendor instructions.</p>'
        '</div><h2>Newly added records</h2><ol class="weekly-additions">'
        + ''.join(items) +
        '</ol><p>Showing at most 25 additions. '
        '<a href="/alerts.html">Search the latest 200 KEV records</a> or'
        ' <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"'
        ' target="_blank" rel="noopener">consult the authoritative CISA catalog</a>.</p>'
        '<h2>What your team should do with this list</h2><ol class="checklist-steps">'
        '<li>Confirm affected product, supported fix, and vulnerable versions in the vendor advisory.</li>'
        '<li>Match the affected component against your asset inventory and actual exposure.</li>'
        '<li>Assign an accountable owner, an authorized remediation path, and a target date.</li>'
        '<li>Verify the change and preserve evidence before marking any finding resolved.</li>'
        '</ol><p>Use the <a href="/kev-triage-checklist.html">free KEV triage checklist'
        ' and CSV worksheet</a> to document your decisions.</p>'
        '<p class="fine">CISA is the primary data source; this page is a'
        ' deterministic summary, not new independent intelligence.'
        ' Source downloads may lag. Verify any urgent decision directly with CISA'
        ' and the responsible vendor.</p></section>'
    )


def build_rss(rows, origin):
    origin = origin.rstrip('/')
    if not origin.startswith('https://'):
        return ''
    items = []
    for r in rows[:30]:
        try:
            published = dt.date.fromisoformat(r['dateAdded'])
        except ValueError:
            continue
        date = published.strftime('%a, %d %b %Y 00:00:00 +0000')
        title = f'{r["cveID"]} — {r["vendorProject"]} / {r["product"]}'
        summary = (
            f'Added to the CISA Known Exploited Vulnerabilities catalog on {r["dateAdded"]}. '
            f'{r["vulnerabilityName"]}. {r["shortDescription"]} '
            'Confirm applicability, vendor guidance, and your actual exposure.'
        )
        url = origin + '/alerts.html#' + quote(r['cveID'])
        items.append(
            f'<item><title>{esc(title)}</title><link>{esc(url)}</link>'
            f'<guid isPermaLink="false">{esc(r["cveID"])}</guid>'
            f'<pubDate>{esc(date)}</pubDate>'
            f'<description>{esc(summary)}</description></item>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
        '<title>CalculatedIT Threat Pulse — CISA KEV additions</title>'
        f'<link>{esc(origin + "/alerts.html")}</link>'
        '<description>Source-traceable CISA catalog additions; not environment-specific findings.</description>'
        '<language>en-us</language>' + ''.join(items) + '</channel></rss>'
    )
