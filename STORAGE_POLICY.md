# Threat Pulse — Storage & Retention Policy

**Effective:** 2026-10-13

Goal: retain useful CISA historical reference data, control static publishing growth, and avoid extra paid infrastructure or daily backup copies.

| Component | Limit | Behavior |
|---|---:|---|
| Cached official CISA KEV catalog (`data/kev.json`) | **8 MB** | One current full-source catalog, not a daily snapshot. Older entries remain available while present in CISA's current catalog. When the downloaded source fails validation, the last valid cache is kept. |
| Public recent-alert JSON (`public/data/kev.json`) | **200 records** | Refreshed in place, not appended daily. |
| Public threat feed | **200 records** | Searchable recent alerts; older catalog records stay in the cached full-source file. |
| Homepage | **6 alerts** | Latest entries only. |
| Seven-day briefing | **7 days** | Rolling date window, regenerated from source. |
| Dedicated public CVE pages | **500 pages** | Published URLs are preserved; new pages stop when capacity is reached. The feed, alerts and source cache keep refreshing. |
| Total published static files (all pages, media, scripts, public data) | **25 MiB** | Builds beyond limit fail rather than deleting content; previous live deployment stays online. |

The hosted site is deliberately **not** an append-only daily data warehouse. Git records prior commits as repository history; Git history is not guaranteed indefinite archival storage and can itself grow. No personal visitor profiles, credentials, or customer data are collected or archived by this static-site code.

**Operations:** Existing GitHub Actions refreshes, tests and republishes daily. It alerts on workflow failure through normal GitHub notifications. A limit failure requires reviewing capacity and deliberately revising this policy; the system must not silently erase older records or inflate a paid plan.

**Current source size at policy creation:** approximately 1.39 MB; 24 dedicated CVE records used around 0.23 MB. There is substantial headroom.

**Future historical search:** Search the retained full CISA catalog or build a separate bounded on-demand archive interface; do not mass-publish thousands of nearly identical CVE pages without a demonstrated reader benefit.
