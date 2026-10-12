# CalculatedIT Threat Pulse — Calculated Ventures branded deployment kit

**Owner:** Calculated Ventures, LLC  
**Purpose:** A separate, ad-supported security publication under the **CalculatedIT / Calculated Ventures** brand. It shares the corporate identity but remains in its **own GitHub repository** and has no access to RMF Accelerator code. The project is not a confirmed income source and does not replicate the unverified NASA-glitch advertisement.

## Live deployment (Render static site)

- Production domain: **https://pulse.calculatedit.com/** (custom domain verified; HTTPS certificate issued on 2026-10-12).
- Render static site: **https://calculatedit-threat-pulse.onrender.com/**.
- Render service name: `calculatedit-threat-pulse`, separate from the `calculatedit-rmf-accelerator` web service.
- Repository: `akilsimmons-ui/calculated-threat-pulse`, branch `main`.
- Build command: `exit 0` (GitHub Actions generates and commits the static output); publish directory: `public`; auto-deploy: enabled.
- GitHub workflow `.github/workflows/update-feed.yml` refreshes official CISA KEV data every day, runs unit tests, regenerates static pages, and commits changed `data/kev.json` and `public` content.
- Authoritative logo is the established Calculated Ventures four-piece puzzle logo, linked from the main WordPress site's media library rather than hand-drawn approximation.
- The WordPress site and the private RMF Accelerator are **not** modified by this deployment.

### Site ownership and advertising

The AdSense publisher ID and advertising slot remain empty in `config.json`; `ads_enabled` is false. On applying for AdSense, follow Google's current domain-level onboarding process for `calculatedit.com` (it generally does not accept independently entered first-party subdomains). Enter the real assigned `ca-pub-` publisher ID when issued and rebuild the site; this inserts a non-serving account-verification meta tag and, where applicable, generates `public/ads.txt`. Do **not** set `ads_enabled` to true until approval and any required privacy/consent implementation are finished. Google reviews site quality and does not guarantee approval or ad revenue.

This publication must offer substantial, truthful editorial utility beyond CISA's republished feed. Always verify automated cybersecurity information against current primary sources. We are not promising passive income; evaluate traffic and useful engagement before spending on monetization.

## Branding and hosting

- Name: **CalculatedIT Threat Pulse**. Parent/operator: Calculated Ventures, LLC.
- Corporate identity is shared through the brand palette and an image linked from the live Calculated Ventures website.
- The source stays separate from the private RMF Accelerator software. Do not copy credentials, Nessus data, scripts, or client material into a public repo.
- The live site uses a Render-provided static hostname plus the existing `pulse.calculatedit.com` custom subdomain; no new domain purchase was necessary.
- The published site needs editorial review before enabling advertising.

## Local test

Run `python3 build.py` and `python3 -m http.server 8000 --directory public`, then visit http://localhost:8000 . Use `python3 build.py --fetch` to download the CISA data. The website does not make up missing data.

## Cautions

- Publish only accurate, human-reviewed security material and source links. The optional AI draft helper is a *draft tool*, not unattended news publication.
- The initial security guides and calculators are educational, not professional assessments.
- Do not publish if the operator contact details and legally required privacy/consent disclosures are incomplete.
- Financial milestone: reach first 100 authentic visits, then measure whether users actually return. Expect no ad revenue until approval and traffic.

## Tests

`python3 -m unittest discover -s tests -v`

---

## Optional local AI writer

If you have a machine capable of running Ollama, you can download a free local model and run `python3 ai_draft.py "How small teams verify critical patches"`. The draft is not automatically published and must be checked for factual accuracy. This is optional and does not require paid AI credits.
