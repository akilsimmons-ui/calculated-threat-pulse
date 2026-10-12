# CalculatedIT Threat Pulse — Calculated Ventures branded deployment kit

**Owner:** Calculated Ventures, LLC  
**Purpose:** A separate, ad-supported security publication under the **CalculatedIT / Calculated Ventures** brand. It shares the corporate identity but remains in its **own GitHub repository** and has no access to RMF Accelerator code. The project is not a confirmed income source and does not replicate the unverified NASA-glitch advertisement.

## Deployment (no paid AI credits required)

1. Use the GitHub repository `calculated-threat-pulse` you already created, separate from `calculatedit-rmf-accelerator`. A **public** repository is simplest for no-charge GitHub Actions but makes source code public. Upload the contents of this folder to the repository root, including `.github/workflows/update-feed.yml`. If the GitHub app cannot see the new repository, configure the installed GitHub app to permit access to `calculated-threat-pulse` (or verify the account and repository URL).
2. In Cloudflare dashboard open Workers & Pages → Create → Pages → Import an existing Git repository → select `calculated-threat-pulse`.
3. Configure production branch `main`, build command **`python3 build.py --fetch`**, and output directory **`public`**. Publish. Cloudflare assigns a `*.pages.dev` address; the exact address is not guaranteed until created.
4. After first deployment, enter the assigned HTTPS URL into `config.json` as `site_url`. The public CalculatedIT inquiry email is the initial contact; confirm it is the preferred contact address. Commit and push. Confirm live feeds, working pages, privacy disclosures and operator/contact information.
5. The GitHub workflow runs every day, downloads the official CISA feed, and commits `data/kev.json` only if official data changed; this triggers Cloudflare Pages redeploy. You can manually trigger it from the GitHub Actions tab. GitHub Actions workflows may be delayed or disabled by the provider. Monitor the job periodically.
6. Apply for Google AdSense **only after** the site contains sufficient original, accurate content, compliant privacy/consent notices, and legitimate traffic. AdSense remains disabled until approved credentials are added to `config.json`. Never click your own advertisements or buy invalid traffic.

Cloudflare Pages Free lists 500 builds/month, and standard GitHub-hosted jobs on public repositories are free under current terms; quotas and terms may change. Cloudflare's static hosting is more appropriate for this monetization experiment than treating GitHub Pages as a free commercial host.

## Branding and hosting

- Name: **CalculatedIT Threat Pulse**. Parent/operator: Calculated Ventures, LLC.
- Corporate identity is shared through the brand palette and an image linked from the live Calculated Ventures website.
- The source stays separate from the private RMF Accelerator software. Do not copy credentials, Nessus data, scripts, or client material into a public repo.
- Launch on the free `*.pages.dev` address first; later a `pulse.calculatedit.com` subdomain is possible if DNS access is available, without purchasing another domain.
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
