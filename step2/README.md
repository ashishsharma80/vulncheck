# Acme Financial Services — Vulnerability Intelligence (Streamlit)

Streamlit rewrite of the Step 2 dashboard. **Ships with no embedded or sample
data** — it only renders real output from the Step 1 enrichment pipeline
(`enrich_cves.py` or `AcmeVuln_enriched.ipynb`).

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Loading data

Two ways:

1. **Upload in the sidebar** — click "Upload enrichment output" and select
   your `acme_enriched_cves.csv` or `acme_enriched_cves.json` exported from
   the Step 1 notebook.
2. **Auto-load from disk** — drop `acme_enriched_cves.csv` (or `.json`) in
   the same folder as `app.py` and it loads automatically on startup.

The app validates the uploaded file has the columns the enrichment notebook
actually produces (`CVE`, `Associated CPE`, `CVSS V3 Base`, `EPSS Score`,
`CISA KEV`, `VulnCheck KEV`, `Max Exploit Maturity`, `Ransomware Associated`,
`Botnet Associated`, `APT Associated`, `Threat Actors`, `Description`) and
shows an error rather than guessing if something else is uploaded.

If the notebook's `Priority Tier` column is present, the app uses it
directly — it does not silently recompute a different tiering than the one
your Step 1 analysis already produced. Older exports without that column
fall back to an in-app tier calculation using the same logic.

## What's on the page

- **KPI strip** — CVEs in scope, high/critical count, confirmed VulnCheck-KEV
  count, and the headline sales stat: CVEs confirmed exploited by VulnCheck
  but absent from CISA KEV, plus an auto-generated "VulnCheck Advantage"
  callout sentence.
- **Prioritization pyramid** — funnel chart of the 7 tiers, same color
  mapping used in the Step 2 HTML dashboard and Step 3 slide deck.
- **Exposure by asset** — stacked horizontal bar per CPE.
- **Prioritized register** — searchable, sortable table.
- **Deep-dive inspector** — pick any CVE to see full telemetry
  (CVSS, EPSS, KEV flags, attribution, description) in one place.
- **Sidebar filters** — by asset and by prioritization tier.

## Theming

`.streamlit/config.toml` sets a dark theme matching the brand palette used
across all three Step 1–3 deliverables (teal accent `#27D3A6` on navy
`#0B1220`), so this reads as the same product as the HTML dashboard and the
slide deck.
