import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="Acme Financial | VulnCheck Vulnerability Intelligence", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------------------
# Brand palette — kept identical to the Step 2 HTML dashboard and Step 3
# executive deck, so all three deliverables read as one product line.
# ---------------------------------------------------------------------------
TIER_ORDER = [
    "Ransomware",
    "Botnets",
    "Threat Actors (APT)",
    "Unattributed KEV",
    "Weaponized",
    "Proof-of-Concept",
    "All Other Vulnerabilities",
]
TIER_COLORS = {
    "Ransomware": "#F2545B",
    "Botnets": "#F5934A",
    "Threat Actors (APT)": "#B98AF7",
    "Unattributed KEV": "#4C9FF2",
    "Weaponized": "#E8C94A",
    "Proof-of-Concept": "#6FCB8E",
    "All Other Vulnerabilities": "#8996B0",
}
ACCENT = "#27D3A6"

st.markdown(f"""
    <style>
    .main-header {{ font-size: 30px; font-weight: 700; margin-bottom: 0px; }}
    .sub-header {{ font-size: 15px; color: #8996B0; margin-bottom: 24px; }}
    .kpi-card {{
        background: #161E30; border: 1px solid #232D44; border-radius: 10px;
        padding: 18px 20px;
    }}
    .kpi-card.highlight {{ background: #0F2A24; border-color: #1B7A62; }}
    .kpi-val {{ font-size: 32px; font-weight: 700; color: #E7ECF6; line-height: 1; }}
    .kpi-card.highlight .kpi-val {{ color: {ACCENT}; }}
    .kpi-label {{ font-size: 12.5px; color: #8996B0; margin-top: 6px; }}
    </style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
REQUIRED_COLUMNS = [
    "CVE", "Associated CPE", "CVSS V3 Base", "EPSS Score",
    "CISA KEV", "VulnCheck KEV", "Max Exploit Maturity",
    "NVD Published", "First Exploit Published", "Weaponized Exploit Published",
    "CISA KEV Date Added", "VulnCheck KEV Date Added",
    "Ransomware Associated", "Botnet Associated", "APT Associated",
    "Threat Actors", "Description",
]

def assign_tier(row):
    """Fallback tiering logic — mirrors compute_priority_tier() in the
    enrichment notebook. Only used if a CSV/JSON predates the notebook's own
    'Priority Tier' column; otherwise that column is used directly so there
    is a single source of truth for tiering."""
    if row["Ransomware Associated"]:
        return "Ransomware"
    if row["Botnet Associated"]:
        return "Botnets"
    if row["APT Associated"]:
        return "Threat Actors (APT)"
    if row["VulnCheck KEV"] or row["CISA KEV"]:
        return "Unattributed KEV"
    if row["Max Exploit Maturity"] == "weaponized":
        return "Weaponized"
    if row["Max Exploit Maturity"] in ("poc", "proof-of-concept", "proof of concept"):
        return "Proof-of-Concept"
    return "All Other Vulnerabilities"


def parse_asset(cpe):
    parts = str(cpe).split(":")
    if len(parts) > 4:
        vendor, product = parts[3], parts[4]
        return f"{product} ({vendor})"
    return str(cpe)


@st.cache_data
def load_data(file_source, is_json=False):
    df = pd.read_json(file_source) if is_json else pd.read_csv(file_source)
    df.columns = [c.strip() for c in df.columns]

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            "This doesn't look like output from the Step 1 enrichment notebook. "
            f"Missing expected column(s): {', '.join(missing)}"
        )

    for col in ["Ransomware Associated", "Botnet Associated", "APT Associated", "VulnCheck KEV", "CISA KEV"]:
        df[col] = df[col].astype(str).str.lower().isin(["true", "1", "yes"])

    df["Max Exploit Maturity"] = df["Max Exploit Maturity"].fillna("unproven").astype(str).str.lower()
    df["Threat Actors"] = df["Threat Actors"].fillna("None")
    df["EPSS Score"] = pd.to_numeric(df["EPSS Score"], errors="coerce")
    df["CVSS V3 Base"] = pd.to_numeric(df["CVSS V3 Base"], errors="coerce")
    
    # Format timeline dates
    date_cols = [
        "NVD Published", "First Exploit Published", "Weaponized Exploit Published",
        "CISA KEV Date Added", "VulnCheck KEV Date Added"
    ]
    for c in date_cols:
        df[c] = pd.to_datetime(df[c], errors="coerce").dt.strftime("%Y-%m-%d").fillna("N/A")

    # Prefer the tier the notebook already computed; recompute only as a
    # fallback so this app also works on older exports.
    if "Priority Tier" in df.columns:
        df["Prioritization Tier"] = df["Priority Tier"]
    else:
        df["Prioritization Tier"] = df.apply(assign_tier, axis=1)
    df["Prioritization Tier"] = pd.Categorical(df["Prioritization Tier"], categories=TIER_ORDER, ordered=True)

    if "Associated CPE" in df.columns:
        df["Asset"] = df["Associated CPE"].apply(parse_asset)

    return df


# ---------------------------------------------------------------------------
# SIDEBAR — load & filter
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("Acme SecOps")
    st.caption("Evidence-Based Vulnerability Prioritization — VulnCheck Intelligence")

    uploaded_file = st.file_uploader(
        "Upload enrichment output (.csv or .json)",
        type=["csv", "json"],
        help="Export directly from the Step 1 notebook: acme_enriched_cves.csv or acme_enriched_cves.json",
    )

    df = None
    if uploaded_file is not None:
        is_json = uploaded_file.name.lower().endswith(".json")
        try:
            df = load_data(uploaded_file, is_json=is_json)
        except ValueError as e:
            st.error(str(e))
            st.stop()
    else:
        for default_name, is_json in [("acme_enriched_cves.csv", False), ("acme_enriched_cves.json", True)]:
            if os.path.exists(default_name):
                df = load_data(default_name, is_json=is_json)
                break

    if df is None:
        st.warning(
            "Upload your real `acme_enriched_cves.csv` or `.json` export from the Step 1 "
            "enrichment notebook to get started. This app ships with no sample data — "
            "nothing renders until you load an actual result set."
        )
        st.stop()

    st.success(f"Loaded {len(df)} enriched CVEs.")

    available_assets = sorted(df["Asset"].dropna().unique())
    selected_assets = st.multiselect("Target Asset", options=available_assets, default=available_assets)

    available_tiers = [t for t in TIER_ORDER if t in df["Prioritization Tier"].unique()]
    selected_tiers = st.multiselect("Prioritization Tier", options=available_tiers, default=available_tiers)

filtered_df = df[df["Asset"].isin(selected_assets) & df["Prioritization Tier"].isin(selected_tiers)].copy()

# ---------------------------------------------------------------------------
# HEADER
# ---------------------------------------------------------------------------
st.markdown('<div class="main-header">Acme Financial Services</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Vulnerability Intelligence Briefing — powered by VulnCheck Exploit & Vulnerability Intelligence</div>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# KPI STRIP + VULNCHECK ADVANTAGE CALLOUT
# ---------------------------------------------------------------------------
total = len(filtered_df)
high_sev = int((filtered_df["CVSS V3 Base"] >= 7).sum())
vc_kev = int(filtered_df["VulnCheck KEV"].sum())
gap = int((filtered_df["VulnCheck KEV"] & ~filtered_df["CISA KEV"]).sum())

k1, k2, k3, k4 = st.columns(4)
for col, val, label, highlight in [
    (k1, str(total), "CVEs in scope", False),
    (k2, str(high_sev), "High or Critical (CVSS ≥ 7)", False),
    (k3, str(vc_kev), "Confirmed actively exploited (VulnCheck KEV)", False),
    (k4, str(gap), "Found only by VulnCheck, missed by CISA KEV", True),
]:
    cls = "kpi-card highlight" if highlight else "kpi-card"
    col.markdown(f'<div class="{cls}"><div class="kpi-val">{val}</div><div class="kpi-label">{label}</div></div>', unsafe_allow_html=True)

st.write("")
if vc_kev > 0 and gap > 0:
    st.info(
        f"**VulnCheck Advantage:** of {vc_kev} confirmed known-exploited CVEs in this view, "
        f"**{gap}** {'is' if gap == 1 else 'are'} tracked by VulnCheck's extended KEV but absent from "
        f"CISA's catalog — a CISA-KEV-only workflow would leave {'this' if gap == 1 else 'these'} "
        f"actively exploited finding{'s' if gap != 1 else ''} unprioritized."
    )
elif vc_kev > 0:
    st.info(f"**{vc_kev}** confirmed known-exploited CVE(s) in this view, all also present in CISA KEV.")

st.divider()

# ---------------------------------------------------------------------------
# PYRAMID + ASSET BREAKDOWN + TABLE
# ---------------------------------------------------------------------------
chart_col, data_col = st.columns([1, 1.4])

with chart_col:
    st.subheader("Vulnerability Prioritization Pyramid")
    tier_counts = [int((filtered_df["Prioritization Tier"] == t).sum()) for t in TIER_ORDER]

    fig_pyramid = go.Figure(go.Funnel(
        y=TIER_ORDER,
        x=tier_counts,
        textinfo="value",
        marker={"color": [TIER_COLORS[t] for t in TIER_ORDER], "line": {"width": 1, "color": "#0B1220"}},
    ))
    fig_pyramid.update_layout(
        margin=dict(l=20, r=20, t=20, b=20),
        height=420,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#E7ECF6"),
    )
    st.plotly_chart(fig_pyramid, use_container_width=True)

    st.subheader("Exposure by Asset")
    if len(filtered_df) > 0:
        asset_tier = filtered_df.groupby(["Asset", "Prioritization Tier"], observed=True).size().reset_index(name="Count")
        fig_asset = px.bar(
            asset_tier, x="Count", y="Asset", color="Prioritization Tier",
            orientation="h", category_orders={"Prioritization Tier": TIER_ORDER},
            color_discrete_map=TIER_COLORS,
        )
        fig_asset.update_layout(
            height=280, margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E7ECF6"), legend=dict(font=dict(size=10)),
        )
        st.plotly_chart(fig_asset, use_container_width=True)

with data_col:
    st.subheader("Prioritized Vulnerability Register")
    search = st.text_input("Search CVE or product", "")
    display_cols = ["CVE", "Asset", "Prioritization Tier", "CVSS V3 Base", "EPSS Score", "VulnCheck KEV", "CISA KEV", "Max Exploit Maturity", "Threat Actors"]
    table_df = filtered_df[display_cols].copy()
    if search:
        mask = table_df["CVE"].str.contains(search, case=False, na=False) | table_df["Asset"].str.contains(search, case=False, na=False)
        table_df = table_df[mask]
    table_df = table_df.sort_values(by=["Prioritization Tier", "CVSS V3 Base"], ascending=[True, False])

    st.dataframe(
        table_df,
        use_container_width=True,
        height=530,
        column_config={
            "CVSS V3 Base": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "EPSS Score": st.column_config.NumberColumn("EPSS", format="%.2f"),
            "VulnCheck KEV": st.column_config.CheckboxColumn("VC KEV"),
            "CISA KEV": st.column_config.CheckboxColumn("CISA KEV"),
            "Threat Actors": st.column_config.TextColumn("Attribution", width="medium"),
        },
        hide_index=True,
    )

st.divider()

# ---------------------------------------------------------------------------
# DEEP-DIVE INSPECTOR
# ---------------------------------------------------------------------------
st.subheader("🔍 Deep-Dive Vulnerability Inspector")

if len(filtered_df) == 0:
    st.info("No CVEs match the current filters.")
else:
    selected_cve = st.selectbox("Select a CVE to inspect technical telemetry:", options=sorted(filtered_df["CVE"].unique()))
    cve_detail = filtered_df[filtered_df["CVE"] == selected_cve].iloc[0]

    detail_col1, detail_col2, detail_col3, detail_col4 = st.columns([1.1, 1, 1.1, 2])

    with detail_col1:
        st.markdown("**Core Metrics**")
        st.markdown(f"**Asset:** `{cve_detail['Associated CPE']}`")
        st.markdown(f"**CVSS Base:** `{cve_detail['CVSS V3 Base']}`")
        st.markdown(f"**EPSS Score:** `{cve_detail['EPSS Score']}`")
        st.markdown(f"**Exploit Maturity:** `{str(cve_detail['Max Exploit Maturity']).upper()}`")
        st.markdown(f"**Tier:** `{cve_detail['Prioritization Tier']}`")

    with detail_col2:
        st.markdown("**Intelligence Telemetry**")
        st.markdown(f"**VulnCheck KEV:** {'✅' if cve_detail['VulnCheck KEV'] else '❌'}")
        st.markdown(f"**CISA KEV:** {'✅' if cve_detail['CISA KEV'] else '❌'}")
        st.markdown(f"**Ransomware Link:** {'✅' if cve_detail['Ransomware Associated'] else '❌'}")
        st.markdown(f"**Botnet Link:** {'✅' if cve_detail['Botnet Associated'] else '❌'}")
        st.markdown(f"**APT Link:** {'✅' if cve_detail['APT Associated'] else '❌'}")

    with detail_col3:
        st.markdown("**Exploit Timelines**")
        st.markdown(f"**NVD Published:** `{cve_detail.get('NVD Published', 'N/A')}`")
        st.markdown(f"**First Exploit:** `{cve_detail.get('First Exploit Published', 'N/A')}`")
        st.markdown(f"**Weaponized:** `{cve_detail.get('Weaponized Exploit Published', 'N/A')}`")
        st.markdown(f"**CISA KEV Added:** `{cve_detail.get('CISA KEV Date Added', 'N/A')}`")
        st.markdown(f"**VC KEV Added:** `{cve_detail.get('VulnCheck KEV Date Added', 'N/A')}`")

    with detail_col4:
        st.markdown("**Vulnerability Description:**")
        st.info(cve_detail["Description"])
        if cve_detail["Threat Actors"] != "None":
            st.warning(f"**Known Threat Actors:** {cve_detail['Threat Actors']}")

st.caption(
    "Methodology: CPE → CVE via VulnCheck CPE API · CVSS/description via VulnCheck NVD2 · "
    "exploit maturity, KEV status, and ransomware/botnet/APT attribution via VulnCheck Exploits & KEV indices · "
    "EPSS via FIRST.org."
)