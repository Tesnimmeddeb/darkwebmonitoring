"""
AEGIS MONITOR — Dark Web CTI Dashboard
Fichier unique : navigation (sidebar) + pages (design Stitch "Obsidian Sentinel")
branchées sur les vraies données (storage.lire_toutes_les_alertes).
"""

import html
import time
import json
import os
import re as _re
from datetime import datetime, timedelta

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from storage import lire_toutes_les_alertes

# ============================================================
# SETTINGS — persistance simple dans un fichier JSON local
# ============================================================
SETTINGS_FILE = "app_settings.json"
UPLOADS_DIR = "settings_uploads"

DEFAULT_SETTINGS = {
    # General
    "general_platform_name": "AEGIS MONITOR",
    "general_timezone": "UTC",
    "general_language": "en",
    "general_logo_filename": None,
    # Security
    "security_mfa": True,
    "security_session_timeout": "30",
    "security_ip_whitelist": "",
    "security_pwd_min_length": True,
    "security_pwd_upper_lower": True,
    "security_pwd_special": True,
    # Monitoring
    "monitoring_scan_interval": "2",
    "monitoring_src_hudsonrock": True,
    "monitoring_src_ransomwarelive": True,
    "monitoring_src_checkthesum": True,
    "monitoring_src_ransomlook": True,
    "monitoring_alert_threshold": "eleve",
    # Notifications
    "notif_email_enabled": True,
    "notif_slack_enabled": False,
    "notif_pagerduty_enabled": False,
    "notif_email_recipients": "",
    "notif_digest_enabled": False,
    # Team (liste gérée séparément, sauvegardée immédiatement)
    "team_members": [
        {"email": "soc_lead@company.com", "role": "Admin"},
        {"email": "analyst_1@company.com", "role": "Analyst"},
        {"email": "analyst_2@company.com", "role": "Analyst"},
    ],
}


def load_settings() -> dict:
    """Charge les paramètres depuis settings.json, complète avec les valeurs
    par défaut si le fichier est absent ou incomplet (première utilisation,
    ou nouveau champ ajouté depuis la dernière sauvegarde)."""
    data = {}
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    merged = dict(DEFAULT_SETTINGS)
    merged.update(data)
    return merged


def save_settings(settings: dict) -> None:
    """Écrit les paramètres dans settings.json (persistant entre les sessions)."""
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)


# Chargé une seule fois par session, avant même set_page_config (aucun rendu
# Streamlit n'est déclenché par un simple accès à session_state, donc c'est sûr).
if "app_settings" not in st.session_state:
    st.session_state.app_settings = load_settings()

_PLATFORM_NAME = st.session_state.app_settings.get("general_platform_name") or "AEGIS MONITOR"

# ============================================================
# CONFIG PAGE
# ============================================================
st.set_page_config(
    page_title=f"{_PLATFORM_NAME} — Dark Web Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# PALETTE — reprise du DESIGN.md de Stitch (Obsidian Sentinel)
# ============================================================
C = {
    "bg": "#051424",
    "surface": "#051424",
    "surface_low": "#0e1c2d",
    "surface_container": "#122031",
    "surface_high": "#1d2b3c",
    "surface_highest": "#283647",
    "on_surface": "#d5e4fa",
    "on_surface_variant": "#bdc8d1",
    "outline": "#87929a",
    "outline_variant": "#1e293b",
    "primary": "#8ed5ff",
    "accent": "#38bdf8",
    "on_primary": "#00354a",
    "error": "#ef4444",
    "warning": "#f59e0b",
    "success": "#10b981",
}

# Sémantique de sévérité
SEVERITY = {
    "critique": {"color": "#ef4444", "bg": "rgba(239,68,68,0.14)", "label": "Critique"},
    "eleve":    {"color": "#f59e0b", "bg": "rgba(245,158,11,0.14)", "label": "Élevée"},
    "faible":   {"color": "#10b981", "bg": "rgba(16,185,129,0.14)", "label": "Faible"},
}
DEFAULT_SEV = {"color": C["outline"], "bg": "rgba(135,146,154,0.12)", "label": "Inconnue"}

NAV_ITEMS = [
    ("dashboard", "dashboard", "Dashboard"),
    ("darkweb", "security", "Dark Web Monitoring"),
    ("assets", "hub", "Assets"),
    ("alerts", "notifications_active", "Alerts"),
    ("leaks", "leak_add", "Leaks"),
    ("search", "search", "Search"),
    ("reports", "assessment", "Reports"),
    ("settings", "settings", "Settings"),
]

# ============================================================
# CSS GLOBAL
# ============================================================
st.markdown(f"""
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&display=swap" rel="stylesheet">
<style>
    html, body, [class*="css"] {{
        font-family: 'Inter', sans-serif;
    }}
    .stApp {{
        background-color: {C['bg']};
        color: {C['on_surface']};
    }}
    #MainMenu, footer {{visibility: hidden;}}
    header[data-testid="stHeader"] {{
        background: transparent;
    }}

    /* ---- Sidebar ---- */
    section[data-testid="stSidebar"] {{
        background-color: {C['surface_low']};
        border-right: 1px solid {C['outline_variant']};
    }}
    section[data-testid="stSidebar"] > div {{
        padding-top: 1.2rem;
    }}
    .aegis-logo {{
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 0 0.5rem 1.4rem 0.5rem;
        margin-bottom: 0.6rem;
        border-bottom: 1px solid {C['outline_variant']};
    }}
    .aegis-logo-icon {{
        width: 34px; height: 34px;
        background: {C['accent']};
        border-radius: 6px;
        display: flex; align-items: center; justify-content: center;
        color: {C['on_primary']};
        flex-shrink: 0;
    }}
    .aegis-logo-text h1 {{
        font-size: 16px; font-weight: 900; color: {C['primary']};
        margin: 0; letter-spacing: 0.02em; line-height: 1.1;
    }}
    .aegis-logo-text p {{
        font-size: 10px; font-weight: 700; letter-spacing: 0.05em;
        text-transform: uppercase; color: {C['on_surface_variant']};
        margin: 2px 0 0 0;
    }}

    /* Boutons de nav dans la sidebar */
    section[data-testid="stSidebar"] div[data-testid="stButton"] > button {{
        width: 100%;
        justify-content: flex-start;
        text-align: left;
        background: transparent;
        border: none;
        border-left: 3px solid transparent;
        border-radius: 0 8px 8px 0;
        color: {C['on_surface_variant']};
        font-weight: 600;
        font-size: 13px;
        letter-spacing: 0.03em;
        padding: 0.55rem 0.9rem;
        margin-bottom: 2px;
        transition: all 0.15s ease;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    section[data-testid="stSidebar"] div[data-testid="stButton"] > button:hover {{
        background: {C['surface_highest']};
        color: {C['on_surface']};
        border-left-color: {C['outline']};
    }}
    section[data-testid="stSidebar"] div[data-testid="stButton"] > button[kind="primary"] {{
        background: rgba(56,189,248,0.10) !important;
        color: {C['accent']} !important;
        border-left: 3px solid {C['accent']} !important;
    }}
    section[data-testid="stSidebar"] div[data-testid="stButton"] > button[kind="primary"]:hover {{
        background: rgba(56,189,248,0.16) !important;
    }}

    /* ---- Top header ---- */
    .aegis-header {{
        display: flex; justify-content: space-between; align-items: center;
        padding: 0.4rem 0 1rem 0;
        border-bottom: 1px solid {C['outline_variant']};
        margin-bottom: 1.4rem;
    }}
    .aegis-header h2 {{ font-size: 20px; font-weight: 700; margin: 0; color: {C['on_surface']}; }}
    .live-pill {{
        display: inline-flex; align-items: center; gap: 6px;
        background: {C['surface_highest']};
        padding: 4px 10px; border-radius: 6px;
        font-size: 11px; font-weight: 600; color: {C['on_surface_variant']};
        margin-left: 12px;
    }}
    .live-dot {{
        width: 7px; height: 7px; border-radius: 50%;
        background: {C['accent']};
        box-shadow: 0 0 0 0 rgba(56,189,248,0.6);
        animation: pulse 1.6s infinite;
    }}
    @keyframes pulse {{
        0% {{ box-shadow: 0 0 0 0 rgba(56,189,248,0.55); }}
        70% {{ box-shadow: 0 0 0 6px rgba(56,189,248,0); }}
        100% {{ box-shadow: 0 0 0 0 rgba(56,189,248,0); }}
    }}

    /* ---- Cards / glass ---- */
    .glass-card {{
        background: rgba(15,23,42,0.55);
        backdrop-filter: blur(10px);
        border: 1px solid {C['outline_variant']};
        border-radius: 12px;
        padding: 16px;
    }}
    .stat-label {{
        font-size: 11px; font-weight: 700; letter-spacing: 0.05em;
        text-transform: uppercase; color: {C['on_surface_variant']};
    }}
    .stat-value {{
        font-size: 30px; font-weight: 700; color: {C['on_surface']};
        margin-top: 6px; line-height: 1.1;
    }}
    .stat-sub {{
        font-size: 11px; font-weight: 500; margin-top: 8px;
        color: {C['outline']};
        font-family: 'Inter', monospace;
    }}
    .card-title {{
        font-size: 15px; font-weight: 700; color: {C['on_surface']};
        margin: 0 0 14px 0; padding-bottom: 12px;
        border-bottom: 1px solid {C['outline_variant']};
    }}

    /* ---- Table ---- */
    table.aegis-table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
    table.aegis-table thead th {{
        text-align: left; font-size: 10.5px; font-weight: 700;
        letter-spacing: 0.05em; text-transform: uppercase;
        color: {C['on_surface_variant']};
        padding: 8px 10px; border-bottom: 1px solid {C['outline_variant']};
    }}
    table.aegis-table tbody td {{
        padding: 9px 10px; color: {C['on_surface']};
        border-bottom: 1px solid rgba(30,41,59,0.5);
        font-family: 'Inter', monospace;
        white-space: nowrap;
    }}
    table.aegis-table tbody tr:hover {{ background: rgba(40,54,71,0.35); }}
    .sev-badge {{
        display: inline-flex; align-items: center; gap: 5px;
        font-weight: 600; font-size: 12px;
    }}
    .sev-dot {{ width: 6px; height: 6px; border-radius: 50%; }}

    /* ---- Live alert ---- */
    .live-alert {{
        background: {C['surface_highest']};
        border: 1px solid {C['outline_variant']};
        border-radius: 8px;
        padding: 10px 12px;
        margin-bottom: 8px;
    }}
    .live-alert-top {{ display: flex; justify-content: space-between; margin-bottom: 4px; }}
    .live-alert-sev {{ font-size: 10px; font-weight: 700; letter-spacing: 0.05em; }}
    .live-alert-time {{ font-size: 10px; color: {C['outline']}; font-family: monospace; }}
    .live-alert-text {{ font-size: 12.5px; color: {C['on_surface']}; line-height: 1.35; }}

    div[data-testid="stMetric"] {{ display: none; }}

    /* ---- Boutons zone principale ---- */
    .main div[data-testid="stButton"] > button,
    .main div[data-testid="stPopover"] > button,
    .main div[data-testid="stDownloadButton"] > button {{
        background: {C['surface_container']};
        border: 1px solid {C['outline_variant']};
        color: {C['on_surface_variant']};
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        padding: 0.35rem 0.9rem;
        white-space: nowrap;
    }}
    .main div[data-testid="stButton"] > button:hover,
    .main div[data-testid="stPopover"] > button:hover,
    .main div[data-testid="stDownloadButton"] > button:hover {{
        color: {C['accent']};
        border-color: {C['accent']};
    }}
    .main div[data-testid="stButton"] > button[kind="primary"] {{
        background: {C['accent']} !important;
        color: {C['on_primary']} !important;
        border: none !important;
    }}
    .main div[data-testid="stButton"] > button[kind="primary"]:hover {{
        background: {C['primary']} !important;
        color: {C['on_primary']} !important;
    }}
    .status-pill {{
        display: inline-flex; align-items: center; gap: 8px;
        background: rgba(56,189,248,0.10);
        border: 1px solid {C['accent']};
        color: {C['accent']};
        padding: 8px 16px; border-radius: 8px;
        font-family: monospace; font-size: 12px; font-weight: 700; letter-spacing: 0.05em;
    }}
    .tag-chip {{
        display: inline-block;
        background: {C['surface_highest']};
        border: 1px solid {C['outline_variant']};
        border-radius: 5px;
        padding: 4px 8px;
        font-size: 10px; font-weight: 600; letter-spacing: 0.04em;
        color: {C['on_surface']};
        font-family: monospace;
        margin: 0 6px 6px 0;
    }}
    .overview-row {{
        display: flex; justify-content: space-between; align-items: center;
        padding: 8px 0;
    }}
    .overview-icon {{
        width: 30px; height: 30px; border-radius: 6px;
        display: flex; align-items: center; justify-content: center;
        flex-shrink: 0;
    }}
    .timeline-wrap {{ position: relative; padding-left: 4px; }}
    .timeline-line {{
        position: absolute; left: 19px; top: 6px; bottom: 6px;
        width: 2px; background: {C['outline_variant']}; z-index: 0;
    }}
    .timeline-item {{ position: relative; z-index: 1; display: flex; gap: 14px; margin-bottom: 16px; }}
    .timeline-dot-wrap {{
        width: 40px; height: 40px; border-radius: 50%;
        background: {C['surface']}; flex-shrink: 0;
        display: flex; align-items: center; justify-content: center;
        margin-top: 2px; z-index: 1;
    }}
    .timeline-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
    .timeline-card {{
        flex: 1; background: rgba(15,23,42,0.5);
        border-radius: 10px; padding: 14px 16px;
    }}
    .timeline-badge {{
        font-size: 10px; font-weight: 700; letter-spacing: 0.05em;
        padding: 2px 8px; border-radius: 4px; margin-right: 8px;
    }}
    .timeline-meta {{
        display: flex; gap: 16px; font-size: 11px; font-family: monospace;
        color: {C['on_surface_variant']}; margin-top: 8px;
    }}

    .badge-pill {{
        display: inline-flex; align-items: center; gap: 4px;
        padding: 2px 9px; border-radius: 4px;
        font-size: 10px; font-weight: 700; letter-spacing: 0.04em;
        text-transform: uppercase; white-space: nowrap;
    }}
    .data-toolbar {{
        display: flex; justify-content: space-between; align-items: center;
        padding: 12px 16px; border-bottom: 1px solid {C['outline_variant']};
        background: rgba(29,43,60,0.35);
    }}
    .pagination-info {{
        font-size: 12px; color: {C['on_surface_variant']}; font-family: monospace;
    }}
    .asset-name-cell {{ display:flex; align-items:center; gap:8px; }}
    .asset-dot {{ width:7px; height:7px; border-radius:50%; flex-shrink:0; }}

    .main div[data-testid="stTextInput"] input {{
        background: {C['surface_container']};
        border: 1px solid {C['outline_variant']};
        color: {C['on_surface']};
        border-radius: 6px;
        font-size: 13px;
    }}
    .main div[data-testid="stTextInput"] input:focus {{
        border-color: {C['accent']};
        box-shadow: 0 0 0 1px {C['accent']};
    }}
    .main div[data-testid="stSelectbox"] > div > div {{
        background: {C['surface_container']};
        border: 1px solid {C['outline_variant']};
        border-radius: 6px;
    }}
    .back-link {{
        display: inline-flex; align-items: center; gap: 6px;
        color: {C['on_surface_variant']}; font-size: 12px; font-weight: 600;
        text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 4px;
    }}
    .progress-track {{
        height: 6px; width: 100%; background: {C['surface_highest']};
        border-radius: 999px; overflow: hidden;
    }}
    .progress-fill {{
        height: 100%; border-radius: 999px;
    }}
    .search-hit {{
        background: {C['surface_highest']};
        padding: 1px 4px; border-radius: 3px; font-weight: 700;
    }}

    /* ---- Settings page specific styles ---- */
    .settings-card {{
        background: rgba(15,23,42,0.55);
        border: 1px solid {C['outline_variant']};
        border-radius: 12px;
        overflow: hidden;
    }}
    .settings-card-header {{
        border-bottom: 1px solid {C['outline_variant']};
        background: rgba(14,28,45,0.5);
        padding: 14px 24px;
        display: flex; align-items: center; gap: 8px;
    }}
    .settings-card-title {{
        font-size: 15px; font-weight: 700; color: {C['on_surface']};
    }}
    .settings-field-label {{
        font-size: 13px; font-weight: 600; color: {C['on_surface']};
        display: block; margin-bottom: 2px;
    }}
    .settings-field-help {{
        font-size: 12px; color: {C['on_surface_variant']}; margin: 0;
    }}
    .settings-nav-item {{
        display: flex; align-items: center; gap: 12px;
        padding: 10px 14px; border-radius: 6px;
        border-left: 2px solid transparent;
        color: {C['on_surface_variant']};
        font-size: 14px; font-weight: 500;
    }}
    .settings-divider {{
        border: none;
        border-top: 1px solid {C['outline_variant']};
        margin: 4px 0 16px 0;
        opacity: 0.5;
    }}
    .settings-team-row {{
        display: flex; align-items: center; justify-content: space-between;
        padding: 8px 12px; border: 1px solid {C['outline_variant']};
        border-radius: 6px; background: rgba(1,15,31,0.3);
        margin-bottom: 8px;
    }}
    .settings-role-badge {{
        font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 4px;
    }}
    /* ---- Settings nav buttons (Streamlit) ---- */
    .settings-nav-btn div[data-testid="stButton"] > button {{
        justify-content: flex-start !important;
        text-align: left !important;
        padding: 10px 14px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        background: transparent !important;
        border: none !important;
        border-left: 2px solid transparent !important;
        border-radius: 6px !important;
        color: {C['on_surface_variant']} !important;
        width: 100% !important;
        white-space: nowrap !important;
        text-transform: none !important;
        letter-spacing: normal !important;
    }}
    .settings-nav-btn div[data-testid="stButton"] > button:hover {{
        background: rgba(40,54,71,0.4) !important;
        color: {C['on_surface']} !important;
    }}
    .settings-nav-btn div[data-testid="stButton"] > button[kind="primary"] {{
        color: {C['accent']} !important;
        background: rgba(56,189,248,0.10) !important;
        border-left: 2px solid {C['accent']} !important;
    }}
    .settings-nav-btn div[data-testid="stButton"] > button[kind="primary"]:hover {{
        background: rgba(56,189,248,0.16) !important;
    }}
</style>
""", unsafe_allow_html=True)

# ============================================================
# DONNÉES
# ============================================================
@st.cache_data(ttl=60)
def charger_donnees() -> pd.DataFrame:
    colonnes = ["id", "source_api", "type", "asset_recherche", "asset_concerne",
                "details", "date_detection", "severity", "date_insertion"]
    alertes = lire_toutes_les_alertes()
    df = pd.DataFrame(alertes, columns=colonnes)
    if not df.empty:
        df["date_insertion_dt"] = pd.to_datetime(df["date_insertion"], errors="coerce")
    return df


def temps_relatif(dt) -> str:
    if pd.isna(dt):
        return "—"
    delta = datetime.now() - dt.to_pydatetime()
    s = int(delta.total_seconds())
    if s < 60:
        return "À l'instant"
    if s < 3600:
        return f"il y a {s // 60} min"
    if s < 86400:
        return f"il y a {s // 3600} h"
    return f"il y a {s // 86400} j"


def sev_meta(sev: str) -> dict:
    return SEVERITY.get((sev or "").lower(), DEFAULT_SEV)


def hex_to_rgba(hex_color: str, alpha: float) -> str:
    hex_color = hex_color.lstrip("#")
    r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def badge_pill(label: str, color: str, bg: str, border: str = None) -> str:
    border = border or f"{color}55"
    return (f'<span class="badge-pill" style="color:{color}; background:{bg}; '
            f'border:1px solid {border};">{html.escape(label)}</span>')


def classify_asset_type(valeur: str) -> str:
    v = (valeur or "").strip()
    if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        return "Adresse IP"
    if "@" in v:
        return "Email"
    if _re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", v):
        return "Domaine"
    return "Mot-clé"

ASSET_TYPE_ICON = {"Domaine": "language", "Adresse IP": "dns", "Email": "mail", "Mot-clé": "sell"}

SEVERITY_RANK = {"critique": 3, "eleve": 2, "faible": 1}


def paginer(df: pd.DataFrame, session_key: str, taille_page: int = 10):
    total = len(df)
    total_pages = max((total - 1) // taille_page + 1, 1)
    if session_key not in st.session_state:
        st.session_state[session_key] = 1
    page = min(max(st.session_state[session_key], 1), total_pages)
    st.session_state[session_key] = page
    debut = (page - 1) * taille_page
    fin = min(debut + taille_page, total)
    return df.iloc[debut:fin], page, total_pages, debut + 1 if total else 0, fin, total


def controles_pagination(session_key: str, page: int, total_pages: int, key_prefix: str):
    c1, c2, c3 = st.columns([1, 2, 1])
    with c1:
        if st.button("‹ Précédent", key=f"{key_prefix}_prev", disabled=(page <= 1)):
            st.session_state[session_key] = page - 1
            st.rerun()
    with c2:
        st.markdown(f"<div style='text-align:center; color:{C['on_surface_variant']}; "
                     f"font-size:12px; padding-top:6px;'>Page {page} / {total_pages}</div>",
                     unsafe_allow_html=True)
    with c3:
        if st.button("Suivant ›", key=f"{key_prefix}_next", disabled=(page >= total_pages)):
            st.session_state[session_key] = page + 1
            st.rerun()


# ============================================================
# NAVIGATION
# ============================================================
if "page" not in st.session_state:
    st.session_state.page = "dashboard"
if "settings_tab" not in st.session_state:
    st.session_state.settings_tab = "general"

with st.sidebar:
    _platform_name = st.session_state.app_settings.get("general_platform_name") or "AEGIS MONITOR"
    st.markdown(f"""
    <div class="aegis-logo">
        <div class="aegis-logo-icon">
            <span class="material-symbols-outlined" style="font-variation-settings:'FILL' 1;">shield</span>
        </div>
        <div class="aegis-logo-text">
            <h1>{html.escape(_platform_name)}</h1>
            <p>Vigilant Defense</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    for key, icon, label in NAV_ITEMS:
        is_active = st.session_state.page == key
        st.button(
            f"{label}",
            key=f"nav_{key}",
            type="primary" if is_active else "secondary",
            use_container_width=True,
        )
        if st.session_state.get(f"nav_{key}"):
            st.session_state.page = key
            if key != "alerts":
                st.session_state["alert_detail_id"] = None
            if key != "leaks":
                st.session_state["leak_detail_id"] = None
            st.rerun()


# ============================================================
# PAGE : DASHBOARD
# ============================================================
def page_dashboard():
    df = charger_donnees()

    st.markdown("""
    <div class="aegis-header">
        <div style="display:flex; align-items:center;">
            <h2>Dashboard</h2>
            <span class="live-pill"><span class="live-dot"></span> Live Feed Active</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if df.empty:
        st.info("Aucune alerte en base pour le moment. Lance le pipeline de collecte (main.py) pour peupler le dashboard.")
        return

    periode = st.radio("Période", ["7D", "30D", "90D", "Tout"], horizontal=True,
                        label_visibility="collapsed", index=1)
    if periode == "Tout":
        df_periode = df
    else:
        n_jours = {"7D": 7, "30D": 30, "90D": 90}[periode]
        seuil = datetime.now() - timedelta(days=n_jours)
        df_periode = df[df["date_insertion_dt"] >= seuil]

    total = len(df_periode)
    critiques = int((df_periode["severity"] == "critique").sum())
    elevees = int((df_periode["severity"] == "eleve").sum())
    actives = critiques + elevees
    sources = df_periode["source_api"].nunique()
    assets_surveilles = df_periode["asset_recherche"].nunique()
    derniere = df_periode["date_insertion_dt"].max() if df_periode["date_insertion_dt"].notna().any() else None

    stats = [
        ("Total Alertes", f"{total:,}".replace(",", " "), "database", None),
        ("Alertes Actives", str(actives), "warning", f"critique + élevée"),
        ("Critiques", str(critiques), "local_fire_department", "Action immédiate requise" if critiques else "Aucune"),
        ("Sources Actives", str(sources), "hub", ", ".join(sorted(df_periode["source_api"].unique())) if sources else "Aucune"),
        ("Assets Surveillés", str(assets_surveilles), "dns", None),
        ("Dernière Détection", temps_relatif(derniere) if derniere is not None else "—", "schedule", None),
    ]

    cols = st.columns(6)
    icon_colors = [C["accent"], "#ef4444", "#ef4444", "#f59e0b", C["accent"], C["outline"]]
    for col, (label, value, icon, sub), icolor in zip(cols, stats, icon_colors):
        with col:
            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <span class="stat-label">{html.escape(label)}</span>
                    <span class="material-symbols-outlined" style="font-size:16px; color:{icolor};">{icon}</span>
                </div>
                <div class="stat-value">{html.escape(value)}</div>
                <div class="stat-sub">{html.escape(sub) if sub else '&nbsp;'}</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Threat Activity Over Time</div>', unsafe_allow_html=True)

        if df_periode.empty or df_periode["date_insertion_dt"].isna().all():
            st.caption("Pas assez de données datées sur cette période.")
        else:
            tmp = df_periode.dropna(subset=["date_insertion_dt"]).copy()
            tmp["jour"] = tmp["date_insertion_dt"].dt.date
            total_par_jour = tmp.groupby("jour").size()
            crit_par_jour = tmp[tmp["severity"] == "critique"].groupby("jour").size()

            idx = pd.date_range(total_par_jour.index.min(), total_par_jour.index.max(), freq="D").date
            total_par_jour = total_par_jour.reindex(idx, fill_value=0)
            crit_par_jour = crit_par_jour.reindex(idx, fill_value=0)

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=idx, y=total_par_jour.values, name="Total détections",
                mode="lines", line=dict(color=C["accent"], width=2, shape="spline"),
                fill="tozeroy", fillcolor="rgba(56,189,248,0.15)",
            ))
            fig.add_trace(go.Scatter(
                x=idx, y=crit_par_jour.values, name="Critiques",
                mode="lines", line=dict(color="#ef4444", width=1.5, shape="spline"),
                fill="tozeroy", fillcolor="rgba(239,68,68,0.10)",
            ))
            fig.update_layout(
                height=260, margin=dict(l=0, r=0, t=10, b=0),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color=C["on_surface_variant"], size=11, family="Inter"),
                xaxis=dict(showgrid=False, color=C["outline"]),
                yaxis=dict(showgrid=True, gridcolor=C["outline_variant"], gridwidth=1, zeroline=False),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0,
                            bgcolor="rgba(0,0,0,0)"),
                hovermode="x unified",
            )
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    with col_right:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Risk Distribution</div>', unsafe_allow_html=True)

        rep = df_periode["severity"].value_counts()
        labels_ordre = ["critique", "eleve", "faible"]
        valeurs = [int(rep.get(s, 0)) for s in labels_ordre]
        couleurs = [SEVERITY[s]["color"] for s in labels_ordre]
        labels_fr = [SEVERITY[s]["label"] for s in labels_ordre]

        fig2 = go.Figure(data=[go.Pie(
            labels=labels_fr, values=valeurs, hole=0.68,
            marker=dict(colors=couleurs, line=dict(color=C["surface_low"], width=2)),
            textinfo="none",
        )])
        fig2.update_layout(
            height=200, margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            annotations=[dict(
                text=f"<b style='font-size:24px;color:{C['on_surface']}'>{total}</b><br>"
                     f"<span style='font-size:9px;color:{C['outline']}'>TOTAL ALERTES</span>",
                showarrow=False,
            )],
        )
        st.plotly_chart(fig2, width="stretch", config={"displayModeBar": False})

        legend_html = "<div style='display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:8px; font-size:12px;'>"
        for s, lbl in zip(labels_ordre, labels_fr):
            legend_html += (f"<div style='display:flex;align-items:center;gap:6px;color:{C['on_surface_variant']}'>"
                             f"<span style='width:8px;height:8px;border-radius:50%;background:{SEVERITY[s]['color']}'></span>"
                             f"{lbl} ({int(rep.get(s, 0))})</div>")
        legend_html += "</div>"
        st.markdown(legend_html, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.write("")
    col_table, col_live = st.columns([3, 1])

    with col_table:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        h1, h2 = st.columns([5, 1])
        h1.markdown('<div class="card-title" style="border:none; margin-bottom:6px;">Recent Detections</div>', unsafe_allow_html=True)
        with h2:
            if st.button("Voir tout →", key="voir_tout_detections"):
                st.session_state.page = "darkweb"
                st.rerun()

        recent = df.sort_values("date_insertion_dt", ascending=False).head(8)
        rows = ""
        for _, r in recent.iterrows():
            meta = sev_meta(r["severity"])
            date_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M") if pd.notna(r["date_insertion_dt"]) else "—"
            rows += f"""<tr>
                <td style="color:{C['outline']}">{html.escape(date_str)}</td>
                <td>{html.escape(str(r['type'] or ''))}</td>
                <td>{html.escape(str(r['asset_concerne'] or ''))}</td>
                <td style="color:{C['on_surface_variant']}">{html.escape(str(r['source_api'] or ''))}</td>
                <td><span class="sev-badge" style="color:{meta['color']}">
                    <span class="sev-dot" style="background:{meta['color']}"></span>{meta['label']}
                </span></td>
            </tr>"""

        st.markdown(f"""
        <table class="aegis-table">
            <thead><tr>
                <th>Date/Heure</th><th>Type</th><th>Asset</th><th>Source</th><th>Sévérité</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_live:
        st.markdown('<div class="glass-card" style="border-left:2px solid rgba(239,68,68,0.5);">', unsafe_allow_html=True)
        st.markdown(f"""<div class="card-title" style="display:flex;align-items:center;gap:8px;">
            <span class="material-symbols-outlined" style="font-size:16px;color:#ef4444;">notifications_active</span>
            Live Alerts
        </div>""", unsafe_allow_html=True)

        prioritaires = df[df["severity"].isin(["critique", "eleve"])].sort_values(
            "date_insertion_dt", ascending=False).head(5)

        if prioritaires.empty:
            st.caption("Aucune alerte critique ou élevée en cours. 👍")
        else:
            cards = ""
            for _, r in prioritaires.iterrows():
                meta = sev_meta(r["severity"])
                cards += f"""<div class="live-alert">
                    <div class="live-alert-top">
                        <span class="live-alert-sev" style="color:{meta['color']}">{meta['label'].upper()}</span>
                        <span class="live-alert-time">{temps_relatif(r['date_insertion_dt'])}</span>
                    </div>
                    <div class="live-alert-text">{html.escape(str(r['details'] or '')[:140])}</div>
                </div>"""
            st.markdown(cards, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ============================================================
# PAGE : DARK WEB MONITORING
# ============================================================
TYPE_META = {
    "infostealer_compromise": {"label": "Infostealer Compromise", "icon": "password"},
    "ransomware_leak": {"label": "Ransomware Leak", "icon": "lock_open"},
    "credential_leak": {"label": "Credential Leak", "icon": "key"},
    "domain_mention": {"label": "Domain Mention", "icon": "language"},
    "malicious_infrastructure_mention": {"label": "Malicious Infrastructure Mention", "icon": "dns"},
}


def type_meta(t: str) -> dict:
    if t in TYPE_META:
        return TYPE_META[t]
    return {"label": (t or "Inconnu").replace("_", " ").title(), "icon": "report"}


LEAK_TYPES = ["infostealer_compromise", "credential_leak", "ransomware_leak"]

TYPE_ACTIONS = {
    "infostealer_compromise": [
        "Forcer la réinitialisation des identifiants des machines/comptes infectés.",
        "Révoquer les sessions actives et les tokens associés aux postes compromis.",
    ],
    "credential_leak": [
        "Effectuer une rotation immédiate des identifiants exposés.",
        "Activer la MFA sur tous les comptes concernés par la fuite.",
    ],
    "ransomware_leak": [
        "Isoler les systèmes concernés et vérifier l'intégrité des sauvegardes.",
        "Notifier les parties prenantes conformément au plan de réponse aux incidents.",
    ],
    "domain_mention": [
        "Analyser le contexte de la mention pour évaluer la pertinence de la menace.",
        "Surveiller les activités suspectes liées à ce domaine dans les prochains jours.",
    ],
}
DEFAULT_ACTIONS = [
    "Analyser le contenu de l'alerte pour qualifier le niveau de risque réel.",
    "Escalader vers l'équipe SOC si la sévérité est confirmée.",
]

EXPOSED_FIELD_KEYWORDS = {
    "password": "Mots de passe",
    "mot de passe": "Mots de passe",
    "email": "Adresses email",
    "e-mail": "Adresses email",
    "api key": "Clés API",
    "api_key": "Clés API",
    "credit card": "Cartes bancaires",
    "carte bancaire": "Cartes bancaires",
    "token": "Tokens",
    "cookie": "Cookies",
    "ip address": "Adresses IP",
    "adresse ip": "Adresses IP",
    "ssn": "Numéros d'identité",
    "hash": "Empreintes / Hashs",
    "username": "Identifiants",
    "login": "Identifiants",
}


def extract_exposed_fields(details: str) -> list:
    if not details:
        return []
    d = details.lower()
    trouves = []
    for kw, label in EXPOSED_FIELD_KEYWORDS.items():
        if kw in d and label not in trouves:
            trouves.append(label)
    return trouves


def get_recommended_actions(type_: str) -> list:
    return TYPE_ACTIONS.get(type_, DEFAULT_ACTIONS)


def page_darkweb():
    df = charger_donnees()

    h1, h2 = st.columns([3, 1])
    with h1:
        st.markdown(f"""
        <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
            Dark Web Monitoring
        </h2>
        <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0;">
            Surveillance continue via les flux CTI connectés — HudsonRock (infostealers) &amp; Ransomware.live.
        </p>
        """, unsafe_allow_html=True)
    with h2:
        st.markdown("""
        <div style="display:flex; justify-content:flex-end; padding-top:8px;">
            <span class="status-pill"><span class="live-dot"></span> MONITORING ACTIVE</span>
        </div>
        """, unsafe_allow_html=True)
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    if df.empty:
        st.info("Aucune alerte en base. Lance le pipeline de collecte (main.py) pour peupler ce flux.")
        return

    col_status, col_stream = st.columns([4, 8])

    with col_status:
        derniere = df["date_insertion_dt"].max() if df["date_insertion_dt"].notna().any() else None
        sources_uniques = sorted(df["source_api"].dropna().unique().tolist())
        assets_uniques = sorted(df["asset_recherche"].dropna().unique().tolist())

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Scan Integrity</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="overview-row">
            <span style="color:{C['on_surface_variant']}; font-size:12.5px; display:flex; align-items:center; gap:6px;">
                <span class="material-symbols-outlined" style="font-size:15px;">history</span> Last Global Scan
            </span>
            <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">
                {html.escape(temps_relatif(derniere) if derniere is not None else '—')}
            </span>
        </div>
        <div class="overview-row">
            <span style="color:{C['on_surface_variant']}; font-size:12.5px; display:flex; align-items:center; gap:6px;">
                <span class="material-symbols-outlined" style="font-size:15px;">update</span> Next Scheduled
            </span>
            <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">Continu (2 min)</span>
        </div>
        <div style="border-top:1px solid {C['outline_variant']}; margin-top:12px; padding-top:12px;">
            <p class="stat-label" style="margin-bottom:8px;">Sources Monitored</p>
            <div>{''.join(f'<span class="tag-chip">{html.escape(s.upper())}</span>' for s in sources_uniques) or '<span style="color:'+C["outline"]+';font-size:12px;">Aucune</span>'}</div>
            <p class="stat-label" style="margin:12px 0 8px 0;">Assets Monitored</p>
            <div>{''.join(f'<span class="tag-chip">{html.escape(str(a))}</span>' for a in assets_uniques) or '<span style="color:'+C["outline"]+';font-size:12px;">Aucun</span>'}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.write("")

        seuil_7j = datetime.now() - timedelta(days=7)
        df_7j = df[df["date_insertion_dt"] >= seuil_7j]
        rep_types = df_7j["type"].value_counts()

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Detection Overview (7j)</div>', unsafe_allow_html=True)
        if rep_types.empty:
            st.caption("Aucune détection sur les 7 derniers jours.")
        else:
            rows_html = ""
            for t, count in rep_types.items():
                meta = type_meta(t)
                rows_html += f"""<div class="overview-row">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <div class="overview-icon" style="background:rgba(56,189,248,0.10); border:1px solid {C['outline_variant']};">
                            <span class="material-symbols-outlined" style="font-size:15px; color:{C['accent']};">{meta['icon']}</span>
                        </div>
                        <span style="font-size:12.5px; color:{C['on_surface']};">{html.escape(meta['label'])}</span>
                    </div>
                    <span style="font-family:monospace; font-weight:700; color:{C['on_surface']};">{count}</span>
                </div>"""
            st.markdown(rows_html, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_stream:
        st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
        st.markdown(f"""
        <div style="display:flex; justify-content:space-between; align-items:center;
                    padding:16px 20px; border-bottom:1px solid {C['outline_variant']};">
            <span style="font-size:15px; font-weight:700; color:{C['on_surface']}; display:flex; align-items:center; gap:8px;">
                <span class="material-symbols-outlined" style="font-size:18px; color:{C['accent']};">rss_feed</span>
                Live Detection Stream
            </span>
        </div>
        """, unsafe_allow_html=True)

        fc1, fc2, fc3 = st.columns([1, 1, 6])
        with fc1:
            with st.popover("FILTER", width="stretch"):
                sel_sources = st.multiselect("Source", sources_uniques, default=sources_uniques, key="dw_sources")
                sel_sev = st.multiselect("Sévérité", ["critique", "eleve", "faible"],
                                          default=["critique", "eleve", "faible"], key="dw_sev")
        with fc2:
            df_filtre_export = df[df["source_api"].isin(st.session_state.get("dw_sources", sources_uniques)) &
                                   df["severity"].isin(st.session_state.get("dw_sev", ["critique", "eleve", "faible"]))]
            st.download_button("EXPORT", data=df_filtre_export.drop(columns=["date_insertion_dt"]).to_csv(index=False),
                                file_name="detections.csv", mime="text/csv", width="stretch")

        sel_sources_val = st.session_state.get("dw_sources", sources_uniques)
        sel_sev_val = st.session_state.get("dw_sev", ["critique", "eleve", "faible"])
        stream = df[df["source_api"].isin(sel_sources_val) & df["severity"].isin(sel_sev_val)]
        stream = stream.sort_values("date_insertion_dt", ascending=False)

        if stream.empty:
            st.info("Aucune détection ne correspond à ce filtre.")
        else:
            items_html = '<div class="timeline-wrap"><div class="timeline-line"></div>'
            for _, r in stream.iterrows():
                sev = (r["severity"] or "").lower()
                meta = sev_meta(sev)
                badge_label = {"critique": "CRITICAL", "eleve": "WARNING", "faible": "INFO"}.get(sev, meta["label"].upper())
                t_meta = type_meta(r["type"])
                date_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M UTC") if pd.notna(r["date_insertion_dt"]) else "—"
                opacity = "opacity:0.75;" if sev == "faible" else ""
                glow = f"box-shadow:0 0 8px {meta['color']}66;" if sev in ("critique", "eleve") else ""

                meta_line = f"""<span style="display:flex; align-items:center; gap:4px;">
                        <span class="material-symbols-outlined" style="font-size:13px;">public</span>
                        Source: {html.escape(str(r['source_api'] or ''))}
                    </span>"""
                if r.get("asset_concerne"):
                    meta_line += f"""<span style="display:flex; align-items:center; gap:4px;">
                        <span class="material-symbols-outlined" style="font-size:13px;">tag</span>
                        {html.escape(str(r['asset_concerne']))}
                    </span>"""

                items_html += f"""
                <div class="timeline-item" style="{opacity}">
                    <div class="timeline-dot-wrap" style="border:1px solid {meta['color']};">
                        <span class="timeline-dot" style="background:{meta['color']}; {glow}"></span>
                    </div>
                    <div class="timeline-card" style="border:1px solid {meta['color']}33;">
                        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
                            <div style="display:flex; align-items:center; gap:8px;">
                                <span class="timeline-badge" style="background:{meta['bg']}; color:{meta['color']}; border:1px solid {meta['color']}4d;">{badge_label}</span>
                                <h4 style="font-family:monospace; font-size:13px; color:{C['on_surface']}; margin:0;">{html.escape(t_meta['label'])}</h4>
                            </div>
                            <span style="font-family:monospace; font-size:11px; color:{C['on_surface_variant']};">{html.escape(date_str)}</span>
                        </div>
                        <p style="font-size:12.5px; color:{C['on_surface_variant']}; margin:0 0 8px 0; line-height:1.4;">
                            {html.escape(str(r['details'] or ''))}
                        </p>
                        <div class="timeline-meta">{meta_line}</div>
                    </div>
                </div>"""
            items_html += "</div>"

            st.markdown(f'<div style="max-height:560px; overflow-y:auto; padding:4px 20px 20px 20px;">{items_html}</div>',
                         unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)


# ============================================================
# PAGE : ASSETS
# ============================================================
def page_assets():
    df = charger_donnees()

    h1, h2 = st.columns([3, 1])
    with h1:
        st.markdown(f"""
        <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
            Monitored Assets
        </h2>
        <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0;">
            Empreinte numérique surveillée par le pipeline CTI (assets réellement recherchés dans main.py).
        </p>
        """, unsafe_allow_html=True)
    with h2:
        recherche = st.text_input("Rechercher un asset", placeholder="🔎 Rechercher un asset...",
                                   label_visibility="collapsed", key="assets_search")
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    if df.empty:
        st.info("Aucune alerte en base. Lance le pipeline de collecte (main.py) pour peupler cette vue.")
        return

    agg_rows = []
    for asset, groupe in df.groupby("asset_recherche"):
        pire_sev = max(groupe["severity"].dropna(), key=lambda s: SEVERITY_RANK.get(s, 0), default="faible")
        derniere = groupe["date_insertion_dt"].max()
        agg_rows.append({
            "asset": asset,
            "type": classify_asset_type(asset),
            "findings": len(groupe),
            "severity": pire_sev,
            "derniere": derniere,
        })
    assets_df = pd.DataFrame(agg_rows)
    if recherche:
        assets_df = assets_df[assets_df["asset"].str.contains(recherche, case=False, na=False)]
    assets_df = assets_df.sort_values("findings", ascending=False)

    total_assets = len(assets_df)
    critique_assets = int((assets_df["severity"] == "critique").sum())
    total_detections = len(df)
    seuil_7j = datetime.now() - timedelta(days=7)
    detections_7j = int((df["date_insertion_dt"] >= seuil_7j).sum())

    stats = [
        ("Total Assets", str(total_assets), "hub", C["accent"]),
        ("Risque Critique", str(critique_assets), "warning", "#ef4444"),
        ("Total Détections", str(total_detections), "monitor_heart", "#f59e0b"),
        ("Détections (7j)", str(detections_7j), "radar", "#10b981"),
    ]
    cols = st.columns(4)
    for col, (label, value, icon, color) in zip(cols, stats):
        with col:
            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <span class="stat-label">{html.escape(label)}</span>
                    <span class="material-symbols-outlined" style="font-size:16px; color:{color};">{icon}</span>
                </div>
                <div class="stat-value" style="color:{color if label=='Risque Critique' else C['on_surface']};">{html.escape(value)}</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)

    page_df, page, total_pages, debut, fin, total = paginer(assets_df, "assets_page", taille_page=10)

    st.markdown(f"""
    <div class="data-toolbar">
        <span style="font-size:13px; font-weight:700; color:{C['on_surface']};">Assets surveillés</span>
        <span class="pagination-info">Affichage {debut}-{fin} sur {total}</span>
    </div>
    """, unsafe_allow_html=True)

    if page_df.empty:
        st.markdown(f"<p style='color:{C['on_surface_variant']}; padding:20px;'>Aucun asset ne correspond à ta recherche.</p>",
                     unsafe_allow_html=True)
    else:
        rows = ""
        for _, r in page_df.iterrows():
            meta = sev_meta(r["severity"])
            derniere_str = temps_relatif(r["derniere"]) if pd.notna(r["derniere"]) else "—"
            icon = ASSET_TYPE_ICON.get(r["type"], "sell")
            findings_style = f"font-weight:700; color:{meta['color']};" if r["findings"] > 0 else ""
            rows += f"""<tr>
                <td>
                    <div class="asset-name-cell">
                        <span class="asset-dot" style="background:{meta['color']};"></span>
                        {html.escape(str(r['asset']))}
                    </div>
                </td>
                <td style="color:{C['on_surface_variant']};">
                    <span class="material-symbols-outlined" style="font-size:13px; vertical-align:middle; margin-right:4px;">{icon}</span>
                    {html.escape(r['type'])}
                </td>
                <td>{badge_pill('ACTIF', '#10b981', 'rgba(16,185,129,0.14)')}</td>
                <td style="color:{C['on_surface_variant']};">{html.escape(derniere_str)}</td>
                <td style="text-align:center; {findings_style}">{r['findings']}</td>
                <td>{badge_pill(meta['label'].upper(), meta['color'], meta['bg'])}</td>
            </tr>"""

        st.markdown(f"""
        <table class="aegis-table">
            <thead><tr>
                <th>Asset</th><th>Type</th><th>Statut</th><th>Dernière détection</th>
                <th style="text-align:center;">Findings</th><th>Risque</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
    st.write("")
    controles_pagination("assets_page", page, total_pages, "assets")


# ============================================================
# PAGE : ALERTS
# ============================================================
def page_alerts():
    if st.session_state.get("alert_detail_id") is not None:
        page_alert_detail(st.session_state["alert_detail_id"])
        return

    df = charger_donnees()

    h1, h2 = st.columns([3, 1])
    with h1:
        st.markdown(f"""
        <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
            Alerts Center
        </h2>
        <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0;">
            File centralisée des incidents de sécurité détectés par le pipeline CTI.
        </p>
        """, unsafe_allow_html=True)
    with h2:
        recherche = st.text_input("Rechercher", placeholder="🔎 ID, asset, source...",
                                   label_visibility="collapsed", key="alerts_search")
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    if df.empty:
        st.info("Aucune alerte en base. Lance le pipeline de collecte (main.py) pour peupler ce flux.")
        return

    f1, f2, f3, f4 = st.columns(4)
    with f1:
        niveaux = st.selectbox("Niveau de risque", ["Tous"] + sorted(df["severity"].dropna().unique().tolist()),
                                key="alerts_f_sev")
    with f2:
        types_dispo = sorted(df["type"].dropna().unique().tolist())
        types_sel = st.selectbox("Type de détection", ["Tous"] + types_dispo, key="alerts_f_type")
    with f3:
        periode = st.selectbox("Période", ["Tout", "Dernières 24h", "7 derniers jours", "30 derniers jours"],
                                key="alerts_f_periode")
    with f4:
        sources_sel = st.selectbox("Source", ["Toutes"] + sorted(df["source_api"].dropna().unique().tolist()),
                                    key="alerts_f_source")

    filtre = df.copy()
    if niveaux != "Tous":
        filtre = filtre[filtre["severity"] == niveaux]
    if types_sel != "Tous":
        filtre = filtre[filtre["type"] == types_sel]
    if sources_sel != "Toutes":
        filtre = filtre[filtre["source_api"] == sources_sel]
    if periode != "Tout":
        heures = {"Dernières 24h": 24, "7 derniers jours": 24 * 7, "30 derniers jours": 24 * 30}[periode]
        filtre = filtre[filtre["date_insertion_dt"] >= datetime.now() - timedelta(hours=heures)]
    if recherche:
        masque = (filtre["id"].astype(str).str.contains(recherche, case=False, na=False) |
                  filtre["asset_concerne"].astype(str).str.contains(recherche, case=False, na=False) |
                  filtre["source_api"].astype(str).str.contains(recherche, case=False, na=False))
        filtre = filtre[masque]

    filtre = filtre.sort_values("date_insertion_dt", ascending=False)

    st.write("")
    st.download_button("⬇ Export CSV", data=filtre.drop(columns=["date_insertion_dt"]).to_csv(index=False),
                        file_name="alertes_export.csv", mime="text/csv")

    st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
    page_df, page, total_pages, debut, fin, total = paginer(filtre, "alerts_page", taille_page=12)

    st.markdown(f"""
    <div class="data-toolbar">
        <span style="font-size:13px; font-weight:700; color:{C['on_surface']};">Incidents</span>
        <span class="pagination-info">Affichage {debut}-{fin} sur {total}</span>
    </div>
    """, unsafe_allow_html=True)

    if page_df.empty:
        st.markdown(f"<p style='color:{C['on_surface_variant']}; padding:20px;'>Aucune alerte ne correspond à ces filtres.</p>",
                     unsafe_allow_html=True)
    else:
        header_cols = st.columns([1.2, 1, 1.6, 1.6, 1.2, 1.6, 0.8])
        headers = ["Alert ID", "Risque", "Type", "Asset concerné", "Source", "Heure", ""]
        for c, h in zip(header_cols, headers):
            c.markdown(f"<span class='stat-label'>{h}</span>", unsafe_allow_html=True)
        st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 0 4px 0;'>", unsafe_allow_html=True)

        for _, r in page_df.iterrows():
            meta = sev_meta(r["severity"])
            t_meta = type_meta(r["type"])
            date_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M") if pd.notna(r["date_insertion_dt"]) else "—"
            row_cols = st.columns([1.2, 1, 1.6, 1.6, 1.2, 1.6, 0.8])
            row_cols[0].markdown(f"<span style='font-family:monospace; color:{C['accent']}; font-size:12.5px;'>"
                                  f"ALRT-{int(r['id']):04d}</span>", unsafe_allow_html=True)
            row_cols[1].markdown(badge_pill(meta["label"].upper(), meta["color"], meta["bg"]), unsafe_allow_html=True)
            row_cols[2].markdown(f"<span style='font-size:12.5px; color:{C['on_surface']};'>{html.escape(t_meta['label'])}</span>",
                                  unsafe_allow_html=True)
            row_cols[3].markdown(f"<span style='font-size:12.5px; color:{C['on_surface_variant']};'>"
                                  f"{html.escape(str(r['asset_concerne'] or '—'))}</span>", unsafe_allow_html=True)
            row_cols[4].markdown(f"<span style='font-size:12.5px; color:{C['on_surface_variant']};'>{html.escape(str(r['source_api'] or ''))}</span>",
                                  unsafe_allow_html=True)
            row_cols[5].markdown(f"<span style='font-family:monospace; font-size:11.5px; color:{C['outline']};'>{html.escape(date_str)}</span>",
                                  unsafe_allow_html=True)
            if row_cols[6].button("Voir →", key=f"open_alert_{r['id']}"):
                st.session_state["alert_detail_id"] = r["id"]
                st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)
    st.write("")
    controles_pagination("alerts_page", page, total_pages, "alerts")


def page_alert_detail(alert_id):
    df = charger_donnees()
    ligne = df[df["id"] == alert_id]
    if ligne.empty:
        st.warning("Cette alerte n'existe plus.")
        if st.button("← Retour aux alertes"):
            st.session_state["alert_detail_id"] = None
            st.rerun()
        return
    r = ligne.iloc[0]
    meta = sev_meta(r["severity"])
    t_meta = type_meta(r["type"])

    if st.button("← Retour aux alertes", key="back_to_alerts"):
        st.session_state["alert_detail_id"] = None
        st.rerun()

    st.markdown(f"""
    <div style="display:flex; align-items:center; gap:10px; margin:12px 0 6px 0;">
        {badge_pill(meta['label'].upper() + ' RISK', meta['color'], meta['bg'])}
        <span style="font-family:monospace; color:{C['outline']}; font-size:12px;">ALRT-{int(r['id']):04d}</span>
    </div>
    <h2 style="font-size:26px; font-weight:700; color:{C['on_surface']}; margin:4px 0 10px 0;">
        {html.escape(t_meta['label'])}
    </h2>
    <p style="color:{C['on_surface_variant']}; font-size:14px; max-width:800px; line-height:1.5; margin-bottom:24px;">
        {html.escape(str(r['details'] or ''))}
    </p>
    """, unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    date_detection_str = str(r["date_detection"]) if r["date_detection"] else "—"
    date_insertion_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notna(r["date_insertion_dt"]) else "—"

    with col_a:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Detection Timeline</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="overview-row"><span style="color:{C['on_surface_variant']}; font-size:12.5px;">First Seen (source)</span>
            <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">{html.escape(date_detection_str)}</span></div>
        <div class="overview-row"><span style="color:{C['on_surface_variant']}; font-size:12.5px;">Added to DB</span>
            <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">{html.escape(date_insertion_str)}</span></div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_b:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Source Intel</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="overview-row"><span style="color:{C['on_surface_variant']}; font-size:12.5px;">Source</span>
            <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">{html.escape(str(r['source_api'] or '—'))}</span></div>
        <div class="overview-row"><span style="color:{C['on_surface_variant']}; font-size:12.5px;">Terme surveillé</span>
            <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">{html.escape(str(r['asset_recherche'] or '—'))}</span></div>
        <div class="overview-row"><span style="color:{C['on_surface_variant']}; font-size:12.5px;">Élément concerné</span>
            <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">{html.escape(str(r['asset_concerne'] or '—'))}</span></div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ============================================================
# PAGE : LEAKS
# ============================================================
def page_leaks():
    df = charger_donnees()
    leaks_all = df[df["type"].isin(LEAK_TYPES)].copy() if not df.empty else df

    h1, h2 = st.columns([3, 1])
    with h1:
        st.markdown(f"""
        <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
            Database Leaks
        </h2>
        <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0;">
            Fuites de données actives et historiques affectant les assets surveillés.
        </p>
        """, unsafe_allow_html=True)
    with h2:
        recherche = st.text_input("Rechercher", placeholder="🔎 Rechercher un leak, un asset...",
                                   label_visibility="collapsed", key="leaks_search")
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    if leaks_all.empty:
        st.info("Aucune fuite de données détectée pour le moment (types concernés : "
                "infostealer_compromise, credential_leak, ransomware_leak).")
        return

    total_leaks = len(leaks_all)
    high_risk = int((leaks_all["severity"] == "critique").sum())
    seuil_7j = datetime.now() - timedelta(days=7)
    nouveaux_7j = int((leaks_all["date_insertion_dt"] >= seuil_7j).sum())

    stat_cols = st.columns(3)
    stats = [
        ("TOTAL LEAKS SURVEILLÉS", str(total_leaks), "database", C["accent"]),
        ("ALERTES HAUT RISQUE", str(high_risk), "warning", "#ef4444"),
        ("NOUVEAUX (7J)", str(nouveaux_7j), "fiber_new", "#f59e0b"),
    ]
    for col, (label, value, icon, color) in zip(stat_cols, stats):
        with col:
            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <span class="stat-label">{html.escape(label)}</span>
                    <span class="material-symbols-outlined" style="font-size:20px; color:{color}; opacity:0.7;">{icon}</span>
                </div>
                <div class="stat-value" style="color:{color if label != 'TOTAL LEAKS SURVEILLÉS' else C['on_surface']};">{html.escape(value)}</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")

    leaks_filtre = leaks_all.copy()
    if recherche:
        masque = (leaks_filtre["asset_concerne"].astype(str).str.contains(recherche, case=False, na=False) |
                  leaks_filtre["asset_recherche"].astype(str).str.contains(recherche, case=False, na=False) |
                  leaks_filtre["source_api"].astype(str).str.contains(recherche, case=False, na=False) |
                  leaks_filtre["type"].astype(str).str.contains(recherche, case=False, na=False))
        leaks_filtre = leaks_filtre[masque]
    leaks_filtre = leaks_filtre.sort_values("date_insertion_dt", ascending=False)

    selected_id = st.session_state.get("leak_detail_id")
    if selected_id not in leaks_filtre["id"].values:
        selected_id = leaks_filtre.iloc[0]["id"] if not leaks_filtre.empty else None
        st.session_state["leak_detail_id"] = selected_id

    col_list, col_detail = st.columns([2, 1])

    with col_list:
        st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
        h1c, h2c = st.columns([5, 1])
        h1c.markdown('<div class="card-title" style="border:none; margin:12px 0 0 16px;">Recent Detections</div>',
                     unsafe_allow_html=True)
        with h2c:
            st.download_button("EXPORT", data=leaks_filtre.drop(columns=["date_insertion_dt"]).to_csv(index=False),
                                file_name="leaks_export.csv", mime="text/csv", key="leaks_export")

        page_df, page, total_pages, debut, fin, total = paginer(leaks_filtre, "leaks_page", taille_page=8)

        st.markdown(f"""
        <div class="data-toolbar" style="border-top:1px solid {C['outline_variant']};">
            <span class="pagination-info">Affichage {debut}-{fin} sur {total}</span>
        </div>
        """, unsafe_allow_html=True)

        if page_df.empty:
            st.markdown(f"<p style='color:{C['on_surface_variant']}; padding:20px;'>Aucun leak ne correspond à ta recherche.</p>",
                         unsafe_allow_html=True)
        else:
            header_cols = st.columns([1.3, 1.6, 1.6, 1.2, 1.3, 0.8])
            for c, h in zip(header_cols, ["Date", "Type", "Asset concerné", "Source", "Risque", ""]):
                c.markdown(f"<span class='stat-label'>{h}</span>", unsafe_allow_html=True)
            st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 16px 4px 16px;'>",
                         unsafe_allow_html=True)

            for _, r in page_df.iterrows():
                meta = sev_meta(r["severity"])
                t_meta = type_meta(r["type"])
                date_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M") if pd.notna(r["date_insertion_dt"]) else "—"
                is_selected = r["id"] == selected_id
                row_cols = st.columns([1.3, 1.6, 1.6, 1.2, 1.3, 0.8])
                row_cols[0].markdown(f"<span style='font-family:monospace; font-size:11.5px; color:{C['outline']};'>{html.escape(date_str)}</span>",
                                      unsafe_allow_html=True)
                row_cols[1].markdown(f"<span style='font-size:12.5px; color:{C['on_surface']}; {'font-weight:700;' if is_selected else ''}'>"
                                      f"{html.escape(t_meta['label'])}</span>", unsafe_allow_html=True)
                row_cols[2].markdown(f"<span style='font-size:12.5px; color:{C['on_surface_variant']};'>"
                                      f"{html.escape(str(r['asset_concerne'] or '—'))}</span>", unsafe_allow_html=True)
                row_cols[3].markdown(f"<span style='font-size:12.5px; color:{C['on_surface_variant']};'>{html.escape(str(r['source_api'] or ''))}</span>",
                                      unsafe_allow_html=True)
                row_cols[4].markdown(badge_pill(meta["label"].upper(), meta["color"], meta["bg"]), unsafe_allow_html=True)
                btn_label = "● Voir" if is_selected else "Voir"
                if row_cols[5].button(btn_label, key=f"open_leak_{r['id']}"):
                    st.session_state["leak_detail_id"] = r["id"]
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
        st.write("")
        controles_pagination("leaks_page", page, total_pages, "leaks")

    with col_detail:
        if selected_id is None:
            st.markdown('<div class="glass-card" style="text-align:center; padding:40px 16px;">', unsafe_allow_html=True)
            st.markdown(f"<span class='material-symbols-outlined' style='font-size:32px; color:{C['outline']};'>leak_add</span>",
                         unsafe_allow_html=True)
            st.markdown(f"<p style='color:{C['on_surface_variant']}; margin-top:8px;'>Sélectionne un leak dans la liste.</p>",
                         unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            return

        r = leaks_all[leaks_all["id"] == selected_id].iloc[0]
        meta = sev_meta(r["severity"])
        t_meta = type_meta(r["type"])
        date_detection_str = str(r["date_detection"]) if r["date_detection"] else "—"

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown(f"""
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
            <div>
                {badge_pill(meta['label'].upper() + ' RISK', meta['color'], meta['bg'])}
                <h3 style="font-size:17px; font-weight:700; color:{C['on_surface']}; margin:8px 0 2px 0;">
                    {html.escape(t_meta['label'])}
                </h3>
                <p style="font-size:11px; color:{C['outline']}; font-family:monospace; margin:0;">ID: LEAK-{int(r['id']):04d}</p>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:16px;">
            <div style="background:{C['surface_low']}; border:1px solid {C['outline_variant']}; border-radius:8px; padding:10px;">
                <p class="stat-label" style="margin-bottom:4px;">DISCOVERY DATE</p>
                <p style="font-family:monospace; font-size:12px; color:{C['on_surface']}; margin:0;">{html.escape(date_detection_str)}</p>
            </div>
            <div style="background:{C['surface_low']}; border:1px solid {C['outline_variant']}; border-radius:8px; padding:10px;">
                <p class="stat-label" style="margin-bottom:4px;">SOURCE</p>
                <p style="font-family:monospace; font-size:12px; color:{C['on_surface']}; margin:0;">{html.escape(str(r['source_api'] or '—'))}</p>
            </div>
            <div style="background:{C['surface_low']}; border:1px solid {C['outline_variant']}; border-radius:8px; padding:10px;">
                <p class="stat-label" style="margin-bottom:4px;">TERME SURVEILLÉ</p>
                <p style="font-family:monospace; font-size:12px; color:{C['on_surface']}; margin:0;">{html.escape(str(r['asset_recherche'] or '—'))}</p>
            </div>
            <div style="background:{C['surface_low']}; border:1px solid {C['outline_variant']}; border-radius:8px; padding:10px;">
                <p class="stat-label" style="margin-bottom:4px;">ASSET CONCERNÉ</p>
                <p style="font-family:monospace; font-size:12px; color:{C['on_surface']}; margin:0;">{html.escape(str(r['asset_concerne'] or '—'))}</p>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""<p class="stat-label" style="border-bottom:1px solid {C['outline_variant']}; padding-bottom:6px;">BREACH ANALYSIS</p>""",
                     unsafe_allow_html=True)
        st.markdown(f"<p style='font-size:12.5px; color:{C['on_surface_variant']}; line-height:1.5;'>{html.escape(str(r['details'] or 'Aucun détail disponible.'))}</p>",
                     unsafe_allow_html=True)

        champs = extract_exposed_fields(r["details"])
        st.markdown(f"""<p class="stat-label" style="border-bottom:1px solid {C['outline_variant']}; padding-bottom:6px; margin-top:12px;">EXPOSED FIELDS</p>""",
                     unsafe_allow_html=True)
        if champs:
            chips = "".join(badge_pill(c, "#ef4444", "rgba(239,68,68,0.12)") + " " for c in champs)
            st.markdown(f"<div style='margin-top:6px;'>{chips}</div>", unsafe_allow_html=True)
        else:
            st.caption("Aucun champ identifiable automatiquement dans le détail de l'alerte.")

        st.markdown(f"""<p class="stat-label" style="border-bottom:1px solid {C['outline_variant']}; padding-bottom:6px; margin-top:12px;">RECOMMENDED ACTIONS</p>""",
                     unsafe_allow_html=True)
        actions_html = ""
        for a in get_recommended_actions(r["type"]):
            actions_html += (f"<div style='display:flex; gap:8px; margin-top:8px; font-size:12.5px; "
                              f"color:{C['on_surface']};'><span class='material-symbols-outlined' "
                              f"style='font-size:16px; color:{C['accent']};'>key</span><span>{html.escape(a)}</span></div>")
        st.markdown(actions_html, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)


# ============================================================
# PAGE : SEARCH
# ============================================================
def page_search():
    df = charger_donnees()

    st.markdown(f"""
    <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
        Dark Web Investigation
    </h2>
    <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0 0 20px 0;">
        Recherche plein texte dans les détections indexées (forums, marketplaces, paste sites...).
    </p>
    """, unsafe_allow_html=True)

    if df.empty:
        st.info("Aucune alerte en base. Lance le pipeline de collecte (main.py) pour peupler cette recherche.")
        return

    q_col, btn_col = st.columns([5, 1])
    with q_col:
        requete = st.text_input("Requête", placeholder="🔎 ex: @corporate_domain.com, password, VPN...",
                                 label_visibility="collapsed", key="search_query")
    with btn_col:
        st.button("Exécuter", key="search_execute", width="stretch")

    f1, f2, f3 = st.columns(3)
    with f1:
        sel_sev = st.multiselect("Sévérité", ["critique", "eleve", "faible"],
                                  default=["critique", "eleve", "faible"], key="search_sev")
    with f2:
        sources_dispo = sorted(df["source_api"].dropna().unique().tolist())
        sel_sources = st.multiselect("Source", sources_dispo, default=sources_dispo, key="search_sources")
    with f3:
        periode = st.selectbox("Période", ["Tout", "Dernières 24h", "7 derniers jours", "30 derniers jours"],
                                key="search_periode")

    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 0 16px 0;'>", unsafe_allow_html=True)

    t0 = time.time()
    resultats = df[df["severity"].isin(sel_sev) & df["source_api"].isin(sel_sources)].copy()
    if periode != "Tout":
        heures = {"Dernières 24h": 24, "7 derniers jours": 24 * 7, "30 derniers jours": 24 * 30}[periode]
        resultats = resultats[resultats["date_insertion_dt"] >= datetime.now() - timedelta(hours=heures)]
    if requete:
        colonnes_recherchees = ["id", "type", "asset_recherche", "asset_concerne", "source_api", "details"]
        masque = pd.Series(False, index=resultats.index)
        for col in colonnes_recherchees:
            masque |= resultats[col].astype(str).str.contains(_re.escape(requete), case=False, na=False)
        resultats = resultats[masque]
    resultats = resultats.sort_values("date_insertion_dt", ascending=False)
    duree = time.time() - t0

    def snippet(details: str, terme: str, largeur: int = 60) -> str:
        details = details or ""
        if not terme:
            return html.escape(details[:140]) + ("…" if len(details) > 140 else "")
        idx = details.lower().find(terme.lower())
        if idx == -1:
            return html.escape(details[:140]) + ("…" if len(details) > 140 else "")
        debut = max(idx - largeur, 0)
        fin = min(idx + len(terme) + largeur, len(details))
        avant = html.escape(details[debut:idx])
        match = html.escape(details[idx:idx + len(terme)])
        apres = html.escape(details[idx + len(terme):fin])
        prefixe = "…" if debut > 0 else ""
        suffixe = "…" if fin < len(details) else ""
        return f"{prefixe}{avant}<span class='search-hit'>{match}</span>{apres}{suffixe}"

    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:10px;">
        <span style="font-size:15px; font-weight:700; color:{C['on_surface']};">Search Results
            <span style="font-size:12px; font-weight:400; color:{C['on_surface_variant']};">
                ({len(resultats)} résultat{'s' if len(resultats) != 1 else ''} en {duree:.2f}s)
            </span>
        </span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
    page_df, page, total_pages, debut_p, fin_p, total = paginer(resultats, "search_page", taille_page=10)

    st.markdown(f"""
    <div class="data-toolbar">
        <span class="pagination-info">Affichage {debut_p}-{fin_p} sur {total}</span>
    </div>
    """, unsafe_allow_html=True)

    if page_df.empty:
        st.markdown(f"<p style='color:{C['on_surface_variant']}; padding:20px;'>Aucun résultat pour cette recherche.</p>",
                     unsafe_allow_html=True)
    else:
        header_cols = st.columns([0.6, 1.3, 3.2, 1.5, 1.2, 1.1, 0.8])
        for c, h in zip(header_cols, ["Risque", "Date", "Contexte", "Asset", "Source", "Type", ""]):
            c.markdown(f"<span class='stat-label'>{h}</span>", unsafe_allow_html=True)
        st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 0 4px 0;'>", unsafe_allow_html=True)

        for _, r in page_df.iterrows():
            meta = sev_meta(r["severity"])
            t_meta = type_meta(r["type"])
            date_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M") if pd.notna(r["date_insertion_dt"]) else "—"
            row_cols = st.columns([0.6, 1.3, 3.2, 1.5, 1.2, 1.1, 0.8])
            row_cols[0].markdown(f"<span class='sev-dot' style='display:inline-block; background:{meta['color']}; "
                                  f"box-shadow:0 0 6px {meta['color']}88;'></span>", unsafe_allow_html=True)
            row_cols[1].markdown(f"<span style='font-family:monospace; font-size:11px; color:{C['on_surface_variant']};'>{html.escape(date_str)}</span>",
                                  unsafe_allow_html=True)
            row_cols[2].markdown(f"<span style='font-size:12px; color:{C['on_surface_variant']};'>{snippet(r['details'], requete)}</span>",
                                  unsafe_allow_html=True)
            row_cols[3].markdown(f"<span style='font-size:12px; color:{C['on_surface']};'>{html.escape(str(r['asset_concerne'] or '—'))}</span>",
                                  unsafe_allow_html=True)
            row_cols[4].markdown(f"<span style='font-size:12px; color:{C['on_surface_variant']};'>{html.escape(str(r['source_api'] or ''))}</span>",
                                  unsafe_allow_html=True)
            row_cols[5].markdown(f"<span style='font-size:12px; color:{C['on_surface_variant']};'>{html.escape(t_meta['label'])}</span>",
                                  unsafe_allow_html=True)
            if row_cols[6].button("Voir →", key=f"search_open_{r['id']}"):
                st.session_state["alert_detail_id"] = r["id"]
                st.session_state.page = "alerts"
                st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)
    st.write("")
    controles_pagination("search_page", page, total_pages, "search")


# ============================================================
# PAGE : REPORTS
# ============================================================
def page_reports():
    df = charger_donnees()

    h1, h2 = st.columns([3, 1])
    with h1:
        st.markdown(f"""
        <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
            Reports &amp; Compliance
        </h2>
        <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0;">
            Vue exécutive des métriques de la période et export des rapports.
        </p>
        """, unsafe_allow_html=True)
    with h2:
        periode = st.selectbox("Période", ["7 derniers jours", "30 derniers jours", "90 derniers jours", "Tout"],
                                index=1, key="reports_periode", label_visibility="collapsed")
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    if df.empty:
        st.info("Aucune alerte en base. Lance le pipeline de collecte (main.py) pour générer des rapports.")
        return

    jours_map = {"7 derniers jours": 7, "30 derniers jours": 30, "90 derniers jours": 90}
    if periode == "Tout":
        n_jours = max((datetime.now() - df["date_insertion_dt"].min()).days, 1) if df["date_insertion_dt"].notna().any() else 1
        df_periode = df
    else:
        n_jours = jours_map[periode]
        seuil = datetime.now() - timedelta(days=n_jours)
        df_periode = df[df["date_insertion_dt"] >= seuil]

    seuil_prec_debut = datetime.now() - timedelta(days=n_jours * 2)
    seuil_prec_fin = datetime.now() - timedelta(days=n_jours)
    df_precedente = df[(df["date_insertion_dt"] >= seuil_prec_debut) & (df["date_insertion_dt"] < seuil_prec_fin)]

    def variation(actuel: int, precedent: int):
        if precedent == 0:
            return None
        return (actuel - precedent) / precedent * 100

    total_periode = len(df_periode)
    actives_periode = int(df_periode["severity"].isin(["critique", "eleve"]).sum())
    critiques_periode = int((df_periode["severity"] == "critique").sum())

    total_prec = len(df_precedente)
    actives_prec = int(df_precedente["severity"].isin(["critique", "eleve"]).sum())
    critiques_prec = int((df_precedente["severity"] == "critique").sum())

    def trend_badge(actuel, precedent):
        var = variation(actuel, precedent)
        if var is None:
            return f"<span style='color:{C['on_surface_variant']}; font-family:monospace; font-size:11px;'>—</span>"
        icon = "trending_up" if var > 0 else ("trending_down" if var < 0 else "trending_flat")
        color = "#ef4444" if var > 0 else ("#10b981" if var < 0 else C["on_surface_variant"])
        return (f"<span style='display:inline-flex; align-items:center; gap:2px; color:{color}; "
                f"font-family:monospace; font-size:11px; background:{color}1a; padding:2px 6px; border-radius:4px;'>"
                f"<span class='material-symbols-outlined' style='font-size:13px;'>{icon}</span>{abs(var):.1f}%</span>")

    cards = [
        ("TOTAL DETECTIONS", total_periode, "radar", C["accent"], trend_badge(total_periode, total_prec)),
        ("ACTIVE ALERTS", actives_periode, "notifications_active", "#f59e0b", trend_badge(actives_periode, actives_prec)),
        ("CRITICAL RISKS", critiques_periode, "warning", "#ef4444", trend_badge(critiques_periode, critiques_prec)),
    ]
    ccols = st.columns(3)
    for col, (label, value, icon, color, trend) in zip(ccols, cards):
        with col:
            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
                    <span class="stat-label" style="display:flex; align-items:center; gap:6px;">
                        <span class="material-symbols-outlined" style="font-size:16px; color:{color};">{icon}</span>{label}
                    </span>
                    {trend}
                </div>
                <div class="stat-value" style="color:{color if label=='CRITICAL RISKS' else C['on_surface']};">{value}</div>
                <div class="stat-sub">Sur la période sélectionnée</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    col_chart, col_side = st.columns([2, 1])

    with col_chart:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Detection Volume Trend</div>', unsafe_allow_html=True)
        if df_periode.empty or df_periode["date_insertion_dt"].isna().all():
            st.caption("Pas assez de données datées sur cette période.")
        else:
            tmp = df_periode.dropna(subset=["date_insertion_dt"]).copy()
            tmp["jour"] = tmp["date_insertion_dt"].dt.date
            idx = pd.date_range(tmp["jour"].min(), tmp["jour"].max(), freq="D").date

            fig = go.Figure()
            for sev in ["critique", "eleve", "faible"]:
                serie = tmp[tmp["severity"] == sev].groupby("jour").size().reindex(idx, fill_value=0)
                fig.add_trace(go.Scatter(
                    x=idx, y=serie.values, name=SEVERITY[sev]["label"],
                    mode="lines", line=dict(color=SEVERITY[sev]["color"], width=2, shape="spline"),
                    fill="tozeroy", fillcolor=hex_to_rgba(SEVERITY[sev]["color"], 0.15),
                ))
            fig.update_layout(
                height=280, margin=dict(l=0, r=0, t=10, b=0),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color=C["on_surface_variant"], size=11, family="Inter"),
                xaxis=dict(showgrid=False, color=C["outline"]),
                yaxis=dict(showgrid=True, gridcolor=C["outline_variant"], gridwidth=1, zeroline=False),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, bgcolor="rgba(0,0,0,0)"),
                hovermode="x unified",
            )
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    with col_side:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Couverture par Source</div>', unsafe_allow_html=True)
        if df_periode.empty:
            st.caption("Aucune donnée sur cette période.")
        else:
            rep_sources = df_periode["source_api"].value_counts()
            total_src = rep_sources.sum()
            for src, count in rep_sources.items():
                pct = round(count / total_src * 100, 1) if total_src else 0
                st.markdown(f"""
                <div style="margin-bottom:14px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <span style="font-family:monospace; font-size:12.5px; color:{C['on_surface']};">{html.escape(str(src))}</span>
                        <span style="font-family:monospace; font-size:12.5px; color:{C['accent']};">{pct}%</span>
                    </div>
                    <div class="progress-track">
                        <div class="progress-fill" style="width:{pct}%; background:{C['accent']}; box-shadow:0 0 8px {C['accent']}80;"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.write("")

    st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
    st.markdown(f"""
    <div style="padding:16px 20px; border-bottom:1px solid {C['outline_variant']};">
        <span style="font-size:15px; font-weight:700; color:{C['on_surface']};">Generated Reports</span>
        <p style="font-size:12px; color:{C['on_surface_variant']}; margin:4px 0 0 0;">Exports générés à partir des données de la période sélectionnée.</p>
    </div>
    """, unsafe_allow_html=True)

    presets = [
        ("Résumé Exécutif", "Executive", "description", df_periode),
        ("Rapport Critiques Uniquement", "Compliance", "gavel", df_periode[df_periode["severity"] == "critique"]),
        ("Export Complet", "Full", "folder_zip", df_periode),
    ]
    maintenant = datetime.now().strftime("%Y-%m-%d %H:%M")
    for nom, type_label, icon, data in presets:
        rcols = st.columns([3, 1.3, 1.6, 1.2, 1.2])
        rcols[0].markdown(f"""
        <div style="display:flex; align-items:center; gap:10px; padding:6px 0;">
            <div style="width:30px; height:30px; border-radius:6px; background:rgba(56,189,248,0.10);
                        display:flex; align-items:center; justify-content:center;">
                <span class="material-symbols-outlined" style="font-size:16px; color:{C['accent']};">{icon}</span>
            </div>
            <span style="font-size:12.5px; color:{C['on_surface']};">{html.escape(nom)}</span>
        </div>
        """, unsafe_allow_html=True)
        rcols[1].markdown(f"<span style='font-size:12px; color:{C['on_surface_variant']};'>{type_label}</span>", unsafe_allow_html=True)
        rcols[2].markdown(f"<span style='font-family:monospace; font-size:11.5px; color:{C['on_surface_variant']};'>{maintenant}</span>",
                           unsafe_allow_html=True)
        rcols[3].markdown(badge_pill("PRÊT", C["accent"], "rgba(56,189,248,0.10)"), unsafe_allow_html=True)
        rcols[4].download_button("CSV", data=data.drop(columns=["date_insertion_dt"]).to_csv(index=False),
                                  file_name=f"{nom.lower().replace(' ', '_')}.csv", mime="text/csv",
                                  key=f"report_dl_{nom}")
    st.markdown('</div>', unsafe_allow_html=True)


# ============================================================
# PAGE : SETTINGS — implémentation fonctionnelle
# ============================================================
def _settings_card_open(icon: str, title: str):
    st.markdown(f"""
    <div class="settings-card">
        <div class="settings-card-header">
            <span class="material-symbols-outlined" style="color:{C['accent']};">{icon}</span>
            <span class="settings-card-title">{html.escape(title)}</span>
        </div>
        <div style="padding:24px;">
    """, unsafe_allow_html=True)


def _settings_card_close():
    st.markdown("</div></div>", unsafe_allow_html=True)


def _settings_field_label(label: str, help_text: str = ""):
    st.markdown(f"""
    <label class="settings-field-label">{html.escape(label)}</label>
    {f'<p class="settings-field-help">{html.escape(help_text)}</p>' if help_text else ''}
    """, unsafe_allow_html=True)


def _save_cancel_buttons(tab_key: str):
    """Boutons Save/Cancel réels. Save écrit dans settings.json et applique
    immédiatement (rerun). Cancel recharge les valeurs sauvegardées et
    réinitialise les widgets de l'onglet courant."""
    st.markdown('<hr class="settings-divider" style="margin-top:20px;">', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([6, 1, 1])
    with c2:
        cancel_clicked = st.button("Cancel", key=f"settings_cancel_{tab_key}", use_container_width=True)
    with c3:
        save_clicked = st.button("💾 Save Changes", key=f"settings_save_{tab_key}",
                                  type="primary", use_container_width=True)

    if cancel_clicked:
        st.session_state.app_settings = load_settings()
        for k in DEFAULT_SETTINGS.keys():
            wk = f"f_{k}"
            if wk in st.session_state:
                del st.session_state[wk]
        st.rerun()

    if save_clicked:
        new_settings = dict(st.session_state.app_settings)
        for k in DEFAULT_SETTINGS.keys():
            if k == "team_members":
                continue
            wk = f"f_{k}"
            if wk in st.session_state:
                new_settings[k] = st.session_state[wk]
        save_settings(new_settings)
        st.session_state.app_settings = new_settings
        st.success("Modifications enregistrées ✅")
        st.rerun()


def page_settings():
    settings = st.session_state.app_settings

    st.markdown(f"""
    <div class="aegis-header">
        <div style="display:flex; align-items:center; gap:12px;">
            <h2>Platform Configuration</h2>
            <span class="live-pill"><span class="live-dot"></span> Settings Active</span>
        </div>
    </div>
    <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:-8px 0 20px 0;">
        Manage global settings, security policies, and team access controls.
    </p>
    """, unsafe_allow_html=True)

    settings_tabs = [
        ("general", "tune", "General"),
        ("security", "shield_person", "Account & Security"),
        ("monitoring", "radar", "Monitoring Config"),
        ("notifications", "campaign", "Notifications"),
        ("team", "group", "Team Management"),
    ]

    col_nav, col_content = st.columns([3, 9])

    with col_nav:
        st.markdown('<div class="glass-card" style="padding:6px;">', unsafe_allow_html=True)
        for tab_key, icon, label in settings_tabs:
            is_active = st.session_state.get("settings_tab", "general") == tab_key
            st.markdown('<div class="settings-nav-btn">', unsafe_allow_html=True)
            if st.button(label, key=f"settings_nav_{tab_key}",
                         type="primary" if is_active else "secondary",
                         use_container_width=True):
                st.session_state.settings_tab = tab_key
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_content:
        current_tab = st.session_state.get("settings_tab", "general")

        # ---------------- GENERAL ----------------
        if current_tab == "general":
            _settings_card_open("tune", "General Settings")

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Platform Name", "Displayed in headers and reports.")
            with c2:
                st.text_input("Platform Name", value=settings["general_platform_name"],
                               key="f_general_platform_name", label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Default Timezone", "Used for event logging and alerts.")
            with c2:
                tz_options = ["UTC", "EST", "PST"]
                st.selectbox("Timezone", tz_options,
                              index=tz_options.index(settings["general_timezone"]) if settings["general_timezone"] in tz_options else 0,
                              key="f_general_timezone", label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Interface Language")
            with c2:
                lang_options = ["en", "fr"]
                lang_labels = {"en": "English (US)", "fr": "Français"}
                st.radio("Langue", lang_options, format_func=lambda x: lang_labels[x],
                          index=lang_options.index(settings["general_language"]) if settings["general_language"] in lang_options else 0,
                          key="f_general_language", horizontal=True, label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Custom Logo", "SVG or PNG, max 2MB.")
            with c2:
                logo_file = st.file_uploader("Logo", type=["svg", "png"], key="f_logo_upload",
                                              label_visibility="collapsed")
                if logo_file is not None:
                    os.makedirs(UPLOADS_DIR, exist_ok=True)
                    dest = os.path.join(UPLOADS_DIR, logo_file.name)
                    with open(dest, "wb") as f:
                        f.write(logo_file.getbuffer())
                    st.session_state["f_general_logo_filename"] = logo_file.name
                    st.success(f"Fichier reçu : {logo_file.name} (sera appliqué après Save Changes)")
                current_logo = settings.get("general_logo_filename")
                st.caption(f"Fichier actuel : {current_logo}" if current_logo else "Aucun logo personnalisé pour le moment.")
                if "f_general_logo_filename" not in st.session_state:
                    st.session_state["f_general_logo_filename"] = current_logo

            _save_cancel_buttons("general")
            _settings_card_close()

        # ---------------- SECURITY ----------------
        elif current_tab == "security":
            _settings_card_open("shield_person", "Account & Security")

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Two-Factor Authentication", "Require MFA for all admin accounts.")
            with c2:
                st.checkbox("Activer la MFA", value=settings["security_mfa"],
                             key="f_security_mfa")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Session Timeout", "Auto-logout after inactivity.")
            with c2:
                to_options = ["15", "30", "60", "120"]
                to_labels = {"15": "15 minutes", "30": "30 minutes", "60": "1 hour", "120": "2 hours"}
                st.selectbox("Session timeout", to_options, format_func=lambda x: to_labels[x],
                              index=to_options.index(settings["security_session_timeout"]) if settings["security_session_timeout"] in to_options else 1,
                              key="f_security_session_timeout", label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("IP Whitelist", "Restrict access to trusted IPs.")
            with c2:
                st.text_input("IP whitelist", value=settings["security_ip_whitelist"],
                               placeholder="192.168.1.0/24, 10.0.0.1",
                               key="f_security_ip_whitelist", label_visibility="collapsed")
                st.caption("Comma-separated IPs or CIDR ranges.")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Password Policy")
            with c2:
                st.checkbox("Minimum 12 characters", value=settings["security_pwd_min_length"],
                             key="f_security_pwd_min_length")
                st.checkbox("Require uppercase & lowercase", value=settings["security_pwd_upper_lower"],
                             key="f_security_pwd_upper_lower")
                st.checkbox("Require numbers & special characters", value=settings["security_pwd_special"],
                             key="f_security_pwd_special")

            _save_cancel_buttons("security")
            _settings_card_close()

        # ---------------- MONITORING ----------------
        elif current_tab == "monitoring":
            _settings_card_open("radar", "Monitoring Configuration")

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Scan Interval", "How often to scan dark web sources.")
            with c2:
                si_options = ["1", "2", "5", "10"]
                si_labels = {"1": "Every minute", "2": "Every 2 minutes", "5": "Every 5 minutes", "10": "Every 10 minutes"}
                st.selectbox("Scan interval", si_options, format_func=lambda x: si_labels[x],
                              index=si_options.index(settings["monitoring_scan_interval"]) if settings["monitoring_scan_interval"] in si_options else 1,
                              key="f_monitoring_scan_interval", label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Active Sources", "Enable/disable data sources.")
            with c2:
                st.checkbox("HudsonRock (Infostealers)", value=settings["monitoring_src_hudsonrock"],
                             key="f_monitoring_src_hudsonrock")
                st.checkbox("Ransomware.live", value=settings["monitoring_src_ransomwarelive"],
                             key="f_monitoring_src_ransomwarelive")
                st.checkbox("Check-The-Sum (honeypot IOC)", value=settings["monitoring_src_checkthesum"],
                             key="f_monitoring_src_checkthesum")
                st.checkbox("RansomLook.io", value=settings["monitoring_src_ransomlook"],
                             key="f_monitoring_src_ransomlook")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Alert Thresholds", "Minimum severity to trigger alerts.")
            with c2:
                th_options = ["critique", "eleve", "faible"]
                th_labels = {"critique": "Critical only", "eleve": "Elevated+", "faible": "All"}
                st.radio("Seuil", th_options, format_func=lambda x: th_labels[x],
                          index=th_options.index(settings["monitoring_alert_threshold"]) if settings["monitoring_alert_threshold"] in th_options else 1,
                          key="f_monitoring_alert_threshold", horizontal=True, label_visibility="collapsed")

            st.caption("ℹ️ Ces réglages sont sauvegardés dans settings.json. Pour qu'ils pilotent réellement "
                       "main.py (fréquence de scan, sources actives), main.py doit être adapté pour lire ce "
                       "fichier au démarrage de chaque cycle — dis-le moi si tu veux qu'on le fasse.")

            _save_cancel_buttons("monitoring")
            _settings_card_close()

        # ---------------- NOTIFICATIONS ----------------
        elif current_tab == "notifications":
            _settings_card_open("campaign", "Notifications")

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Notification Channels")
            with c2:
                st.checkbox("Email", value=settings["notif_email_enabled"], key="f_notif_email_enabled")
                st.checkbox("Slack (Coming Soon)", value=settings["notif_slack_enabled"],
                             key="f_notif_slack_enabled", disabled=True)
                st.checkbox("PagerDuty (Coming Soon)", value=settings["notif_pagerduty_enabled"],
                             key="f_notif_pagerduty_enabled", disabled=True)
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Email Recipients", "Alerts will be sent to these addresses.")
            with c2:
                st.text_input("Destinataires", value=settings["notif_email_recipients"],
                               placeholder="soc@company.com, admin@company.com",
                               key="f_notif_email_recipients", label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Alert Digest", "Send daily summary of all alerts.")
            with c2:
                st.checkbox("Activer le résumé quotidien", value=settings["notif_digest_enabled"],
                             key="f_notif_digest_enabled")

            st.caption("ℹ️ L'envoi d'e-mails réel n'est pas encore branché (il n'y a pas de serveur SMTP "
                       "configuré côté pipeline) — ces préférences sont sauvegardées et prêtes à être "
                       "utilisées le jour où l'envoi sera implémenté dans main.py.")

            _save_cancel_buttons("notifications")
            _settings_card_close()

        # ---------------- TEAM ----------------
        elif current_tab == "team":
            _settings_card_open("group", "Team Management")

            st.caption("ℹ️ Il n'y a pas de système d'authentification connecté : ceci stocke la liste "
                       "localement dans settings.json, sans envoi d'invitation réelle ni contrôle d'accès effectif.")

            members = settings.get("team_members", [])
            for i, member in enumerate(members):
                mc1, mc2, mc3 = st.columns([5, 2, 1])
                role_color = C["accent"] if member["role"] == "Admin" else C["on_surface_variant"]
                mc1.markdown(f"""
                <div class="settings-team-row" style="margin-bottom:0;">
                    <span style="font-size:13px; color:{C['on_surface']};">{html.escape(member['email'])}</span>
                    <span class="settings-role-badge" style="color:{role_color}; background:{role_color}1a;">{member['role']}</span>
                </div>
                """, unsafe_allow_html=True)
                if mc3.button("✕", key=f"team_remove_{i}"):
                    new_settings = dict(st.session_state.app_settings)
                    new_members = list(new_settings.get("team_members", []))
                    new_members.pop(i)
                    new_settings["team_members"] = new_members
                    save_settings(new_settings)
                    st.session_state.app_settings = new_settings
                    st.rerun()

            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)
            st.markdown('<p class="settings-field-label">Invite Team Member</p>', unsafe_allow_html=True)
            ic1, ic2, ic3 = st.columns([3, 1.5, 1])
            with ic1:
                new_email = st.text_input("Email", placeholder="new_member@company.com",
                                           key="team_new_email", label_visibility="collapsed")
            with ic2:
                new_role = st.selectbox("Rôle", ["Analyst", "Admin"], key="team_new_role",
                                         label_visibility="collapsed")
            with ic3:
                if st.button("+ Invite", key="team_invite_btn", width="stretch"):
                    if new_email and "@" in new_email:
                        new_settings = dict(st.session_state.app_settings)
                        new_members = list(new_settings.get("team_members", []))
                        new_members.append({"email": new_email.strip(), "role": new_role})
                        new_settings["team_members"] = new_members
                        save_settings(new_settings)
                        st.session_state.app_settings = new_settings
                        st.session_state["team_new_email"] = ""
                        st.success(f"{new_email} ajouté à l'équipe.")
                        st.rerun()
                    else:
                        st.error("Adresse email invalide.")

            _settings_card_close()


# ============================================================
# PAGE : PLACEHOLDER
# ============================================================
def page_placeholder(titre: str):
    st.markdown(f"""
    <div class="aegis-header"><h2>{html.escape(titre)}</h2></div>
    """, unsafe_allow_html=True)
    st.markdown(f"""
    <div class="glass-card" style="text-align:center; padding:60px 20px;">
        <span class="material-symbols-outlined" style="font-size:40px; color:{C['outline']};">construction</span>
        <p style="color:{C['on_surface_variant']}; margin-top:12px;">
            Cet écran sera habillé avec le design Stitch à la prochaine étape.
        </p>
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# ROUTAGE
# ============================================================
page = st.session_state.page
if page == "dashboard":
    page_dashboard()
elif page == "darkweb":
    page_darkweb()
elif page == "assets":
    page_assets()
elif page == "alerts":
    page_alerts()
elif page == "leaks":
    page_leaks()
elif page == "search":
    page_search()
elif page == "reports":
    page_reports()
elif page == "settings":
    page_settings()
else:
    labels = {k: v for k, _, v in NAV_ITEMS}
    page_placeholder(labels.get(page, page))