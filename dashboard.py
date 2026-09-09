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
# ASSETS MANAGEMENT
# ============================================================
ASSETS_FILE = "monitored_assets.json"
SETTINGS_FILE = "app_settings.json"

def charger_assets() -> list:
    """Charge la liste des assets surveillés depuis le fichier JSON"""
    if os.path.exists(ASSETS_FILE):
        try:
            with open(ASSETS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def sauvegarder_assets(assets: list) -> None:
    """Sauvegarde la liste des assets surveillés"""
    with open(ASSETS_FILE, "w", encoding="utf-8") as f:
        json.dump(assets, f, indent=2, ensure_ascii=False)

def ajouter_asset(asset: str, asset_type: str) -> bool:
    """Ajoute un nouvel asset à la liste de surveillance"""
    assets = charger_assets()
    for a in assets:
        if a["identifier"].lower() == asset.lower():
            return False
    assets.append({
        "identifier": asset,
        "type": asset_type,
        "date_ajout": datetime.now().isoformat()
    })
    sauvegarder_assets(assets)
    return True

def supprimer_asset(asset: str) -> bool:
    """Supprime un asset de la liste de surveillance"""
    assets = charger_assets()
    nouvelle_liste = [a for a in assets if a["identifier"].lower() != asset.lower()]
    if len(nouvelle_liste) < len(assets):
        sauvegarder_assets(nouvelle_liste)
        return True
    return False

# ============================================================
# FONCTIONS DE SYNCHRONISATION AVEC APP_SETTINGS.JSON
# ============================================================

def ajouter_asset_avec_sync(asset: str, asset_type: str) -> bool:
    """Ajoute un asset et synchronise avec app_settings.json"""
    assets = charger_assets()
    for a in assets:
        if a["identifier"].lower() == asset.lower():
            return False
    
    assets.append({
        "identifier": asset,
        "type": asset_type,
        "date_ajout": datetime.now().isoformat()
    })
    sauvegarder_assets(assets)
    
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                settings = json.load(f)
            
            if asset_type == "Domaine":
                if "monitored_domains" not in settings:
                    settings["monitored_domains"] = []
                if asset not in settings["monitored_domains"]:
                    settings["monitored_domains"].append(asset)
            elif asset_type == "Email":
                if "monitored_emails" not in settings:
                    settings["monitored_emails"] = []
                if asset not in settings["monitored_emails"]:
                    settings["monitored_emails"].append(asset)
            else:
                if "monitored_keywords" not in settings:
                    settings["monitored_keywords"] = []
                if asset not in settings["monitored_keywords"]:
                    settings["monitored_keywords"].append(asset)
            
            if "monitoring_assets" in settings:
                settings["monitoring_assets"] = [
                    a for a in settings["monitoring_assets"] 
                    if not (isinstance(a, dict) and a.get("identifier") == asset) and a != asset
                ]
            
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Erreur mise à jour app_settings.json: {e}")
    
    return True

def supprimer_asset_avec_sync(asset: str) -> bool:
    """Supprime un asset et synchronise avec app_settings.json"""
    assets = charger_assets()
    nouvelle_liste = [a for a in assets if a["identifier"].lower() != asset.lower()]
    if len(nouvelle_liste) == len(assets):
        return False
    sauvegarder_assets(nouvelle_liste)
    
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                settings = json.load(f)
            
            for key in ["monitored_domains", "monitored_keywords", "monitored_emails", "monitoring_assets"]:
                if key in settings:
                    if key == "monitoring_assets":
                        settings[key] = [
                            a for a in settings[key] 
                            if not (isinstance(a, dict) and a.get("identifier") == asset) and a != asset
                        ]
                    else:
                        settings[key] = [a for a in settings[key] if a != asset]
            
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ Erreur mise à jour app_settings.json: {e}")
    
    return True

# ============================================================
# SETTINGS
# ============================================================
UPLOADS_DIR = "settings_uploads"

DEFAULT_SETTINGS = {
    "general_platform_name": "AEGIS MONITOR",
    "general_timezone": "UTC",
    "general_language": "en",
    "general_logo_filename": None,
    "security_mfa": True,
    "security_session_timeout": "30",
    "security_ip_whitelist": "",
    "security_pwd_min_length": True,
    "security_pwd_upper_lower": True,
    "security_pwd_special": True,
    "monitoring_scan_interval": "2",
    "monitoring_src_hudsonrock": True,
    "monitoring_src_ransomwarelive": True,
    "monitoring_src_checkthesum": True,
    "monitoring_src_ransomlook": True,
    "monitoring_tunisia_watch": True,
    "monitoring_apt_watch": True,
    "monitoring_deepdarkcti": True,
    "monitoring_wazuh_export": True,
    "monitoring_alert_threshold": "eleve",
    "notif_email_enabled": True,
    "notif_slack_enabled": False,
    "notif_pagerduty_enabled": False,
    "notif_email_recipients": "",
    "notif_digest_enabled": False,
    "team_members": [],
}

def load_settings() -> dict:
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
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)

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
# SOURCES DISPONIBLES
# ============================================================
# Sources de détection (pour le Dashboard et Alerts)
SOURCES_DETECTION = [
    {"id": "RansomwareLive", "label": "Ransomware.live", "icon": "🎯", "color": "#ef4444"},
    {"id": "HudsonRock", "label": "Hudson Rock", "icon": "🎯", "color": "#38bdf8"},
    {"id": "CheckTheSum", "label": "Check-The-Sum", "icon": "🎯", "color": "#f59e0b"},
    {"id": "RansomLook", "label": "RansomLook.io", "icon": "🎯", "color": "#8b5cf6"},
]

# Sources de veille stratégique (pour Ransomware Intel uniquement)
SOURCES_VEILLE = [
    {"id": "deepdarkCTI", "label": "deepdarkCTI (veille)", "icon": "📊", "color": "#10b981"},
    {"id": "APTnotes", "label": "APTnotes (veille)", "icon": "📊", "color": "#f97316"},
]

# ============================================================
# PALETTE
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

SEVERITY = {
    "critique": {"color": "#ef4444", "bg": "rgba(239,68,68,0.14)", "label": "Critique"},
    "eleve":    {"color": "#f59e0b", "bg": "rgba(245,158,11,0.14)", "label": "Élevée"},
    "moyenne":  {"color": "#fbbf24", "bg": "rgba(251,191,36,0.14)", "label": "Moyenne"},
    "faible":   {"color": "#10b981", "bg": "rgba(16,185,129,0.14)", "label": "Faible"},
}
DEFAULT_SEV = {"color": C["outline"], "bg": "rgba(135,146,154,0.12)", "label": "Inconnue"}

SEVERITY_RANK = {"critique": 4, "eleve": 3, "moyenne": 2, "faible": 1}

STATUS_META = {
    "Nouveau": {"dot": "🟡", "color": "#f5a524", "bg": "rgba(245,165,36,0.12)"},
    "En cours": {"dot": "🔵", "color": "#5b8def", "bg": "rgba(91,141,239,0.12)"},
    "Traité":   {"dot": "🟢", "color": "#22c55e", "bg": "rgba(34,197,94,0.12)"},
    "Faux positif": {"dot": "⚪", "color": "#6b7590", "bg": "rgba(107,117,144,0.12)"},
}

CHECKLIST_ITEMS = ["Analyser l'alerte", "Documenter les preuves", "Archiver"]

NAV_ITEMS = [
    ("dashboard", "dashboard", "Dashboard"),
    ("assets", "hub", "Assets"),
    ("alerts", "notifications_active", "Alerts"),
    ("ransomware", "gpp_maybe", "Ransomware Intel"),
    ("search", "search", "Search"),
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
    /* Masque le bouton "Deploy" et la barre d'outils Streamlit en haut à droite */
    .stAppDeployButton, .stDeployButton {{display: none !important;}}
    div[data-testid="stToolbar"] {{display: none !important;}}
    div[data-testid="stDecoration"] {{display: none !important;}}
    div[data-testid="stStatusWidget"] {{display: none !important;}}
    header[data-testid="stHeader"] {{
        background: transparent;
    }}
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
    
    /* ===== SIDEBAR NAVIGATION ===== */
    .nav-container {{
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 4px 0;
    }}
    
    .nav-item {{
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 10px 16px;
        margin: 0 8px;
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s ease;
        color: #94a3b8;
        font-weight: 500;
        font-size: 14px;
        text-decoration: none;
        border-left: 3px solid transparent;
    }}
    
    .nav-item:hover {{
        background: rgba(56, 189, 248, 0.08);
        color: #e2e8f0;
    }}
    
    .nav-item.active {{
        background: rgba(56, 189, 248, 0.12);
        color: #38bdf8;
        border-left-color: #38bdf8;
        border-radius: 0 8px 8px 0;
    }}
    
    .nav-item .nav-icon {{
        font-size: 22px;
        font-variation-settings: 'FILL' 0;
        width: 28px;
        text-align: center;
        font-family: 'Material Symbols Outlined';
    }}
    
    .nav-item.active .nav-icon {{
        font-variation-settings: 'FILL' 1;
    }}
    
    .nav-item .nav-label {{
        font-size: 14px;
        letter-spacing: 0.02em;
    }}
    
   
    
    /* Buttons anywhere OUTSIDE the sidebar */
    div[data-testid="stButton"] > button {{
        background-color: {C['surface_high']} !important;
        color: {C['on_surface']} !important;
        border: 1px solid {C['outline_variant']} !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-size: 12.5px !important;
        transition: all 0.15s ease !important;
    }}
    div[data-testid="stButton"] > button:hover {{
        background-color: {C['surface_highest']} !important;
        border-color: {C['accent']} !important;
        color: {C['accent']} !important;
    }}
    div[data-testid="stButton"] > button[kind="primary"] {{
        background-color: rgba(56,189,248,0.14) !important;
        color: {C['accent']} !important;
        border-color: {C['accent']} !important;
    }}
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
    .glass-card {{
        background: rgba(15,23,42,0.55);
        backdrop-filter: blur(10px);
        border: 1px solid {C['outline_variant']};
        border-radius: 12px;
        padding: 16px;
    }}
    .glass-card-clickable {{
        cursor: pointer;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }}
    .glass-card-clickable:hover {{
        border-color: {C['accent']};
        box-shadow: 0 0 20px rgba(56,189,248,0.08);
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
        display: flex;
        align-items: center;
        gap: 8px;
    }}
    .card-title .click-hint {{
        font-size: 10px;
        font-weight: 400;
        color: {C['on_surface_variant']};
        margin-left: auto;
    }}
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
    .badge-pill {{
        display: inline-flex; align-items: center; gap: 4px;
        padding: 2px 9px; border-radius: 4px;
        font-size: 10px; font-weight: 700; letter-spacing: 0.04em;
        text-transform: uppercase; white-space: nowrap;
    }}
    .tag-chip {{
        display: inline-block;
        background: {C['surface_highest']};
        border: 1px solid {C['outline_variant']};
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 9px;
        font-weight: 600;
        letter-spacing: 0.04em;
        color: {C['on_surface_variant']};
        font-family: monospace;
        margin: 0 4px 4px 0;
        cursor: pointer;
        transition: border-color 0.2s ease, color 0.2s ease;
    }}
    .tag-chip:hover {{
        border-color: {C['accent']};
        color: {C['accent']};
    }}
    .overview-row {{
        display: flex; justify-content: space-between; align-items: center;
        padding: 6px 0;
    }}
    .progress-track {{
        height: 4px;
        width: 100%;
        background: {C['surface_highest']};
        border-radius: 999px;
        overflow: hidden;
        margin-top: 4px;
    }}
    .progress-fill {{
        height: 100%;
        border-radius: 999px;
    }}
    .info-grid {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
    }}
    .info-item {{
        display: flex;
        justify-content: space-between;
        padding: 4px 0;
        font-size: 12.5px;
        border-bottom: 1px solid rgba(30,41,59,0.2);
    }}
    .info-item .label {{
        color: {C['on_surface_variant']};
    }}
    .info-item .value {{
        color: {C['on_surface']};
        font-family: monospace;
    }}
    .modal-overlay {{
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(5, 20, 36, 0.85);
        z-index: 999;
        display: flex;
        align-items: center;
        justify-content: center;
        backdrop-filter: blur(4px);
    }}
    .modal-content {{
        background: #0e1c2d;
        border: 1px solid #1e293b;
        border-radius: 16px;
        padding: 32px;
        max-width: 560px;
        width: 90%;
        max-height: 90vh;
        overflow-y: auto;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    }}
</style>
""", unsafe_allow_html=True)

# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================
@st.cache_data(ttl=60)
def charger_donnees() -> pd.DataFrame:
    colonnes = ["id", "source_api", "type", "asset_recherche", "asset_concerne",
                "details", "date_detection", "severity", "date_insertion",
                "country", "sector"]
    alertes = lire_toutes_les_alertes()
    df = pd.DataFrame(alertes, columns=colonnes)
    if not df.empty:
        df["date_insertion_dt"] = pd.to_datetime(df["date_insertion"], errors="coerce")
        df["date_detection_dt"] = pd.to_datetime(df["date_detection"], errors="coerce", utc=True)
        df["date_tri"] = df["date_detection_dt"].fillna(df["date_insertion_dt"])
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

def country_to_flag(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🏳️"
    code = code.upper()
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)

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

def extract_infostealer_details(details: str) -> dict:
    result = {}
    if not details:
        return result
    patterns = {
        "total": r"Total comptes compromis:\s*(\d+)",
        "employes": r"Employés:\s*(\d+)",
        "utilisateurs": r"Utilisateurs:\s*(\d+)",
        "services_corporate": r"Services corporate:\s*(\d+)",
        "services_perso": r"Services perso:\s*(\d+)",
        "ordinateur": r"Ordinateur infecté\s*\(([^)]+)\)",
        "computer_name": r"computer_name['\"]?\s*:\s*['\"]([^'\"]+)",
        "infecte_depuis": r"Infecté depuis:\s*([^,\s]+)",
        "date_compromised": r"date_compromised['\"]?\s*:\s*['\"]([^'\"]+)",
    }
    for key, pattern in patterns.items():
        match = _re.search(pattern, details, _re.IGNORECASE)
        if match:
            result[key] = match.group(1)
    return result

def extract_ransomware_details(details: str) -> dict:
    result = {}
    if not details:
        return result
    patterns = {
        "groupe": r"Groupe ransomware:\s*([^,]+)",
        "entreprise": r"Entreprise:\s*([^,]+)",
        "site": r"Site:\s*([^,\s]+)",
    }
    for key, pattern in patterns.items():
        match = _re.search(pattern, details, _re.IGNORECASE)
        if match:
            result[key] = match.group(1).strip()
    return result

def type_meta(t: str) -> dict:
    TYPE_META = {
        "infostealer_compromise": {"label": "Infostealer Compromise", "icon": "password"},
        "ransomware_leak": {"label": "Ransomware Leak", "icon": "lock_open"},
        "credential_leak": {"label": "Credential Leak", "icon": "key"},
        "domain_mention": {"label": "Domain Mention", "icon": "language"},
        "malicious_infrastructure_mention": {"label": "Malicious Infrastructure Mention", "icon": "dns"},
        "ransomware_leak_tn": {"label": "Ransomware Leak (Tunisia)", "icon": "flag"},
        "ransomware_leak_pays": {"label": "Ransomware Leak (Pays surveillé)", "icon": "flag"},
        "ransomware_global_feed": {"label": "Ransomware Global Feed", "icon": "public"},
        "apt_mention": {"label": "APT Report Mention", "icon": "travel_explore"},
        "deepdarkcti_status": {"label": "deepdarkCTI Status", "icon": "network_check"},
        "infostealer_email_check": {"label": "Infostealer Email Check", "icon": "mail"},
    }
    return TYPE_META.get(t, {"label": (t or "Inconnu").replace("_", " ").title(), "icon": "report"})

def get_recommended_actions(type_: str) -> list:
    TYPE_ACTIONS = {
        "infostealer_compromise": [
            "🔑 Forcer la réinitialisation des identifiants des machines/comptes infectés.",
            "🔄 Révoquer les sessions actives et les tokens associés aux postes compromis.",
            "🛡️ Activer la MFA sur tous les comptes concernés.",
        ],
        "credential_leak": [
            "🔑 Effectuer une rotation immédiate des identifiants exposés.",
            "🛡️ Activer la MFA sur tous les comptes concernés par la fuite.",
            "🔍 Analyser les logs pour détecter des utilisations suspectes.",
        ],
        "ransomware_leak": [
            "🛑 Isoler les systèmes concernés et vérifier l'intégrité des sauvegardes.",
            "📢 Notifier les parties prenantes conformément au plan de réponse aux incidents.",
            "🔍 Analyser la nature des données exposées.",
        ],
        "domain_mention": [
            "🔍 Analyser le contexte de la mention pour évaluer la pertinence de la menace.",
            "📡 Surveiller les activités suspectes liées à ce domaine dans les prochains jours.",
        ],
    }
    return TYPE_ACTIONS.get(type_, [
        "🔍 Analyser le contenu de l'alerte pour qualifier le niveau de risque réel.",
        "📤 Escalader vers l'équipe SOC si la sévérité est confirmée.",
    ])

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

def get_source_url(source_api: str, asset: str = "") -> str:
    """Retourne l'URL de la source en fonction de l'API"""
    source_urls = {
        "RansomwareLive": "https://ransomware.live",
        "HudsonRock": "https://cavalier.hudsonrock.com",
        "CheckTheSum": "https://www.check-the-sum.fr",
        "RansomLook": "https://www.ransomlook.io",
        "APTnotes": "https://github.com/aptnotes/data",
        "deepdarkCTI": "https://github.com/fastfire/deepdarkCTI",
    }
    return source_urls.get(source_api, "#")

# ============================================================
# EXTRACTION STRUCTURÉE DES DÉTAILS PAR TYPE D'ALERTE
# ============================================================

def extraire_infos_ransomware_leak(details: str) -> dict:
    """Extrait les informations d'une alerte ransomware_leak"""
    result = {
        "groupe": "Non spécifié",
        "entreprise": "Non spécifiée",
        "site": "Non spécifié"
    }
    if not details:
        return result
    
    patterns = {
        "groupe": r"Groupe ransomware:\s*([^,]+)",
        "entreprise": r"Entreprise:\s*([^,]+)",
        "site": r"Site:\s*([^,\s]+)",
    }
    for key, pattern in patterns.items():
        match = _re.search(pattern, details, _re.IGNORECASE)
        if match:
            result[key] = match.group(1).strip()
    return result


def extraire_infos_infostealer_compromise(details: str) -> dict:
    """Extrait les informations d'une alerte infostealer_compromise"""
    result = {
        "total": "0",
        "employes": "0",
        "utilisateurs": "0"
    }
    if not details:
        return result
    
    patterns = {
        "total": r"Total comptes compromis:\s*(\d+)",
        "employes": r"Employés:\s*(\d+)",
        "utilisateurs": r"Utilisateurs:\s*(\d+)",
    }
    for key, pattern in patterns.items():
        match = _re.search(pattern, details, _re.IGNORECASE)
        if match:
            result[key] = match.group(1)
    return result


def extraire_infos_infostealer_email(details: str) -> dict:
    """Extrait les informations d'une alerte infostealer_email_check"""
    result = {
        "ordinateur": "Inconnu",
        "services_corporate": "0",
        "services_perso": "0",
        "infecte_depuis": "Inconnue"
    }
    if not details:
        return result
    
    patterns = {
        "ordinateur": r"Ordinateur infecté\s*\(([^)]+)\)",
        "computer_name": r"computer_name['\"]?\s*:\s*['\"]([^'\"]+)",
        "services_corporate": r"Services corporate:\s*(\d+)",
        "services_perso": r"Services perso:\s*(\d+)",
        "infecte_depuis": r"Infecté depuis:\s*([^,\s]+)",
        "date_compromised": r"date_compromised['\"]?\s*:\s*['\"]([^'\"]+)",
    }
    for key, pattern in patterns.items():
        match = _re.search(pattern, details, _re.IGNORECASE)
        if match:
            result[key] = match.group(1)
    return result


def extraire_infos_generiques(details: str) -> dict:
    """Extrait les informations génériques d'une alerte"""
    result = {}
    if not details:
        return result
    
    # Recherche de mots-clés communs
    if "credential" in details.lower() or "mot de passe" in details.lower():
        result["type_donnees"] = "Identifiants"
    if "email" in details.lower():
        result["type_donnees"] = "Emails"
    if "api" in details.lower() or "token" in details.lower():
        result["type_donnees"] = "Tokens/Clés API"
    
    return result


def extraire_infos_specifiques_alerte(type_alerte: str, details: str) -> dict:
    """Extrait les informations spécifiques selon le type d'alerte"""
    if not details:
        return {"raw": details}
    
    if type_alerte in ["ransomware_leak", "ransomware_leak_tn", "ransomware_leak_pays"]:
        return extraire_infos_ransomware_leak(details)
    elif type_alerte == "infostealer_compromise":
        return extraire_infos_infostealer_compromise(details)
    elif type_alerte == "infostealer_email_check":
        return extraire_infos_infostealer_email(details)
    elif type_alerte == "credential_leak":
        return extraire_infos_generiques(details)
    else:
        return {"raw": details}


# ============================================================
# NAVIGATION - MATERIAL ICONS SIDEBAR (WORKING)
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
    st.markdown("""
    <style>
    section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
        gap: 0rem !important;
    }
    section[data-testid="stSidebar"] .element-container,
    section[data-testid="stSidebar"] [data-testid="stElementContainer"] {
        margin: 0 !important;
        padding: 0 !important;
    }

    section[data-testid="stSidebar"] div[data-testid="stButton"] {
        margin: 6px 0 !important;
    }

    section[data-testid="stSidebar"] div[data-testid="stButton"] > button {
        display: flex !important;
        align-items: center !important;
        justify-content: flex-start !important;
        width: 100% !important;
        background: transparent !important;
        border: none !important;
        border-left: 3px solid transparent !important;
        border-radius: 0 8px 8px 0 !important;
        color: #94a3b8 !important;
        font-weight: 500 !important;
        font-size: 14px !important;
        padding: 11px 16px !important;
        margin: 0 8px !important;
        box-shadow: none !important;
        min-height: 0 !important;
        line-height: 1.3 !important;
    }

    /* The inner wrapper Streamlit puts around icon+label */
    section[data-testid="stSidebar"] div[data-testid="stButton"] > button > div {
        display: flex !important;
        justify-content: flex-start !important;
        align-items: center !important;
        gap: 12px !important;
        width: 100% !important;
    }

    section[data-testid="stSidebar"] div[data-testid="stButton"] > button p {
        font-size: 14px !important;
        margin: 0 !important;
        text-align: left !important;
    }

    section[data-testid="stSidebar"] div[data-testid="stButton"] > button:hover {
        background: rgba(56, 189, 248, 0.08) !important;
        color: #e2e8f0 !important;
    }
    section[data-testid="stSidebar"] div[data-testid="stButton"] > button[kind="primary"] {
        background: rgba(56, 189, 248, 0.12) !important;
        color: #38bdf8 !important;
        border-left-color: #38bdf8 !important;
    }
    </style>
    """, unsafe_allow_html=True)

    for key, icon, label in NAV_ITEMS:
        is_active = st.session_state.page == key
        if st.button(
            label,
            key=f"nav_btn_{key}",
            icon=f":material/{icon}:",
            type="primary" if is_active else "secondary",
            use_container_width=True,
        ):
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
        st.info("Aucune alerte en base. Lance le pipeline de collecte (main.py) pour peupler le dashboard.")
        return

    periode = st.radio("Période", ["7D", "30D", "90D", "Tout"], horizontal=True, index=1)

    if periode == "Tout":
        df_periode = df
    else:
        n_jours = {"7D": 7, "30D": 30, "90D": 90}[periode]
        seuil = datetime.now() - timedelta(days=n_jours)
        df_periode = df[df["date_insertion_dt"] >= seuil]

    total = len(df_periode)
    critiques = int((df_periode["severity"] == "critique").sum())
    elevees = int((df_periode["severity"] == "eleve").sum())
    moyennes = int((df_periode["severity"] == "moyenne").sum())
    faibles = int((df_periode["severity"] == "faible").sum())
    actives = critiques + elevees + moyennes

    stats = [
        {"label": "Total Alertes", "value": f"{total:,}".replace(",", " "), "color": C["accent"], "sub": None},
        {"label": "Alertes Actives", "value": str(actives), "sub": "critique + élevée + moyenne", "color": "#ef4444" if actives > 0 else C["accent"]},
        {"label": "Critiques", "value": str(critiques), "sub": "Action immédiate" if critiques else "Aucune", "color": "#ef4444"},
        {"label": "Élevées", "value": str(elevees), "sub": "Priorité haute" if elevees else "Aucune", "color": "#f59e0b"},
        {"label": "Moyennes", "value": str(moyennes), "sub": "À surveiller" if moyennes else "Aucune", "color": "#fbbf24"},
        {"label": "Faibles", "value": str(faibles), "sub": "Information" if faibles else "Aucune", "color": "#10b981"},
    ]

    cols = st.columns(6)
    for col, stat in zip(cols, stats):
        with col:
            sub_html = ""
            if stat.get("sub") and stat["sub"] != "&nbsp;":
                sub_html = f'<div class="stat-sub" style="font-size:9px; margin-top:2px;">{html.escape(str(stat["sub"]))}</div>'
            
            st.markdown(f"""
            <div class="glass-card" style="text-align:center; border-top: 2px solid {stat['color']}; padding:12px;">
                <div style="display:flex; justify-content:center; align-items:center; margin-bottom:2px;">
                    <span class="stat-label" style="font-size:9px;">{html.escape(stat['label'])}</span>
                </div>
                <div class="stat-value" style="font-size:24px; color:{stat['color']}; margin-top:2px;">
                    {html.escape(str(stat['value']))}
                </div>
                {sub_html}
            </div>
            """, unsafe_allow_html=True)

    col_chart, col_pie = st.columns([2, 1])

    with col_chart:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Threat Activity Over Time</div>', unsafe_allow_html=True)

        if df_periode.empty or df_periode["date_insertion_dt"].isna().all():
            st.caption("Pas assez de données datées sur cette période.")
        else:
            tmp = df_periode.dropna(subset=["date_insertion_dt"]).copy()
            tmp["jour"] = tmp["date_insertion_dt"].dt.date
            idx = pd.date_range(tmp["jour"].min(), tmp["jour"].max(), freq="D").date

            fig = go.Figure()
            
            colors = {"critique": "#ef4444", "eleve": "#f97316", "moyenne": "#fbbf24", "faible": "#10b981"}
            
            for sev in ["critique", "eleve", "moyenne", "faible"]:
                serie = tmp[tmp["severity"] == sev].groupby("jour").size().reindex(idx, fill_value=0)
                if serie.sum() > 0:
                    fig.add_trace(go.Scatter(
                        x=idx, y=serie.values, 
                        name=SEVERITY[sev]["label"],
                        mode="lines+markers", 
                        line=dict(color=colors[sev], width=2.5),
                        marker=dict(size=6, color=colors[sev], symbol="circle"),
                        fill="tozeroy", 
                        fillcolor=hex_to_rgba(colors[sev], 0.10),
                    ))

            fig.update_layout(
                height=280,
                margin=dict(l=0, r=0, t=10, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color=C["on_surface_variant"], size=11, family="Inter"),
                xaxis=dict(
                    showgrid=False, 
                    color=C["outline"],
                    tickformat="%b %d",
                    tickangle=0,
                ),
                yaxis=dict(
                    showgrid=True, 
                    gridcolor=C["outline_variant"], 
                    gridwidth=1, 
                    zeroline=False,
                    title="",
                ),
                legend=dict(
                    orientation="h", 
                    yanchor="bottom", 
                    y=1.02, 
                    xanchor="left", 
                    x=0,
                    bgcolor="rgba(0,0,0,0)",
                    font=dict(size=11),
                ),
                hovermode="x unified",
            )
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
            
        st.markdown('</div>', unsafe_allow_html=True)

    with col_pie:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Risk Distribution</div>', unsafe_allow_html=True)

        rep = df_periode["severity"].value_counts()
        labels_ordre = ["critique", "eleve", "moyenne", "faible"]
        valeurs = [int(rep.get(s, 0)) for s in labels_ordre]
        couleurs = [SEVERITY[s]["color"] for s in labels_ordre]
        labels_fr = [SEVERITY[s]["label"] for s in labels_ordre]
        
        total_sev = sum(valeurs)

        fig2 = go.Figure(data=[go.Pie(
            labels=labels_fr, 
            values=valeurs, 
            hole=0.60,
            marker=dict(
                colors=couleurs, 
                line=dict(color=C["surface"], width=3)
            ),
            textinfo="percent+label",
            textposition="auto",
            textfont=dict(color=C["on_surface"], size=10),
            showlegend=False,
            hoverinfo="label+percent+value",
            hovertemplate="%{label}<br>%{value} alertes (%{percent})<extra></extra>",
            automargin=True,
            sort=False,
        )])
        fig2.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            annotations=[
                dict(
                    text=f"<b style='font-size:22px;color:{C['on_surface']}'>{total_sev}</b><br>"
                         f"<span style='font-size:9px;color:{C['outline']}'>TOTAL</span>",
                    showarrow=False,
                    font=dict(size=14),
                )
            ],
        )
        st.plotly_chart(fig2, width="stretch", config={"displayModeBar": False})

        legend_html = '<div style="display:flex; justify-content:center; gap:16px; margin-top:4px; flex-wrap:wrap;">'
        for s, lbl in zip(labels_ordre, labels_fr):
            count = int(rep.get(s, 0))
            pct = round(count / total_sev * 100, 1) if total_sev > 0 else 0
            legend_html += (f'<div style="display:flex;align-items:center;gap:4px;color:{C["on_surface_variant"]};font-size:12px;">'
                             f'<span style="width:10px;height:10px;border-radius:50%;background:{SEVERITY[s]["color"]};"></span>'
                             f'{lbl} ({count}) - {pct}%</div>')
        legend_html += '</div>'
        st.markdown(legend_html, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Recent Detections section
    st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
    h1, h2 = st.columns([5, 1])
    h1.markdown(f"""
    <div style="padding:12px 20px; border-bottom:1px solid {C['outline_variant']};">
        <span style="font-size:14px; font-weight:700; color:{C['on_surface']};">Recent Detections</span>
        
    </div>
    """, unsafe_allow_html=True)
    with h2:
        if st.button("Voir tout →", key="voir_tout_detections_dash"):
            st.session_state.page = "alerts"
            st.rerun()

    recent = df.sort_values("date_insertion_dt", ascending=False).head(8)
    if recent.empty:
        st.markdown(f"<p style='color:{C['on_surface_variant']}; padding:20px;'>Aucune détection récente.</p>",
                     unsafe_allow_html=True)
    else:
        rows = ""
        for _, r in recent.iterrows():
            meta = sev_meta(r["severity"])
            date_str = r["date_tri"].strftime("%Y-%m-%d %H:%M") if pd.notna(r["date_tri"]) else "—"
            rows += f"""<tr>
                <td style="color:{C['outline']}; font-size:10px; white-space:nowrap;">{html.escape(date_str)}</td>
                <td><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:{meta['color']}; margin-right:4px;"></span><span style="font-size:11px;">{meta['label']}</span></td>
                <td style="font-size:11px;">{html.escape(str(r['type'] or ''))}</td>
                <td style="font-size:11px; color:{C['on_surface_variant']};">{html.escape(str(r['asset_concerne'] or '—'))}</td>
                <td style="font-size:10px; color:{C['on_surface_variant']};">{html.escape(str(r['source_api'] or ''))}</td>
            </tr>"""

        st.markdown(f"""
        <table class="aegis-table" style="font-size:11px;">
            <thead><tr>
                <th>Date/Heure</th><th>Sévérité</th><th>Type</th><th>Asset</th><th>Source</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

# ============================================================
# PAGE : ASSETS
# ============================================================
def page_assets():
    df = charger_donnees()
    assets_surveilles = charger_assets()

    # Si l'utilisateur est en train de taper dans la barre de recherche,
    # on force la fermeture du popup "Ajouter un asset" (il ne doit pas
    # réapparaître tout seul pendant une recherche).
    if st.session_state.get("assets_search"):
        st.session_state.show_add_asset_dialog = False
    
    st.markdown(f"""
    <style>
    .btn-add-asset {{
        background: linear-gradient(135deg, {C['accent']} 0%, #7c3aed 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 8px 16px !important;
        font-weight: 600 !important;
        font-size: 14px !important;
        width: 100% !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(56, 189, 248, 0.3) !important;
    }}
    .btn-add-asset:hover {{
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 25px rgba(56, 189, 248, 0.5) !important;
    }}
    .form-label-custom {{
        display: block;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: {C['on_surface_variant']};
        margin-bottom: 4px;
    }}
    .form-hint-custom {{
        font-size: 12px;
        color: {C['outline']};
        margin-top: 2px;
    }}
    .form-error-custom {{
        font-size: 12px;
        color: #ef4444;
        margin-top: 4px;
        padding: 4px 8px;
        background: rgba(239, 68, 68, 0.1);
        border-radius: 4px;
        border-left: 3px solid #ef4444;
    }}
    .form-success-custom {{
        font-size: 12px;
        color: #10b981;
        margin-top: 4px;
        padding: 4px 8px;
        background: rgba(16, 185, 129, 0.1);
        border-radius: 4px;
        border-left: 3px solid #10b981;
    }}
    .asset-count-custom {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 12px;
        background: {C['surface_highest']};
        border-radius: 20px;
        font-size: 12px;
        color: {C['on_surface_variant']};
    }}
    div[data-testid="stDialog"] > div {{
        max-width: 600px !important;
        width: 90% !important;
        margin: auto !important;
    }}
    </style>
    """, unsafe_allow_html=True)
    
    col_header, col_search, col_add = st.columns([2, 1.5, 0.8])
    
    with col_header:
        st.markdown(f"""
        <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
            Monitored Assets
        </h2>
        <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0;">
            Tous les assets surveillés par le pipeline CTI 
            <span style="color:{C['accent']}; font-weight:600;">({len(assets_surveilles)} actifs)</span>
        </p>
        """, unsafe_allow_html=True)
    
    with col_search:
        st.markdown('<div style="height:28px;"></div>', unsafe_allow_html=True)
        recherche = st.text_input(
            "Rechercher un asset", 
            placeholder="Rechercher un asset", 
            key="assets_search",
            label_visibility="collapsed",
        )
    
    with col_add:
        st.markdown('<div style="height:28px;"></div>', unsafe_allow_html=True)
        if st.button("Ajouter un asset", key="btn_open_add_asset_unique", use_container_width=True):
            st.session_state.show_add_asset_dialog = True
            st.rerun()
        
        if st.session_state.get("show_add_asset_dialog", False):
            @st.dialog("➕ Ajouter un nouvel asset", width="small")
            def add_asset_dialog():
                if "asset_error" not in st.session_state:
                    st.session_state.asset_error = ""
                if "asset_success" not in st.session_state:
                    st.session_state.asset_success = ""
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown('<span class="form-label-custom">Type d\'asset *</span>', unsafe_allow_html=True)
                    new_asset_type = st.selectbox(
                        "Type",
                        ["Domaine", "Adresse IP", "Email", "Mot-clé"],
                        key="new_asset_type_dialog"
                    )
                    
                    st.markdown('<span class="form-label-custom">Valeur de l\'asset *</span>', unsafe_allow_html=True)
                    new_asset_value = st.text_input(
                        "Valeur",
                        placeholder="ex: entreprise.tn, 192.168.1.1",
                        key="new_asset_value_dialog"
                    )
                
                with col2:
                    st.markdown('<span class="form-label-custom">Catégorie *</span>', unsafe_allow_html=True)
                    category_options = ["Critique", "Élevée", "Moyenne", "Faible"]
                    new_asset_category = st.selectbox(
                        "Catégorie",
                        category_options,
                        index=3,
                        key="new_asset_category_dialog"
                    )
                    
                    examples = {
                        "Domaine": "💡 ex: entreprise.tn, google.com",
                        "Adresse IP": "💡 ex: 192.168.1.1, 10.0.0.1",
                        "Email": "💡 ex: contact@entreprise.tn",
                        "Mot-clé": "💡 ex: ransomware, phishing"
                    }
                    st.markdown(f'<div class="form-hint-custom">{examples.get(new_asset_type, "")}</div>', unsafe_allow_html=True)
                
                if st.session_state.asset_error:
                    st.markdown(f'<div class="form-error-custom">⚠️ {st.session_state.asset_error}</div>', unsafe_allow_html=True)
                if st.session_state.asset_success:
                    st.markdown(f'<div class="form-success-custom">✅ {st.session_state.asset_success}</div>', unsafe_allow_html=True)
                
                current_assets_count = len(assets_surveilles)
                st.markdown(f"""
                <div style="display:flex; justify-content:flex-end; margin: 8px 0;">
                    <span class="asset-count-custom">📌 {current_assets_count} asset(s) déjà surveillé(s)</span>
                </div>
                """, unsafe_allow_html=True)
                
                col_actions1, col_actions2 = st.columns([1, 2])
                
                with col_actions1:
                    if st.button("Annuler", key="cancel_asset_dialog", use_container_width=True):
                        st.session_state.asset_error = ""
                        st.session_state.asset_success = ""
                        st.session_state.show_add_asset_dialog = False
                        st.rerun()
                
                with col_actions2:
                    if st.button("Ajouter l'asset", key="save_asset_dialog", use_container_width=True):
                        st.session_state.asset_error = ""
                        st.session_state.asset_success = ""
                        
                        if not new_asset_value.strip():
                            st.session_state.asset_error = "Veuillez saisir une valeur pour l'asset."
                            st.rerun()
                        else:
                            import re
                            value = new_asset_value.strip()
                            is_valid = True
                            error_msg = ""
                            
                            if new_asset_type == "Domaine":
                                domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
                                if not re.match(domain_pattern, value):
                                    is_valid = False
                                    error_msg = "Format de domaine invalide. Exemple: entreprise.tn"
                            
                            elif new_asset_type == "Adresse IP":
                                ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                                if not re.match(ip_pattern, value):
                                    is_valid = False
                                    error_msg = "Format d'adresse IP invalide. Exemple: 192.168.1.1"
                                else:
                                    octets = value.split('.')
                                    for octet in octets:
                                        if not (0 <= int(octet) <= 255):
                                            is_valid = False
                                            error_msg = "Octet d'adresse IP invalide (doit être entre 0 et 255)"
                                            break
                            
                            elif new_asset_type == "Email":
                                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                                if not re.match(email_pattern, value):
                                    is_valid = False
                                    error_msg = "Format d'email invalide. Exemple: contact@entreprise.tn"
                            
                            else:
                                if len(value) < 2:
                                    is_valid = False
                                    error_msg = "Le mot-clé doit contenir au moins 2 caractères"
                                elif re.search(r'[<>"\'/]', value):
                                    is_valid = False
                                    error_msg = "Le mot-clé contient des caractères invalides"
                            
                            if not is_valid:
                                st.session_state.asset_error = error_msg
                                st.rerun()
                            else:
                                exists = any(
                                    a["identifier"].lower() == value.lower() 
                                    for a in assets_surveilles
                                )
                                
                                if exists:
                                    st.session_state.asset_error = f"L'asset '{value}' existe déjà."
                                    st.rerun()
                                else:
                                    type_map = {
                                        "Domaine": "Domaine",
                                        "Adresse IP": "Adresse IP",
                                        "Email": "Email",
                                        "Mot-clé": "Mot-clé"
                                    }
                                    mapped_type = type_map.get(new_asset_type, "Mot-clé")
                                    
                                    if ajouter_asset_avec_sync(value, mapped_type):
                                        st.session_state.asset_success = f"Asset '{value}' ajouté avec succès !"
                                        time.sleep(0.5)
                                        st.session_state.show_add_asset_dialog = False
                                        st.rerun()
                                    else:
                                        st.session_state.asset_error = f"Erreur lors de l'ajout de l'asset."
                                        st.rerun()
            
            add_asset_dialog()
    
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    if df.empty and not assets_surveilles:
        st.info("No alerts in database and no assets monitored. Use the button above to add assets to monitor.")
        return

    agg_rows = []
    
    if not df.empty:
        for asset, groupe in df.groupby("asset_recherche"):
            pire_sev = max(
                groupe["severity"].dropna(), 
                key=lambda s: SEVERITY_RANK.get(s, 0), 
                default="faible"
            )
            derniere = groupe["date_insertion_dt"].max()
            agg_rows.append({
                "asset": asset,
                "type": classify_asset_type(asset),
                "findings": len(groupe),
                "severity": pire_sev,
                "derniere": derniere,
                "description": "",
                "is_monitored": any(a["identifier"] == asset for a in assets_surveilles)
            })
    
    for asset_surveille in assets_surveilles:
        if not any(row["asset"] == asset_surveille["identifier"] for row in agg_rows):
            agg_rows.append({
                "asset": asset_surveille["identifier"],
                "type": asset_surveille.get("type", classify_asset_type(asset_surveille["identifier"])),
                "findings": 0,
                "severity": "faible",
                "derniere": None,
                "description": asset_surveille.get("description", ""),
                "is_monitored": True
            })
    
    if not agg_rows:
        st.info("No assets to display. Use the button above to add assets to monitor.")
        return
    
    assets_df = pd.DataFrame(agg_rows)
    
    if recherche:
        assets_df = assets_df[assets_df["asset"].str.contains(recherche, case=False, na=False)]
    assets_df = assets_df.sort_values("findings", ascending=False)

    total_assets = len(assets_df)
    critique_assets = int((assets_df["severity"] == "critique").sum())
    elevee_assets = int((assets_df["severity"] == "eleve").sum())
    moyenne_assets = int((assets_df["severity"] == "moyenne").sum())
    faible_assets = int((assets_df["severity"] == "faible").sum())
    monitored_count = len([a for a in assets_surveilles if any(row["asset"] == a["identifier"] for row in agg_rows)])

    stats = [
        ("Total Assets", str(total_assets), "hub", C["accent"]),
        ("Monitored", str(monitored_count), "check_circle", "#10b981"),
        ("Critique", str(critique_assets), "warning", "#ef4444"),
        ("Élevée", str(elevee_assets), "trending_up", "#f59e0b"),
        ("Moyenne", str(moyenne_assets), "remove", "#fbbf24"),
        ("Faible", str(faible_assets), "info", "#10b981"),
    ]
    cols = st.columns(6)
    for col, (label, value, icon, color) in zip(cols, stats):
        with col:
            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <span class="stat-label">{html.escape(label)}</span>
                    <span class="material-symbols-outlined" style="font-size:16px; color:{color};">{icon}</span>
                </div>
                <div class="stat-value" style="color:{color if label in ['Critique', 'Élevée'] else C['on_surface']};">{html.escape(value)}</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    
    st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)

    page_df, page, total_pages, debut, fin, total = paginer(assets_df, "assets_page", taille_page=10)

    st.markdown(f"""
    <div class="data-toolbar" style="display:flex; justify-content:space-between; align-items:center; padding:12px 16px; border-bottom:1px solid {C['outline_variant']};">
        <span style="font-size:13px; font-weight:700; color:{C['on_surface']};">Assets List ({len(assets_df)})</span>
        <span class="pagination-info">Showing {debut}-{fin} of {total}</span>
    </div>
    """, unsafe_allow_html=True)

    if page_df.empty:
        st.markdown(f"<p style='color:{C['on_surface_variant']}; padding:20px;'>No assets match your search.</p>",
                     unsafe_allow_html=True)
    else:
        headers = ["Asset", "Type", "Status", "Last Detection", "Findings", "Risk", "Action"]
        header_cols = st.columns([2.2, 1.1, 0.9, 1.1, 0.7, 0.9, 0.6])
        
        for col, header in zip(header_cols, headers):
            col.markdown(f"<span class='stat-label'>{header}</span>", unsafe_allow_html=True)
        
        st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 0 8px 0;'>", unsafe_allow_html=True)
        
        for idx, r in page_df.iterrows():
            meta = sev_meta(r["severity"])
            derniere_str = temps_relatif(r["derniere"]) if pd.notna(r["derniere"]) else "Never"
            icon = ASSET_TYPE_ICON.get(r["type"], "sell")
            findings_style = f"font-weight:700; color:{meta['color']};" if r["findings"] > 0 else ""
            
            is_monitored = r.get("is_monitored", False)
            status_color = "#10b981" if is_monitored else "#64748b"
            status_text = "Active" if is_monitored else "Inactive"
            
            row_cols = st.columns([2.2, 1.1, 0.9, 1.1, 0.7, 0.9, 0.6])
            
            row_cols[0].markdown(f"""
            <div style="display:flex; align-items:center; gap:8px;">
                <span class="asset-dot" style="background:{meta['color']}; display:inline-block; width:10px; height:10px; border-radius:50%;"></span>
                <span style="font-weight:600; color:{C['on_surface']};">{html.escape(str(r['asset']))}</span>
            </div>
            """, unsafe_allow_html=True)
            
            row_cols[1].markdown(f"""<span style="color:{C['on_surface_variant']};">
    {html.escape(r['type'])}</span>""", unsafe_allow_html=True)
            
            row_cols[2].markdown(badge_pill(status_text, status_color, f'rgba({int(status_color[1:3],16)},{int(status_color[3:5],16)},{int(status_color[5:7],16)},0.14)'), unsafe_allow_html=True)
            
            row_cols[3].markdown(f"<span style='color:{C['on_surface_variant']};'>{html.escape(derniere_str)}</span>", unsafe_allow_html=True)
            
            row_cols[4].markdown(f"<span style='text-align:center; {findings_style}'>{r['findings']}</span>", unsafe_allow_html=True)
            
            row_cols[5].markdown(badge_pill(meta['label'].upper(), meta['color'], meta['bg']), unsafe_allow_html=True)
            
            if is_monitored:
                delete_key = f"delete_asset_{r['asset']}_{idx}"
                with row_cols[6]:
                    with st.popover("🗑️", use_container_width=True):
                        st.markdown(f"""
                        <div style="text-align:center; padding: 4px 0;">
                            <p style="font-size: 14px; font-weight: 600; margin-bottom: 4px; color:{C['on_surface']};">
                                Supprimer <span style="color: {C['accent']};">{html.escape(str(r['asset']))}</span> ?
                            </p>
                            <p style="font-size: 12px; color: {C['outline']}; margin-bottom: 12px;">
                                ⚠️ Action irréversible
                            </p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.button("Annuler", key=f"cancel_{delete_key}", use_container_width=True)
                        
                        with col2:
                            if st.button("Supprimer", key=f"confirm_{delete_key}", use_container_width=True, type="primary"):
                                if supprimer_asset_avec_sync(r['asset']):
                                    st.success(f"✅ Asset '{r['asset']}' supprimé !")
                                    time.sleep(0.5)
                                    st.rerun()
                                else:
                                    st.error("❌ Erreur lors de la suppression.")
            else:
                row_cols[6].markdown("—")

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
        recherche = st.text_input("Rechercher", placeholder="ID, asset, source...", key="alerts_search")
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    if df.empty:
        st.info("Aucune alerte en base. Lance le pipeline de collecte (main.py) pour peupler ce flux.")
        return

    # ===== FILTRES =====
    f1, f2, f3, f4 = st.columns(4)

    with f1:
        niveaux_options = ["Tous", "Critique", "Élevée", "Moyenne", "Faible"]
        niveaux_label = st.selectbox("Niveau de risque", niveaux_options, key="alerts_f_sev")
        severity_map = {
            "Tous": None,
            "Critique": "critique",
            "Élevée": "eleve",
            "Moyenne": "moyenne",
            "Faible": "faible"
        }
        niveaux = severity_map[niveaux_label]

    with f2:
        types_dispo = sorted(df["type"].dropna().unique().tolist())
        types_sel = st.selectbox("Type de détection", ["Tous"] + types_dispo, key="alerts_f_type")

    with f3:
        periode = st.selectbox("Période", ["Tout", "Dernières 24h", "7 derniers jours", "30 derniers jours"],
                                key="alerts_f_periode")

    with f4:
        source_labels = ["Toutes"] + [s["label"] for s in SOURCES_DETECTION]
        sources_sel_label = st.selectbox("Source", source_labels, key="alerts_f_source")
        source_map = {s["label"]: s["id"] for s in SOURCES_DETECTION}
        source_filter_value = source_map.get(sources_sel_label)

    # ===== APPLICATION DES FILTRES =====
    filtre = df.copy()

    if niveaux is not None:
        filtre = filtre[filtre["severity"] == niveaux]

    if types_sel != "Tous":
        filtre = filtre[filtre["type"] == types_sel]

    if sources_sel_label != "Toutes" and source_filter_value:
        filtre = filtre[filtre["source_api"] == source_filter_value]

    if periode != "Tout":
        heures = {"Dernières 24h": 24, "7 derniers jours": 24 * 7, "30 derniers jours": 24 * 30}[periode]
        filtre = filtre[filtre["date_insertion_dt"] >= datetime.now() - timedelta(hours=heures)]

    if recherche:
        masque = (filtre["id"].astype(str).str.contains(recherche, case=False, na=False) |
                  filtre["asset_concerne"].astype(str).str.contains(recherche, case=False, na=False) |
                  filtre["source_api"].astype(str).str.contains(recherche, case=False, na=False))
        filtre = filtre[masque]

    # ===== TRI PAR DATE DE PREMIÈRE DÉTECTION =====
    def to_naive_datetime(col):
        dt = pd.to_datetime(col, errors="coerce", utc=True)
        if hasattr(dt, 'dt') and dt.dt.tz is not None:
            dt = dt.dt.tz_localize(None)
        return dt

    if "date_detection" in filtre.columns:
        filtre["date_detection_dt"] = to_naive_datetime(filtre["date_detection"])
    else:
        filtre["date_detection_dt"] = pd.NaT

    filtre = filtre.sort_values("date_detection_dt", ascending=False, na_position="last")

    # ===== EXPORT =====
    st.write("")
    export_df = filtre.drop(columns=["date_detection_dt"], errors="ignore")
    st.download_button("⬇ Export CSV", data=export_df.to_csv(index=False),
                        file_name="alertes_export.csv", mime="text/csv")

    # ===== TABLEAU DES ALERTES =====
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
        headers = ["Alert ID", "Risque", "Type", "Asset concerné", "Source", "Détection", ""]
        for c, h in zip(header_cols, headers):
            c.markdown(f"<span class='stat-label'>{h}</span>", unsafe_allow_html=True)
        st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 0 4px 0;'>", unsafe_allow_html=True)

        for _, r in page_df.iterrows():
            meta = sev_meta(r["severity"])
            t_meta = type_meta(r["type"])

            if pd.notna(r.get("date_detection_dt")):
                date_str = r["date_detection_dt"].strftime("%Y-%m-%d %H:%M")
            elif pd.notna(r.get("date_insertion_dt")):
                date_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M")
            else:
                date_str = "—"

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

# [The rest of the functions remain the same - page_alert_detail, page_ransomware_intel, page_search, page_settings, etc.]

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

    infos_specifiques = extraire_infos_specifiques_alerte(r["type"], r["details"])

    date_detection = str(r["date_detection"]) if r["date_detection"] else "Non disponible"
    date_insertion = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notna(r["date_insertion_dt"]) else "Non disponible"
    asset = str(r["asset_concerne"] or "Non spécifié")
    asset_type = classify_asset_type(asset)

    details_text = str(r["details"] or "Aucun détail disponible.")

    # ID stable
    aid = int(r["id"])

    # --- Statut : initialisé AVANT l'en-tête ---
    status_key = f"status_alert_{aid}"
    if status_key not in st.session_state:
        st.session_state[status_key] = "Nouveau"
    current_status = st.session_state[status_key]
    status_meta = STATUS_META[current_status]

    if r["type"] in ["ransomware_leak", "ransomware_leak_tn", "ransomware_leak_pays"]:
        groupe = infos_specifiques.get("groupe", "Non spécifié")
        entreprise = infos_specifiques.get("entreprise", "Non spécifiée")
        description_groupe = f"Groupe {groupe} · Entreprise {entreprise}"
    elif r["type"] == "infostealer_compromise":
        total = infos_specifiques.get("total", "0")
        description_groupe = f"{total} comptes compromis"
    elif r["type"] == "infostealer_email_check":
        ordinateur = infos_specifiques.get("ordinateur", "Inconnu")
        description_groupe = f"Email {asset} · Appareil: {ordinateur}"
    elif r["type"] == "credential_leak":
        description_groupe = f"Identifiants de {asset} exposés"
    elif r["type"] == "domain_mention":
        description_groupe = f"Domaine {asset} mentionné"
    elif r["type"] == "apt_mention":
        description_groupe = f"Rapport APT mentionnant {asset}"
    elif r["type"] == "deepdarkcti_status":
        description_groupe = "Statut des sites de fuite ransomware"
    elif r["type"] == "ransomware_global_feed":
        description_groupe = f"Victime: {asset}"
    else:
        description_groupe = t_meta['label']

    severity_colors = {
        "critique": {"bg": "rgba(239,68,68,0.12)", "color": "#ef4444"},
        "eleve": {"bg": "rgba(245,165,36,0.12)", "color": "#f5a524"},
        "moyenne": {"bg": "rgba(251,191,36,0.12)", "color": "#fbbf24"},
        "faible": {"bg": "rgba(34,197,94,0.12)", "color": "#22c55e"},
    }
    sev_color = severity_colors.get(r["severity"], {"bg": "rgba(107,117,144,0.12)", "color": "#6b7590"})

    # === BOUTON RETOUR ===
    col_back, _ = st.columns([1, 4])
    with col_back:
        if st.button("← Retour aux alertes", key="back_to_alerts"):
            st.session_state["alert_detail_id"] = None
            st.rerun()

    # === EN-TÊTE ===
    st.markdown(f"""
    <div style="display:flex; align-items:center; gap:12px; margin-top:16px; flex-wrap:wrap;">
        <span style="background:{sev_color['bg']}; color:{sev_color['color']}; font-size:11px; font-weight:700; letter-spacing:0.06em; padding:5px 10px; border-radius:5px; text-transform:uppercase;">
            {meta['label'].upper()}
        </span>
        <span style="background:{status_meta['bg']}; color:{status_meta['color']}; font-size:11px; font-weight:700; letter-spacing:0.06em; padding:5px 10px; border-radius:5px; text-transform:uppercase;">
            {status_meta['dot']} {current_status}
        </span>
        <span style="color:#6b7590; font-family:monospace; font-size:13px;">ALRT-{int(r['id']):04d}</span>
        <span style="color:#6b7590; font-family:monospace; font-size:12px; background:#161d30; padding:3px 10px; border-radius:4px;">
            {html.escape(str(r['source_api'] or 'Inconnu'))}
        </span>
    </div>
    <h1 style="font-size:30px; font-weight:700; color:#eef1f8; margin:12px 0 4px 0; letter-spacing:-0.01em;">
        {html.escape(t_meta['label'])}
    </h1>
    <div style="color:#9aa4bd; font-size:14px; margin-bottom:24px;">
        {html.escape(description_groupe)}
    </div>
    """, unsafe_allow_html=True)

    # === RÉSUMÉ ===
    st.markdown(f"""
    <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:24px;">
        <div style="font-size:14px; line-height:1.6; color:#9aa4bd;">
            {html.escape(details_text)}
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:12px;">
            <span style="background:#161d30; border:1px solid #1c2436; color:#9aa4bd; font-size:11px; padding:4px 10px; border-radius:4px;">{html.escape(r['type'])}</span>
            <span style="background:#161d30; border:1px solid #1c2436; color:#9aa4bd; font-size:11px; padding:4px 10px; border-radius:4px;">{html.escape(str(r['source_api'] or ''))}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # === GRILLE 2 COLONNES ===
    col1, col2 = st.columns(2)

    with col1:
        # --- VICTIME ---
        st.markdown(f"""
        <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
            <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
                Victime
            </div>
            <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                <span style="color:#9aa4bd;">Asset</span>
                <span style="font-family:monospace; color:#eef1f8;">{html.escape(asset)}</span>
            </div>
            <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                <span style="color:#9aa4bd;">Type</span>
                <span style="font-family:monospace; color:#eef1f8;">{html.escape(asset_type)}</span>
            </div>
            <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                <span style="color:#9aa4bd;">Secteur</span>
                <span style="font-family:monospace; color:#eef1f8;">{html.escape(str(r['sector'] or 'Non disponible'))}</span>
            </div>
            <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                <span style="color:#9aa4bd;">Pays</span>
                <span style="font-family:monospace; color:#eef1f8;">{html.escape(str(r['country'] or 'Non disponible'))}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # --- CHRONOLOGIE ---
        st.markdown(f"""
        <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
            <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 14px 0; font-weight:700;">
                Chronologie
            </div>
            <div style="display:flex; flex-direction:column; gap:4px;">
                <div style="display:flex; align-items:baseline; gap:12px; padding:6px 0; border-bottom:1px solid #1c2436;">
                    <span style="font-family:monospace; font-size:12px; color:#6b7590;">{html.escape(date_detection)}</span>
                    <span style="font-size:13px; color:#eef1f8;">Première détection</span>
                    <span style="margin-left:auto; font-size:11px; color:#22c55e;">✓</span>
                </div>
                <div style="display:flex; align-items:baseline; gap:12px; padding:6px 0;">
                    <span style="font-family:monospace; font-size:12px; color:#6b7590;">{html.escape(date_insertion)}</span>
                    <span style="font-size:13px; color:#eef1f8;">Ajout à la base</span>
                    <span style="margin-left:auto; font-size:11px; color:#22c55e;">✓</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        # --- INFORMATIONS SPÉCIFIQUES ---
        if r["type"] == "infostealer_compromise":
            total = infos_specifiques.get("total", "0")
            employes = infos_specifiques.get("employes", "0")
            utilisateurs = infos_specifiques.get("utilisateurs", "0")
            st.markdown(f"""
            <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
                    Compromission
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Comptes compromis</span>
                    <span style="font-family:monospace; color:#ef4444; font-weight:700;">{total}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Employés</span>
                    <span style="font-family:monospace; color:#eef1f8;">{employes}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Utilisateurs</span>
                    <span style="font-family:monospace; color:#eef1f8;">{utilisateurs}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        elif r["type"] == "infostealer_email_check":
            ordinateur = infos_specifiques.get("ordinateur", "Inconnu")
            corporate = infos_specifiques.get("services_corporate", "0")
            perso = infos_specifiques.get("services_perso", "0")
            infecte_depuis = infos_specifiques.get("infecte_depuis", "Non disponible")
            st.markdown(f"""
            <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
                    Détails email
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Appareil</span>
                    <span style="font-family:monospace; color:#eef1f8;">{html.escape(ordinateur)}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Services corporate</span>
                    <span style="font-family:monospace; color:#eef1f8;">{corporate}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Services perso</span>
                    <span style="font-family:monospace; color:#eef1f8;">{perso}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Infecté depuis</span>
                    <span style="font-family:monospace; color:#eef1f8;">{html.escape(infecte_depuis)}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        elif r["type"] in ["ransomware_leak", "ransomware_leak_tn", "ransomware_leak_pays"]:
            groupe = infos_specifiques.get("groupe", "Non spécifié")
            entreprise = infos_specifiques.get("entreprise", "Non spécifiée")
            st.markdown(f"""
            <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
                    Groupe ransomware
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Groupe</span>
                    <span style="font-family:monospace; color:#eef1f8;">{html.escape(groupe)}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Entreprise</span>
                    <span style="font-family:monospace; color:#eef1f8;">{html.escape(entreprise)}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        elif r["type"] == "apt_mention":
            st.markdown(f"""
            <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
                    Rapport APT
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Asset mentionné</span>
                    <span style="font-family:monospace; color:#eef1f8;">{html.escape(asset)}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        elif r["type"] == "deepdarkcti_status":
            st.markdown(f"""
            <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
                <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
                    Statut deepdarkCTI
                </div>
                <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                    <span style="color:#9aa4bd;">Détails</span>
                    <span style="font-family:monospace; color:#eef1f8; font-size:12px;">{html.escape(details_text)}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # --- SOURCE ---
        source_api = str(r['source_api'] or 'Non disponible')
        source_url = get_source_url(source_api)

        if source_url != "#" and source_api != "Non disponible":
            source_link = f'<a href="{source_url}" target="_blank" style="color:#5b8def; text-decoration:none; font-family:monospace; font-weight:600; transition:color 0.2s;">{html.escape(source_api)} ↗</a>'
        else:
            source_link = f'<span style="font-family:monospace; color:#eef1f8;">{html.escape(source_api)}</span>'

        st.markdown(f"""
        <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:20px;">
            <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
                Source
            </div>
            <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                <span style="color:#9aa4bd;">Source</span>
                {source_link}
            </div>
            <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                <span style="color:#9aa4bd;">Terme surveillé</span>
                <span style="font-family:monospace; color:#eef1f8;">{html.escape(str(r['asset_recherche'] or 'Non spécifié'))}</span>
            </div>
            <div style="display:flex; justify-content:space-between; padding:8px 0; border-top:1px solid #1c2436; font-size:14px;">
                <span style="color:#9aa4bd;">Élément</span>
                <span style="font-family:monospace; color:#5b8def; text-align:right; word-break:break-all;">{html.escape(asset)}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ============================================================
    # === ACTIONS ===
    # ============================================================
    st.markdown(f"""
    <style>
    .st-key-actions_panel_{aid} {{
        background:#0f1524;
        border:1px solid #1c2436;
        border-radius:10px;
        padding:20px 24px;
        margin-bottom:24px;
    }}
    </style>
    """, unsafe_allow_html=True)

    with st.container(key=f"actions_panel_{aid}"):
        st.markdown("""
        <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 14px 0; font-weight:700;">
            Actions
        </div>
        """, unsafe_allow_html=True)

        col_status, col_export = st.columns([2, 1])
        with col_status:
            current_status = st.session_state.get(status_key, "Nouveau")
            status_options = list(STATUS_META.keys())
            try:
                default_index = status_options.index(current_status)
            except ValueError:
                default_index = 0

            new_status = st.selectbox(
                "Statut",
                options=status_options,
                format_func=lambda s: f"{STATUS_META[s]['dot']} {s}",
                index=default_index,
                key=f"select_status_{aid}",
                label_visibility="collapsed",
            )
            if new_status != current_status:
                st.session_state[status_key] = new_status
                st.rerun()

        with col_export:
            csv_data = ligne.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇ Exporter (CSV)",
                data=csv_data,
                file_name=f"alerte_{aid:04d}.csv",
                mime="text/csv",
                key=f"export_{aid}",
                use_container_width=True,
            )

        st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)

        # Checklist
        checklist_store_key = f"checklist_{aid}"
        if checklist_store_key not in st.session_state:
            st.session_state[checklist_store_key] = {item: False for item in CHECKLIST_ITEMS}

        done_count = 0
        for item in CHECKLIST_ITEMS:
            cb_key = f"check_{aid}_{item}"
            checked = st.checkbox(
                item,
                value=st.session_state[checklist_store_key][item],
                key=cb_key,
            )
            st.session_state[checklist_store_key][item] = checked
            if checked:
                done_count += 1

        st.progress(done_count / len(CHECKLIST_ITEMS))
        st.caption(f"{done_count}/{len(CHECKLIST_ITEMS)} actions complétées")

        if st.button("💾 Enregistrer", key=f"save_checklist_{aid}"):
            st.toast("Actions enregistrées", icon="✅")

    # ============================================================
    # === NOTES (corrigé) ===
    # ============================================================
    notes_list_key = f"notes_list_{aid}"
    if notes_list_key not in st.session_state:
        st.session_state[notes_list_key] = []

    st.markdown(f"""
    <div style="background:#0f1524; border:1px solid #1c2436; border-radius:10px; padding:20px 24px; margin-bottom:24px;">
        <div style="font-size:12px; text-transform:uppercase; letter-spacing:0.08em; color:#9aa4bd; margin:0 0 12px 0; font-weight:700;">
            Notes
        </div>
    """, unsafe_allow_html=True)

    if not st.session_state[notes_list_key]:
        st.markdown('<div style="font-size:13px; color:#5c6480; font-style:italic; padding:4px 0 12px 0;">Aucune note pour le moment.</div>', unsafe_allow_html=True)
    else:
        for note in st.session_state[notes_list_key]:
            st.markdown(f"""
            <div style="padding:10px 0; border-bottom:1px solid #1c2436;">
                <div style="font-family:monospace; font-size:11px; color:#5c6480; margin-bottom:3px;">{note['time']}</div>
                <div style="font-size:13px; color:#9aa4bd; line-height:1.5;">{html.escape(note['text'])}</div>
            </div>
            """, unsafe_allow_html=True)

    # CORRECTION : label non vide
    new_note = st.text_area(
        "Nouvelle note",
        key=f"new_note_input_{aid}",
        placeholder="Ajouter une note d'investigation...",
        height=60,
        label_visibility="collapsed",
    )

    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 3])
    with col_btn1:
        if st.button("Ajouter la note", key=f"add_note_{aid}"):
            if new_note.strip():
                st.session_state[notes_list_key].append({
                    "text": new_note.strip(),
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
                })
                st.rerun()
            else:
                st.toast("Écris une note avant d'enregistrer.", icon="⚠️")

    st.markdown('</div>', unsafe_allow_html=True)
# ============================================================
# PAGE : RANSOMWARE INTELLIGENCE (TRI PAR DATE)
# ============================================================
_RE_GROUPE = _re.compile(r"Groupe ransomware:\s*([^,]+)")

def extraire_groupe_ransomware(details: str) -> str:
    if not details:
        return "Inconnu"
    m = _RE_GROUPE.search(details)
    return m.group(1).strip() if m else "Inconnu"

def page_ransomware_intel():
    df = charger_donnees()

    h1, h2 = st.columns([3, 1])
    with h1:
        st.markdown(f"""
        <h2 style="font-size:28px; font-weight:700; color:{C['on_surface']}; margin:0 0 4px 0;">
            Ransomware Intelligence
        </h2>
        <p style="color:{C['on_surface_variant']}; font-size:13.5px; margin:0; display:flex; align-items:center; gap:6px;">
            <span class="live-dot" style="background:#ef4444;"></span>
            Suivi en temps réel des sites de fuite et des cibles tunisiennes (propulsé par Ransomware.live)
        </p>
        """, unsafe_allow_html=True)
    with h2:
        pass

    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:16px 0 20px 0;'>", unsafe_allow_html=True)

    ransomware_types = ["ransomware_leak", "ransomware_leak_tn", "ransomware_leak_pays", "ransomware_global_feed"]
    df_rw = df[df["type"].isin(ransomware_types)].copy() if not df.empty else df
    df_global = df_rw[df_rw["type"] == "ransomware_global_feed"].copy()
    df_tn = df_rw[df_rw["type"] == "ransomware_leak_tn"].copy()

    if df_rw.empty:
        st.info("Aucune donnée ransomware en base. Active RansomwareLive et/ou Tunisia Watch dans Settings.")
        return

    df_rw["groupe"] = df_rw["details"].apply(extraire_groupe_ransomware)
    if not df_tn.empty:
        df_tn["groupe"] = df_tn["details"].apply(extraire_groupe_ransomware)

    ddcti = df[df["type"] == "deepdarkcti_status"] if not df.empty else pd.DataFrame()
    if not ddcti.empty:
        derniere_ligne = ddcti.sort_values("date_insertion_dt", ascending=False).iloc[0]
        m_ddcti = _re.search(r"(\d+)\s+groupes ransomware marqués ONLINE sur (\d+)", derniere_ligne["details"] or "")
        sites_actifs = m_ddcti.group(1) if m_ddcti else str(df_rw["groupe"].nunique())
        sites_sub = f"Sur {m_ddcti.group(2)} suivis" if m_ddcti else "Groupes ransomware distincts observés"
    else:
        sites_actifs = str(df_rw["groupe"].nunique())
        sites_sub = "Groupes ransomware distincts observés"

    seuil_24h = datetime.now() - timedelta(hours=24)
    victimes_24h = int((df_rw["date_insertion_dt"] >= seuil_24h).sum())
    total_tn = len(df_tn)
    groupe_actif_tn = df_tn["groupe"].mode().iloc[0] if not df_tn.empty and not df_tn["groupe"].mode().empty else "—"

    stat_cols = st.columns(4)
    stats = [
        ("ACTIVE LEAK SITES", str(sites_actifs), "public", C["accent"], sites_sub),
        ("VICTIMES (24H)", str(victimes_24h), "warning", "#ef4444", "Toutes sources confondues"),
        ("CIBLES TUNISIENNES", str(total_tn), "location_on", "#f59e0b", f"{total_tn} cibles tunisiennes identifiées"),
        ("GROUPE LE + ACTIF (TN)", groupe_actif_tn, "group", C["on_surface"], "Sur les cibles tunisiennes connues"),
    ]
    for col, (label, value, icon, color, sub) in zip(stat_cols, stats):
        with col:
            st.markdown(f"""
            <div class="glass-card">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <span class="stat-label">{html.escape(label)}</span>
                    <span class="material-symbols-outlined" style="font-size:18px; color:{color};">{icon}</span>
                </div>
                <div class="stat-value" style="font-size:22px; color:{color if label!='GROUPE LE + ACTIF (TN)' else C['on_surface']};">{html.escape(str(value))}</div>
                <div class="stat-sub">{html.escape(sub)}</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    col_feed, col_tn = st.columns([8, 4])

    with col_feed:
        st.markdown('<div class="glass-card" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
        h1c, h2c = st.columns([5, 1.5])
        h1c.markdown(f"""
        <div style="padding:14px 16px 0 16px; display:flex; align-items:center; gap:8px;">
            <span class="material-symbols-outlined" style="font-size:18px; color:{C['accent']};">stream</span>
            <span style="font-size:15px; font-weight:700; color:{C['on_surface']};">Global Ransomware Feed</span>
        </div>
        """, unsafe_allow_html=True)
        with h2c:
            source_export = df_global if not df_global.empty else df_rw
            st.download_button("EXPORT", data=source_export.drop(columns=["date_insertion_dt"]).to_csv(index=False),
                                file_name="ransomware_feed.csv", mime="text/csv", key="rw_export")

        # ===== TRI PAR DATE DE PREMIÈRE DÉTECTION (même logique que la page Alerts) =====
        def _to_naive_datetime(col):
            dt = pd.to_datetime(col, errors="coerce", utc=True)
            if hasattr(dt, 'dt') and dt.dt.tz is not None:
                dt = dt.dt.tz_localize(None)
            return dt

        feed = (df_global if not df_global.empty else df_rw).copy()
        if "date_detection" in feed.columns:
            feed["date_detection_dt_tri"] = _to_naive_datetime(feed["date_detection"])
        else:
            feed["date_detection_dt_tri"] = pd.NaT
        # Comme pour les Alerts : tri décroissant par date de première détection,
        # les alertes sans cette date sont reléguées en fin de liste.
        feed = feed.sort_values("date_detection_dt_tri", ascending=False, na_position="last")

        page_df, page, total_pages, debut, fin, total = paginer(feed, "ransomware_feed_page", taille_page=10)
        st.markdown(f"""
        <div class="data-toolbar" style="margin-top:10px;">
            <span class="pagination-info">Affichage {debut}-{fin} sur {total}</span>
        </div>
        """, unsafe_allow_html=True)

        if page_df.empty:
            st.markdown(f"<p style='color:{C['on_surface_variant']}; padding:20px;'>Aucune victime dans le flux.</p>",
                         unsafe_allow_html=True)
        else:
            rows = ""
            for _, r in page_df.iterrows():
                date_str = r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M") if pd.notna(r["date_insertion_dt"]) else "—"
                drapeau = country_to_flag(r["country"]) if r["country"] else "🏳️"
                groupe = extraire_groupe_ransomware(r["details"])
                victime = str(r["asset_concerne"] or "—")
                is_tn = r["type"] == "ransomware_leak_tn"
                row_style = f"background:{hex_to_rgba('#f59e0b', 0.08)};" if is_tn else ""
                nom_style = f"color:#ef4444; font-weight:700;" if is_tn else f"color:{C['on_surface']};"
                lien = ""
                if victime and "." in victime and " " not in victime:
                    cible = victime if victime.startswith("http") else f"https://{victime}"
                    lien = (f"<a href='{html.escape(cible)}' target='_blank' style='color:{C['accent']};'>"
                            f"<span class='material-symbols-outlined' style='font-size:15px; vertical-align:middle;'>open_in_new</span></a>")
                rows += f"""<tr style="{row_style}">
                    <td style="color:{C['outline']}">{html.escape(date_str)}</td>
                    <td style="{nom_style}">{html.escape(groupe)}</td>
                    <td style="{nom_style}">{html.escape(victime)}</td>
                    <td style="text-align:center; font-size:15px;">{drapeau}</td>
                    <td style="text-align:right;">{lien}</td>
                </tr>"""

            st.markdown(f"""
            <table class="aegis-table">
                <thead><tr>
                    <th>Date ajoutée</th><th>Groupe</th><th>Victime</th>
                    <th style="text-align:center;">Pays</th><th style="text-align:right;">Lien</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        st.write("")
        controles_pagination("ransomware_feed_page", page, total_pages, "ransomware_feed")

    with col_tn:
        # ============================================================
        # COLONNE DE DROITE - FOCUS TUNISIE
        # ============================================================
        st.markdown(f"""
        <div class="glass-card" style="border:1px solid rgba(245,158,11,0.3);">
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:14px;">
                <span class="material-symbols-outlined" style="font-size:18px; color:#f59e0b;">crisis_alert</span>
                <span style="font-size:15px; font-weight:700; color:#f59e0b;">Focus Tunisie</span>
                <span style="margin-left:auto; font-size:11px; background:rgba(245,158,11,0.15); padding:2px 8px; border-radius:4px; color:#f59e0b;">{total_tn} cibles</span>
            </div>
        """, unsafe_allow_html=True)

        if df_tn.empty:
            st.caption("Aucune cible tunisienne connue pour le moment.")
        else:
            # ===== RÉPARTITION PAR SECTEUR =====
            st.markdown(f"<p class='stat-label' style='border-bottom:1px solid {C['outline_variant']}; padding-bottom:6px; margin-top:4px;'>RÉPARTITION PAR SECTEUR</p>",
                         unsafe_allow_html=True)
            rep_secteur = df_tn["sector"].fillna("Non renseigné").value_counts().head(5)
            total_secteur = rep_secteur.sum()
            couleurs_secteur = ["#ef4444", "#f59e0b", C["accent"], "#10b981", C["outline"]]
            
            if total_secteur > 0:
                for (secteur, count), coul in zip(rep_secteur.items(), couleurs_secteur):
                    pct = round(count / total_secteur * 100, 1) if total_secteur else 0
                    st.markdown(f"""
                    <div style="margin-bottom:8px;">
                        <div style="display:flex; justify-content:space-between; font-size:11px; color:{C['on_surface_variant']}; margin-bottom:2px;">
                            <span>{html.escape(str(secteur))}</span>
                            <span style="font-weight:600;">{count}</span>
                        </div>
                        <div class="progress-track"><div class="progress-fill" style="width:{pct}%; background:{coul};"></div></div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.caption("Aucune donnée sectorielle disponible.")

            # ===== GROUPES LES PLUS ACTIFS =====
            st.markdown(f"<p class='stat-label' style='border-bottom:1px solid {C['outline_variant']}; padding-bottom:6px; margin-top:16px;'>GROUPES LES PLUS ACTIFS</p>",
                         unsafe_allow_html=True)
            rep_groupes = df_tn["groupe"].value_counts().head(5)
            max_count = rep_groupes.max()
            couleurs_groupes = ["#ef4444", "#f59e0b", C["accent"], "#10b981", C["outline"]]
            
            if not rep_groupes.empty and max_count > 0:
                for (groupe, count), coul in zip(rep_groupes.items(), couleurs_groupes):
                    pct = round(count / max_count * 100, 1) if max_count else 0
                    st.markdown(f"""
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                        <span style="width:70px; font-family:monospace; font-size:11px; font-weight:600; color:{C['on_surface']}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">{html.escape(groupe)}</span>
                        <div style="flex:1; background:{C['surface_highest']}; height:8px; border-radius:4px; overflow:hidden;">
                            <div style="width:{pct}%; background:{coul}; height:100%;"></div>
                        </div>
                        <span style="width:25px; text-align:right; font-family:monospace; font-size:11px; color:{coul}; font-weight:700;">{count}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.caption("Aucun groupe identifié.")

        st.markdown('</div>', unsafe_allow_html=True)

    # ============================================================
    # GRAPHIQUE TENDANCE ET GROUPES LES PLUS ACTIFS
    # ============================================================
    st.write("")
    col_trend, col_top = st.columns(2)

    with col_trend:
        st.markdown("""
        <div >
            <div class="card-title">Tendance des attaques</div>
        """, unsafe_allow_html=True)
        
        tmp = df_rw.dropna(subset=["date_insertion_dt"]).copy()
        if tmp.empty:
            st.caption("Pas encore assez d'historique collecté pour tracer une tendance.")
        else:
            tmp["jour"] = tmp["date_insertion_dt"].dt.date
            idx = pd.date_range(tmp["jour"].min(), tmp["jour"].max(), freq="D").date
            total_jour = tmp.groupby("jour").size().reindex(idx, fill_value=0)
            tn_jour = tmp[tmp["type"] == "ransomware_leak_tn"].groupby("jour").size().reindex(idx, fill_value=0)

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=idx, y=total_jour.values, name="Toutes victimes",
                                      mode="lines", line=dict(color=C["accent"], width=2, shape="spline"),
                                      fill="tozeroy", fillcolor=hex_to_rgba(C["accent"], 0.15)))
            fig.add_trace(go.Scatter(x=idx, y=tn_jour.values, name="Tunisie",
                                      mode="lines", line=dict(color="#f59e0b", width=2, shape="spline"),
                                      fill="tozeroy", fillcolor=hex_to_rgba("#f59e0b", 0.15)))
            fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0),
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font=dict(color=C["on_surface_variant"], size=11, family="Inter"),
                              xaxis=dict(showgrid=False, color=C["outline"]),
                              yaxis=dict(showgrid=True, gridcolor=C["outline_variant"], zeroline=False),
                              legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, bgcolor="rgba(0,0,0,0)"),
                              hovermode="x unified")
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    with col_top:
        st.markdown("""
        <div >
            <div class="card-title">Groupes les plus actifs en Tunisie</div>
        """, unsafe_allow_html=True)
        
        if df_tn.empty:
            st.caption("Aucune donnée tunisienne pour établir ce classement.")
        else:
            rep_groupes = df_tn["groupe"].value_counts().head(5)
            max_count = rep_groupes.max()
            couleurs = ["#ef4444", "#f59e0b", C["accent"], "#10b981", C["outline"]]
            
            if max_count > 0:
                for (groupe, count), coul in zip(rep_groupes.items(), couleurs):
                    pct = round(count / max_count * 100, 1) if max_count else 0
                    st.markdown(f"""
                    <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
                        <span style="width:90px; font-family:monospace; font-size:12px; font-weight:700; color:{C['on_surface']}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">{html.escape(groupe)}</span>
                        <div style="flex:1; background:{C['surface_highest']}; height:16px; border-radius:4px; overflow:hidden;">
                            <div style="width:{pct}%; background:{coul}; height:100%;"></div>
                        </div>
                        <span style="width:30px; text-align:right; font-family:monospace; font-size:12px; color:{coul}; font-weight:700;">{count}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.caption("Aucun groupe identifié.")
        st.markdown('</div>', unsafe_allow_html=True)
# ============================================================
# PAGE : SEARCH (AVEC INTERROGATION DES API EN TEMPS RÉEL)
# ============================================================
def page_search():
    df = charger_donnees()

    # Importer les fonctions de main.py pour interroger les APIs
    try:
        from main import (
            verifier_domaine_hudsonrock,
            verifier_email_hudsonrock,
            recuperer_victimes_ransomware,
            chercher_dans_ransomware,
            recuperer_domaines_checkthesum,
            chercher_dans_checkthesum,
            rechercher_ransomlook
        )
        API_AVAILABLE = True
    except ImportError:
        API_AVAILABLE = False

    st.markdown("""
    <div class="aegis-header">
        <div style="display:flex; align-items:center;">
            <h2>Dark Web Investigation</h2>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ============================================================
    # FILTRES (4 colonnes - incluant la recherche)
    # ============================================================
    f1, f2, f3, f4 = st.columns(4)

    with f1:
        search_modes = ["Recherche globale", "Recherche par Domaine", "Recherche par Email"]
        mode = st.selectbox("Type de recherche", search_modes, key="search_mode_select")

    with f2:
        severity_options = ["Tous", "Critique", "Élevée", "Moyenne", "Faible"]
        severity_label = st.selectbox("Niveau de risque", severity_options, key="search_severity")

        severity_map = {
            "Tous": None,
            "Critique": "critique",
            "Élevée": "eleve",
            "Moyenne": "moyenne",
            "Faible": "faible"
        }
        selected_severity = severity_map[severity_label]

    with f3:
        periode = st.selectbox("Période", ["Tout", "Dernières 24h", "7 derniers jours", "30 derniers jours"],
                                key="search_periode")

    with f4:
        requete = st.text_input(
            "Recherche",
            placeholder= "Rechercher un asset...",
            key="search_query",
            label_visibility="hidden",
        )

    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 0 16px 0;'>", unsafe_allow_html=True)

    # ============================================================
    # RECHERCHE DANS LA BASE (assets déjà connus / historisés)
    # ============================================================
    resultats_base = pd.DataFrame()
    resultats_api = []
    api_errors = []

    if not df.empty:
        df_filtered = df.copy()

        # --- Filtrer par type de recherche ---
        if mode == "🌐 Recherche par Domaine":
            df["_type_recherche"] = df["asset_recherche"].apply(classify_asset_type)
            df_filtered = df[df["_type_recherche"].isin(["Domaine", "Mot-clé", "Adresse IP"])].copy()
        elif mode == "📧 Recherche par Email":
            df["_type_recherche"] = df["asset_recherche"].apply(classify_asset_type)
            df_filtered = df[df["_type_recherche"] == "Email"].copy()

        if not df_filtered.empty:
            # --- Filtrer par sévérité ---
            if selected_severity is not None:
                df_filtered = df_filtered[df_filtered["severity"] == selected_severity]

            # --- Filtrer par période ---
            if periode != "Tout":
                heures = {"Dernières 24h": 24, "7 derniers jours": 24 * 7, "30 derniers jours": 24 * 30}[periode]
                df_filtered = df_filtered[df_filtered["date_insertion_dt"] >= datetime.now() - timedelta(hours=heures)]

            # --- Recherche textuelle ---
            if requete:
                requete_clean = requete.strip()
                colonnes_recherchees = ["id", "type", "asset_recherche", "asset_concerne", "source_api", "details", "country", "sector"]
                masque = pd.Series(False, index=df_filtered.index)
                for col in colonnes_recherchees:
                    if col in df_filtered.columns:
                        masque |= df_filtered[col].astype(str).str.contains(_re.escape(requete_clean), case=False, na=False)
                df_filtered = df_filtered[masque]

            resultats_base = df_filtered.sort_values("date_insertion_dt", ascending=False)

    if not resultats_base.empty:
        resultats_base = resultats_base.copy()
        resultats_base["_origine"] = "base"

    # ============================================================
    # INTERROGATION LIVE DES APIs SUR L'ASSET TAPÉ
    # ------------------------------------------------------------
    # IMPORTANT : contrairement à avant, on interroge TOUJOURS les APIs
    # dès qu'un texte est saisi — pas uniquement quand la base est vide.
    # L'objectif : pouvoir chercher n'importe quel asset (ex: delice.tn)
    # même s'il n'a jamais été déclaré/collecté au préalable dans la base.
    # ============================================================
    if requete and API_AVAILABLE:
        with st.spinner(f"🔍 Interrogation des APIs pour '{requete}'..."):
            asset_search = requete.strip()
            resultats_api = []

            # Déterminer le type d'asset
            asset_type = classify_asset_type(asset_search)

            # --- 1. Ransomware.live ---
            try:
                victimes = recuperer_victimes_ransomware()
                for victime in victimes:
                    titre = (victime.get("post_title") or "").lower()
                    website = (victime.get("website") or "").lower()
                    if asset_search.lower() in titre or asset_search.lower() in website:
                        from main import normaliser_resultat_ransomware
                        resultats_api.append(normaliser_resultat_ransomware(victime, asset_search))
            except Exception as e:
                api_errors.append(f"Ransomware.live: {str(e)[:50]}...")

            # --- 2. Hudson Rock (domaines) ---
            if asset_type == "Domaine" and mode != "📧 Recherche par Email":
                try:
                    resultat_hr = verifier_domaine_hudsonrock(asset_search)
                    if resultat_hr:
                        from main import normaliser_resultat_hudsonrock
                        resultats_api.append(normaliser_resultat_hudsonrock(resultat_hr, asset_search))
                except Exception as e:
                    api_errors.append(f"Hudson Rock: {str(e)[:50]}...")

            # --- 3. Hudson Rock (emails) ---
            if asset_type == "Email" and mode != "🌐 Recherche par Domaine":
                try:
                    resultat_hr_email = verifier_email_hudsonrock(asset_search)
                    if resultat_hr_email:
                        from main import normaliser_resultat_hudsonrock_email
                        resultats_api.append(normaliser_resultat_hudsonrock_email(resultat_hr_email, asset_search))
                except Exception as e:
                    api_errors.append(f"Hudson Rock email: {str(e)[:50]}...")

            # --- 4. Check-The-Sum (silencieux) ---
            try:
                urls = recuperer_domaines_checkthesum()
                if urls:
                    for url in urls:
                        if asset_search.lower() in url.lower():
                            from main import normaliser_resultat_checkthesum
                            resultats_api.append(normaliser_resultat_checkthesum(url, asset_search))
            except Exception:
                pass

            # --- 5. RansomLook ---
            try:
                from main import rechercher_ransomlook
                resultats_ransomlook = rechercher_ransomlook([asset_search])
                if resultats_ransomlook:
                    resultats_api.extend(resultats_ransomlook)
            except Exception:
                pass

    # ============================================================
    # AFFICHAGE DES RÉSULTATS
    # ============================================================
    def snippet(details: str, terme: str, largeur: int = 60) -> str:
        details = details or ""
        if not terme:
            return html.escape(details[:140]) + ("…" if len(details) > 140 else "")
        terme_clean = terme.strip()
        idx = details.lower().find(terme_clean.lower())
        if idx == -1:
            return html.escape(details[:140]) + ("…" if len(details) > 140 else "")
        debut = max(idx - largeur, 0)
        fin = min(idx + len(terme_clean) + largeur, len(details))
        avant = html.escape(details[debut:idx])
        match = html.escape(details[idx:idx + len(terme_clean)])
        apres = html.escape(details[idx + len(terme_clean):fin])
        prefixe = "…" if debut > 0 else ""
        suffixe = "…" if fin < len(details) else ""
        return f"{prefixe}{avant}<span style='background:#1e293b; padding:1px 4px; border-radius:3px; font-weight:600; color:{C['accent']};'>{match}</span>{apres}{suffixe}"

    # --- Combiner les résultats (base + APIs live, dédupliqués) ---
    df_api = pd.DataFrame()
    if resultats_api:
        df_api = pd.DataFrame(resultats_api)
        df_api["_origine"] = "live"
        if "date_insertion_dt" not in df_api.columns:
            df_api["date_insertion_dt"] = datetime.now()
        if "date_insertion" not in df_api.columns:
            df_api["date_insertion"] = datetime.now().isoformat()

        # Dédoublonnage léger : si un résultat live correspond déjà à une ligne
        # de la base (même asset_concerne + même source), on ne le montre pas deux fois.
        if not resultats_base.empty and "asset_concerne" in df_api.columns:
            deja_connus = set(
                zip(
                    resultats_base.get("asset_concerne", pd.Series(dtype=str)).astype(str),
                    resultats_base.get("source_api", pd.Series(dtype=str)).astype(str),
                )
            )
            masque_nouveaux = ~df_api.apply(
                lambda row: (str(row.get("asset_concerne", "")), str(row.get("source_api", ""))) in deja_connus,
                axis=1,
            )
            df_api = df_api[masque_nouveaux]

        # Génère un id unique pour les résultats live (évite les collisions de key Streamlit)
        if "id" not in df_api.columns or df_api["id"].isna().any():
            df_api["id"] = [f"live_{i}" for i in range(len(df_api))]

    resultats_combined = pd.concat([resultats_base, df_api], ignore_index=True) if (not resultats_base.empty or not df_api.empty) else pd.DataFrame()

    # ===== TRI PAR DATE DE PREMIÈRE DÉTECTION (même logique que la page Alerts) =====
    if not resultats_combined.empty:
        def to_naive_datetime(col):
            dt = pd.to_datetime(col, errors="coerce", utc=True)
            if hasattr(dt, 'dt') and dt.dt.tz is not None:
                dt = dt.dt.tz_localize(None)
            return dt

        if "date_detection" in resultats_combined.columns:
            resultats_combined["date_detection_dt"] = to_naive_datetime(resultats_combined["date_detection"])
        else:
            resultats_combined["date_detection_dt"] = pd.NaT

        # Les résultats live (API) n'ont généralement pas de date_detection propre :
        # ils sont relégués après les alertes en base qui en ont une, exactement
        # comme sur la page Alerts (na_position="last").
        resultats_combined = resultats_combined.sort_values("date_detection_dt", ascending=False, na_position="last")

    # --- Afficher les résultats ---
    if resultats_combined.empty:
        if requete:
            st.info(f"🔍 Aucun résultat trouvé pour '{requete}' dans la base et les APIs.")
            if api_errors:
                with st.expander("ℹ️ Détails techniques (APIs)"):
                    for err in api_errors[:3]:
                        st.caption(f"• {err}")
                    if len(api_errors) > 3:
                        st.caption(f"• ... et {len(api_errors) - 3} autres erreurs")
        else:
            st.info("🔍 Saisissez un terme de recherche pour commencer — n'importe quel asset (domaine, email, mot-clé), même s'il n'a jamais été collecté auparavant.")
        return

    nb_base = int((resultats_combined["_origine"] == "base").sum()) if "_origine" in resultats_combined.columns else 0
    nb_live = int((resultats_combined["_origine"] == "live").sum()) if "_origine" in resultats_combined.columns else 0

    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:10px;">
        <span style="font-size:15px; font-weight:600; color:#f8fafc;">Search Results
            <span style="font-size:12px; font-weight:400; color:#94a3b8;">
                ({len(resultats_combined)} résultat{'s' if len(resultats_combined) != 1 else ''}
                {f' · 📊 {nb_base} en base' if nb_base else ''}{f' · 🌐 {nb_live} en direct (API)' if nb_live else ''})
            </span>
        </span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="bg-panel" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
    page_df, page, total_pages, debut_p, fin_p, total = paginer(resultats_combined, "search_page", taille_page=10)

    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; padding:12px 16px; border-bottom:1px solid {C['outline_variant']}; background:rgba(30,41,59,0.2);">
        <span style="font-size:12px; color:#94a3b8;">Affichage {debut_p}-{fin_p} sur {total}</span>
    </div>
    """, unsafe_allow_html=True)

    header_cols = st.columns([0.5, 1.2, 2.8, 1.5, 1.2, 1, 0.6])
    for c, h in zip(header_cols, ["", "Date", "Contexte", "Asset", "Source", "Type", ""]):
        c.markdown(f"<span style='font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:#94a3b8;'>{h}</span>", unsafe_allow_html=True)
    st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:6px 0 4px 0;'>", unsafe_allow_html=True)

    for _, r in page_df.iterrows():
        meta = sev_meta(r["severity"]) if "severity" in r and pd.notna(r.get("severity")) else sev_meta("faible")
        t_meta = type_meta(r["type"]) if "type" in r and pd.notna(r.get("type")) else {"label": "Inconnu", "icon": "report"}
        date_str = (
            r["date_detection_dt"].strftime("%Y-%m-%d %H:%M") if pd.notna(r.get("date_detection_dt"))
            else r["date_insertion_dt"].strftime("%Y-%m-%d %H:%M") if pd.notna(r.get("date_insertion_dt"))
            else "—"
        )
        row_cols = st.columns([0.5, 1.2, 2.8, 1.5, 1.2, 1, 0.6])

        row_cols[0].markdown(f"""
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:{meta['color']}; box-shadow:0 0 8px {meta['color']}66;"></span>
        """, unsafe_allow_html=True)

        row_cols[1].markdown(f"<span style='font-family:monospace; font-size:11px; color:#475569;'>{html.escape(date_str)}</span>", unsafe_allow_html=True)
        row_cols[2].markdown(f"<span style='font-size:12px; color:#94a3b8; line-height:1.4;'>{snippet(str(r.get('details', '')), requete)}</span>", unsafe_allow_html=True)
        row_cols[3].markdown(f"<span style='font-size:12px; color:#f8fafc;'>{html.escape(str(r.get('asset_concerne', '—')))}</span>", unsafe_allow_html=True)
        row_cols[4].markdown(f"<span style='font-size:12px; color:#94a3b8;'>{html.escape(str(r.get('source_api', '')))}</span>", unsafe_allow_html=True)
        row_cols[5].markdown(f"<span style='font-size:11px; color:#94a3b8;'>{html.escape(t_meta['label'])}</span>", unsafe_allow_html=True)

        origine = r.get("_origine", "base")

        alert_id = r.get("id")
        if origine == "base" and alert_id is not None and row_cols[6].button("→", key=f"search_open_{alert_id}"):
            st.session_state["alert_detail_id"] = alert_id
            st.session_state.page = "alerts"
            st.rerun()

        # --- Panneau "Plus de détails" : uniquement pour les résultats LIVE ---
        # Les résultats déjà en base ont déjà la flèche "→" qui ouvre la fiche complète,
        # donc pas besoin d'un expander redondant pour eux.
        if origine == "live":
            details_full = str(r.get("details", "") or "Aucun détail disponible.")
            asset_concerne_val = str(r.get("asset_concerne", "") or "Non spécifié")
            asset_recherche_val = str(r.get("asset_recherche", "") or requete or "Non spécifié")
            secteur_val = str(r.get("sector", "") or "Non disponible")
            pays_val = str(r.get("country", "") or "Non disponible")
            source_val = str(r.get("source_api", "") or "Non disponible")
            severity_label = meta.get("label", "—")

            expander_label = f"Plus de détails — {asset_concerne_val}" if asset_concerne_val != "Non spécifié" else "Plus de détails"
            with st.expander(expander_label, expanded=False):
                st.markdown(f"""
                <div style="margin-bottom:12px;">
                    <span style="background:rgba(91,141,239,0.12); color:#5b8def; font-size:10px; font-weight:700; padding:3px 8px; border-radius:4px;">🌐 RÉSULTAT LIVE (API, non stocké)</span>
                </div>
                <div style="font-size:13.5px; line-height:1.6; color:#9aa4bd; margin-bottom:14px;">
                    {html.escape(details_full)}
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0 20px;">
                    <div style="display:flex; justify-content:space-between; padding:6px 0; border-top:1px solid {C['outline_variant']}; font-size:13px;">
                        <span style="color:#9aa4bd;">Asset concerné</span>
                        <span style="font-family:monospace; color:#eef1f8;">{html.escape(asset_concerne_val)}</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; padding:6px 0; border-top:1px solid {C['outline_variant']}; font-size:13px;">
                        <span style="color:#9aa4bd;">Terme recherché</span>
                        <span style="font-family:monospace; color:#eef1f8;">{html.escape(asset_recherche_val)}</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; padding:6px 0; border-top:1px solid {C['outline_variant']}; font-size:13px;">
                        <span style="color:#9aa4bd;">Secteur</span>
                        <span style="font-family:monospace; color:#eef1f8;">{html.escape(secteur_val)}</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; padding:6px 0; border-top:1px solid {C['outline_variant']}; font-size:13px;">
                        <span style="color:#9aa4bd;">Pays</span>
                        <span style="font-family:monospace; color:#eef1f8;">{html.escape(pays_val)}</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; padding:6px 0; border-top:1px solid {C['outline_variant']}; font-size:13px;">
                        <span style="color:#9aa4bd;">Source</span>
                        <span style="font-family:monospace; color:#eef1f8;">{html.escape(source_val)}</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; padding:6px 0; border-top:1px solid {C['outline_variant']}; font-size:13px;">
                        <span style="color:#9aa4bd;">Sévérité</span>
                        <span style="font-family:monospace; color:{meta['color']};">{html.escape(severity_label)}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.caption("Ce résultat provient d'une interrogation en direct des APIs et n'est pas encore enregistré dans la base d'alertes.")

            st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
    st.write("")
    controles_pagination("search_page", page, total_pages, "search")

# ============================================================
# PAGE : SETTINGS
# ============================================================
def _envoyer_notification_invitation(destinataires, sujet, corps) -> bool:
    """Envoie un simple email d'information ('vous êtes invité au dashboard'),
    en réutilisant la config SMTP déjà en place dans main.py pour les alertes.
    Pas de mot de passe ni de lien d'activation : juste une notification."""
    try:
        from main import _envoyer_email_smtp
        return _envoyer_email_smtp(destinataires, sujet, corps)
    except Exception as e:
        print(f"⚠️ Erreur d'envoi d'email (invitation) : {e}")
        return False


def _settings_card_open(icon: str, title: str):
    # Le titre de section est déjà visible dans la nav de gauche (General,
    # Account & Security, ...) : on ne le répète plus ici pour éviter la
    # redondance visuelle. On garde juste la carte + le padding intérieur.
    st.markdown("""
    <div class="settings-card">
        <div style="padding:24px;">
    """, unsafe_allow_html=True)

def _settings_card_close():
    st.markdown("</div></div>", unsafe_allow_html=True)

def _settings_field_label(label: str, help_text: str = ""):
    st.markdown(f"""
    <label class="settings-field-label">{html.escape(label)}</label>
    {f'<p class="settings-field-help">{html.escape(help_text)}</p>' if help_text else ''}
    """, unsafe_allow_html=True)

def _fk(base: str) -> str:
    """Clé de widget "versionnée". Cliquer sur Cancel incrémente
    settings_widget_version, ce qui force Streamlit à recréer chaque widget
    de zéro (nouvelle clé jamais vue) au lieu de réutiliser un état existant.
    C'est ce qui garantit un reset immédiat et fiable à 100%, même pour une
    case qu'on vient tout juste de cocher/décocher avant de cliquer Cancel."""
    version = st.session_state.get("settings_widget_version", 0)
    return f"f_{base}_v{version}"

def _save_cancel_buttons(tab_key: str):
    st.markdown('<hr class="settings-divider" style="margin-top:20px;">', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([6, 1, 1])
    with c2:
        cancel_clicked = st.button("Cancel", key=f"settings_cancel_{tab_key}", use_container_width=True)
    with c3:
        save_clicked = st.button("Save Changes", key=f"settings_save_{tab_key}",
                                  type="primary", use_container_width=True)

    if cancel_clicked:
        st.session_state.app_settings = load_settings()
        # On "change de génération" pour tous les widgets de Settings : la
        # prochaine version de clé n'existe pas encore en session, donc
        # chaque champ repart de zéro avec la valeur sauvegardée sur disque,
        # immédiatement et sans exception possible.
        st.session_state["settings_widget_version"] = st.session_state.get("settings_widget_version", 0) + 1
        st.toast("Modifications annulées")
        st.rerun()

    if save_clicked:
        new_settings = dict(st.session_state.app_settings)
        for k in DEFAULT_SETTINGS.keys():
            if k == "team_members":
                continue
            wk = _fk(k)
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
        ("monitoring", "radar", "Monitoring Config"),
        ("team", "group", "Team Management"),
    ]

    col_nav, col_content = st.columns([3, 9])

    with col_nav:
        for tab_key, icon, label in settings_tabs:
            is_active = st.session_state.get("settings_tab", "general") == tab_key
            if st.button(label, key=f"settings_nav_{tab_key}",
                         type="primary" if is_active else "secondary",
                         use_container_width=True):
                st.session_state.settings_tab = tab_key
                st.rerun()

    with col_content:
        current_tab = st.session_state.get("settings_tab", "general")

        if current_tab == "general":
            _settings_card_open("tune", "General Settings")

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Platform Name")
            with c2:
                st.text_input("Platform Name", value=settings["general_platform_name"],
                               key=_fk("general_platform_name"), label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Default Timezone")
            with c2:
                tz_options = ["UTC", "EST", "PST"]
                st.selectbox("Timezone", tz_options,
                              index=tz_options.index(settings["general_timezone"]) if settings["general_timezone"] in tz_options else 0,
                              key=_fk("general_timezone"), label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Custom Logo")
            with c2:
                logo_file = st.file_uploader("Logo", type=["svg", "png"], key=_fk("logo_upload"),
                                              label_visibility="collapsed")
                if logo_file is not None:
                    os.makedirs(UPLOADS_DIR, exist_ok=True)
                    dest = os.path.join(UPLOADS_DIR, logo_file.name)
                    with open(dest, "wb") as f:
                        f.write(logo_file.getbuffer())
                    st.session_state[_fk("general_logo_filename")] = logo_file.name
                    st.success(f"Fichier reçu : {logo_file.name} (sera appliqué après Save Changes)")
                current_logo = settings.get("general_logo_filename")
                if _fk("general_logo_filename") not in st.session_state:
                    st.session_state[_fk("general_logo_filename")] = current_logo

            _save_cancel_buttons("general")
            _settings_card_close()

        elif current_tab == "monitoring":
            _settings_card_open("radar", "Monitoring Configuration")

            df_status = charger_donnees()
            src_mask = df_status["source_api"] if not df_status.empty else None

            def _stats_source(mask=None, alt_stats=None):
                """Retourne (nombre_de_détections, date_derniere) à partir des vraies données en base."""
                if alt_stats is not None:
                    return alt_stats()
                if df_status.empty or mask is None:
                    return 0, None
                sous = df_status[mask]
                if sous.empty:
                    return 0, None
                derniere = sous["date_insertion_dt"].max() if "date_insertion_dt" in sous.columns else None
                return len(sous), derniere

            WAZUH_STATUS_PATH = "wazuh_export/aegis_cti_alerts.json"

            def _stats_wazuh():
                if not os.path.exists(WAZUH_STATUS_PATH):
                    return 0, None
                try:
                    with open(WAZUH_STATUS_PATH, "r", encoding="utf-8") as f:
                        nb_lignes = sum(1 for _ in f)
                    mtime = pd.Timestamp(datetime.fromtimestamp(os.path.getmtime(WAZUH_STATUS_PATH)))
                    return nb_lignes, mtime
                except Exception:
                    return 0, None

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Scan Interval")
            with c2:
                si_options = ["1", "2", "5", "10"]
                si_labels = {"1": "Every minute", "2": "Every 2 minutes", "5": "Every 5 minutes", "10": "Every 10 minutes"}
                st.selectbox("Scan interval", si_options, format_func=lambda x: si_labels[x],
                              index=si_options.index(settings["monitoring_scan_interval"]) if settings["monitoring_scan_interval"] in si_options else 1,
                              key=_fk("monitoring_scan_interval"), label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Active Sources")
            with c2:
                header_cols = st.columns([2.4, 0.9, 0.9, 1.3])
                for hc, htxt in zip(header_cols, ["", "Statut", "Détections", "Dernière activité"]):
                    hc.markdown(f"<span class='stat-label'>{htxt}</span>", unsafe_allow_html=True)
                st.markdown(f"<hr style='border-color:{C['outline_variant']}; margin:4px 0 6px 0;'>", unsafe_allow_html=True)

                sources_rows = [
                    ("HudsonRock (Infostealers)", _fk("monitoring_src_hudsonrock"), settings["monitoring_src_hudsonrock"],
                     *_stats_source(src_mask == "HudsonRock" if src_mask is not None else None)),
                    ("Ransomware.live", _fk("monitoring_src_ransomwarelive"), settings["monitoring_src_ransomwarelive"],
                     *_stats_source(src_mask == "RansomwareLive" if src_mask is not None else None)),
                    ("Check-The-Sum (honeypot IOC)", _fk("monitoring_src_checkthesum"), settings["monitoring_src_checkthesum"],
                     *_stats_source(src_mask == "CheckTheSum" if src_mask is not None else None)),
                    ("RansomLook.io", _fk("monitoring_src_ransomlook"), settings["monitoring_src_ransomlook"],
                     *_stats_source(src_mask == "RansomLook" if src_mask is not None else None)),
                    ("Tunisia Watch (Ransomware.live /countryvictims)", _fk("monitoring_tunisia_watch"), settings["monitoring_tunisia_watch"],
                     *_stats_source(df_status["type"] == "ransomware_leak_tn" if not df_status.empty else None)),
                    ("APT Watch (APTnotes — mentions Tunisia/assets)", _fk("monitoring_apt_watch"), settings["monitoring_apt_watch"],
                     *_stats_source(src_mask == "APTnotes" if src_mask is not None else None)),
                    ("deepdarkCTI (statut global des sites de fuite)", _fk("monitoring_deepdarkcti"), settings["monitoring_deepdarkcti"],
                     *_stats_source(src_mask == "deepdarkCTI" if src_mask is not None else None)),
                    ("Export vers Wazuh (log JSON pour agent SIEM)", _fk("monitoring_wazuh_export"), settings["monitoring_wazuh_export"],
                     *_stats_wazuh()),
                ]

                for label, wkey, wvalue, count, derniere in sources_rows:
                    row_cols = st.columns([2.4, 0.9, 0.9, 1.3])
                    row_cols[0].checkbox(label, value=wvalue, key=wkey)

                    est_actif = count > 0
                    badge_color = C["success"] if est_actif else C["outline"]
                    row_cols[1].markdown(
                        badge_pill("ACTIF" if est_actif else "INACTIF", badge_color, hex_to_rgba(badge_color, 0.14)),
                        unsafe_allow_html=True,
                    )
                    row_cols[2].markdown(f"<span style='color:{C['on_surface_variant']};'>{count}</span>", unsafe_allow_html=True)
                    derniere_str = temps_relatif(derniere) if derniere is not None and pd.notna(derniere) else "—"
                    row_cols[3].markdown(f"<span style='color:{C['outline']}; font-size:12px;'>{html.escape(derniere_str)}</span>", unsafe_allow_html=True)
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Alert Thresholds")
            with c2:
                th_options = ["critique", "eleve", "moyenne", "faible"]
                th_labels = {"critique": "Critical only", "eleve": "Elevated+", "moyenne": "Moyenne+", "faible": "All"}
                st.radio("Seuil", th_options, format_func=lambda x: th_labels[x],
                          index=th_options.index(settings["monitoring_alert_threshold"]) if settings["monitoring_alert_threshold"] in th_options else 1,
                          key=_fk("monitoring_alert_threshold"), horizontal=True, label_visibility="collapsed")

            _save_cancel_buttons("monitoring")
            _settings_card_close()

        elif current_tab == "team":
            _settings_card_open("group", "Team Management")

            members = settings.get("team_members", [])
            for i, member in enumerate(members):
                mc1, mc2, mc3 = st.columns([5, 2, 1])
                role_color = C["accent"] if member["role"] == "Admin" else C["on_surface_variant"]
                role_badge = badge_pill(member["role"].upper(), role_color, hex_to_rgba(role_color, 0.14))
                mc1.markdown(f"""
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:13px; color:{C['on_surface']};">{html.escape(member['email'])}</span>
                    {role_badge}
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
            st.caption("Ajoute la personne à la liste et lui envoie un email pour l'informer "
                       "qu'elle a été invitée à consulter le dashboard.")

            _invite_version = st.session_state.get("team_invite_version", 0)
            _email_key = f"team_new_email_v{_invite_version}"
            _role_key = f"team_new_role_v{_invite_version}"

            ic1, ic2, ic3 = st.columns([3, 1.5, 1])
            with ic1:
                new_email = st.text_input("Email", placeholder="new_member@company.com",
                                           key=_email_key, label_visibility="collapsed")
            with ic2:
                new_role = st.selectbox("Rôle", ["Analyst", "Admin"], key=_role_key,
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
                        # Change de "génération" de clé pour que le champ email
                        # reparte vide au prochain rerun, sans jamais modifier
                        # directement la valeur d'un widget déjà instancié.
                        st.session_state["team_invite_version"] = _invite_version + 1

                        corps = (
                            f"Bonjour,\n\n"
                            f"Vous avez été invité(e) à consulter le dashboard {_PLATFORM_NAME} "
                            f"en tant que {new_role}.\n\n"
                            f"Adresse du dashboard : {os.getenv('AEGIS_PUBLIC_URL', 'http://localhost:8501')}\n\n"
                            f"— {_PLATFORM_NAME}"
                        )
                        email_envoye = _envoyer_notification_invitation(
                            [new_email.strip()],
                            f"[{_PLATFORM_NAME}] Vous êtes invité(e) au dashboard",
                            corps,
                        )
                        if email_envoye:
                            st.success(f"{new_email} ajouté(e) à l'équipe et email envoyé.")
                        else:
                            st.warning(f"{new_email} ajouté(e) à l'équipe, mais l'email n'a pas pu être "
                                       f"envoyé (vérifie la configuration SMTP dans .env).")
                        st.rerun()
                    else:
                        st.error("Adresse email invalide.")

            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)


            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Email Recipients", "Alerts will be sent to these addresses.")
            with c2:
                st.text_input("Destinataires", value=settings["notif_email_recipients"],
                               placeholder="soc@company.com, admin@company.com",
                               key=_fk("notif_email_recipients"), label_visibility="collapsed")
            st.markdown('<hr class="settings-divider">', unsafe_allow_html=True)

            c1, c2 = st.columns([1, 2])
            with c1:
                _settings_field_label("Alert Digest", "Send daily summary of all alerts.")
            with c2:
                st.checkbox("Activer le résumé quotidien", value=settings["notif_digest_enabled"],
                             key=_fk("notif_digest_enabled"))

            _save_cancel_buttons("team")
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
elif page == "assets":
    page_assets()
elif page == "alerts":
    page_alerts()
elif page == "ransomware":
    page_ransomware_intel()
elif page == "search":
    page_search()
elif page == "settings":
    page_settings()
else:
    labels = {k: v for k, _, v in NAV_ITEMS}
    page_placeholder(labels.get(page, page))