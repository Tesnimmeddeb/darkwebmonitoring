import requests
import os
import json
import csv
import io
import re
import time
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
from storage import creer_base, sauvegarder_alerte, lire_toutes_les_alertes

load_dotenv()

# ============================================
# 0. LECTURE DES RÉGLAGES (settings.json, partagé avec le Dashboard)
# ============================================

SETTINGS_FILE = "app_settings.json"
ASSETS_FILE = "monitored_assets.json"

DEFAULT_MAIN_SETTINGS = {
    "monitoring_scan_interval": "2",
    "monitoring_src_hudsonrock": True,
    "monitoring_src_ransomwarelive": True,
    "monitoring_src_checkthesum": True,
    "monitoring_src_ransomlook": True,
    "monitoring_tunisia_watch": True,
    "monitoring_apt_watch": True,
    "monitoring_deepdarkcti": True,
    "monitoring_wazuh_export": True,
    "monitoring_alert_threshold": "faible",
    "notif_email_recipients": "",
    "notif_digest_enabled": False,
}

SEVERITY_RANK = {"critique": 3, "eleve": 2, "faible": 1}


def charger_reglages():
    data = {}
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ Impossible de lire {SETTINGS_FILE} ({e})")
            data = {}
    reglages = dict(DEFAULT_MAIN_SETTINGS)
    reglages.update({k: v for k, v in data.items() if k in DEFAULT_MAIN_SETTINGS})
    return reglages


# ============================================
# 0bis. CHARGEMENT DES ASSETS DEPUIS JSON
# ============================================

def charger_assets_depuis_json():
    """Charge la liste des assets depuis monitored_assets.json"""
    if os.path.exists(ASSETS_FILE):
        try:
            with open(ASSETS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [item["identifier"] for item in data]
        except Exception as e:
            print(f"⚠️ Impossible de charger les assets depuis {ASSETS_FILE} : {e}")
    # Assets par défaut si le fichier n'existe pas
    return ["yueki", "entreprise-test"]

def charger_domaines_depuis_json():
    """Charge les domaines depuis monitored_assets.json (filtre sur les domaines)"""
    if os.path.exists(ASSETS_FILE):
        try:
            with open(ASSETS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [item["identifier"] for item in data if item.get("type") == "Domaine"]
        except Exception as e:
            print(f"⚠️ Impossible de charger les domaines depuis {ASSETS_FILE} : {e}")
    return ["monoprix.tn"]

def charger_emails_depuis_json():
    """Charge les emails depuis monitored_assets.json (filtre sur les emails)"""
    if os.path.exists(ASSETS_FILE):
        try:
            with open(ASSETS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [item["identifier"] for item in data if item.get("type") == "Email"]
        except Exception as e:
            print(f"⚠️ Impossible de charger les emails depuis {ASSETS_FILE} : {e}")
    return ["manvirdi2000@gmail.com"]


# ============================================
# 1. FONCTIONS DE RECUPERATION (APPEL DES API)
# ============================================

def recuperer_victimes_ransomware():
    url = "https://api.ransomware.live/recentvictims"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            return response.json()
        print(f"Erreur Ransomware.live : {response.status_code}")
        return []
    except requests.RequestException as e:
        print(f"Erreur réseau Ransomware.live : {e}")
        return []


def recuperer_victimes_pays(code_pays):
    url = f"https://api.ransomware.live/v2/countryvictims/{code_pays}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return response.json()
        print(f"Erreur Ransomware.live (pays {code_pays}) : {response.status_code}")
        return []
    except requests.RequestException as e:
        print(f"Erreur réseau Ransomware.live (pays {code_pays}) : {e}")
        return []


def recuperer_domaines_checkthesum():
    url = "https://www.check-the-sum.fr/feeds/domains/all_domains.txt"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return [ligne.strip() for ligne in response.text.splitlines()
                    if ligne.strip() and not ligne.startswith("#")]
        print(f"Erreur Check-The-Sum : {response.status_code}")
        return []
    except requests.RequestException as e:
        print(f"Erreur réseau Check-The-Sum : {e}")
        return []


_PATTERN_DEEPDARKCTI = re.compile(r"^\|\[([^\]]+)\]\(([^)]+)\)\|(\w+)\|")

def recuperer_statut_deepdarkcti():
    url = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md"
    try:
        response = requests.get(url, timeout=20)
        if response.status_code != 200:
            print(f"Erreur deepdarkCTI : {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Erreur réseau deepdarkCTI : {e}")
        return None

    total = 0
    online = 0
    for ligne in response.text.splitlines():
        m = _PATTERN_DEEPDARKCTI.match(ligne)
        if m:
            _, _, statut = m.groups()
            total += 1
            if statut.strip().upper() == "ONLINE":
                online += 1
    return {"total": total, "online": online}


def rechercher_ransomlook(mots_cles):
    url = "https://www.ransomlook.io/api/search"
    resultats = []
    for mot_cle in mots_cles:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.get(url, params={"query": mot_cle}, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for hit in data:
                        resultats.append(normaliser_resultat_ransomlook(hit, mot_cle))
            else:
                print(f"Erreur RansomLook (recherche '{mot_cle}') : {response.status_code}")
        except requests.RequestException as e:
            print(f"Erreur réseau RansomLook : {e}")
    return resultats


def rechercher_aptnotes(mots_cles):
    url = "https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv"
    try:
        response = requests.get(url, timeout=20)
        if response.status_code != 200:
            print(f"Erreur APTnotes : {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"Erreur réseau APTnotes : {e}")
        return []

    resultats = []
    lecteur = csv.DictReader(io.StringIO(response.text))
    for ligne in lecteur:
        titre = (ligne.get("Title") or "")
        titre_lower = titre.lower()
        for mot_cle in mots_cles:
            if mot_cle.lower() in titre_lower:
                resultats.append(normaliser_resultat_aptnotes(ligne, mot_cle))
    return resultats


def verifier_domaine_hudsonrock(domaine):
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domaine}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return response.json()
        print(f"Erreur Hudson Rock (domaine) : {response.status_code}")
        return None
    except requests.RequestException as e:
        print(f"Erreur réseau Hudson Rock : {e}")
        return None


def verifier_email_hudsonrock(email):
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return response.json()
        print(f"Erreur Hudson Rock (email) : {response.status_code}")
        return None
    except requests.RequestException as e:
        print(f"Erreur réseau Hudson Rock : {e}")
        return None


# ============================================
# 2. FONCTIONS DE NORMALISATION
# ============================================

def normaliser_resultat_ransomware(victime_brute, asset_recherche):
    return {
        "source_api": "RansomwareLive",
        "type": "ransomware_leak",
        "asset_recherche": asset_recherche,
        "asset_concerne": victime_brute.get("website"),
        "details": f"Groupe ransomware: {victime_brute.get('group_name')}, Entreprise: {victime_brute.get('post_title')}",
        "date_detection": victime_brute.get("published"),
        "severity": "critique",
        "country": victime_brute.get("country"),
        "sector": victime_brute.get("activity") or victime_brute.get("sector"),
    }


def normaliser_victime_flux_global(victime_brute):
    return {
        "source_api": "RansomwareLive",
        "type": "ransomware_global_feed",
        "asset_recherche": "GLOBAL_FEED",
        "asset_concerne": victime_brute.get("website") or victime_brute.get("post_title"),
        "details": f"Groupe ransomware: {victime_brute.get('group_name')}, Entreprise: {victime_brute.get('post_title')}",
        "date_detection": victime_brute.get("published"),
        "severity": "faible",
        "country": victime_brute.get("country"),
        "sector": victime_brute.get("activity") or victime_brute.get("sector"),
    }


def normaliser_victime_pays(victime_brute, code_pays):
    return {
        "source_api": "RansomwareLive",
        "type": "ransomware_leak_tn" if code_pays == "TN" else "ransomware_leak_pays",
        "asset_recherche": f"WATCH_{code_pays}",
        "asset_concerne": victime_brute.get("website") or victime_brute.get("post_title"),
        "details": f"Groupe ransomware: {victime_brute.get('group_name')}, Entreprise: {victime_brute.get('post_title')}",
        "date_detection": victime_brute.get("published"),
        "severity": "critique",
        "country": victime_brute.get("country") or code_pays,
        "sector": victime_brute.get("activity") or victime_brute.get("sector"),
    }


def normaliser_resultat_checkthesum(url_brute, asset_recherche):
    return {
        "source_api": "CheckTheSum",
        "type": "malicious_infrastructure_mention",
        "asset_recherche": asset_recherche,
        "asset_concerne": url_brute,
        "details": f"Notre terme surveillé apparaît dans une URL/domaine observé(e) dans des commandes d'attaquants (honeypot Cowrie) : {url_brute}",
        "date_detection": None,
        "severity": "eleve",
        "country": None,
        "sector": None,
    }


def normaliser_statut_deepdarkcti(stats):
    return {
        "source_api": "deepdarkCTI",
        "type": "deepdarkcti_status",
        "asset_recherche": "DEEPDARKCTI_STATUS",
        "asset_concerne": "Ransomware leak sites (suivi global)",
        "details": f"{stats['online']} groupes ransomware marqués ONLINE sur {stats['total']} suivis (deepdarkCTI)",
        "date_detection": None,
        "severity": "faible",
        "country": None,
        "sector": None,
    }


def normaliser_resultat_ransomlook(hit_brut, asset_recherche):
    return {
        "source_api": "RansomLook",
        "type": "ransomware_leak",
        "asset_recherche": asset_recherche,
        "asset_concerne": hit_brut.get("post_title"),
        "details": f"Groupe ransomware: {hit_brut.get('group_name')}, Publication: {hit_brut.get('post_title')}",
        "date_detection": hit_brut.get("discovered"),
        "severity": "critique",
        "country": None,
        "sector": None,
    }


def normaliser_resultat_aptnotes(ligne_brute, asset_recherche):
    return {
        "source_api": "APTnotes",
        "type": "apt_mention",
        "asset_recherche": asset_recherche,
        "asset_concerne": ligne_brute.get("Title"),
        "details": f"Rapport APT publié par {ligne_brute.get('Source') or 'source inconnue'} : « {ligne_brute.get('Title')} »",
        "date_detection": ligne_brute.get("Date"),
        "severity": "eleve",
        "country": None,
        "sector": None,
    }


def normaliser_resultat_hudsonrock(resultat_brut, domaine_teste):
    nb_employes = resultat_brut.get("employees", 0)
    nb_users = resultat_brut.get("users", 0)
    nb_total = resultat_brut.get("total", 0)

    if nb_employes > 0:
        severite = "critique"
    elif nb_users > 0:
        severite = "eleve"
    else:
        severite = "faible"

    return {
        "source_api": "HudsonRock",
        "type": "infostealer_compromise",
        "asset_recherche": domaine_teste,
        "asset_concerne": domaine_teste,
        "details": f"Total comptes compromis: {nb_total} (Employés: {nb_employes}, Utilisateurs: {nb_users})",
        "date_detection": None,
        "severity": severite,
        "country": None,
        "sector": None,
    }


def normaliser_resultat_hudsonrock_email(resultat_brut, email_teste):
    stealers = resultat_brut.get("stealers", [])

    if not stealers:
        return {
            "source_api": "HudsonRock",
            "type": "infostealer_email_check",
            "asset_recherche": email_teste,
            "asset_concerne": email_teste,
            "details": "Aucune compromission détectée pour cet email",
            "date_detection": None,
            "severity": "faible",
            "country": None,
            "sector": None,
        }

    premier_stealer = stealers[0]
    nb_corporate = premier_stealer.get("total_corporate_services", 0)
    nb_user = premier_stealer.get("total_user_services", 0)
    date_compromis = premier_stealer.get("date_compromised")
    computer = premier_stealer.get("computer_name")

    severite = "critique" if nb_corporate > 0 else "eleve"

    return {
        "source_api": "HudsonRock",
        "type": "infostealer_email_check",
        "asset_recherche": email_teste,
        "asset_concerne": email_teste,
        "details": f"Ordinateur infecté ({computer}) - Services corporate: {nb_corporate}, Services perso: {nb_user}, Infecté depuis: {date_compromis}",
        "date_detection": date_compromis,
        "severity": severite,
        "country": None,
        "sector": None,
    }


# ============================================
# 3. LOGIQUE DE RECHERCHE / MATCHING
# ============================================

def chercher_dans_ransomware(victimes, mots_cles):
    resultats_normalises = []
    for victime in victimes:
        titre = (victime.get("post_title") or "").lower()
        website = (victime.get("website") or "").lower()
        for mot_cle in mots_cles:
            if mot_cle.lower() in titre or mot_cle.lower() in website:
                resultat = normaliser_resultat_ransomware(victime, mot_cle)
                resultats_normalises.append(resultat)
    return resultats_normalises


def chercher_dans_checkthesum(urls_malveillantes, mots_cles):
    resultats_normalises = []
    for url in urls_malveillantes:
        url_lower = url.lower()
        for mot_cle in mots_cles:
            if mot_cle.lower() in url_lower:
                resultats_normalises.append(normaliser_resultat_checkthesum(url, mot_cle))
    return resultats_normalises


# ============================================
# 3bis. EXPORT VERS WAZUH
# ============================================

WAZUH_LOG_PATH = "wazuh_export/aegis_cti_alerts.json"

def exporter_alertes_vers_wazuh(alertes):
    if not alertes:
        return
    dossier = os.path.dirname(WAZUH_LOG_PATH)
    if dossier and not os.path.exists(dossier):
        os.makedirs(dossier, exist_ok=True)
    try:
        with open(WAZUH_LOG_PATH, "a", encoding="utf-8") as f:
            for alerte in alertes:
                f.write(json.dumps(alerte, ensure_ascii=False) + "\n")
        print(f"{len(alertes)} alerte(s) exportée(s) vers {WAZUH_LOG_PATH} (pour l'agent Wazuh)\n")
    except OSError as e:
        print(f"⚠️ Impossible d'écrire le log Wazuh : {e}\n")


def envoyer_alerte_syslog(alerte, serveur="192.168.48.134", port=514):
    try:
        message = f"<134>AEGIS CTI: {alerte['severity'].upper()} - {alerte['type']} - {alerte.get('asset_concerne', '')} - {alerte.get('details', '')}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode(), (serveur, port))
        sock.close()
        return True
    except Exception as e:
        print(f"❌ Erreur d'envoi syslog: {e}")
        return False


# ============================================
# 3ter. ENVOI D'EMAIL (ALERTES CRITIQUES/ÉLEVÉES + DIGEST QUOTIDIEN)
# ============================================
#
# Configuration requise dans le fichier .env (à la racine du projet) :
#   SMTP_HOST=smtp.gmail.com
#   SMTP_PORT=587
#   SMTP_USER=ton_compte@gmail.com
#   SMTP_PASSWORD=xxxx xxxx xxxx xxxx      (mot de passe d'application, pas ton mot de passe normal)
#   SMTP_FROM=ton_compte@gmail.com         (optionnel, sinon = SMTP_USER)
#
# Les destinataires sont lus depuis app_settings.json -> "notif_email_recipients"
# (le champ "Email Recipients" du Dashboard, dans Settings > Team Management).
# Plusieurs adresses peuvent être séparées par des virgules.

DIGEST_HOUR = 0  # heure fixe d'envoi du résumé quotidien (0 = minuit, 0-23)
DIGEST_STATE_PATH = "digest_state.json"


def _envoyer_email_smtp(destinataires, sujet, corps):
    """Fonction bas-niveau partagée : ouvre la connexion SMTP et envoie un email."""
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM") or smtp_user

    if not smtp_host or not smtp_user or not smtp_password:
        print("⚠️ Envoi d'email désactivé : SMTP_HOST / SMTP_USER / SMTP_PASSWORD manquants dans .env\n")
        return False

    message = MIMEMultipart()
    message["From"] = smtp_from
    message["To"] = ", ".join(destinataires)
    message["Subject"] = sujet
    message.attach(MIMEText(corps, "plain", "utf-8"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as serveur:
            serveur.starttls()
            serveur.login(smtp_user, smtp_password)
            serveur.sendmail(smtp_from, destinataires, message.as_string())
        print(f"📧 Email envoyé à {', '.join(destinataires)} — sujet : {sujet}\n")
        return True
    except Exception as e:
        print(f"❌ Erreur d'envoi d'email : {e}\n")
        return False


def envoyer_email_alertes(alertes, destinataires_str):
    """Envoie un e-mail immédiat pour les nouvelles alertes critiques/élevées d'un cycle."""
    if not alertes:
        return False
    if not destinataires_str or not destinataires_str.strip():
        return False
    destinataires = [d.strip() for d in destinataires_str.split(",") if d.strip()]
    if not destinataires:
        return False

    lignes = []
    for a in alertes:
        lignes.append(
            f"[{(a.get('severity') or '').upper()}] {a.get('type')}\n"
            f"  Asset concerné : {a.get('asset_concerne', 'N/A')}\n"
            f"  Source         : {a.get('source_api')}\n"
            f"  Détails        : {a.get('details', '')}"
        )

    corps = (
        f"AEGIS MONITOR — {len(alertes)} nouvelle(s) alerte(s) critique(s)/élevée(s) détectée(s)\n"
        f"Exécution : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        + "\n\n".join(lignes)
        + "\n\n— Généré automatiquement par le pipeline AEGIS MONITOR."
    )
    sujet = f"[AEGIS MONITOR] {len(alertes)} nouvelle(s) alerte(s) critique(s)/élevée(s)"
    return _envoyer_email_smtp(destinataires, sujet, corps)


# ---- Digest quotidien (résumé de 24h, envoyé une seule fois par jour à heure fixe) ----

def _lire_dernier_digest_envoye():
    """Retourne la date (YYYY-MM-DD) du dernier digest envoyé, ou None."""
    if not os.path.exists(DIGEST_STATE_PATH):
        return None
    try:
        with open(DIGEST_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("last_sent_date")
    except Exception:
        return None


def _marquer_digest_envoye(date_str):
    try:
        with open(DIGEST_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump({"last_sent_date": date_str}, f)
    except OSError as e:
        print(f"⚠️ Impossible d'enregistrer l'état du digest ({DIGEST_STATE_PATH}) : {e}\n")


def construire_corps_digest():
    """Construit le texte du résumé quotidien à partir des alertes des dernières 24h."""
    colonnes = ["id", "source_api", "type", "asset_recherche", "asset_concerne",
                "details", "date_detection", "severity", "date_insertion",
                "country", "sector"]

    alertes_brutes = lire_toutes_les_alertes()
    maintenant = datetime.now()
    seuil_24h = maintenant.timestamp() - 24 * 3600

    total = 0
    par_severite = {"critique": 0, "eleve": 0, "faible": 0}
    par_source = {}

    for ligne in alertes_brutes:
        d = dict(zip(colonnes, ligne))
        date_insertion_str = d.get("date_insertion")
        if not date_insertion_str:
            continue
        try:
            dt = datetime.fromisoformat(str(date_insertion_str))
        except (ValueError, TypeError):
            continue
        if dt.timestamp() < seuil_24h:
            continue

        total += 1
        sev = (d.get("severity") or "faible").lower()
        par_severite[sev] = par_severite.get(sev, 0) + 1
        src = d.get("source_api") or "Inconnue"
        par_source[src] = par_source.get(src, 0) + 1

    lignes_severite = "\n".join(f"  - {sev.capitalize()} : {count}" for sev, count in par_severite.items())
    if par_source:
        lignes_source = "\n".join(
            f"  - {src} : {count}"
            for src, count in sorted(par_source.items(), key=lambda x: -x[1])
        )
    else:
        lignes_source = "  (aucune détection sur cette période)"

    corps = (
        f"AEGIS MONITOR — Résumé quotidien\n"
        f"Période : dernières 24 heures (généré le {maintenant.strftime('%Y-%m-%d à %H:%M')})\n\n"
        f"Total alertes : {total}\n\n"
        f"Par sévérité :\n{lignes_severite}\n\n"
        f"Par source :\n{lignes_source}\n\n"
        f"— Généré automatiquement par le pipeline AEGIS MONITOR."
    )
    return corps, total


def envoyer_digest_quotidien(destinataires_str):
    if not destinataires_str or not destinataires_str.strip():
        return False
    destinataires = [d.strip() for d in destinataires_str.split(",") if d.strip()]
    if not destinataires:
        return False

    corps, total = construire_corps_digest()
    sujet = f"[AEGIS MONITOR] Résumé quotidien — {total} alerte(s) sur 24h"
    return _envoyer_email_smtp(destinataires, sujet, corps)


def verifier_et_envoyer_digest(reglages):
    """Envoie le digest une seule fois par jour, à l'heure définie par DIGEST_HOUR."""
    if not reglages.get("notif_digest_enabled"):
        return
    destinataires = reglages.get("notif_email_recipients", "")
    if not destinataires:
        print("ℹ️ Digest quotidien activé mais aucun destinataire configuré "
              "(Settings > Team Management > Email Recipients).\n")
        return

    maintenant = datetime.now()
    if maintenant.hour != DIGEST_HOUR:
        return  # on n'est pas dans l'heure prévue pour le digest

    aujourdhui = maintenant.strftime("%Y-%m-%d")
    if _lire_dernier_digest_envoye() == aujourdhui:
        return  # déjà envoyé aujourd'hui, on ne le renvoie pas à chaque cycle de la même heure

    print(f"=== Envoi du digest quotidien ({DIGEST_HOUR}h) ===")
    if envoyer_digest_quotidien(destinataires):
        _marquer_digest_envoye(aujourdhui)


# ============================================
# 4. FONCTION PRINCIPALE
# ============================================

def executer_recherche():
    print(f"\n========================================")
    print(f"Exécution lancée à : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"========================================\n")

    reglages = charger_reglages()
    seuil_minimal = SEVERITY_RANK.get(reglages["monitoring_alert_threshold"], 1)
    
    # ===== CHARGEMENT DES ASSETS DEPUIS LE FICHIER JSON =====
    mes_assets = charger_assets_depuis_json()
    mes_domaines = charger_domaines_depuis_json()
    mes_emails = charger_emails_depuis_json()
    
    print(f"Assets chargés depuis {ASSETS_FILE} :")
    print(f"  - Mots-clés/assets: {mes_assets}")
    print(f"  - Domaines: {mes_domaines}")
    print(f"  - Emails: {mes_emails}\n")
    
    print(f"Réglages actifs — RansomwareLive: {reglages['monitoring_src_ransomwarelive']} | "
          f"HudsonRock: {reglages['monitoring_src_hudsonrock']} | "
          f"CheckTheSum: {reglages['monitoring_src_checkthesum']} | "
          f"RansomLook: {reglages['monitoring_src_ransomlook']} | "
          f"Tunisia Watch: {reglages['monitoring_tunisia_watch']} | "
          f"APT Watch: {reglages['monitoring_apt_watch']} | "
          f"deepdarkCTI: {reglages['monitoring_deepdarkcti']} | "
          f"Seuil: {reglages['monitoring_alert_threshold']} | "
          f"Email destinataires: {reglages.get('notif_email_recipients') or '(aucun)'}\n")

    toutes_les_alertes = []
    victimes_globales = []

    print("########## RECHERCHE PAR DOMAINE ##########\n")

    if reglages["monitoring_src_ransomwarelive"]:
        print("=== Étape 1 : Recherche sur Ransomware.live (mots-clés) ===")
        victimes_globales = recuperer_victimes_ransomware()
        resultats_ransomware = chercher_dans_ransomware(victimes_globales, mes_assets)
        print(f"{len(resultats_ransomware)} correspondance(s) trouvée(s)\n")
        toutes_les_alertes.extend(resultats_ransomware)
    else:
        print("=== Étape 1 : Ransomware.live désactivé ===\n")

    if reglages["monitoring_src_hudsonrock"]:
        print("=== Étape 2 : Vérification Hudson Rock (domaines) ===")
        for domaine in mes_domaines:
            resultat_hr = verifier_domaine_hudsonrock(domaine)
            if resultat_hr:
                alerte_hr = normaliser_resultat_hudsonrock(resultat_hr, domaine)
                toutes_les_alertes.append(alerte_hr)
                print(f"Résultat pour {domaine} : {alerte_hr['details']}")
        print()
    else:
        print("=== Étape 2 : Hudson Rock (domaines) désactivé ===\n")

    if reglages["monitoring_src_checkthesum"]:
        print("=== Étape 3 : Vérification Check-The-Sum ===")
        urls_malveillantes = recuperer_domaines_checkthesum()
        resultats_cts = chercher_dans_checkthesum(urls_malveillantes, mes_assets + mes_domaines)
        print(f"{len(resultats_cts)} correspondance(s) trouvée(s) sur {len(urls_malveillantes)} URL(s) analysée(s)\n")
        toutes_les_alertes.extend(resultats_cts)
    else:
        print("=== Étape 3 : Check-The-Sum désactivé ===\n")

    if reglages["monitoring_src_ransomlook"]:
        print("=== Étape 4 : Recherche sur RansomLook.io ===")
        resultats_ransomlook = rechercher_ransomlook(mes_assets)
        print(f"{len(resultats_ransomlook)} correspondance(s) trouvée(s)\n")
        toutes_les_alertes.extend(resultats_ransomlook)
    else:
        print("=== Étape 4 : RansomLook désactivé ===\n")

    print("########## RECHERCHE PAR EMAIL ##########\n")

    if reglages["monitoring_src_hudsonrock"]:
        print("=== Étape 5 : Vérification Hudson Rock (emails) ===")
        for email in mes_emails:
            resultat_hr_email = verifier_email_hudsonrock(email)
            if resultat_hr_email:
                alerte_hr_email = normaliser_resultat_hudsonrock_email(resultat_hr_email, email)
                toutes_les_alertes.append(alerte_hr_email)
                print(f"Résultat pour {email} : {alerte_hr_email['details']}")
        print()
    else:
        print("=== Étape 5 : Hudson Rock (emails) désactivé ===\n")

    print("########## RANSOMWARE INTELLIGENCE ##########\n")

    if reglages["monitoring_src_ransomwarelive"]:
        print("=== Étape 6 : Flux global des victimes ransomware ===")
        resultats_flux_global = [normaliser_victime_flux_global(v) for v in victimes_globales]
        print(f"{len(resultats_flux_global)} victime(s) ajoutée(s) au flux global\n")
        toutes_les_alertes.extend(resultats_flux_global)
    else:
        print("=== Étape 6 : Flux global désactivé ===\n")

    if reglages["monitoring_tunisia_watch"]:
        print("=== Étape 7 : Tunisia Watch — victimes ransomware en Tunisie ===")
        victimes_tn = recuperer_victimes_pays("TN")
        resultats_tn = [normaliser_victime_pays(v, "TN") for v in victimes_tn]
        print(f"{len(resultats_tn)} victime(s) tunisienne(s) trouvée(s)\n")
        toutes_les_alertes.extend(resultats_tn)
    else:
        print("=== Étape 7 : Tunisia Watch désactivé ===\n")

    if reglages["monitoring_apt_watch"]:
        print("=== Étape 8 : APT Watch — mentions dans des rapports APT publics ===")
        mots_cles_apt = mes_assets + ["Tunisia", "Tunisie"]
        resultats_apt = rechercher_aptnotes(mots_cles_apt)
        print(f"{len(resultats_apt)} mention(s) trouvée(s) dans les titres de rapports APT\n")
        toutes_les_alertes.extend(resultats_apt)
    else:
        print("=== Étape 8 : APT Watch désactivé ===\n")

    if reglages["monitoring_deepdarkcti"]:
        print("=== Étape 9 : Scraping deepdarkCTI ===")
        stats_ddcti = recuperer_statut_deepdarkcti()
        if stats_ddcti:
            toutes_les_alertes.append(normaliser_statut_deepdarkcti(stats_ddcti))
            print(f"{stats_ddcti['online']} sites ONLINE sur {stats_ddcti['total']} suivis\n")
        else:
            print("Aucune donnée récupérée depuis deepdarkCTI\n")
    else:
        print("=== Étape 9 : deepdarkCTI désactivé ===\n")

    # Filtrage selon le seuil
    avant_filtre = len(toutes_les_alertes)
    toutes_les_alertes = [a for a in toutes_les_alertes
                          if SEVERITY_RANK.get(a.get("severity", "faible"), 1) >= seuil_minimal]
    ignorees = avant_filtre - len(toutes_les_alertes)
    if ignorees:
        print(f"{ignorees} alerte(s) sous le seuil « {reglages['monitoring_alert_threshold']} » ignorée(s).")

    # Sauvegarde
    creer_base()
    nouvelles = 0
    alertes_reellement_inserees = []
    for alerte in toutes_les_alertes:
        if sauvegarder_alerte(alerte):
            nouvelles += 1
            alertes_reellement_inserees.append(alerte)

    print(f"\n=== {nouvelles} nouvelle(s) alerte(s) sauvegardée(s) en base "
          f"(sur {len(toutes_les_alertes)} traitée(s), doublons ignorés) ===\n")

    # Export vers Wazuh
    if reglages.get("monitoring_wazuh_export", True):
        exporter_alertes_vers_wazuh(alertes_reellement_inserees)
        
        # Envoi Syslog pour les alertes critiques
        for alerte in alertes_reellement_inserees:
            if alerte.get('severity') in ['critique', 'eleve']:
                envoyer_alerte_syslog(alerte)

    # Envoi Email pour les alertes critiques/élevées, vers les destinataires
    # configurés dans Settings > Team Management > Email Recipients.
    destinataires_email = reglages.get("notif_email_recipients", "")
    alertes_critiques_elevees = [a for a in alertes_reellement_inserees if a.get('severity') in ['critique', 'eleve']]
    if alertes_critiques_elevees and destinataires_email:
        envoyer_email_alertes(alertes_critiques_elevees, destinataires_email)
    elif alertes_critiques_elevees and not destinataires_email:
        print("ℹ️ Alertes critiques/élevées détectées mais aucun destinataire configuré "
              "(Settings > Team Management > Email Recipients).\n")

    # Résumé quotidien (digest), envoyé une seule fois par jour à DIGEST_HOUR
    verifier_et_envoyer_digest(reglages)


# ============================================
# 5. AUTOMATISATION
# ============================================

if __name__ == "__main__":
    # Créer un fichier d'assets par défaut s'il n'existe pas
    if not os.path.exists(ASSETS_FILE):
        assets_par_defaut = [
            {"identifier": "yueki", "type": "Mot-clé", "date_ajout": datetime.now().isoformat()},
            {"identifier": "entreprise-test", "type": "Mot-clé", "date_ajout": datetime.now().isoformat()},
            {"identifier": "monoprix.tn", "type": "Domaine", "date_ajout": datetime.now().isoformat()},
            {"identifier": "manvirdi2000@gmail.com", "type": "Email", "date_ajout": datetime.now().isoformat()},
        ]
        with open(ASSETS_FILE, "w", encoding="utf-8") as f:
            json.dump(assets_par_defaut, f, indent=2, ensure_ascii=False)
        print(f"✅ Fichier {ASSETS_FILE} créé avec les assets par défaut.")
    
    while True:
        executer_recherche()
        reglages = charger_reglages()
        try:
            intervalle_minutes = int(reglages["monitoring_scan_interval"])
        except (TypeError, ValueError):
            intervalle_minutes = 2
        print(f"Prochaine exécution dans {intervalle_minutes} minute(s) (Ctrl+C pour arrêter)...")
        time.sleep(intervalle_minutes * 60)