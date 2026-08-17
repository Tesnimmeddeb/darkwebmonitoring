import requests
import os
import json
import time
from datetime import datetime
from dotenv import load_dotenv
from storage import creer_base, sauvegarder_alerte, lire_toutes_les_alertes

load_dotenv()

# ============================================
# 0. LECTURE DES RÉGLAGES (settings.json, partagé avec le Dashboard)
# ============================================

SETTINGS_FILE = "app_settings.json"

# Valeurs par défaut si le fichier n'existe pas encore (avant tout Save dans le Dashboard),
# ou si un réglage précis est absent. "faible" comme seuil par défaut = on ne perd aucune
# donnée tant que l'utilisateur n'a pas explicitement choisi de filtrer.
DEFAULT_MAIN_SETTINGS = {
    "monitoring_scan_interval": "2",
    "monitoring_src_hudsonrock": True,
    "monitoring_src_ransomwarelive": True,
    "monitoring_src_checkthesum": True,
    "monitoring_src_ransomlook": True,
    "monitoring_alert_threshold": "faible",
}

SEVERITY_RANK = {"critique": 3, "eleve": 2, "faible": 1}


def charger_reglages():
    """Relit settings.json à chaque appel (donc à chaque cycle) pour que les
    changements faits dans le Dashboard s'appliquent sans avoir à redémarrer
    main.py — sauf pour l'intervalle de scan, qui ne peut prendre effet qu'au
    prochain cycle puisque le programme est déjà en train d'attendre (time.sleep)."""
    data = {}
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ Impossible de lire {SETTINGS_FILE} ({e}) — utilisation des valeurs par défaut.")
            data = {}
    reglages = dict(DEFAULT_MAIN_SETTINGS)
    reglages.update({k: v for k, v in data.items() if k in DEFAULT_MAIN_SETTINGS})
    return reglages


# ============================================
# 1. FONCTIONS DE RECUPERATION (APPEL DES API)
# ============================================

def recuperer_victimes_ransomware():
    url = "https://api.ransomware.live/recentvictims"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return []

def recuperer_domaines_checkthesum():
    """Télécharge la liste des URLs/domaines vus dans les commandes shell des
    attaquants, observées par le honeypot Cowrie de Check-The-Sum (gratuit,
    sans clé API). Ce sont typiquement des points de dépôt de malware ou des
    endpoints C2 — si un de nos domaines/mots-clés y apparaît, ça signale une
    infrastructure malveillante qui utilise potentiellement notre nom."""
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

def rechercher_ransomlook(mots_cles):
    """Interroge l'API publique de RansomLook.io (gratuite, sans clé) pour
    chaque mot-clé/asset. Deuxième agrégateur de fuites ransomware,
    indépendant de Ransomware.live — les deux ne couvrent pas exactement les
    mêmes sites de fuite, donc ça élargit la couverture."""
    url = "https://www.ransomlook.io/api/search"
    resultats = []
    for mot_cle in mots_cles:
        try:
            response = requests.get(url, params={"query": mot_cle}, timeout=15)
            if response.status_code == 200:
                for hit in response.json():
                    resultats.append(normaliser_resultat_ransomlook(hit, mot_cle))
            else:
                print(f"Erreur RansomLook (recherche '{mot_cle}') : {response.status_code}")
        except requests.RequestException as e:
            print(f"Erreur réseau RansomLook : {e}")
    return resultats

def verifier_domaine_hudsonrock(domaine):
    """Interroge Hudson Rock pour vérifier les compromissions infostealer liées à un domaine"""
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domaine}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erreur Hudson Rock (domaine) : {response.status_code}")
        return None

def verifier_email_hudsonrock(email):
    """Interroge Hudson Rock pour vérifier si un email est lié à un ordinateur infecté"""
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erreur Hudson Rock (email) : {response.status_code}")
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
        "severity": "critique"
    }

def normaliser_resultat_checkthesum(url_brute, asset_recherche):
    return {
        "source_api": "CheckTheSum",
        "type": "malicious_infrastructure_mention",
        "asset_recherche": asset_recherche,
        "asset_concerne": url_brute,
        "details": f"Notre terme surveillé apparaît dans une URL/domaine observé(e) dans des "
                    f"commandes d'attaquants (honeypot Cowrie) : {url_brute}",
        "date_detection": None,
        "severity": "eleve"
    }

def normaliser_resultat_ransomlook(hit_brut, asset_recherche):
    return {
        "source_api": "RansomLook",
        "type": "ransomware_leak",
        "asset_recherche": asset_recherche,
        "asset_concerne": hit_brut.get("post_title"),
        "details": f"Groupe ransomware: {hit_brut.get('group_name')}, Publication: {hit_brut.get('post_title')}",
        "date_detection": hit_brut.get("discovered"),
        "severity": "critique"
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
        "severity": severite
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
            "severity": "faible"
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
        "severity": severite
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
    """Cherche si un de nos mots-clés/domaines apparaît dans les URLs vues par
    le honeypot. mots_cles est une LISTE de termes à tester un par un (pas un
    seul mot à découper caractère par caractère — attention à l'ordre des
    arguments si tu appelles cette fonction ailleurs)."""
    resultats_normalises = []
    for url in urls_malveillantes:
        url_lower = url.lower()
        for mot_cle in mots_cles:
            if mot_cle.lower() in url_lower:
                resultats_normalises.append(normaliser_resultat_checkthesum(url, mot_cle))
    return resultats_normalises

# ============================================
# 4. FONCTION PRINCIPALE
# ============================================

def executer_recherche():
    print(f"\n========================================")
    print(f"Exécution lancée à : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"========================================\n")

    reglages = charger_reglages()
    seuil_minimal = SEVERITY_RANK.get(reglages["monitoring_alert_threshold"], 1)
    print(f"Réglages actifs — RansomwareLive: {reglages['monitoring_src_ransomwarelive']} | "
          f"HudsonRock: {reglages['monitoring_src_hudsonrock']} | "
          f"CheckTheSum: {reglages['monitoring_src_checkthesum']} | "
          f"RansomLook: {reglages['monitoring_src_ransomlook']} | "
          f"Seuil: {reglages['monitoring_alert_threshold']}\n")

    mes_assets = ["yueki", "entreprise-test"]
    mes_domaines = ["monoprix.tn"]
    mes_emails = ["manvirdi2000@gmail.com"]

    toutes_les_alertes = []

    if reglages["monitoring_src_ransomwarelive"]:
        print("=== Étape 1 : Recherche sur Ransomware.live ===")
        victimes = recuperer_victimes_ransomware()
        resultats_ransomware = chercher_dans_ransomware(victimes, mes_assets)
        print(f"{len(resultats_ransomware)} correspondance(s) trouvée(s)\n")
        toutes_les_alertes.extend(resultats_ransomware)
    else:
        print("=== Étape 1 : Ransomware.live désactivé dans Settings — ignoré ===\n")

    if reglages["monitoring_src_hudsonrock"]:
        print("=== Étape 2 : Vérification Hudson Rock (domaines) ===")
        for domaine in mes_domaines:
            resultat_hr = verifier_domaine_hudsonrock(domaine)
            if resultat_hr:
                alerte_hr = normaliser_resultat_hudsonrock(resultat_hr, domaine)
                toutes_les_alertes.append(alerte_hr)
                print(f"Résultat pour {domaine} : {alerte_hr['details']}")

        print("\n=== Étape 3 : Vérification Hudson Rock (emails) ===")
        for email in mes_emails:
            resultat_hr_email = verifier_email_hudsonrock(email)
            if resultat_hr_email:
                alerte_hr_email = normaliser_resultat_hudsonrock_email(resultat_hr_email, email)
                toutes_les_alertes.append(alerte_hr_email)
                print(f"Résultat pour {email} : {alerte_hr_email['details']}")
    else:
        print("=== Étape 2/3 : Hudson Rock désactivé dans Settings — ignoré ===")

    if reglages["monitoring_src_checkthesum"]:
        print("\n=== Étape 4 : Vérification Check-The-Sum (infrastructure malveillante) ===")
        urls_malveillantes = recuperer_domaines_checkthesum()
        resultats_cts = chercher_dans_checkthesum(urls_malveillantes, mes_assets + mes_domaines)
        print(f"{len(resultats_cts)} correspondance(s) trouvée(s) sur {len(urls_malveillantes)} URL(s) analysée(s)\n")
        toutes_les_alertes.extend(resultats_cts)
    else:
        print("\n=== Étape 4 : Check-The-Sum désactivé dans Settings — ignoré ===")

    if reglages["monitoring_src_ransomlook"]:
        print("\n=== Étape 5 : Recherche sur RansomLook.io ===")
        resultats_ransomlook = rechercher_ransomlook(mes_assets)
        print(f"{len(resultats_ransomlook)} correspondance(s) trouvée(s)\n")
        toutes_les_alertes.extend(resultats_ransomlook)
    else:
        print("\n=== Étape 5 : RansomLook désactivé dans Settings — ignoré ===")

    # Filtrage selon le seuil d'alerte choisi dans Settings (Critical only / Elevated+ / All)
    avant_filtre = len(toutes_les_alertes)
    toutes_les_alertes = [a for a in toutes_les_alertes
                          if SEVERITY_RANK.get(a["severity"], 1) >= seuil_minimal]
    ignorees = avant_filtre - len(toutes_les_alertes)
    if ignorees:
        print(f"\n{ignorees} alerte(s) sous le seuil « {reglages['monitoring_alert_threshold']} » ignorée(s).")

    creer_base()
    for alerte in toutes_les_alertes:
        sauvegarder_alerte(alerte)

    print(f"\n=== {len(toutes_les_alertes)} alerte(s) sauvegardée(s) en base ===\n")


# ============================================
# 5. AUTOMATISATION
# ============================================

if __name__ == "__main__":
    while True:
        executer_recherche()

        # Relu à chaque cycle : si l'intervalle a été changé dans Settings pendant
        # que le script tournait, le nouveau délai s'applique dès le prochain tour.
        reglages = charger_reglages()
        try:
            intervalle_minutes = int(reglages["monitoring_scan_interval"])
        except (TypeError, ValueError):
            intervalle_minutes = 2

        print(f"Prochaine exécution dans {intervalle_minutes} minute(s) "
              f"(Ctrl+C pour arrêter)...")
        time.sleep(intervalle_minutes * 60)