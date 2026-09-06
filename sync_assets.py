# sync_assets.py
import json
import os
from datetime import datetime

SETTINGS_FILE = "app_settings.json"
ASSETS_FILE = "monitored_assets.json"

def sync_app_to_monitored():
    """Synchronise app_settings.json → monitored_assets.json"""
    
    print("=" * 60)
    print("🔄 SYNCHRONISATION app_settings.json → monitored_assets.json")
    print("=" * 60)
    
    # Vérifier si app_settings.json existe
    if not os.path.exists(SETTINGS_FILE):
        print("❌ app_settings.json non trouvé !")
        return False
    
    # Charger app_settings.json
    with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
        settings = json.load(f)
    
    assets = []
    seen = set()
    
    # 1. Ajouter les domaines
    print("\n📋 Récupération des domaines...")
    for domaine in settings.get("monitored_domains", []):
        if domaine not in seen:
            assets.append({
                "identifier": domaine,
                "type": "Domaine",
                "date_ajout": datetime.now().isoformat()
            })
            seen.add(domaine)
            print(f"   ✅ Domaine: {domaine}")
    
    # 2. Ajouter les mots-clés
    print("\n📋 Récupération des mots-clés...")
    for keyword in settings.get("monitored_keywords", []):
        if keyword not in seen:
            # Vérifier si c'est un domaine
            if "." in keyword and not keyword.endswith("."):
                asset_type = "Domaine"
            else:
                asset_type = "Mot-clé"
            assets.append({
                "identifier": keyword,
                "type": asset_type,
                "date_ajout": datetime.now().isoformat()
            })
            seen.add(keyword)
            print(f"   ✅ Mot-clé: {keyword} ({asset_type})")
    
    # 3. Ajouter les emails
    print("\n📋 Récupération des emails...")
    for email in settings.get("monitored_emails", []):
        if email not in seen:
            assets.append({
                "identifier": email,
                "type": "Email",
                "date_ajout": datetime.now().isoformat()
            })
            seen.add(email)
            print(f"   ✅ Email: {email}")
    
    # 4. Ajouter les assets de monitoring_assets (si présents)
    print("\n📋 Récupération des monitoring_assets...")
    for asset in settings.get("monitoring_assets", []):
        if isinstance(asset, dict):
            identifier = asset.get("identifier")
            if identifier and identifier not in seen:
                assets.append(asset)
                seen.add(identifier)
                print(f"   ✅ Asset: {identifier} ({asset.get('type', 'Inconnu')})")
        elif isinstance(asset, str):
            if asset not in seen:
                assets.append({
                    "identifier": asset,
                    "type": "Mot-clé",
                    "date_ajout": datetime.now().isoformat()
                })
                seen.add(asset)
                print(f"   ✅ Asset: {asset} (Mot-clé)")
    
    # Sauvegarder dans monitored_assets.json
    print("\n💾 Sauvegarde dans monitored_assets.json...")
    with open(ASSETS_FILE, "w", encoding="utf-8") as f:
        json.dump(assets, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 60)
    print(f"✅ Synchronisation terminée ! {len(assets)} assets sauvegardés dans monitored_assets.json")
    print("=" * 60)
    
    print("\n📋 Liste des assets maintenant actifs :")
    for asset in assets:
        print(f"  - {asset['identifier']} ({asset['type']})")
    
    return True

if __name__ == "__main__":
    sync_app_to_monitored()