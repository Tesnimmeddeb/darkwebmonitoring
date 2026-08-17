import sqlite3

DB_NAME = "darkweb_monitoring.db"

def creer_base():
    """Crée la base de données et la table si elles n'existent pas encore.
    Index UNIQUE sur (source_api, asset_recherche, details, jour) : une même
    alerte ne peut être enregistrée qu'UNE FOIS PAR JOUR. Ça évite le spam
    du pipeline qui tourne toutes les 2 minutes, tout en laissant le total
    progresser naturellement jour après jour."""
    connexion = sqlite3.connect(DB_NAME)
    cursor = connexion.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_api TEXT,
            type TEXT,
            asset_recherche TEXT,
            asset_concerne TEXT,
            details TEXT,
            date_detection TEXT,
            severity TEXT,
            date_insertion TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_alerte_unique
        ON alertes (source_api, asset_recherche, details, date(date_insertion))
    """)
    connexion.commit()
    connexion.close()

def sauvegarder_alerte(alerte):
    """Insère une alerte normalisée dans la base.
    Grâce à INSERT OR IGNORE + l'index unique journalier, la même alerte
    n'est enregistrée qu'une fois par jour, même si le pipeline tourne
    plusieurs fois dans la journée."""
    connexion = sqlite3.connect(DB_NAME)
    cursor = connexion.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO alertes
            (source_api, type, asset_recherche, asset_concerne, details, date_detection, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alerte["source_api"],
        alerte["type"],
        alerte["asset_recherche"],
        alerte["asset_concerne"],
        alerte["details"],
        alerte["date_detection"],
        alerte["severity"]
    ))
    connexion.commit()
    nouvelle_ligne = cursor.rowcount > 0
    connexion.close()
    return nouvelle_ligne

def lire_toutes_les_alertes():
    """Récupère toutes les alertes stockées (utile pour vérifier ou pour le dashboard)"""
    connexion = sqlite3.connect(DB_NAME)
    cursor = connexion.cursor()
    cursor.execute("SELECT * FROM alertes")
    resultats = cursor.fetchall()
    connexion.close()
    return resultats