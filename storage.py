import sqlite3

DB_NAME = "darkweb_monitoring.db"


def creer_base():
    """Crée la base de données et la table si elles n'existent pas encore.

    Ajoute aussi un index UNIQUE sur (source_api, asset_recherche, details) :
    ça empêche la base d'accepter deux fois la même alerte (même source, même
    asset, même contenu). C'est ce qui bloque les doublons créés par le
    pipeline qui tourne en boucle toutes les 2 minutes.

    Gère aussi la migration automatique des colonnes "country" et "sector"
    (ajoutées pour la partie Ransomware Intelligence / Tunisia Watch) sur une
    base déjà existante, sans avoir besoin de la réinitialiser.
    """
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
            date_insertion TEXT DEFAULT CURRENT_TIMESTAMP,
            country TEXT,
            sector TEXT
        )
    """)

    # Migration défensive : si la table existait déjà sans ces colonnes
    # (base créée avant cette mise à jour), on les ajoute sans perdre les
    # données déjà présentes.
    cursor.execute("PRAGMA table_info(alertes)")
    colonnes_existantes = {ligne[1] for ligne in cursor.fetchall()}
    if "country" not in colonnes_existantes:
        cursor.execute("ALTER TABLE alertes ADD COLUMN country TEXT")
    if "sector" not in colonnes_existantes:
        cursor.execute("ALTER TABLE alertes ADD COLUMN sector TEXT")

    # Empêche les doublons : une même alerte (source + asset + contenu)
    # ne peut exister qu'une seule fois dans la table.
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_alerte_unique
        ON alertes (source_api, asset_recherche, details)
    """)
    connexion.commit()
    connexion.close()


def sauvegarder_alerte(alerte):
    """Insère une alerte normalisée dans la base.

    Si une alerte identique (même source_api, même asset_recherche, même
    details) existe déjà, l'insertion est silencieusement ignorée grâce à
    l'index unique + INSERT OR IGNORE : pas de doublon, pas d'erreur.

    "country" et "sector" sont optionnels (toutes les sources ne les
    fournissent pas) — on utilise .get() pour éviter un KeyError si absents.

    Retourne True si une nouvelle ligne a réellement été insérée,
    False si c'était un doublon (donc ignoré).
    """
    connexion = sqlite3.connect(DB_NAME)
    cursor = connexion.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO alertes
            (source_api, type, asset_recherche, asset_concerne, details,
             date_detection, severity, country, sector)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alerte["source_api"],
        alerte["type"],
        alerte["asset_recherche"],
        alerte["asset_concerne"],
        alerte["details"],
        alerte["date_detection"],
        alerte["severity"],
        alerte.get("country"),
        alerte.get("sector"),
    ))
    connexion.commit()
    nouvelle_ligne = cursor.rowcount > 0  # 1 si insérée, 0 si ignorée (doublon)
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