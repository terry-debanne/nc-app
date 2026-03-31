const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

console.log('[DB] DATABASE_URL:', process.env.DATABASE_URL ? 'OK trouvee' : 'MANQUANTE');

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`CREATE TABLE IF NOT EXISTS utilisateurs (
      id SERIAL PRIMARY KEY,
      nom VARCHAR(100) NOT NULL,
      prenom VARCHAR(100),
      login VARCHAR(50) UNIQUE NOT NULL,
      pin_hash VARCHAR(255) NOT NULL,
      role VARCHAR(20) DEFAULT 'operateur',
      actif BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      nom VARCHAR(150) NOT NULL,
      contact VARCHAR(150),
      email VARCHAR(150),
      telephone VARCHAR(50),
      adresse TEXT,
      type_client VARCHAR(50) DEFAULT 'Particulier',
      actif BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS parametres (
      id SERIAL PRIMARY KEY,
      categorie VARCHAR(50) NOT NULL,
      valeur VARCHAR(200) NOT NULL,
      ordre INTEGER DEFAULT 0,
      actif BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS parametres_liens (
      id SERIAL PRIMARY KEY,
      operation_valeur VARCHAR(200) NOT NULL,
      cause_valeur VARCHAR(200) NOT NULL,
      UNIQUE(operation_valeur, cause_valeur)
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS nc_internes (
      id SERIAL PRIMARY KEY,
      numero VARCHAR(30) UNIQUE NOT NULL,
      date_detection DATE NOT NULL,
      of_ref VARCHAR(100),
      client_id INTEGER REFERENCES clients(id),
      client_nom VARCHAR(150),
      designation_piece TEXT,
      operation VARCHAR(100),
      type_defaut VARCHAR(100),
      description TEXT,
      qte_nc INTEGER,
      qte_totale INTEGER,
      cout_interne NUMERIC(10,2),
      montant_client NUMERIC(10,2),
      cause TEXT,
      action_corrective TEXT,
      responsable VARCHAR(100),
      delai_cloture DATE,
      statut VARCHAR(30) DEFAULT 'En attente',
      created_by INTEGER REFERENCES utilisateurs(id),
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS nc_externes (
      id SERIAL PRIMARY KEY,
      numero VARCHAR(30) UNIQUE NOT NULL,
      date_reclamation DATE NOT NULL,
      date_livraison DATE,
      numero_bl VARCHAR(100),
      client_id INTEGER REFERENCES clients(id),
      client_nom VARCHAR(150),
      contact_client VARCHAR(150),
      designation_piece TEXT,
      type_defaut VARCHAR(100),
      description TEXT,
      qte_reclamee INTEGER,
      qte_livree INTEGER,
      cout_interne NUMERIC(10,2),
      impact_financier NUMERIC(10,2),
      decision VARCHAR(100),
      cause_racine TEXT,
      action_corrective TEXT,
      responsable VARCHAR(100),
      delai_reponse DATE,
      statut VARCHAR(30) DEFAULT 'En attente',
      created_by INTEGER REFERENCES utilisateurs(id),
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS nc_temps (
      id SERIAL PRIMARY KEY,
      numero VARCHAR(30) UNIQUE NOT NULL,
      date_fabrication DATE NOT NULL,
      of_ref VARCHAR(100),
      client_id INTEGER REFERENCES clients(id),
      client_nom VARCHAR(150),
      operation VARCHAR(150),
      temps_prevu INTEGER,
      temps_reel INTEGER,
      nbre_pieces INTEGER,
      cout_interne NUMERIC(10,2),
      cause TEXT,
      type_cause VARCHAR(100),
      action_amelioration TEXT,
      responsable VARCHAR(100),
      statut VARCHAR(30) DEFAULT 'En attente',
      created_by INTEGER REFERENCES utilisateurs(id),
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await client.query(`CREATE TABLE IF NOT EXISTS nc_materiel (
      id SERIAL PRIMARY KEY,
      numero VARCHAR(30) UNIQUE NOT NULL,
      date_constat DATE NOT NULL,
      of_operation VARCHAR(150),
      equipement VARCHAR(150),
      num_inventaire VARCHAR(80),
      type_degradation VARCHAR(100),
      description TEXT,
      gravite INTEGER,
      origine TEXT,
      cout_pieces NUMERIC(10,2) DEFAULT 0,
      cout_mo NUMERIC(10,2) DEFAULT 0,
      cout_indisponibilite NUMERIC(10,2) DEFAULT 0,
      action_realisee TEXT,
      type_intervention VARCHAR(100),
      prestataire VARCHAR(150),
      date_cloture DATE,
      statut VARCHAR(30) DEFAULT 'En attente',
      created_by INTEGER REFERENCES utilisateurs(id),
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    // Migrations colonnes si elles n'existent pas encore
    const migrations = [
      `ALTER TABLE nc_internes ADD COLUMN IF NOT EXISTS client_id INTEGER REFERENCES clients(id)`,
      `ALTER TABLE nc_internes ADD COLUMN IF NOT EXISTS client_nom VARCHAR(150)`,
      `ALTER TABLE nc_internes ADD COLUMN IF NOT EXISTS cout_interne NUMERIC(10,2)`,
      `ALTER TABLE nc_internes ADD COLUMN IF NOT EXISTS montant_client NUMERIC(10,2)`,
      `ALTER TABLE nc_externes ADD COLUMN IF NOT EXISTS client_id INTEGER REFERENCES clients(id)`,
      `ALTER TABLE nc_externes ADD COLUMN IF NOT EXISTS client_nom VARCHAR(150)`,
      `ALTER TABLE nc_externes ADD COLUMN IF NOT EXISTS cout_interne NUMERIC(10,2)`,
      `ALTER TABLE nc_temps ADD COLUMN IF NOT EXISTS client_id INTEGER REFERENCES clients(id)`,
      `ALTER TABLE nc_temps ADD COLUMN IF NOT EXISTS client_nom VARCHAR(150)`,
      `ALTER TABLE nc_temps ADD COLUMN IF NOT EXISTS cout_interne NUMERIC(10,2)`,
    ];
    for (const m of migrations) {
      try { await client.query(m); } catch(e) { /* colonne existe deja */ }
    }

    await client.query('COMMIT');

    // Admin par defaut
    const { rows } = await client.query("SELECT id FROM utilisateurs WHERE login='admin'");
    if (rows.length === 0) {
      const bcrypt = require('bcryptjs');
      const hash = await bcrypt.hash('690769', 12);
      await client.query(
        "INSERT INTO utilisateurs (nom, prenom, login, pin_hash, role) VALUES ($1,$2,$3,$4,$5)",
        ['Admin', 'Systeme', 'admin', hash, 'admin']
      );
      console.log('[DB] Utilisateur admin cree');
    }

    // Parametres par defaut
    const { rows: pRows } = await client.query("SELECT COUNT(*) FROM parametres");
    if (parseInt(pRows[0].count) === 0) {
      const defaults = [
        ['operation', 'Préparation surface', 1],
        ['operation', 'Accrochage', 2],
        ['operation', 'Dégraissage', 3],
        ['operation', 'Phosphatation', 4],
        ['operation', 'Thermolaquage', 5],
        ['operation', 'Cuisson', 6],
        ['operation', 'Contrôle', 7],
        ['operation', 'Décrochage', 8],
        ['operation', 'Retouche', 9],
        ['type_defaut', 'Couleur incorrecte', 1],
        ['type_defaut', 'Aspect de surface', 2],
        ['type_defaut', 'Épaisseur hors tolérance', 3],
        ['type_defaut', 'Adhérence insuffisante', 4],
        ['type_defaut', 'Bullage', 5],
        ['type_defaut', 'Rayure', 6],
        ['type_defaut', 'Coulure', 7],
        ['type_defaut', 'Corps étranger', 8],
        ['type_defaut', 'Autre', 9],
        ['type_cause', 'Panne machine', 1],
        ['type_cause', 'Qualité matière entrante', 2],
        ['type_cause', 'Complexité pièce', 3],
        ['type_cause', 'Manque effectif', 4],
        ['type_cause', 'Erreur gamme', 5],
        ['type_cause', 'Formation opérateur', 6],
        ['type_cause', 'Autre', 7],
        ['type_degradation', 'Panne électrique', 1],
        ['type_degradation', 'Panne mécanique', 2],
        ['type_degradation', 'Usure mécanique', 3],
        ['type_degradation', 'Dégradation outillage', 4],
        ['type_degradation', 'Choc / accident', 5],
        ['type_degradation', 'Corrosion', 6],
        ['type_degradation', 'Fuite hydraulique', 7],
        ['type_degradation', 'Autre', 8],
        ['decision', 'Avoir total', 1],
        ['decision', 'Avoir partiel', 2],
        ['decision', 'Reprise gratuite', 3],
        ['decision', 'Remplacement', 4],
        ['decision', 'Refus réclamation', 5],
        ['responsable', 'Terry', 1],
        ['responsable', 'Ambre', 2],
        ['responsable', 'Vincent', 3],
        ['responsable', 'Tom', 4],
        ['responsable', 'Cédric', 5],
        ['responsable', 'Dorothée', 6],
        ['cause', 'Erreur opérateur', 1],
        ['cause', 'Erreur de gamme / fiche OF', 2],
        ['cause', 'Défaut matière première', 3],
        ['cause', 'Panne équipement', 4],
        ['cause', 'Mauvaise préparation surface', 5],
        ['cause', 'Paramètres four incorrects', 6],
        ['cause', 'Erreur étiquetage / RAL', 7],
        ['cause', 'Problème emballage / transport', 8],
        ['cause', 'Autre', 9],
      ];
      for (const [cat, val, ord] of defaults) {
        await client.query(
          "INSERT INTO parametres (categorie, valeur, ordre) VALUES ($1,$2,$3)",
          [cat, val, ord]
        );
      }
      console.log('[DB] Parametres par defaut inseres');
    }

    // Migration : ajouter responsable et cause si manquants
    const { rows: hasResp } = await client.query("SELECT COUNT(*) FROM parametres WHERE categorie='responsable'");
    if (parseInt(hasResp[0].count) === 0) {
      const defResps = [['Terry',1],['Ambre',2],['Vincent',3],['Tom',4],['Cédric',5],['Dorothée',6]];
      for (const [val, ord] of defResps)
        await client.query("INSERT INTO parametres (categorie,valeur,ordre) VALUES ('responsable',$1,$2)", [val, ord]);
      console.log('[DB] Responsables par defaut inseres');
    }
    const { rows: hasCause } = await client.query("SELECT COUNT(*) FROM parametres WHERE categorie='cause'");
    if (parseInt(hasCause[0].count) === 0) {
      const defCauses = [['Erreur opérateur',1],['Erreur de gamme / fiche OF',2],['Défaut matière première',3],['Panne équipement',4],['Mauvaise préparation surface',5],['Paramètres four incorrects',6],['Erreur étiquetage / RAL',7],['Problème emballage / transport',8],['Autre',9]];
      for (const [val, ord] of defCauses)
        await client.query("INSERT INTO parametres (categorie,valeur,ordre) VALUES ('cause',$1,$2)", [val, ord]);
      console.log('[DB] Causes par defaut inserees');
    }

    console.log('[DB] Base de donnees initialisee.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[DB] Erreur init:', err.message);
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB };
