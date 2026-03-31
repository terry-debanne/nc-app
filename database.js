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

    await client.query(`CREATE TABLE IF NOT EXISTS nc_internes (
      id SERIAL PRIMARY KEY,
      numero VARCHAR(30) UNIQUE NOT NULL,
      date_detection DATE NOT NULL,
      of_ref VARCHAR(100),
      client VARCHAR(150),
      designation_piece TEXT,
      operation VARCHAR(100),
      type_defaut VARCHAR(100),
      description TEXT,
      qte_nc INTEGER,
      qte_totale INTEGER,
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
      client VARCHAR(150),
      contact_client VARCHAR(150),
      designation_piece TEXT,
      type_defaut VARCHAR(100),
      description TEXT,
      qte_reclamee INTEGER,
      qte_livree INTEGER,
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
      client VARCHAR(150),
      operation VARCHAR(150),
      temps_prevu INTEGER,
      temps_reel INTEGER,
      nbre_pieces INTEGER,
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

    await client.query('COMMIT');

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
