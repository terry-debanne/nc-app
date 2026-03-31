const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { pool, initDB } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
console.log('[ENV] PORT:', process.env.PORT);
console.log('[ENV] DATABASE_URL:', process.env.DATABASE_URL ? 'OK' : 'MANQUANTE');

const JWT_SECRET = process.env.JWT_SECRET || 'nc_ama_secret_2024';
const SESSION_DURATION = '4h';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Token invalide ou expire' });
  }
}

function managerOnly(req, res, next) {
  if (!['admin', 'manager'].includes(req.user.role))
    return res.status(403).json({ error: 'Acces reserve manager/admin' });
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Acces reserve admin' });
  next();
}

async function genNumero(prefix, table) {
  const year = new Date().getFullYear();
  const { rows } = await pool.query(
    `SELECT numero FROM ${table} WHERE numero LIKE $1 ORDER BY numero DESC LIMIT 1`,
    [`${prefix}-${year}-%`]
  );
  if (rows.length === 0) return `${prefix}-${year}-001`;
  const last = rows[0].numero;
  const seq = parseInt(last.split('-').pop(), 10) + 1;
  return `${prefix}-${year}-${String(seq).padStart(3, '0')}`;
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { login, pin } = req.body;
  if (!login || !pin) return res.status(400).json({ error: 'Login et PIN requis' });
  try {
    const { rows } = await pool.query('SELECT * FROM utilisateurs WHERE login=$1 AND actif=true', [login]);
    if (!rows.length) return res.status(401).json({ error: 'Identifiant incorrect' });
    const user = rows[0];
    const valid = await bcrypt.compare(String(pin), user.pin_hash);
    if (!valid) return res.status(401).json({ error: 'PIN incorrect' });
    const token = jwt.sign(
      { id: user.id, login: user.login, nom: user.nom, prenom: user.prenom, role: user.role },
      JWT_SECRET, { expiresIn: SESSION_DURATION }
    );
    res.json({ token, user: { id: user.id, login: user.login, nom: user.nom, prenom: user.prenom, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json(req.user));

// ── UTILISATEURS ──────────────────────────────────────────────────────────────
app.get('/api/utilisateurs', authMiddleware, adminOnly, async (req, res) => {
  const { rows } = await pool.query('SELECT id,nom,prenom,login,role,actif,created_at FROM utilisateurs ORDER BY nom');
  res.json(rows);
});

app.post('/api/utilisateurs', authMiddleware, adminOnly, async (req, res) => {
  const { nom, prenom, login, pin, role } = req.body;
  if (!nom || !login || !pin) return res.status(400).json({ error: 'Champs obligatoires manquants' });
  try {
    const hash = await bcrypt.hash(String(pin), 12);
    const { rows } = await pool.query(
      'INSERT INTO utilisateurs (nom,prenom,login,pin_hash,role) VALUES ($1,$2,$3,$4,$5) RETURNING id,nom,prenom,login,role',
      [nom, prenom || '', login, hash, role || 'operateur']
    );
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Login deja utilise' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/utilisateurs/:id', authMiddleware, adminOnly, async (req, res) => {
  const { nom, prenom, role, actif, pin } = req.body;
  try {
    if (pin) {
      const hash = await bcrypt.hash(String(pin), 12);
      await pool.query('UPDATE utilisateurs SET nom=$1,prenom=$2,role=$3,actif=$4,pin_hash=$5 WHERE id=$6',
        [nom, prenom, role, actif, hash, req.params.id]);
    } else {
      await pool.query('UPDATE utilisateurs SET nom=$1,prenom=$2,role=$3,actif=$4 WHERE id=$5',
        [nom, prenom, role, actif, req.params.id]);
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── CLIENTS ───────────────────────────────────────────────────────────────────
app.get('/api/clients', authMiddleware, async (req, res) => {
  const { search } = req.query;
  let q = 'SELECT * FROM clients WHERE actif=true';
  const params = [];
  if (search) { params.push(`%${search}%`); q += ` AND (nom ILIKE $1 OR contact ILIKE $1)`; }
  q += ' ORDER BY nom';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/clients', authMiddleware, managerOnly, async (req, res) => {
  const { nom, contact, email, telephone, adresse, type_client } = req.body;
  if (!nom) return res.status(400).json({ error: 'Nom obligatoire' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO clients (nom,contact,email,telephone,adresse,type_client) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [nom, contact||'', email||'', telephone||'', adresse||'', type_client||'Particulier']
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/clients/:id', authMiddleware, managerOnly, async (req, res) => {
  const { nom, contact, email, telephone, adresse, type_client, actif } = req.body;
  try {
    await pool.query(
      'UPDATE clients SET nom=$1,contact=$2,email=$3,telephone=$4,adresse=$5,type_client=$6,actif=$7,updated_at=NOW() WHERE id=$8',
      [nom, contact||'', email||'', telephone||'', adresse||'', type_client||'Particulier', actif!==false, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/clients/:id/historique', authMiddleware, async (req, res) => {
  const id = req.params.id;
  try {
    const [nci, nce, nct] = await Promise.all([
      pool.query(`SELECT id,numero,date_detection AS date,type_defaut,statut,cout_interne,montant_client FROM nc_internes WHERE client_id=$1 ORDER BY date_detection DESC`, [id]),
      pool.query(`SELECT id,numero,date_reclamation AS date,type_defaut,statut,cout_interne,impact_financier FROM nc_externes WHERE client_id=$1 ORDER BY date_reclamation DESC`, [id]),
      pool.query(`SELECT id,numero,date_fabrication AS date,operation,statut,cout_interne FROM nc_temps WHERE client_id=$1 ORDER BY date_fabrication DESC`, [id]),
    ]);
    res.json({ nci: nci.rows, nce: nce.rows, nct: nct.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PARAMETRES ────────────────────────────────────────────────────────────────
app.get('/api/parametres', authMiddleware, async (req, res) => {
  const { categorie } = req.query;
  let q = 'SELECT * FROM parametres WHERE actif=true';
  const params = [];
  if (categorie) { params.push(categorie); q += ` AND categorie=$1`; }
  q += ' ORDER BY categorie, ordre, valeur';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/parametres', authMiddleware, managerOnly, async (req, res) => {
  const { categorie, valeur } = req.body;
  if (!categorie || !valeur) return res.status(400).json({ error: 'Categorie et valeur obligatoires' });
  try {
    const { rows: existing } = await pool.query(
      'SELECT id FROM parametres WHERE categorie=$1 AND valeur=$2', [categorie, valeur]
    );
    if (existing.length) return res.status(409).json({ error: 'Valeur deja existante' });
    const { rows: maxOrd } = await pool.query('SELECT MAX(ordre) AS m FROM parametres WHERE categorie=$1', [categorie]);
    const ordre = (maxOrd[0].m || 0) + 1;
    const { rows } = await pool.query(
      'INSERT INTO parametres (categorie,valeur,ordre) VALUES ($1,$2,$3) RETURNING *',
      [categorie, valeur, ordre]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/parametres/:id', authMiddleware, managerOnly, async (req, res) => {
  const { valeur, actif } = req.body;
  try {
    await pool.query('UPDATE parametres SET valeur=$1,actif=$2 WHERE id=$3', [valeur, actif!==false, req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/parametres/:id', authMiddleware, managerOnly, async (req, res) => {
  await pool.query('UPDATE parametres SET actif=false WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// ── NC INTERNES ───────────────────────────────────────────────────────────────
app.get('/api/nc-internes', authMiddleware, async (req, res) => {
  const { statut, search } = req.query;
  let q = `SELECT n.*,u.nom||COALESCE(' '||u.prenom,'') AS created_by_nom FROM nc_internes n LEFT JOIN utilisateurs u ON n.created_by=u.id WHERE 1=1`;
  const params = [];
  if (statut) { params.push(statut); q += ` AND n.statut=$${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (n.numero ILIKE $${params.length} OR n.client_nom ILIKE $${params.length} OR n.of_ref ILIKE $${params.length})`; }
  q += ' ORDER BY n.date_detection DESC';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/nc-internes', authMiddleware, async (req, res) => {
  const d = req.body;
  try {
    const numero = await genNumero('NCI', 'nc_internes');
    const { rows } = await pool.query(
      `INSERT INTO nc_internes (numero,date_detection,of_ref,client_id,client_nom,designation_piece,operation,type_defaut,description,qte_nc,qte_totale,cout_interne,montant_client,cause,action_corrective,responsable,delai_cloture,statut,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *`,
      [numero,d.date_detection,d.of_ref,d.client_id||null,d.client_nom,d.designation_piece,d.operation,d.type_defaut,d.description,d.qte_nc||null,d.qte_totale||null,d.cout_interne||null,d.montant_client||null,d.cause,d.action_corrective,d.responsable,d.delai_cloture||null,d.statut||'En attente',req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/nc-internes/:id', authMiddleware, managerOnly, async (req, res) => {
  const d = req.body;
  try {
    await pool.query(
      `UPDATE nc_internes SET date_detection=$1,of_ref=$2,client_id=$3,client_nom=$4,designation_piece=$5,operation=$6,type_defaut=$7,description=$8,qte_nc=$9,qte_totale=$10,cout_interne=$11,montant_client=$12,cause=$13,action_corrective=$14,responsable=$15,delai_cloture=$16,statut=$17,updated_at=NOW() WHERE id=$18`,
      [d.date_detection,d.of_ref,d.client_id||null,d.client_nom,d.designation_piece,d.operation,d.type_defaut,d.description,d.qte_nc||null,d.qte_totale||null,d.cout_interne||null,d.montant_client||null,d.cause,d.action_corrective,d.responsable,d.delai_cloture||null,d.statut,req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/nc-internes/:id', authMiddleware, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM nc_internes WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// ── NC EXTERNES ───────────────────────────────────────────────────────────────
app.get('/api/nc-externes', authMiddleware, async (req, res) => {
  const { statut, search } = req.query;
  let q = `SELECT n.*,u.nom||COALESCE(' '||u.prenom,'') AS created_by_nom FROM nc_externes n LEFT JOIN utilisateurs u ON n.created_by=u.id WHERE 1=1`;
  const params = [];
  if (statut) { params.push(statut); q += ` AND n.statut=$${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (n.numero ILIKE $${params.length} OR n.client_nom ILIKE $${params.length} OR n.numero_bl ILIKE $${params.length})`; }
  q += ' ORDER BY n.date_reclamation DESC';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/nc-externes', authMiddleware, async (req, res) => {
  const d = req.body;
  try {
    const numero = await genNumero('NCE', 'nc_externes');
    const { rows } = await pool.query(
      `INSERT INTO nc_externes (numero,date_reclamation,date_livraison,numero_bl,client_id,client_nom,contact_client,designation_piece,type_defaut,description,qte_reclamee,qte_livree,cout_interne,impact_financier,decision,cause_racine,action_corrective,responsable,delai_reponse,statut,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) RETURNING *`,
      [numero,d.date_reclamation,d.date_livraison||null,d.numero_bl,d.client_id||null,d.client_nom,d.contact_client,d.designation_piece,d.type_defaut,d.description,d.qte_reclamee||null,d.qte_livree||null,d.cout_interne||null,d.impact_financier||null,d.decision,d.cause_racine,d.action_corrective,d.responsable,d.delai_reponse||null,d.statut||'En attente',req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/nc-externes/:id', authMiddleware, managerOnly, async (req, res) => {
  const d = req.body;
  try {
    await pool.query(
      `UPDATE nc_externes SET date_reclamation=$1,date_livraison=$2,numero_bl=$3,client_id=$4,client_nom=$5,contact_client=$6,designation_piece=$7,type_defaut=$8,description=$9,qte_reclamee=$10,qte_livree=$11,cout_interne=$12,impact_financier=$13,decision=$14,cause_racine=$15,action_corrective=$16,responsable=$17,delai_reponse=$18,statut=$19,updated_at=NOW() WHERE id=$20`,
      [d.date_reclamation,d.date_livraison||null,d.numero_bl,d.client_id||null,d.client_nom,d.contact_client,d.designation_piece,d.type_defaut,d.description,d.qte_reclamee||null,d.qte_livree||null,d.cout_interne||null,d.impact_financier||null,d.decision,d.cause_racine,d.action_corrective,d.responsable,d.delai_reponse||null,d.statut,req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/nc-externes/:id', authMiddleware, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM nc_externes WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// ── NC TEMPS ──────────────────────────────────────────────────────────────────
app.get('/api/nc-temps', authMiddleware, async (req, res) => {
  const { statut, search } = req.query;
  let q = `SELECT n.*,u.nom||COALESCE(' '||u.prenom,'') AS created_by_nom FROM nc_temps n LEFT JOIN utilisateurs u ON n.created_by=u.id WHERE 1=1`;
  const params = [];
  if (statut) { params.push(statut); q += ` AND n.statut=$${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (n.numero ILIKE $${params.length} OR n.client_nom ILIKE $${params.length} OR n.of_ref ILIKE $${params.length})`; }
  q += ' ORDER BY n.date_fabrication DESC';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/nc-temps', authMiddleware, async (req, res) => {
  const d = req.body;
  try {
    const numero = await genNumero('NCT', 'nc_temps');
    const { rows } = await pool.query(
      `INSERT INTO nc_temps (numero,date_fabrication,of_ref,client_id,client_nom,operation,temps_prevu,temps_reel,nbre_pieces,cout_interne,cause,type_cause,action_amelioration,responsable,statut,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [numero,d.date_fabrication,d.of_ref,d.client_id||null,d.client_nom,d.operation,d.temps_prevu||null,d.temps_reel||null,d.nbre_pieces||null,d.cout_interne||null,d.cause,d.type_cause,d.action_amelioration,d.responsable,d.statut||'En attente',req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/nc-temps/:id', authMiddleware, managerOnly, async (req, res) => {
  const d = req.body;
  try {
    await pool.query(
      `UPDATE nc_temps SET date_fabrication=$1,of_ref=$2,client_id=$3,client_nom=$4,operation=$5,temps_prevu=$6,temps_reel=$7,nbre_pieces=$8,cout_interne=$9,cause=$10,type_cause=$11,action_amelioration=$12,responsable=$13,statut=$14,updated_at=NOW() WHERE id=$15`,
      [d.date_fabrication,d.of_ref,d.client_id||null,d.client_nom,d.operation,d.temps_prevu||null,d.temps_reel||null,d.nbre_pieces||null,d.cout_interne||null,d.cause,d.type_cause,d.action_amelioration,d.responsable,d.statut,req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/nc-temps/:id', authMiddleware, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM nc_temps WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// ── NC MATERIEL ───────────────────────────────────────────────────────────────
app.get('/api/nc-materiel', authMiddleware, async (req, res) => {
  const { statut, search } = req.query;
  let q = `SELECT n.*,u.nom||COALESCE(' '||u.prenom,'') AS created_by_nom,(n.cout_pieces+n.cout_mo+n.cout_indisponibilite) AS cout_total FROM nc_materiel n LEFT JOIN utilisateurs u ON n.created_by=u.id WHERE 1=1`;
  const params = [];
  if (statut) { params.push(statut); q += ` AND n.statut=$${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (n.numero ILIKE $${params.length} OR n.equipement ILIKE $${params.length} OR n.of_operation ILIKE $${params.length})`; }
  q += ' ORDER BY n.date_constat DESC';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/nc-materiel', authMiddleware, async (req, res) => {
  const d = req.body;
  try {
    const numero = await genNumero('NCM', 'nc_materiel');
    const { rows } = await pool.query(
      `INSERT INTO nc_materiel (numero,date_constat,of_operation,equipement,num_inventaire,type_degradation,description,gravite,origine,cout_pieces,cout_mo,cout_indisponibilite,action_realisee,type_intervention,prestataire,date_cloture,statut,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING *`,
      [numero,d.date_constat,d.of_operation,d.equipement,d.num_inventaire,d.type_degradation,d.description,d.gravite||1,d.origine,d.cout_pieces||0,d.cout_mo||0,d.cout_indisponibilite||0,d.action_realisee,d.type_intervention,d.prestataire,d.date_cloture||null,d.statut||'En attente',req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/nc-materiel/:id', authMiddleware, managerOnly, async (req, res) => {
  const d = req.body;
  try {
    await pool.query(
      `UPDATE nc_materiel SET date_constat=$1,of_operation=$2,equipement=$3,num_inventaire=$4,type_degradation=$5,description=$6,gravite=$7,origine=$8,cout_pieces=$9,cout_mo=$10,cout_indisponibilite=$11,action_realisee=$12,type_intervention=$13,prestataire=$14,date_cloture=$15,statut=$16,updated_at=NOW() WHERE id=$17`,
      [d.date_constat,d.of_operation,d.equipement,d.num_inventaire,d.type_degradation,d.description,d.gravite||1,d.origine,d.cout_pieces||0,d.cout_mo||0,d.cout_indisponibilite||0,d.action_realisee,d.type_intervention,d.prestataire,d.date_cloture||null,d.statut,req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/nc-materiel/:id', authMiddleware, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM nc_materiel WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// ── STATS ─────────────────────────────────────────────────────────────────────
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const [nci, nce, nct, ncm, nce_fin, ncm_cout, recent, top_clients] = await Promise.all([
      pool.query(`SELECT statut, COUNT(*) FROM nc_internes GROUP BY statut`),
      pool.query(`SELECT statut, COUNT(*), COALESCE(SUM(impact_financier),0) AS total_financier FROM nc_externes GROUP BY statut`),
      pool.query(`SELECT statut, COUNT(*) FROM nc_temps GROUP BY statut`),
      pool.query(`SELECT statut, COUNT(*), COALESCE(SUM(cout_pieces+cout_mo+cout_indisponibilite),0) AS cout_total FROM nc_materiel GROUP BY statut`),
      pool.query(`SELECT COALESCE(SUM(impact_financier),0) AS total FROM nc_externes`),
      pool.query(`SELECT COALESCE(SUM(cout_pieces+cout_mo+cout_indisponibilite),0) AS total FROM nc_materiel`),
      pool.query(`(SELECT 'NCI' AS type, numero, client_nom AS client, statut, date_detection::text AS date FROM nc_internes ORDER BY created_at DESC LIMIT 3)
                  UNION ALL (SELECT 'NCE', numero, client_nom, statut, date_reclamation::text FROM nc_externes ORDER BY created_at DESC LIMIT 3)
                  UNION ALL (SELECT 'NCT', numero, client_nom, statut, date_fabrication::text FROM nc_temps ORDER BY created_at DESC LIMIT 3)
                  UNION ALL (SELECT 'NCM', numero, equipement, statut, date_constat::text FROM nc_materiel ORDER BY created_at DESC LIMIT 3)
                  ORDER BY date DESC LIMIT 8`),
      pool.query(`SELECT client_nom, COUNT(*) as total FROM (
                  SELECT client_nom FROM nc_internes WHERE client_nom IS NOT NULL
                  UNION ALL SELECT client_nom FROM nc_externes WHERE client_nom IS NOT NULL
                  UNION ALL SELECT client_nom FROM nc_temps WHERE client_nom IS NOT NULL
                  ) t GROUP BY client_nom ORDER BY total DESC LIMIT 5`),
    ]);
    const top_defauts = await pool.query(`SELECT type_defaut, COUNT(*) FROM nc_internes GROUP BY type_defaut ORDER BY COUNT(*) DESC LIMIT 5`);
    res.json({
      nci: nci.rows, nce: nce.rows, nct: nct.rows, ncm: ncm.rows,
      top_defauts: top_defauts.rows,
      top_clients: top_clients.rows,
      total_financier_ext: nce_fin.rows[0].total,
      total_cout_materiel: ncm_cout.rows[0].total,
      recent: recent.rows
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`[NC-App] Serveur demarre sur le port ${PORT}`));
}).catch(err => {
  console.error('[NC-App] Echec demarrage:', err.message);
  process.exit(1);
});
