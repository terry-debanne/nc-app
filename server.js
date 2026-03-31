const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { pool, initDB } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
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
    return res.status(403).json({ error: 'Token invalide ou expiré' });
  }
}

function managerOnly(req, res, next) {
  if (!['admin', 'manager'].includes(req.user.role))
    return res.status(403).json({ error: 'Accès réservé manager/admin' });
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Accès réservé admin' });
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

app.post('/api/auth/login', async (req, res) => {
  const { login, pin } = req.body;
  if (!login || !pin) return res.status(400).json({ error: 'Login et PIN requis' });
  try {
    const { rows } = await pool.query(
      'SELECT * FROM utilisateurs WHERE login=$1 AND actif=true', [login]
    );
    if (!rows.length) return res.status(401).json({ error: 'Identifiant incorrect' });
    const user = rows[0];
    const valid = await bcrypt.compare(String(pin), user.pin_hash);
    if (!valid) return res.status(401).json({ error: 'PIN incorrect' });
    const token = jwt.sign(
      { id: user.id, login: user.login, nom: user.nom, prenom: user.prenom, role: user.role },
      JWT_SECRET,
      { expiresIn: SESSION_DURATION }
    );
    res.json({ token, user: { id: user.id, login: user.login, nom: user.nom, prenom: user.prenom, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json(req.user));

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
    if (err.code === '23505') return res.status(409).json({ error: 'Login déjà utilisé' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/utilisateurs/:id', authMiddleware, adminOnly, async (req, res) => {
  const { nom, prenom, role, actif, pin } = req.body;
  try {
    if (pin) {
      const hash = await bcrypt.hash(String(pin), 12);
      await pool.query(
        'UPDATE utilisateurs SET nom=$1,prenom=$2,role=$3,actif=$4,pin_hash=$5 WHERE id=$6',
        [nom, prenom, role, actif, hash, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE utilisateurs SET nom=$1,prenom=$2,role=$3,actif=$4 WHERE id=$5',
        [nom, prenom, role, actif, req.params.id]
      );
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/nc-internes', authMiddleware, async (req, res) => {
  const { statut, search } = req.query;
  let q = 'SELECT n.*,u.nom||COALESCE(\' \'||u.prenom,\'\') AS created_by_nom FROM nc_internes n LEFT JOIN utilisateurs u ON n.created_by=u.id WHERE 1=1';
  const params = [];
  if (statut) { params.push(statut); q += ` AND n.statut=$${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (n.numero ILIKE $${params.length} OR n.client ILIKE $${params.length} OR n.of_ref ILIKE $${params.length})`; }
  q += ' ORDER BY n.date_detection DESC';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/nc-internes', authMiddleware, async (req, res) => {
  const d = req.body;
  try {
    const numero = await genNumero('NCI', 'nc_internes');
    const { rows } = await pool.query(
      `INSERT INTO nc_internes (numero,date_detection,of_ref,client,designation_piece,operation,type_defaut,description,qte_nc,qte_totale,cause,action_corrective,responsable,delai_cloture,statut,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [numero,d.date_detection,d.of_ref,d.client,d.designation_piece,d.operation,d.type_defaut,d.description,d.qte_nc||null,d.qte_totale||null,d.cause,d.action_corrective,d.responsable,d.delai_cloture||null,d.statut||'En attente',req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/nc-internes/:id', authMiddleware, managerOnly, async (req, res) => {
  const d = req.body;
  try {
    await pool.query(
      `UPDATE nc_internes SET date_detection=$1,of_ref=$2,client=$3,designation_piece=$4,operation=$5,type_defaut=$6,description=$7,qte_nc=$8,qte_totale=$9,cause=$10,action_corrective=$11,responsable=$12,delai_cloture=$13,statut=$14,updated_at=NOW() WHERE id=$15`,
      [d.date_detection,d.of_ref,d.client,d.designation_piece,d.operation,d.type_defaut,d.description,d.qte_nc||null,d.qte_totale||null,d.cause,d.action_corrective,d.responsable,d.delai_cloture||null,d.statut,req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/nc-internes/:id', authMiddleware, adminOnly, async (req, res) => {
