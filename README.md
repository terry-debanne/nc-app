# NC App — AMA ITEA / Ardèche Thermolaquage

Application de gestion des Non-Conformités de fabrication.

## Modules
- 🔵 NC Internes — Défauts détectés avant livraison
- 🔴 NC Externes — Réclamations clients
- 🟢 NC Temps — Dépassements temps de fabrication
- 🟣 NC Matériel — Dégradations équipements & coûts

## Déploiement sur Railway

### 1. Créer le projet GitHub
```bash
git init
git add .
git commit -m "Initial commit — NC App AMA ITEA"
git remote add origin https://github.com/TON_USER/nc-app.git
git push -u origin main
```

### 2. Sur Railway (railway.app)
1. **New Project** → Deploy from GitHub repo → sélectionner `nc-app`
2. **Add Plugin** → PostgreSQL → Railway créé la DB automatiquement
3. Aller dans **Variables** du service web et ajouter :
   ```
   DATABASE_URL  = (copier depuis le plugin PostgreSQL → Connect → DATABASE_URL)
   JWT_SECRET    = nc_ama_votre_secret_unique_2024
   NODE_ENV      = production
   ```
4. Railway détecte automatiquement `npm start` via le `package.json`
5. Le service démarre, la base de données est initialisée automatiquement

### 3. Accès initial
- **Login** : `admin`
- **PIN** : `690769`
- ⚠️ Changer le PIN admin après la première connexion !

## Rôles
| Rôle | Lecture | Créer NC | Modifier NC | Supprimer | Admin users |
|------|---------|----------|-------------|-----------|-------------|
| Opérateur | ✅ | ✅ | ❌ | ❌ | ❌ |
| Manager | ✅ | ✅ | ✅ | ❌ | ❌ |
| Admin | ✅ | ✅ | ✅ | ✅ | ✅ |

## Architecture
```
nc-app/
├── server.js          # Backend Express + toutes les routes API
├── database.js        # Connexion PostgreSQL + init schéma
├── package.json
├── public/
│   └── index.html     # Frontend SPA (fichier unique)
└── .env.example
```

## Variables d'environnement Railway
| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | URL PostgreSQL (fournie par Railway Plugin) |
| `JWT_SECRET` | Clé secrète JWT (choisir une valeur longue et unique) |
| `NODE_ENV` | `production` |
| `PORT` | Automatique sur Railway |
