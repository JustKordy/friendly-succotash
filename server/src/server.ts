import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcrypt';
import { Request } from 'express';

dotenv.config();

const app = express();
const db = new sqlite3.Database(':memory:');

// Vlastní typ pro session
declare module 'express-session' {
  interface SessionData {
    userId: number;
  }
}

// Vlastní typ pro user
interface IUser {
  id: number;
  username: string;
  name: string;
  email: string;
  password: string;
}

// Vytvoření tabulky
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    name TEXT,
    email TEXT,
    password TEXT
  )`);  
});

app.use(cors({ origin: "http://127.0.0.1:5501", credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false
}));

// Registrace
app.post('/api/register', async (req, res) => {
  const { username, name, email, password } = req.body;
  if (!username || !name || !email || !password)
    return res.status(400).send('All fields required');

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (username, name, email, password) VALUES (?, ?, ?, ?)`,
    [username, name, email, hashedPassword],
    (err) => {
      if (err) return res.status(400).send('User already exists');
      res.sendStatus(201);
    }
  );
});

// Přihlášení
app.post('/api/login', (req: Request, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).send('All fields required');

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, row) => {
    const user = row as IUser;
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).send('Invalid credentials');

    req.session.userId = user.id;
    res.send({
      id: user.id,
      username: user.username,
      name: user.name,
      email: user.email
    });
  });
});

// Načtení přihlášeného uživatele
app.get('/api/me', (req, res) => {
  if (!req.session.userId)
    return res.status(401).send('Not logged in');

  db.get(
    `SELECT id, username, name, email FROM users WHERE id = ?`,
    [req.session.userId],
    (err, row) => {
      if (!row) return res.status(404).send('User not found');
      res.send(row);
    }
  );
});

// Úprava uživatele
app.put('/api/me', (req, res) => {
  if (!req.session.userId)
    return res.status(401).send('Not logged in');

  const { name, email } = req.body;
  if (!name || !email)
    return res.status(400).send('All fields required');

  db.run(
    `UPDATE users SET name = ?, email = ? WHERE id = ?`,
    [name, email, req.session.userId],
    (err) => {
      if (err) return res.status(500).send('Failed to update');
      res.sendStatus(200);
    }
  );
});

const PORT = parseInt(process.env.PORT || '3000');
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
