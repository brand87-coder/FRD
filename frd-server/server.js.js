require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // сюда положим HTML-файл

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // требуется для Neon и Render
});

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // пароль приложения Gmail
  }
});

const JWT_SECRET = process.env.JWT_SECRET;

// ---------- Инициализация таблиц ----------
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(20) DEFAULT 'user',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS frd_entries (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      task TEXT,
      minutes INTEGER,
      hours NUMERIC(5,2),
      complexity VARCHAR(50),
      interest VARCHAR(50),
      work_type VARCHAR(255),
      comment TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
}

// ---------- Отправка пароля ----------
async function sendPasswordEmail(to, password) {
  const mailOptions = {
    from: `"ФРД Система" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Доступ к системе ФРД',
    text: `Здравствуйте!\n\nВаш логин: ${to}\nВаш пароль: ${password}\n\nСмените пароль после первого входа.`
  };
  await transporter.sendMail(mailOptions);
}

// ---------- Регистрация ----------
app.post('/api/register', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email обязателен' });

  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) return res.status(400).json({ error: 'Пользователь уже существует' });

  const rawPassword = Math.random().toString(36).slice(-10); // 10 символов
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(rawPassword, salt);

  const result = await pool.query(
    'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
    [email, passwordHash]
  );

  try {
    await sendPasswordEmail(email, rawPassword);
    res.json({ success: true, message: 'Пароль отправлен на почту' });
  } catch (err) {
    console.error('Ошибка отправки почты:', err);
    // Если почта не ушла, всё равно возвращаем пароль в ответе (для отладки)
    res.status(500).json({ error: 'Не удалось отправить письмо', tempPassword: rawPassword });
  }
});

// ---------- Вход ----------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (result.rows.length === 0) return res.status(401).json({ error: 'Неверный логин или пароль' });

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Неверный логин или пароль' });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email, role: user.role });
});

// ---------- Middleware проверки токена ----------
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Нет токена' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
}

// ---------- Смена пароля ----------
app.post('/api/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  const user = result.rows[0];

  const valid = await bcrypt.compare(currentPassword, user.password_hash);
  if (!valid) return res.status(400).json({ error: 'Текущий пароль неверен' });

  const salt = await bcrypt.genSalt(10);
  const newHash = await bcrypt.hash(newPassword, salt);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.user.id]);
  res.json({ success: true });
});

// ---------- Получение данных ФРД ----------
app.get('/api/data', auth, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM frd_entries WHERE user_id = $1 ORDER BY date, id',
    [req.user.id]
  );
  // Группируем по датам для удобства фронтенда
  const grouped = {};
  result.rows.forEach(row => {
    const dateStr = row.date.toISOString().slice(0, 10);
    if (!grouped[dateStr]) grouped[dateStr] = [];
    grouped[dateStr].push({
      id: row.id,
      task: row.task,
      minutes: row.minutes,
      hours: parseFloat(row.hours),
      complexity: row.complexity,
      interest: row.interest,
      workType: row.work_type,
      comment: row.comment
    });
  });
  res.json(grouped);
});

// ---------- Сохранение строки ФРД ----------
app.post('/api/data', auth, async (req, res) => {
  const { date, task, minutes, hours, complexity, interest, workType, comment } = req.body;
  const result = await pool.query(
    `INSERT INTO frd_entries (user_id, date, task, minutes, hours, complexity, interest, work_type, comment)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [req.user.id, date, task, minutes, hours, complexity, interest, workType, comment]
  );
  res.json({ id: result.rows[0].id });
});

// ---------- Удаление строки ----------
app.delete('/api/data/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM frd_entries WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ---------- Админ: список пользователей ----------
app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ только для админа' });
  const result = await pool.query('SELECT id, email, created_at FROM users ORDER BY id');
  res.json(result.rows);
});

// ---------- Админ: данные другого пользователя ----------
app.get('/api/admin/data/:userId', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ только для админа' });
  const result = await pool.query('SELECT * FROM frd_entries WHERE user_id = $1 ORDER BY date, id', [req.params.userId]);
  res.json(result.rows);
});

// ---------- Запуск ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await initDB();
  console.log(`Сервер запущен на порту ${PORT}`);
});