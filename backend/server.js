'use strict';

/*
 * BudgetBuddy backend API (Milestone 2)
 * Runs on the BackEnd VM. Talks to MongoDB on the Database VM.
 * Dependencies: express, mongodb. Everything else is built into Node.
 */

const express = require('express');
const crypto = require('crypto');
const { promisify } = require('util');
const { MongoClient } = require('mongodb');

const scrypt = promisify(crypto.scrypt);

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const MONGO_URL = process.env.MONGO_URL;
const DB_NAME = process.env.DB_NAME || 'budgetbuddy';
const SESSION_SECONDS = 60 * 60; // sessions last 1 hour
const COOKIE_NAME = 'bb_session';

if (!MONGO_URL) {
  console.error('MONGO_URL is not set. Copy .env.example to .env and fill it in.');
  process.exit(1);
}

/* ---------- logging (one JSON line per event, goes to journald) ---------- */

function log(event, details) {
  console.log(JSON.stringify(Object.assign({ time: new Date().toISOString(), event }, details)));
}

/* ---------- input validation ----------
 * Every value must be a plain string before it goes near the database.
 * This blocks NoSQL injection such as {"email": {"$gt": ""}}.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function cleanEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && EMAIL_RE.test(email) ? email : null;
}

function cleanName(value) {
  if (typeof value !== 'string') return null;
  const name = value.trim();
  return name.length >= 1 && name.length <= 100 ? name : null;
}

function validPassword(value) {
  return typeof value === 'string' && value.length >= 8 && value.length <= 128;
}

/* ---------- password hashing (scrypt + random salt, built into Node) ---------- */

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + key.toString('hex');
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const expected = Buffer.from(parts[2], 'hex');
  const actual = await scrypt(password, Buffer.from(parts[1], 'hex'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

/* ---------- tiny in-memory rate limiter (per IP, per minute) ---------- */

const attempts = new Map();

function tooManyAttempts(ip) {
  const now = Date.now();
  let entry = attempts.get(ip);
  if (!entry || entry.resetAt < now) {
    entry = { count: 0, resetAt: now + 60 * 1000 };
    attempts.set(ip, entry);
  }
  entry.count += 1;
  return entry.count > 10;
}

setInterval(function () {
  const now = Date.now();
  attempts.forEach(function (entry, ip) {
    if (entry.resetAt < now) attempts.delete(ip);
  });
}, 60 * 1000).unref();

/* ---------- sessions ---------- */

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  const pieces = header.split(';');
  for (let i = 0; i < pieces.length; i++) {
    const pair = pieces[i].trim().split('=');
    if (pair[0] === name) return pair.slice(1).join('=');
  }
  return null;
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function sessionCookie(token, maxAge) {
  let cookie = COOKIE_NAME + '=' + token + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + maxAge;
  if (process.env.COOKIE_SECURE === 'true') cookie += '; Secure';
  return cookie;
}

/* ---------- app ---------- */

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // we sit behind Nginx on the front-end VM
app.use(express.json({ limit: '10kb' }));
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

let users;
let sessions;
let DUMMY_HASH;

const wrap = function (fn) {
  return function (req, res, next) {
    fn(req, res, next).catch(next);
  };
};

const requireAuth = wrap(async function (req, res, next) {
  const token = getCookie(req, COOKIE_NAME);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(401).json({ ok: false, error: 'Not logged in.' });
  }
  const session = await sessions.findOne({ tokenHash: sha256(token), expiresAt: { $gt: new Date() } });
  if (!session) return res.status(401).json({ ok: false, error: 'Not logged in.' });
  const user = await users.findOne({ _id: session.userId }, { projection: { name: 1, email: 1 } });
  if (!user) return res.status(401).json({ ok: false, error: 'Not logged in.' });
  req.user = user;
  req.tokenHash = session.tokenHash;
  next();
});

app.get('/api/health', function (req, res) {
  res.json({ ok: true });
});

app.post('/api/register', wrap(async function (req, res) {
  if (tooManyAttempts(req.ip)) {
    log('rate_limited', { route: 'register', ip: req.ip });
    return res.status(429).json({ ok: false, error: 'Too many attempts. Try again in a minute.' });
  }
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const name = cleanName(body.name);
  const email = cleanEmail(body.email);
  if (!name) return res.status(400).json({ ok: false, error: 'Enter your full name.' });
  if (!email) return res.status(400).json({ ok: false, error: 'Enter a valid email address.' });
  if (!validPassword(body.password)) {
    return res.status(400).json({ ok: false, error: 'Password must be 8 to 128 characters.' });
  }

  const passwordHash = await hashPassword(body.password);
  try {
    await users.insertOne({ name: name, email: email, passwordHash: passwordHash, createdAt: new Date() });
  } catch (err) {
    if (err && err.code === 11000) {
      log('register_duplicate', { email: email, ip: req.ip });
      return res.status(409).json({ ok: false, error: 'An account with that email already exists.' });
    }
    throw err;
  }
  log('register_success', { email: email, ip: req.ip });
  res.status(201).json({ ok: true });
}));

app.post('/api/login', wrap(async function (req, res) {
  if (tooManyAttempts(req.ip)) {
    log('rate_limited', { route: 'login', ip: req.ip });
    return res.status(429).json({ ok: false, error: 'Too many attempts. Try again in a minute.' });
  }
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const email = cleanEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : null;

  const fail = function () {
    log('login_failed', { email: email || 'invalid', ip: req.ip });
    return res.status(401).json({ ok: false, error: 'Incorrect email or password.' });
  };
  if (!email || !password || password.length > 128) return fail();

  const user = await users.findOne({ email: email });
  // Always run one hash check so unknown emails and wrong passwords take similar time.
  const good = await verifyPassword(password, user ? user.passwordHash : DUMMY_HASH);
  if (!user || !good) return fail();

  const token = crypto.randomBytes(32).toString('hex');
  await sessions.insertOne({
    tokenHash: sha256(token),
    userId: user._id,
    expiresAt: new Date(Date.now() + SESSION_SECONDS * 1000)
  });
  res.setHeader('Set-Cookie', sessionCookie(token, SESSION_SECONDS));
  log('login_success', { email: email, ip: req.ip });
  res.json({ ok: true, user: { name: user.name, email: user.email } });
}));

app.get('/api/me', requireAuth, function (req, res) {
  res.json({ ok: true, user: { name: req.user.name, email: req.user.email } });
});

app.post('/api/logout', requireAuth, wrap(async function (req, res) {
  await sessions.deleteOne({ tokenHash: req.tokenHash });
  res.setHeader('Set-Cookie', sessionCookie('', 0));
  log('logout', { email: req.user.email, ip: req.ip });
  res.json({ ok: true });
}));

app.use('/api', function (req, res) {
  res.status(404).json({ ok: false, error: 'Not found.' });
});

// eslint-disable-next-line no-unused-vars
app.use(function (err, req, res, next) {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ ok: false, error: 'Request body must be valid JSON.' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ ok: false, error: 'Request too large.' });
  }
  log('server_error', { message: err && err.message });
  res.status(500).json({ ok: false, error: 'Something went wrong.' });
});

async function main() {
  const client = new MongoClient(MONGO_URL, { serverSelectionTimeoutMS: 5000 });
  await client.connect();
  const db = client.db(DB_NAME);
  users = db.collection('users');
  sessions = db.collection('sessions');
  await users.createIndex({ email: 1 }, { unique: true });
  await sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await sessions.createIndex({ tokenHash: 1 });
  DUMMY_HASH = await hashPassword(crypto.randomBytes(16).toString('hex'));
  app.listen(PORT, HOST, function () {
    log('server_started', { host: HOST, port: PORT });
  });
}

main().catch(function (err) {
  console.error('Startup failed: ' + err.message);
  process.exit(1);
});
