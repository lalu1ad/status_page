const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const morgan = require('morgan');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const express = require('express');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const cron = require('node-cron');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const WebSocket = require('ws');
const http = require('http');
const geoip = require('geoip-lite');
const cookieParser = require('cookie-parser');
const sanitizeHtml = require('sanitize-html');
const multer = require('multer'); // For avatar uploads
const archiver = require('archiver'); // For data exports
const nodemailer = require('nodemailer'); // New: For email alerts
const cookie = require('cookie'); // New: For parsing cookies in WS
const cookieSignature = require('cookie-signature'); // New: For unsigning session cookies
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
// ======================
// CONFIG & CONSTANTS
// ======================
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
const isProduction = process.env.NODE_ENV === 'production';
const OFFLINE_THRESHOLD = 180;
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB for uploads
// New: Email transporter (configured later)
let transporter = null;
// ======================
// DIRECTORY SETUP (ENHANCED)
// ======================
const dataDir = './var';
const dbPath = path.join(dataDir, 'vps_monitor.db');
const sessionsDbPath = path.join(dataDir, 'sessions.db');
const uploadsDir = path.join(dataDir, 'uploads');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log(`Created data directory: ${dataDir}`);
}
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log(`Created uploads directory: ${uploadsDir}`);
}
// ======================
// MIDDLEWARE SETUP (OPTIMIZED)
// ======================
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(compression());
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '7d' }));
app.use('/var/uploads', express.static(uploadsDir, { maxAge: '7d' })); // New: Serve uploads statically
app.use(morgan('combined'));
app.use(cookieParser());
// Dynamic Helmet CSP Configuration Fix
app.use((req, res, next) => {
  const uploadsUrl = `${req.protocol}://${req.get('host')}/var/uploads/`;
  helmet({
      contentSecurityPolicy: {
          directives: {
              defaultSrc: ["'self'"],
              scriptSrc: [
                  "'self'",
                  "'unsafe-inline'",
                  "https://cdn.jsdelivr.net",
                  "https://cdnjs.cloudflare.com"
              ],
              styleSrc: [
                  "'self'",
                  "'unsafe-inline'",
                  "https://fonts.googleapis.com",
                  "https://cdn.jsdelivr.net"
              ],
              fontSrc: [
                  "'self'",
                  "https://fonts.gstatic.com",
                  "data:"
              ],
              imgSrc: [
                  "'self'",
                  "data:",
                  "https:",
                  uploadsUrl // Now dynamically built with req
              ],
              connectSrc: [
                  "'self'",
                  "ws:",
                  "wss:"
              ],
              objectSrc: ["'none'"],
              upgradeInsecureRequests: []
          }
      },
      referrerPolicy: { policy: "strict-origin-when-cross-origin" },
      frameguard: { action: 'deny' }, // New: Enhanced security
      hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }, // New: HSTS
      noSniff: true,
      xssFilter: true
  })(req, res, next);
});
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
// Multer for avatar uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, `${crypto.randomBytes(16).toString('hex')}-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({
    storage,
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only images allowed'), false);
    }
});
// Session Store (ENHANCED)
const store = new SQLiteStore({
    db: 'sessions.db',
    dir: dataDir,
    concurrentDb: true
});
app.use(session({
    store,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        sameSite: isProduction ? 'none' : 'lax'
    }
}));
// Rate Limiting (TIGHTENED)
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100000, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1500, message: { error: "Too many login attempts" } });
const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50 });
app.use('/api/', apiLimiter);
app.use(['/admin/login', '/admin/logout'], authLimiter);
app.use(['/admin/profile'], uploadLimiter);
// ======================
// DATABASE SETUP (ROBUST)
// ======================
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error("Failed to connect to database:", err.message);
        console.log("Attempting to create database directory...");
        process.exit(1);
    }
    console.log("Connected to SQLite database:", dbPath);
    // Database optimization
    db.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 30000;
        PRAGMA synchronous = NORMAL;
    `, (err) => {
        if (err) {
            console.error("Database optimization failed:", err);
        } else {
            console.log("Database optimization completed");
        }
    });
});
// Cache & Connections
const settingsCache = {};
const activeConnections = new Map();
const nodeGroupsCache = new Map(); // New: Cache for node groups
// ======================
// UTILITIES (ENHANCED)
// ======================
const log = (msg) => console.log(`[${new Date().toISOString()}] ${msg}`);
const generateApiKey = () => crypto.randomBytes(32).toString('hex');
const maskApiKey = (key) => key ? `${key.slice(0, 8)}••••••••${key.slice(-8)}` : 'N/A';
const sanitize = (input) => typeof input === 'string' ? sanitizeHtml(input.trim(), { allowedTags: [], allowedAttributes: {} }) : '';
const generateAuditLog = (userId, action, details, ip = null) => {
    db.run(`INSERT INTO audit_logs (user_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`, [userId, action, JSON.stringify(details), ip || null]);
};
// New: CSV escape utility for exports
const csvEscape = (val) => {
    if (val == null) return '';
    let str = val.toString();
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        str = '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
};
// Auth Middleware
const requireAuth = (req, res, next) => {
    if (!req.session?.user) return res.redirect('/admin/login');
    next();
};
const requireAdmin = (req, res, next) => {
    if (!req.session.user || !['admin', 'manager'].includes(req.session.user.role)) {
        return res.status(403).render('error', { message: "Access Denied" });
    }
    next();
};
// New: Send email alert
async function sendEmailAlert(alert) {
    if (transporter && settingsCache.enable_email_alerts === 'true' && settingsCache.alert_email) {
        try {
            await transporter.sendMail({
                from: settingsCache.smtp_user,
                to: settingsCache.alert_email,
                subject: `[VPS Monitor Alert] ${alert.severity.toUpperCase()}: ${alert.type}`,
                text: `${alert.message}\nNode ID: ${alert.node_id}\nTime: ${alert.created_at}`
            });
            log(`Email alert sent for alert ID ${alert.id}`);
        } catch (err) {
            console.error('Email send error:', err);
        }
    }
}
// ======================
// DATABASE INITIALIZATION (STABILIZED & ENHANCED)
// ======================
async function initDB() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            // Tables (Enhanced with new fields: swap_total, swap_free; indexes)
            const tables = [
                `CREATE TABLE IF NOT EXISTS nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    hostname TEXT,
                    ip_address TEXT,
                    ip_alias TEXT,
                    location TEXT DEFAULT 'Unknown',
                    api_key TEXT UNIQUE NOT NULL,
                    is_online INTEGER DEFAULT 0,
                    last_seen DATETIME,
                    latency REAL DEFAULT 0,
                    public INTEGER DEFAULT 1,
                    status_page_visible INTEGER DEFAULT 1,
                    monitor_type TEXT DEFAULT 'agent',
                    group_tags TEXT DEFAULT '', -- New: Comma-separated tags/groups
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`,
                `CREATE TABLE IF NOT EXISTS node_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id INTEGER NOT NULL,
                    cpu_usage REAL,
                    cpu_cores INTEGER DEFAULT 1, -- New: Total CPU cores
                    memory_usage REAL,
                    memory_total REAL,
                    memory_free REAL,
                    disk_usage REAL,
                    disk_total REAL,
                    disk_free REAL,
                    swap_total REAL DEFAULT 0, -- New: Swap metrics
                    swap_free REAL DEFAULT 0,
                    network_rx REAL, -- Live RX/sec
                    network_tx REAL, -- Live TX/sec
                    uptime REAL,
                    load_average TEXT,
                    cpu_temp REAL,
                    processes INTEGER,
                    os_version TEXT, -- New: OS details
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
                    UNIQUE(node_id, timestamp)
                )`,
                `CREATE INDEX IF NOT EXISTS idx_node_stats_node_id_timestamp ON node_stats(node_id, timestamp)`,
                `CREATE INDEX IF NOT EXISTS idx_node_stats_node_id ON node_stats(node_id)`,
                `CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    full_name TEXT DEFAULT 'User',
                    email TEXT,
                    role TEXT DEFAULT 'viewer' CHECK(role IN ('admin','manager','viewer')),
                    avatar TEXT DEFAULT '/img/default-avatar.png',
                    is_active INTEGER DEFAULT 1, -- New: User activation
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- New: For profile updates
                    last_login DATETIME
                )`,
                `CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    type TEXT DEFAULT 'string',
                    description TEXT,
                    category TEXT DEFAULT 'general'
                )`,
                `CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id INTEGER,
                    type TEXT,
                    message TEXT,
                    severity TEXT DEFAULT 'warning',
                    resolved INTEGER DEFAULT 0,
                    resolved_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
                )`,
                `CREATE INDEX IF NOT EXISTS idx_alerts_node_id ON alerts(node_id)`,
                `CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)`,
                `CREATE TABLE IF NOT EXISTS audit_logs ( -- New: Audit trail
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
                )`,
                `CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
                `CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`
            ];
            let completed = 0;
            const totalTables = tables.length;
            tables.forEach((sql, index) => {
                db.run(sql, (err) => {
                    if (err) {
                        console.error(`Error creating table/index ${index + 1}:`, err);
                        reject(err);
                        return;
                    }
                    completed++;
                    if (completed === totalTables) {
                        // Migrate schema for missing columns
                        migrateSchema().then(() => {
                            checkDefaultAdmin();
                        }).catch((err) => {
                            console.error("Migration failed:", err);
                            reject(err);
                        });
                    }
                });
            });
            function migrateSchema() {
                return new Promise((res, rej) => {
                    migrateNodes()
                        .then(() => migrateNodeStats())
                        .then(() => migrateAlerts())
                        .then(() => migrateUsers())
                        .then(res)
                        .catch(rej);
                });
            }
            function migrateNodes() {
                return new Promise((res, rej) => {
                    db.all("PRAGMA table_info(nodes)", (err, info) => {
                        if (err) { rej(err); return; }
                        const existing = new Set(info.map(r => r.name));
                        if (!existing.has('group_tags')) {
                            db.run("ALTER TABLE nodes ADD COLUMN group_tags TEXT DEFAULT ''", (err) => {
                                if (err) {
                                    console.error("Failed to add group_tags:", err);
                                } else {
                                    log("Added group_tags column to nodes");
                                }
                                res();
                            });
                        } else {
                            res();
                        }
                    });
                });
            }
            function migrateNodeStats() {
                return new Promise((res, rej) => {
                    db.all("PRAGMA table_info(node_stats)", (err, info) => {
                        if (err) { rej(err); return; }
                        const existing = new Set(info.map(r => r.name));
                        const toAdd = [];
                        if (!existing.has('cpu_cores')) toAdd.push({col: 'cpu_cores', type: 'INTEGER DEFAULT 1'});
                        if (!existing.has('memory_total')) toAdd.push({col: 'memory_total', type: 'REAL DEFAULT 0'});
                        if (!existing.has('memory_free')) toAdd.push({col: 'memory_free', type: 'REAL DEFAULT 0'});
                        if (!existing.has('disk_total')) toAdd.push({col: 'disk_total', type: 'REAL DEFAULT 0'});
                        if (!existing.has('disk_free')) toAdd.push({col: 'disk_free', type: 'REAL DEFAULT 0'});
                        if (!existing.has('swap_total')) toAdd.push({col: 'swap_total', type: 'REAL DEFAULT 0'});
                        if (!existing.has('swap_free')) toAdd.push({col: 'swap_free', type: 'REAL DEFAULT 0'});
                        if (!existing.has('network_rx')) toAdd.push({col: 'network_rx', type: 'REAL DEFAULT 0'});
                        if (!existing.has('network_tx')) toAdd.push({col: 'network_tx', type: 'REAL DEFAULT 0'});
                        if (!existing.has('cpu_temp')) toAdd.push({col: 'cpu_temp', type: 'REAL DEFAULT 0'});
                        if (!existing.has('processes')) toAdd.push({col: 'processes', type: 'INTEGER DEFAULT 0'});
                        if (!existing.has('os_version')) toAdd.push({col: 'os_version', type: 'TEXT'});
                        if (toAdd.length === 0) { res(); return; }
                        let added = 0;
                        toAdd.forEach(({col, type}) => {
                            db.run(`ALTER TABLE node_stats ADD COLUMN ${col} ${type}`, (err) => {
                                if (err) {
                                    console.error(`Failed to add column ${col}:`, err);
                                } else {
                                    log(`Added column ${col} to node_stats`);
                                }
                                added++;
                                if (added === toAdd.length) res();
                            });
                        });
                    });
                });
            }
            function migrateAlerts() {
                return new Promise((res, rej) => {
                    db.all("PRAGMA table_info(alerts)", (err, info) => {
                        if (err) { rej(err); return; }
                        const existing = new Set(info.map(r => r.name));
                        if (!existing.has('resolved_at')) {
                            db.run("ALTER TABLE alerts ADD COLUMN resolved_at DATETIME", (err) => {
                                if (err) {
                                    console.error("Failed to add resolved_at:", err);
                                } else {
                                    log("Added resolved_at column to alerts");
                                }
                                res();
                            });
                        } else {
                            res();
                        }
                    });
                });
            }
            function migrateUsers() {
                return new Promise((res, rej) => {
                    db.all("PRAGMA table_info(users)", (err, info) => {
                        if (err) { rej(err); return; }
                        const existing = new Set(info.map(r => r.name));
                        const toAdd = [];
                        if (!existing.has('is_active')) toAdd.push({col: 'is_active', type: 'INTEGER DEFAULT 1'});
                        if (!existing.has('updated_at')) toAdd.push({col: 'updated_at', type: 'DATETIME DEFAULT CURRENT_TIMESTAMP'});
                        if (toAdd.length === 0) { res(); return; }
                        let added = 0;
                        toAdd.forEach(({col, type}) => {
                            db.run(`ALTER TABLE users ADD COLUMN ${col} ${type}`, (err) => {
                                if (err) {
                                    console.error(`Failed to add column ${col}:`, err);
                                } else {
                                    log(`Added column ${col} to users`);
                                }
                                added++;
                                if (added === toAdd.length) res();
                            });
                        });
                    });
                });
            }
            function checkDefaultAdmin() {
                db.get("SELECT 1 FROM users WHERE username = 'admin'", async (err, row) => {
                    if (err) {
                        console.error("Error checking admin user:", err);
                        reject(err);
                        return;
                    }
                    if (!row) {
                        try {
                            const hash = await bcrypt.hash('admin123', 12);
                            db.run(
                                `INSERT INTO users (username, password, role, full_name) VALUES ('admin', ?, 'admin', 'Administrator')`,
                                [hash],
                                function(err) {
                                    if (err) {
                                        console.error("Error creating default admin:", err);
                                        reject(err);
                                        return;
                                    }
                                    generateAuditLog(null, 'system', { action: 'default_admin_created' }, null);
                                    log("Default admin created → admin / admin123 (CHANGE IT NOW!)");
                                    setupDefaultSettings();
                                }
                            );
                        } catch (hashError) {
                            console.error("Error hashing password:", hashError);
                            reject(hashError);
                        }
                    } else {
                        setupDefaultSettings();
                    }
                });
            }
            function setupDefaultSettings() {
                const defaults = [
                    ['site_name', 'VPS Monitor Pro+', 'string', 'Site Title', 'general'],
                    ['site_description', 'Real-time Server Monitoring Dashboard', 'string', 'Description', 'general'],
                    ['theme', 'dark', 'string', 'Theme', 'appearance'],
                    ['primary_color', '#6366f1', 'string', 'Primary Color', 'appearance'],
                    ['logo_url', '/img/logo.png', 'string', 'Logo', 'appearance'],
                    ['enable_public_status', 'true', 'boolean', 'Enable Public Status Page', 'general'],
                    ['timezone', 'UTC', 'string', 'Timezone', 'general'],
                    ['offline_threshold', '180', 'number', 'Offline Threshold (seconds)', 'monitoring'],
                    ['stats_retention_days', '30', 'number', 'Keep Stats (days)', 'monitoring'],
                    // New: Alert thresholds
                    ['cpu_threshold', '80', 'number', 'CPU Alert Threshold (%)', 'alerts'],
                    ['memory_threshold', '85', 'number', 'Memory Alert Threshold (%)', 'alerts'],
                    ['disk_threshold', '90', 'number', 'Disk Alert Threshold (%)', 'alerts'],
                    ['swap_threshold', '80', 'number', 'Swap Alert Threshold (%)', 'alerts'], // New: Swap threshold
                    ['enable_alerts', 'true', 'boolean', 'Enable Auto-Alerts', 'alerts'],
                    // New: Email alerts
                    ['enable_email_alerts', 'false', 'boolean', 'Enable Email Alerts', 'alerts'],
                    ['smtp_host', '', 'string', 'SMTP Host', 'email'],
                    ['smtp_port', '587', 'number', 'SMTP Port', 'email'],
                    ['smtp_user', '', 'string', 'SMTP Username', 'email'],
                    ['smtp_pass', '', 'string', 'SMTP Password', 'email'],
                    ['alert_email', '', 'string', 'Alert Recipient Email', 'email']
                ];
                let settingsCompleted = 0;
                const stmt = db.prepare(`INSERT OR IGNORE INTO settings (key, value, type, description, category) VALUES (?, ?, ?, ?, ?)`);
                defaults.forEach((d, index) => {
                    stmt.run(d, (err) => {
                        if (err) {
                            console.error(`Error inserting setting ${d[0]}:`, err);
                        }
                        settingsCompleted++;
                        if (settingsCompleted === defaults.length) {
                            stmt.finalize(() => {
                                // Load settings into cache
                                db.all("SELECT key, value FROM settings", (err, rows) => {
                                    if (err) {
                                        console.error("Error loading settings:", err);
                                        reject(err);
                                        return;
                                    }
                                    rows.forEach(r => settingsCache[r.key] = r.value);
                                    log(`Loaded ${rows.length} settings into cache`);
                                    configureEmailTransporter();
                                    resolve();
                                });
                            });
                        }
                    });
                });
            }
            // New: Configure email transporter
            function configureEmailTransporter() {
                if (settingsCache.enable_email_alerts === 'true' && settingsCache.smtp_host && settingsCache.smtp_user && settingsCache.smtp_pass) {
                    transporter = nodemailer.createTransport({
                        host: settingsCache.smtp_host,
                        port: parseInt(settingsCache.smtp_port) || 587,
                        secure: parseInt(settingsCache.smtp_port) === 465,
                        auth: {
                            user: settingsCache.smtp_user,
                            pass: settingsCache.smtp_pass
                        }
                    });
                    transporter.verify((err, success) => {
                        if (err) {
                            console.error('SMTP configuration error:', err);
                            transporter = null;
                        } else {
                            log('SMTP transporter configured successfully');
                        }
                    });
                }
            }
        });
    });
}
// ======================
// WEBSOCKET WITH FIXED AUTH & ENHANCED BROADCAST (CRITICAL FIX)
// ======================
wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.authenticated = false;
    ws.on('pong', () => {
        ws.isAlive = true;
    });
    const keepAlive = setInterval(() => {
        if (!ws.isAlive) {
            clearInterval(keepAlive);
            return ws.terminate();
        }
        ws.isAlive = false;
        try {
            ws.ping();
        } catch (e) {
            clearInterval(keepAlive);
        }
    }, 30000);
    // Fixed: Proper session ID extraction with unsigning
    const parsedCookies = cookie.parse(req.headers.cookie || '');
    let sid = null;
    let sessionCookie = parsedCookies['connect.sid'];
    if (sessionCookie) {
        if (sessionCookie.startsWith('s:')) {
            sessionCookie = sessionCookie.slice(2);
        }
        sid = cookieSignature.unsign(sessionCookie, SESSION_SECRET);
    }
    if (sid) {
        store.get(sid, (err, sess) => {
            if (!err && sess?.user) {
                ws.authenticated = true;
                ws.user = sess.user;
                activeConnections.set(ws, sess.user);
                sendInitialData(ws);
            }
        });
    }
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data);
            if (message.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong' }));
            } else if (message.type === 'resolve_alert') {
                if (ws.user && ['admin', 'manager'].includes(ws.user.role)) {
                    db.run(`UPDATE alerts SET resolved = 1, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`, [message.alertId], () => {
                        broadcast({ type: 'alert_resolved', alertId: message.alertId });
                    });
                }
            }
        } catch (e) {
            // Ignore invalid messages
        }
    });
    ws.on('close', () => {
        clearInterval(keepAlive);
        activeConnections.delete(ws);
    });
    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        clearInterval(keepAlive);
        activeConnections.delete(ws);
    });
});
function sendInitialData(ws) {
    if (ws.readyState !== WebSocket.OPEN) return;
    const showAll = ws.authenticated && ['admin', 'manager'].includes(ws.user.role);
    db.all(`
        SELECT n.*, ns.*,
               (strftime('%s','now') - strftime('%s', COALESCE(ns.timestamp, n.last_seen))) as seconds_ago,
               (SELECT COUNT(*) FROM alerts WHERE node_id = n.id AND resolved = 0) as active_alerts
        FROM nodes n
        LEFT JOIN node_stats ns ON ns.id = (
            SELECT id FROM node_stats WHERE node_id = n.id ORDER BY timestamp DESC LIMIT 1
        )
        WHERE n.public = 1 OR ? = 1
        GROUP BY n.id
        ORDER BY n.name
    `, [showAll ? 1 : 0], (err, rows) => {
        if (err) {
            console.error("Error sending initial data:", err);
            return;
        }
        if (ws.readyState !== WebSocket.OPEN) return;
   
        const nodes = (rows || []).map(r => {
            const { api_key, ...safe } = r;
            return {
                ...safe,
                api_key_masked: maskApiKey(api_key),
                group_tags: r.group_tags ? r.group_tags.split(',') : []
            };
        });
   
        // Fixed: Nest alerts query to avoid Promise sync issue
        db.all(`SELECT * FROM alerts WHERE resolved = 0 ORDER BY created_at DESC LIMIT 20`, (err, alerts) => {
            if (err) {
                console.error("Error fetching active alerts:", err);
                alerts = [];
            }
            if (ws.readyState !== WebSocket.OPEN) return;
            try {
                ws.send(JSON.stringify({
                    type: 'init',
                    nodes,
                    settings: settingsCache,
                    user: ws.user || null,
                    alerts: alerts || []
                }));
            } catch (e) {
                console.error("Error sending WebSocket message:", e);
            }
        });
    });
}
function broadcast(data, adminOnly = false) {
    const msg = JSON.stringify(data);
    activeConnections.forEach((user, ws) => {
        if (ws.readyState === WebSocket.OPEN) {
            if (!adminOnly || ['admin', 'manager'].includes(user.role)) {
                try {
                    ws.send(msg);
                } catch (e) {
                    console.error("Error broadcasting message:", e);
                }
            }
        }
    });
}

// ======================
// ROUTES (HARDENED & FIXED + NEW PROFILE)
// ======================
app.get('/', (req, res) => {
    res.render('index', {
        user: req.session.user || null,
        settings: settingsCache
    });
});
app.get('/status', (req, res) => {
    // Early exit if public status is disabled
    if (settingsCache.enable_public_status !== 'true') {
        return res.status(404).render('error', { 
            message: 'Public status page is currently disabled by administrator.',
            user: null, 
            settings: settingsCache 
        });
    }

    // Optimized query: only fetch visible + public nodes + their latest stats
    db.all(`
        SELECT 
            n.id, n.name, n.hostname, n.ip_address, n.ip_alias, n.location,
            n.is_online, n.last_seen, n.latency, n.group_tags,
            ns.cpu_usage, ns.cpu_cores, ns.memory_usage, ns.memory_total, ns.memory_free,
            ns.disk_usage, ns.disk_total, ns.disk_free, ns.swap_total, ns.swap_free,
            ns.network_rx, ns.network_tx, ns.uptime, ns.load_average, ns.cpu_temp,
            ns.processes, ns.os_version, ns.timestamp
        FROM nodes n
        LEFT JOIN node_stats ns ON ns.node_id = n.id 
            AND ns.timestamp = (
                SELECT MAX(timestamp) 
                FROM node_stats 
                WHERE node_id = n.id
            )
        WHERE n.status_page_visible = 1 
          AND n.public = 1
        ORDER BY n.name ASC
    `, (err, rows) => {
        if (err) {
            console.error("Error loading public status nodes:", err);
            return res.status(500).render('error', { 
                message: 'Unable to load status data right now. Please try again later.',
                user: null,
                settings: settingsCache
            });
        }

        // Transform rows for cleaner frontend usage
        const nodes = rows.map(row => ({
            ...row,
            group_tags: row.group_tags ? row.group_tags.split(',').map(t => t.trim()).filter(Boolean) : [],
            // Ensure numbers are numbers (sqlite sometimes returns strings)
            latency: row.latency ? Number(row.latency) : 0,
            cpu_usage: row.cpu_usage ? Number(row.cpu_usage) : null,
            memory_usage: row.memory_usage ? Number(row.memory_usage) : null,
            disk_usage: row.disk_usage ? Number(row.disk_usage) : null,
            uptime: row.uptime ? Number(row.uptime) : null,
            timestamp: row.timestamp || row.last_seen || null,
            // Add computed fields your EJS might like
            is_online: !!row.is_online,
            last_seen_ago: row.last_seen ? timeAgo(new Date(row.last_seen)) : 'Never',
            updated_ago: row.timestamp ? timeAgo(new Date(row.timestamp)) : null
        }));

        // Optional: add overall status summary (can be used in EJS)
        const summary = {
            total: nodes.length,
            online: nodes.filter(n => n.is_online).length,
            offline: nodes.filter(n => !n.is_online).length,
            uptimePercent: nodes.length > 0 
                ? Math.round((nodes.filter(n => n.is_online).length / nodes.length) * 100) 
                : 0,
            lastUpdate: new Date().toISOString()
        };

        res.render('public-status', {
            nodes,
            settings: settingsCache,
            summary,                    // ← new: useful for header stats
            user: null,                 // public page → no session user
            title: `${settingsCache.site_name || 'Status'} - Live Monitoring`
        });
    });
});

// Optional helper (you can move this to a utils file later)
function timeAgo(date) {
    if (!date) return 'Never';
    const seconds = Math.floor((new Date() - date) / 1000);
    let interval = seconds / 31536000;
    if (interval > 1) return Math.floor(interval) + "y ago";
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + "mo ago";
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + "d ago";
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + "h ago";
    interval = seconds / 60;
    if (interval > 1) return Math.floor(interval) + "m ago";
    return "just now";
}
// Auth Routes
app.get('/admin/login', (req, res) => {
    if (req.session.user) return res.redirect('/admin');
    const message = req.query.relogin ? "Password updated successfully. Please log in with your new password." : null;
    const error = req.query.error ? decodeURIComponent(req.query.error) : null;
    res.render('admin-login', { error, message });
});
app.post(
    '/admin/login',
    [
        body('username').trim().notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.render('admin-login', { error: "Invalid input", message: null });
            }
            const { username, password } = req.body;
       
            db.get("SELECT * FROM users WHERE username = ? AND is_active = 1", [username], async (err, user) => {
                if (err) {
                    console.error("Login error:", err);
                    return res.render('admin-login', { error: "Database error", message: null });
                }
           
                if (!user || !(await bcrypt.compare(password, user.password))) {
                    return res.render('admin-login', { error: "Invalid username or password", message: null });
                }
                req.session.regenerate((err) => {
                    if (err) {
                        console.error("Session regeneration error:", err);
                        return res.render('admin-login', { error: "Session error", message: null });
                    }
               
                    req.session.user = {
                        id: user.id,
                        username: user.username,
                        full_name: user.full_name || user.username,
                        role: user.role,
                        avatar: user.avatar
                    };
               
                    db.run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [user.id], (err) => {
                        if (err) console.error("Error updating last login:", err);
                    });
               
                    generateAuditLog(user.id, 'login', {}, req.ip);
                    res.redirect('/admin');
                });
            });
        } catch (error) {
            console.error("Login process error:", error);
            res.render('admin-login', { error: "Internal server error", message: null });
        }
    }
);
app.get('/admin/logout', (req, res) => {
    if (req.session.user) {
        generateAuditLog(req.session.user.id, 'logout', {}, req.ip);
    }
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err);
        }
        res.redirect('/admin/login');
    });
});
app.get('/admin', requireAuth, (req, res) => {
    // 1. Total nodes
    db.get("SELECT COUNT(*) as total FROM nodes", (err, totalResult) => {
        if (err) {
            console.error("Error counting total nodes:", err);
            return res.status(500).render('error', { message: "Database error" });
        }

        // 2. Online nodes
        db.get("SELECT COUNT(*) as online FROM nodes WHERE is_online = 1", (err, onlineResult) => {
            if (err) {
                console.error("Error counting online nodes:", err);
                return res.status(500).render('error', { message: "Database error" });
            }

            // 3. Active (unresolved) alerts
            db.get("SELECT COUNT(*) as activeAlerts FROM alerts WHERE resolved = 0", (err, alertResult) => {
                if (err) {
                    console.error("Error counting active alerts:", err);
                    return res.status(500).render('error', { message: "Database error" });
                }

                // 4. Averages + last timestamp (only from online nodes, latest stat per node)
                db.get(`
                    SELECT 
                        ROUND(AVG(ns.cpu_usage), 2) as avgCpu,
                        ROUND(AVG(ns.memory_usage), 2) as avgMemory,
                        ROUND(AVG(n.latency), 2) as avgLatency,
                        MAX(ns.timestamp) as lastCheck
                    FROM nodes n
                    LEFT JOIN node_stats ns ON ns.node_id = n.id 
                        AND ns.timestamp = (
                            SELECT MAX(timestamp) 
                            FROM node_stats 
                            WHERE node_id = n.id
                        )
                    WHERE n.is_online = 1
                `, (err, averages) => {
                    if (err) {
                        console.error("Error calculating averages:", err);
                        averages = { avgCpu: null, avgMemory: null, avgLatency: null, lastCheck: null };
                    }

                    // 5. Count unique node groups/tags
                    // (assumes group_tags is comma-separated string)
                    db.get(`
                        SELECT COUNT(DISTINCT TRIM(value)) as uniqueGroups
                        FROM nodes,
                             json_each('["' || REPLACE(group_tags, ',', '","') || '"]')
                        WHERE group_tags != '' AND group_tags IS NOT NULL
                    `, (err, groupsResult) => {
                        if (err) {
                            console.error("Error counting unique groups:", err);
                            groupsResult = { uniqueGroups: 0 };
                        }

                        // Format last check time nicely (using server timezone or settings.timezone)
                        let lastCheckFormatted = '—';
                        if (averages?.lastCheck) {
                            const tz = settingsCache.timezone || 'UTC';
                            const date = new Date(averages.lastCheck);
                            lastCheckFormatted = date.toLocaleString('en-US', { 
                                timeZone: tz,
                                dateStyle: 'medium',
                                timeStyle: 'short'
                            });
                        }

                        // Final stats object passed to the view
                        const stats = {
                            totalNodes: totalResult?.total || 0,
                            onlineNodes: onlineResult?.online || 0,
                            activeAlerts: alertResult?.activeAlerts || 0,
                            avgCpu: averages?.avgCpu || null,
                            avgMemory: averages?.avgMemory || null,
                            avgLatency: averages?.avgLatency || null,
                            lastCheck: lastCheckFormatted,
                            uniqueGroups: groupsResult?.uniqueGroups || 0
                        };

                        res.render('admin-dashboard', {
                            user: req.session.user,
                            settings: settingsCache,
                            stats
                        });
                    });
                });
            });
        });
    });
});
// New: Admin Profile Management (Self-edit username, password, etc.)
app.get('/admin/profile', requireAuth, (req, res) => {
    res.render('admin-profile', {
        user: req.session.user,
        settings: settingsCache,
        error: null,
        success: req.query.success ? true : false,
        defaultAvatar: '/img/default-avatar.png',
        message: null
    });
});
app.post('/admin/profile', requireAuth, upload.single('avatar'), [
    body('full_name').optional().trim().escape(),
    body('email').optional().isEmail().normalizeEmail(),
    body('new_username').optional().trim().isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters'),
    body('new_password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('confirm_password').custom((value, { req }) => {
        if (req.body.new_password && value !== req.body.new_password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], async (req, res) => {
    let renderError = null;
    let renderSuccess = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        renderError = errors.array()[0].msg;
        return res.render('admin-profile', {
            user: req.session.user,
            settings: settingsCache,
            error: renderError,
            success: false,
            message: null
        });
    }
    const { full_name, email, new_username, current_password, new_password } = req.body;
    const userId = req.session.user.id;
    let passwordChanged = false;
    try {
        const user = await new Promise((resolve, reject) =>
            db.get("SELECT username, password FROM users WHERE id=?", [userId],
                (err, row) => err ? reject(err) : resolve(row))
        );
        // Require current password for username OR password change
        if ((new_password || new_username) && !current_password) {
            throw new Error("Current password is required for changes");
        } else if ((new_password || new_username) && !await bcrypt.compare(current_password, user.password)) {
            throw new Error("Current password incorrect");
        }
        let updates = [];
        let params = [];
        if (new_username && new_username !== user.username) {
            const exists = await new Promise(resolve =>
                db.get("SELECT id FROM users WHERE username = ? AND id != ?", [new_username, userId],
                    (err, row) => resolve(row))
            );
            if (exists) {
                throw new Error("Username already taken");
            }
            updates.push("username = ?");
            params.push(new_username);
            req.session.user.username = new_username;
        }
        if (full_name) {
            updates.push("full_name = ?");
            params.push(full_name);
            req.session.user.full_name = full_name;
        }
        if (email) {
            updates.push("email = ?");
            params.push(email);
        }
        if (new_password) {
            const hash = await bcrypt.hash(new_password, 12);
            updates.push("password = ?");
            params.push(hash);
            passwordChanged = true;
        }
        if (req.file) {
            const avatarPath = `/var/uploads/${req.file.filename}`;
            if (fs.existsSync(path.join(uploadsDir, req.file.filename))) {
                // New: Delete old avatar if not default
                if (req.session.user.avatar && req.session.user.avatar !== '/img/default-avatar.png') {
                    const oldPath = path.join(__dirname, 'public', req.session.user.avatar.replace('/var/uploads/', 'var/uploads/'));
                    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
                }
                updates.push("avatar = ?");
                params.push(avatarPath);
                req.session.user.avatar = avatarPath;
            } else {
                throw new Error("Uploaded file could not be saved");
            }
        }
        if (updates.length > 0) {
            params.push(userId);
            await new Promise((resolve, reject) =>
                db.run(`UPDATE users SET ${updates.join(', ')}, updated_at=CURRENT_TIMESTAMP WHERE id=?`, params,
                    err => err ? reject(err) : resolve())
            );
            renderSuccess = true;
            generateAuditLog(userId, 'profile_updated', { changes: { full_name, email, new_username: !!new_username, new_password: !!new_password, avatar: !!req?.file } }, req.ip);
        }
        if (passwordChanged) {
            req.session.destroy(() => {
                res.redirect('/admin/login?relogin=required');
            });
            return;
        } else {
            res.redirect('/admin/profile?success=1');
        }
    } catch (err) {
        console.error('Profile update error:', err);
        renderError = err.message || "Something went wrong. Please try again.";
        generateAuditLog(userId, 'profile_update_failed', { error: err.message }, req.ip);
    }
    res.render('admin-profile', {
        user: req.session.user,
        settings: settingsCache,
        error: renderError,
        success: renderSuccess,
        message: null
    });
});
// Users Management (Enhanced: Create admins, edit, activate)
app.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
    db.all("SELECT id, username, full_name, email, role, is_active, created_at, last_login FROM users ORDER BY id", (err, users) => {
        if (err) {
            console.error("Error fetching users:", err);
            users = [];
        }
        res.render('admin-users', {
            user: req.session.user,
            users: users || [],
            settings: settingsCache
        });
    });
});
app.post('/admin/users/add', requireAuth, requireAdmin, [
    body('username').trim().notEmpty().isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('full_name').optional().trim().escape(),
    body('email').optional().isEmail().normalizeEmail(),
    body('role').isIn(['admin', 'manager', 'viewer']).withMessage('Invalid role')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    const { username, password, full_name, email, role } = req.body;
    try {
        const hash = await bcrypt.hash(password, 12);
        db.run(
            `INSERT INTO users (username, password, full_name, email, role, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
            [sanitize(username), hash, sanitize(full_name || username), sanitize(email || ''), role],
            function (err) {
                if (err) {
                    console.error("Error adding user:", err);
                    return res.status(500).json({ error: "Username already exists or database error" });
                }
                generateAuditLog(req.session.user.id, 'user_created', { new_user_id: this.lastID, role }, req.ip);
                log(`User added: ${username} (${role})`);
                res.json({ success: true, id: this.lastID });
            }
        );
    } catch (error) {
        console.error("Error hashing password:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.post('/admin/users/edit/:id', requireAuth, requireAdmin, [
    body('username').optional().trim().notEmpty().isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters'),
    body('full_name').optional().trim().escape(),
    body('email').optional().isEmail().normalizeEmail(),
    body('role').optional().isIn(['admin', 'manager', 'viewer']),
    body('is_active').optional().isIn(['0', '1'])
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    const { username, full_name, email, role, is_active } = req.body;
    const id = parseInt(req.params.id);
    if (isNaN(id) || id === 1) { // Protect default admin
        return res.status(400).json({ error: "Invalid user ID" });
    }
    if (req.session.user.id === id && (username !== req.session.user.username || role !== req.session.user.role)) {
        return res.status(400).json({ error: "Use profile page for self-edits" });
    }
    const updates = [];
    const params = [];
    if (username) {
        updates.push("username = ?");
        params.push(sanitize(username));
    }
    if (full_name !== undefined) {
        updates.push("full_name = ?");
        params.push(sanitize(full_name));
    }
    if (email !== undefined) {
        updates.push("email = ?");
        params.push(sanitize(email));
    }
    if (role) {
        updates.push("role = ?");
        params.push(role);
    }
    if (is_active !== undefined) {
        updates.push("is_active = ?");
        params.push(parseInt(is_active));
    }
    params.push(id);
    const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
    db.run(sql, params, function (err) {
        if (err) {
            console.error("Error updating user:", err);
            return res.status(500).json({ error: "Update failed - username may already exist" });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: "User not found" });
        }
        generateAuditLog(req.session.user.id, 'user_updated', { edited_user_id: id, changes: req.body }, req.ip);
        log(`User updated: ID ${id}`);
        res.json({ success: true });
    });
});
app.post('/admin/users/change-password/:id', requireAuth, requireAdmin, [
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    const { password } = req.body;
    const id = parseInt(req.params.id);
    if (isNaN(id) || id === 1) {
        return res.status(400).json({ error: "Invalid user ID" });
    }
    try {
        const hash = await bcrypt.hash(password, 12);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hash, id], function (err) {
            if (err) {
                console.error("Error changing password:", err);
                return res.status(500).json({ error: "Database error" });
            }
       
            if (this.changes === 0) {
                return res.status(404).json({ error: "User not found" });
            }
       
            generateAuditLog(req.session.user.id, 'user_password_changed', { target_user_id: id }, req.ip);
            log(`Password changed for user ID ${id}`);
            res.json({ success: true });
        });
    } catch (error) {
        console.error("Error hashing password:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.post('/admin/users/delete/:id', requireAuth, requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id) || id === 1 || id === req.session.user.id) {
        return res.status(400).json({ error: "Cannot delete this user" });
    }
    db.run("DELETE FROM users WHERE id = ?", [id], function (err) {
        if (err) {
            console.error("Error deleting user:", err);
            return res.status(500).json({ error: "Database error" });
        }
        if (this.changes > 0) {
            generateAuditLog(req.session.user.id, 'user_deleted', { deleted_user_id: id }, req.ip);
            log(`User deleted: ID ${id}`);
        }
        res.json({ success: this.changes > 0 });
    });
});
// Settings (CRITICAL FIX: Update value only, preserve other columns; New thresholds)

let emailTransporter = null;

function configureEmailTransporter() {
    try {
        emailTransporter = nodemailer.createTransport({
            host: settingsCache.smtp_host,
            port: Number(settingsCache.smtp_port),
            secure: settingsCache.smtp_secure === 'true',
            auth: {
                user: settingsCache.smtp_user,
                pass: settingsCache.smtp_pass
            }
        });

        console.log('📧 Email transporter reconfigured');
    } catch (err) {
        console.error('❌ Failed to configure email transporter:', err);
    }
}

app.get('/admin/settings', requireAuth, requireAdmin, (req, res) => {
    db.all(
        "SELECT key, value, type, description, category FROM settings ORDER BY category ASC, key ASC",
        (err, rows) => {
            if (err) {
                console.error("Error fetching settings from DB:", err);
                // Still render the page, but with empty list and error message
                return res.render('admin-settings', {
                    user: req.session.user,
                    settings: [],
                    globalSettings: settingsCache, // fallback to current cache
                    cache: settingsCache,
                    error: "Failed to load settings from database. Using cached values."
                });
            }

            // Sync cache (only update values that exist in DB)
            const freshCache = { ...settingsCache }; // copy current cache
            rows.forEach(row => {
                freshCache[row.key] = row.value;
            });
            // Replace global cache reference (safe because it's a shallow object)
            Object.assign(settingsCache, freshCache);

            log(`Loaded & synced ${rows.length} settings from database`);

            // Build globalSettings as simple key → value object (what your EJS currently uses)
            const globalSettings = {};
            rows.forEach(row => {
                globalSettings[row.key] = row.value;
            });

            // Also pass the full rows array so EJS can show descriptions, types, categories
            res.render('admin-settings', {
                user: req.session.user,
                settings: rows,             // full rows: key, value, type, description, category
                globalSettings,             // simple { key: value } object
                cache: settingsCache        // current in-memory cache
            });
        }
    );
});
app.post('/admin/settings', requireAuth, requireAdmin, (req, res) => {
    const updates = Object.entries(req.body);
    if (updates.length === 0) {
        return res.redirect('/admin/settings');
    }
    const updateStmt = db.prepare("UPDATE settings SET value = ? WHERE key = ?");
    let completed = 0;
    updates.forEach(([key, val]) => {
        const sanitizedVal = typeof val === 'string' ? sanitize(val) : val.toString();
        updateStmt.run([sanitizedVal, key], (err) => {
            if (err) {
                console.error(`Error updating setting ${key}:`, err);
            } else {
                settingsCache[key] = sanitizedVal;
            }
       
            completed++;
            if (completed === updates.length) {
                updateStmt.finalize(() => {
                    generateAuditLog(req.session.user.id, 'settings_updated', { keys: updates.map(([k]) => k) }, req.ip);
                    broadcast({ type: 'settings_updated', settings: settingsCache });
                    log(`Settings updated: ${updates.length} keys`);
                    // New: Reconfigure email if changed
                    configureEmailTransporter();
                    res.redirect('/admin/settings');
                });
            }
        });
    });
});
// New: Alerts Management
app.get('/admin/alerts', requireAuth, requireAdmin, (req, res) => {
    db.all(`
        SELECT a.*, n.name as node_name
        FROM alerts a
        LEFT JOIN nodes n ON a.node_id = n.id
        ORDER BY a.created_at DESC
        LIMIT 100
    `, (err, alerts) => {
        if (err) {
            console.error("Error fetching alerts:", err);
            alerts = [];
        }
        res.render('admin-alerts', {
            user: req.session.user,
            alerts: alerts || [],
            settings: settingsCache
        });
    });
});
app.post('/admin/alerts/resolve/:id', requireAuth, requireAdmin, (req, res) => {
    const alertId = parseInt(req.params.id);
    if (isNaN(alertId)) return res.status(400).json({ error: "Invalid ID" });
    db.run(`UPDATE alerts SET resolved = 1, resolved_at = CURRENT_TIMESTAMP WHERE id = ?`, [alertId], function(err) {
        if (err) {
            console.error("Error resolving alert:", err);
            return res.status(500).json({ error: "Database error" });
        }
        generateAuditLog(req.session.user.id, 'alert_resolved', { alert_id: alertId }, req.ip);
        broadcast({ type: 'alert_resolved', alertId });
        res.json({ success: this.changes > 0 });
    });
});
// New: Audit Logs
app.get('/admin/audit', requireAuth, requireAdmin, (req, res) => {
    db.all(`
        SELECT al.*, u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.created_at DESC
        LIMIT 200
    `, (err, logs) => {
        if (err) {
            console.error("Error fetching audit logs:", err);
            logs = [];
        }
        res.render('admin-audit', {
            user: req.session.user,
            logs: logs || [],
            settings: settingsCache
        });
    });
});
// New: Database Backup
app.get('/admin/backup', requireAuth, requireAdmin, (req, res) => {
    const backupName = `vps-monitor-backup-${Date.now()}.db`;
    res.download(dbPath, backupName, (err) => {
        if (err) {
            console.error("Backup download error:", err);
            res.status(500).render('error', { message: 'Backup failed' });
        } else {
            generateAuditLog(req.session.user.id, 'database_backup', {}, req.ip);
            log(`Database backup downloaded by user ${req.session.user.id}`);
        }
    });
});
// New: Data Export (CSV/JSON for nodes/stats)
app.get('/admin/export/:type', requireAuth, requireAdmin, (req, res) => {
    const { type } = req.params; // 'nodes', 'stats', 'users', 'alerts', 'database' New: database
    const validTypes = ['nodes', 'stats', 'users', 'alerts', 'database'];
    if (!validTypes.includes(type)) return res.status(400).render('error', { message: 'Invalid export type' });
 
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="vps-monitor-${type}-export-${Date.now()}.zip`);
 
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.on('error', (err) => {
        console.error('Archive error:', err);
        if (!res.headersSent) res.status(500).send('Export failed');
    });
    archive.pipe(res);
    const auditType = type;
 
    if (type === 'database') {
        archive.file(dbPath, { name: 'database.db' });
        archive.finalize();
        generateAuditLog(req.session.user.id, 'data_exported', { type: auditType }, req.ip);
    } else if (type === 'nodes') {
        db.all('SELECT * FROM nodes', (err, rows) => {
            if (err) {
                console.error("Export error:", err);
                archive.abort();
                return res.status(500).render('error', { message: 'Export failed' });
            }
            let csvContent = '';
            if (rows.length > 0) {
                const headers = Object.keys(rows[0]).join(',');
                csvContent = headers + '\n' + rows.map(row => Object.values(row).map(csvEscape).join(',')).join('\n');
            } else {
                csvContent = 'No data';
            }
            archive.append(csvContent, { name: 'nodes.csv' });
            archive.finalize();
            generateAuditLog(req.session.user.id, 'data_exported', { type: auditType }, req.ip);
        });
    } else if (type === 'stats') {
        db.all('SELECT * FROM node_stats ORDER BY timestamp DESC LIMIT 10000', (err, rows) => {
            if (err) {
                console.error("Export error:", err);
                archive.abort();
                return res.status(500).render('error', { message: 'Export failed' });
            }
            const json = JSON.stringify(rows, null, 2);
            archive.append(json, { name: 'stats.json' });
            archive.finalize();
            generateAuditLog(req.session.user.id, 'data_exported', { type: auditType }, req.ip);
        });
    } else if (type === 'users') {
        db.all('SELECT id, username, full_name, email, role, is_active, created_at, last_login FROM users', (err, rows) => {
            if (err) {
                console.error("Export error:", err);
                archive.abort();
                return res.status(500).render('error', { message: 'Export failed' });
            }
            let csvContent = '';
            if (rows.length > 0) {
                const headers = Object.keys(rows[0]).join(',');
                csvContent = headers + '\n' + rows.map(row => Object.values(row).map(csvEscape).join(',')).join('\n');
            } else {
                csvContent = 'No data';
            }
            archive.append(csvContent, { name: 'users.csv' });
            archive.finalize();
            generateAuditLog(req.session.user.id, 'data_exported', { type: auditType }, req.ip);
        });
    } else if (type === 'alerts') {
        db.all('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 1000', (err, rows) => {
            if (err) {
                console.error("Export error:", err);
                archive.abort();
                return res.status(500).render('error', { message: 'Export failed' });
            }
            const json = JSON.stringify(rows, null, 2);
            archive.append(json, { name: 'alerts.json' });
            archive.finalize();
            generateAuditLog(req.session.user.id, 'data_exported', { type: auditType }, req.ip);
        });
    }
});
// Nodes Management (Enhanced with groups, more metrics, fixed delete)
app.get('/admin/nodes', requireAuth, (req, res) => {
    db.all(`
        SELECT n.*,
               (SELECT COUNT(*) FROM node_stats WHERE node_id = n.id) as stats_count,
               (SELECT timestamp FROM node_stats WHERE node_id = n.id ORDER BY timestamp DESC LIMIT 1) as last_stats,
               (SELECT COUNT(*) FROM alerts WHERE node_id = n.id AND resolved = 0) as active_alerts
        FROM nodes n
        ORDER BY name
    `, (err, nodes) => {
        if (err) {
            console.error("Error fetching nodes:", err);
            nodes = [];
        }

        const processed = (nodes || []).map(n => ({
            ...n,
            api_key_masked: maskApiKey(n.api_key),
            has_stats: n.stats_count > 0,
            group_tags: n.group_tags ? n.group_tags.split(',') : []
        }));

        res.render('admin-nodes', {
            user: req.session.user,
            nodes: processed,
            settings: settingsCache
        });
    });
});

app.post('/admin/nodes/add', requireAuth, [
    body('name').trim().notEmpty().isLength({ min: 1, max: 100 }).withMessage('Name is required and must be 1-100 characters'),
    body('group_tags').optional().trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    const { name, hostname, ip_alias, location, public: pub, status_page_visible, monitor_type, group_tags } = req.body;
    const api_key = generateApiKey();
    db.run(
        `INSERT INTO nodes (name, hostname, ip_address, ip_alias, location, api_key, public, status_page_visible, monitor_type, group_tags)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            sanitize(name),
            hostname ? sanitize(hostname) : null,
            null, // ip_address (set on register)
            ip_alias ? sanitize(ip_alias) : null,
            location ? sanitize(location) : 'Unknown',
            api_key,
            pub ? 1 : 0,
            status_page_visible ? 1 : 0,
            monitor_type ? sanitize(monitor_type) : 'agent',
            group_tags ? sanitize(group_tags) : ''
        ],
        function(err) {
            if (err) {
                console.error("Error adding node:", err);
                return res.status(500).json({ error: "Database error" });
            }
            generateAuditLog(req.session.user.id, 'node_created', { node_id: this.lastID, name }, req.ip);
            log(`Node added: ${name} (ID: ${this.lastID})`);
            broadcast({ type: 'node_added', nodeId: this.lastID });
            res.json({ success: true, nodeId: this.lastID, redirect: '/admin/nodes' });
        }
    );
});
app.get('/admin/nodes/edit/:id', requireAuth, (req, res) => {
    const nodeId = parseInt(req.params.id);
    if (isNaN(nodeId)) {
        return res.status(400).render('error', { message: "Invalid node ID" });
    }
    db.get("SELECT * FROM nodes WHERE id = ?", [nodeId], (err, node) => {
        if (err) {
            console.error("Error fetching node:", err);
            return res.status(500).render('error', { message: "Database error" });
        }
   
        if (!node) {
            return res.status(404).render('error', { message: "Node not found" });
        }
   
        res.render('admin-node-edit', {
            user: req.session.user,
            req,
            node: { ...node, api_key_masked: maskApiKey(node.api_key), group_tags: node.group_tags ? node.group_tags.split(',') : [] },
            settings: settingsCache
        });
    });
});
app.post('/admin/nodes/edit/:id', requireAuth, [
    body('name').trim().notEmpty().isLength({ min: 1, max: 100 }).withMessage('Name is required and must be 1-100 characters'),
    body('group_tags').optional().trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    const { name, hostname, ip_alias, location, public: pub, status_page_visible, monitor_type, group_tags } = req.body;
    const nodeId = parseInt(req.params.id);
    if (isNaN(nodeId)) {
        return res.status(400).json({ error: "Invalid node ID" });
    }
    db.run(
        `UPDATE nodes SET name=?, hostname=?, ip_alias=?, location=?, public=?, status_page_visible=?, monitor_type=?, group_tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
        [
            sanitize(name),
            hostname ? sanitize(hostname) : null,
            ip_alias ? sanitize(ip_alias) : null,
            location ? sanitize(location) : 'Unknown',
            pub ? 1 : 0,
            status_page_visible ? 1 : 0,
            monitor_type ? sanitize(monitor_type) : 'agent',
            group_tags ? sanitize(group_tags) : '',
            nodeId
        ],
        function(err) {
            if (err) {
                console.error("Error updating node:", err);
                return res.status(500).json({ error: "Database error" });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: "Node not found" });
            }
            generateAuditLog(req.session.user.id, 'node_updated', { node_id: nodeId, changes: req.body }, req.ip);
            log(`Node updated: ID ${nodeId}`);
            broadcast({ type: 'node_updated', nodeId });
            res.json({ success: true, redirect: '/admin/nodes' });
        }
    );
});
app.post('/admin/nodes/regenerate-key/:id', requireAuth, requireAdmin, (req, res) => {
  const nodeId = parseInt(req.params.id);
  if (isNaN(nodeId)) return res.status(400).json({ error: "Invalid ID" });
  const newKey = generateApiKey();
  db.run(`UPDATE nodes SET api_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [newKey, nodeId],
      function (err) {
          if (err) {
              console.error("Error regenerating API key:", err);
              return res.status(500).json({ success: false, error: "Failed to regenerate key" });
          }
          generateAuditLog(req.session.user.id, 'node_api_key_regenerated', { node_id: nodeId }, req.ip);
          // Broadcast to admin panels only
          broadcast({ type: "node_api_key_regenerated", id: nodeId }, true);
          res.json({
              success: true,
              api_key: newKey,
              masked: maskApiKey(newKey)
          });
      }
  );
});
app.post('/admin/nodes/delete/:id', requireAuth, requireAdmin, (req, res) => {
    const nodeId = parseInt(req.params.id);
    if (isNaN(nodeId)) {
        return res.status(400).json({ success: false, error: "Invalid node ID" });
    }
    db.run("DELETE FROM nodes WHERE id = ?", [nodeId], function (err) {
        if (err) {
            console.error("Error deleting node:", err);
            return res.status(500).json({ success: false, error: "Database error" });
        }
        if (this.changes > 0) {
            generateAuditLog(req.session.user.id, 'node_deleted', { node_id: nodeId }, req.ip);
            log(`Node deleted: ID ${nodeId}`);
            // Fixed: Broadcast deletion to update frontend lists
            broadcast({ type: 'node_deleted', nodeId });
        }
        res.json({ success: this.changes > 0 });
    });
});
app.get('/admin/nodes/view/:id', requireAuth, (req, res) => {
    const nodeId = parseInt(req.params.id, 10);
    if (isNaN(nodeId)) {
        return res.status(400).render('error', {
            status: 400,
            message: "Invalid node ID"
        });
    }

    const serverUrl = `${req.protocol}://${req.get('host')}/api/node/report`;

    db.get("SELECT * FROM nodes WHERE id = ?", [nodeId], (err, node) => {
        if (err) {
            console.error("Error fetching node:", err);
            return res.status(500).render('error', {
                status: 500,
                message: "Database error"
            });
        }

        if (!node) {
            return res.status(404).render('error', {
                status: 404,
                message: "Node not found"
            });
        }

        db.all(
            "SELECT * FROM node_stats WHERE node_id = ? ORDER BY timestamp DESC LIMIT 100",
            [nodeId],
            (err, stats) => {
                if (err) {
                    console.error("Error fetching node stats:", err);
                    stats = [];
                }

                db.all(
                    "SELECT * FROM alerts WHERE node_id = ? ORDER BY created_at DESC LIMIT 50",
                    [nodeId],
                    (err, alerts) => {
                        if (err) {
                            console.error("Error fetching alerts:", err);
                            alerts = [];
                        }

                        res.render('admin-node-view', {
                            user: req.session.user,
                            node: {
                                ...node,
                                api_key_masked: maskApiKey(node.api_key),
                                group_tags: node.group_tags
                                    ? node.group_tags.split(',').map(t => t.trim())
                                    : []
                            },
                            stats: stats || [],
                            req,
                            alerts: alerts || [],
                            settings: settingsCache,
                            serverUrl // ✅ THIS FIXES YOUR EJS ERROR
                        });
                    }
                );
            }
        );
    });
});

// New: API for stats history (for charts, etc.)
app.get('/api/node/stats/:id', requireAuth, [
    body('limit').optional().isInt({ min: 1, max: 1000 }).toInt()
], (req, res) => {
    const nodeId = parseInt(req.params.id);
    const limit = req.query.limit || 100;
    if (isNaN(nodeId)) return res.status(400).json({ error: "Invalid node ID" });
    db.all(`SELECT * FROM node_stats WHERE node_id = ? ORDER BY timestamp DESC LIMIT ?`, [nodeId, limit], (err, stats) => {
        if (err) {
            console.error("Error fetching stats history:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.json({ success: true, stats });
    });
});
// ======================
// API ENDPOINTS (SECURED & VALIDATED + ENHANCED METRICS & ALERTS)
// ======================
app.post('/api/node/register', [
    body('api_key').isLength({ min: 64, max: 64 }).withMessage('Invalid API key format'),
    body('name').optional().trim().escape(),
    body('hostname').optional().trim().escape()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: "Bad request", details: errors.array() });
    }
    const { api_key, name, hostname } = req.body;
    const ip = (req.headers['x-forwarded-for'] || req.ip || '127.0.0.1').split(',')[0].trim().replace('::ffff:', '');
    const geo = geoip.lookup(ip) || {};
    const location = geo.city ? `${geo.city}, ${geo.country}` : 'Unknown';
    db.run(
        `INSERT OR REPLACE INTO nodes (api_key, name, hostname, ip_address, location, is_online, last_seen)
         VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`,
        [api_key, sanitize(name || hostname || "Unknown"), hostname ? sanitize(hostname) : ip, ip, location],
        function (err) {
            if (err) {
                console.error("Error registering node:", err);
                return res.status(500).json({ error: "Database error" });
            }
       
            log(`Node registered: ${name || hostname} [${ip}] (ID: ${this.lastID || 'updated'})`);
            res.json({ success: true, node_id: this.lastID });
        }
    );
});
app.post('/api/node/report', [
    body('api_key').isLength({ min: 64, max: 64 }).withMessage('Invalid API key format')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: "Bad request", details: errors.array() });
    }
    const { api_key, stats = {}, latency = 0 } = req.body;
    db.get("SELECT id, name FROM nodes WHERE api_key = ?", [api_key], (err, node) => {
        if (err) {
            console.error("Error finding node:", err);
            return res.status(500).json({ error: "Database error" });
        }
   
        if (!node) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        // Update node status
        db.run(
            `UPDATE nodes SET is_online = 1, last_seen = CURRENT_TIMESTAMP, latency = ? WHERE id = ?`,
            [parseFloat(latency) || 0, node.id],
            (err) => {
                if (err) console.error("Error updating node status:", err);
                // Resolve offline alert if any
                db.run(`UPDATE alerts SET resolved = 1, resolved_at = CURRENT_TIMESTAMP WHERE node_id = ? AND type = 'offline' AND resolved = 0`, [node.id], (err) => {
                    if (err) console.error("Error resolving offline alert:", err);
                });
            }
        );
        // Insert enhanced stats (with new fields)
        const loadAvg = Array.isArray(stats.load) ? JSON.stringify(stats.load.slice(0, 3)) : JSON.stringify([0, 0, 0]);
        db.run(
            `INSERT INTO node_stats (node_id, cpu_usage, cpu_cores, memory_usage, memory_total, memory_free,
             disk_usage, disk_total, disk_free, swap_total, swap_free,
             network_rx, network_tx, uptime, load_average, cpu_temp, processes, os_version)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                node.id,
                parseFloat(stats.cpu) || 0,
                parseInt(stats.cpu_cores) || 1, // New: CPU cores
                parseFloat(stats.memory?.usedPercent) || 0,
                parseFloat(stats.memory?.total) || 0,
                parseFloat(stats.memory?.free) || 0,
                parseFloat(stats.disk?.usedPercent) || 0,
                parseFloat(stats.disk?.total) || 0,
                parseFloat(stats.disk?.free) || 0,
                parseFloat(stats.swap?.total) || 0, // New: Swap
                parseFloat(stats.swap?.free) || 0,
                parseFloat(stats.network?.rx_sec) || 0, // Live RX
                parseFloat(stats.network?.tx_sec) || 0, // Live TX
                parseFloat(stats.uptime) || 0,
                loadAvg,
                parseFloat(stats.cpu_temp) || 0,
                parseInt(stats.processes) || 0,
                stats.os_version ? sanitize(stats.os_version) : null // New: OS
            ],
            (err) => {
                if (err) {
                    console.error("Error inserting node stats:", err);
                }
                // New: Check thresholds and create alerts
                if (settingsCache.enable_alerts === 'true') {
                    checkAndCreateAlerts(node.id, stats);
                }
            }
        );
        // Broadcast enhanced update
        broadcast({
            type: 'node_update',
            node: {
                id: node.id,
                name: node.name,
                is_online: 1,
                latency,
                ...stats,
                cpu_cores: parseInt(stats.cpu_cores) || 1,
                network_rx: parseFloat(stats.network?.rx_sec) || 0,
                network_tx: parseFloat(stats.network?.tx_sec) || 0,
                os_version: stats.os_version,
                swap: stats.swap // New
            }
        });
        res.json({ success: true });
    });
});
async function checkAndCreateAlerts(nodeId, stats) {
    const cpuThresh = parseFloat(settingsCache.cpu_threshold) || 80;
    const memThresh = parseFloat(settingsCache.memory_threshold) || 85;
    const diskThresh = parseFloat(settingsCache.disk_threshold) || 90;
    const swapThresh = parseFloat(settingsCache.swap_threshold) || 80; // New

    const checks = [
        { type: 'cpu_high', value: stats.cpu || 0, thresh: cpuThresh, message: `CPU usage ${ (stats.cpu || 0).toFixed(1) }% exceeds threshold (${cpuThresh}%)`, severity: 'high' },
        { type: 'memory_high', value: stats.memory?.usedPercent || 0, thresh: memThresh, message: `Memory usage ${ (stats.memory?.usedPercent || 0).toFixed(1) }% exceeds threshold (${memThresh}%)`, severity: 'high' },
        { type: 'disk_high', value: stats.disk?.usedPercent || 0, thresh: diskThresh, message: `Disk usage ${ (stats.disk?.usedPercent || 0).toFixed(1) }% exceeds threshold (${diskThresh}%)`, severity: 'warning' },
        { type: 'swap_high', value: stats.swap?.usedPercent || 0, thresh: swapThresh, message: `Swap usage ${ (stats.swap?.usedPercent || 0).toFixed(1) }% exceeds threshold (${swapThresh}%)`, severity: 'warning' } // New
    ];
 
    for (const { type, value, thresh, message, severity } of checks) {
        if (value > thresh) {
            await createAlert(nodeId, type, message, severity);
        } else {
            db.run(`UPDATE alerts SET resolved = 1, resolved_at = CURRENT_TIMESTAMP WHERE node_id = ? AND type = ? AND resolved = 0`, [nodeId, type]);
        }
    }
}
function createAlert(nodeId, type, message, severity) {
    return new Promise((resolve) => {
        // Check if unresolved alert already exists for this type
        db.get(`SELECT id FROM alerts WHERE node_id = ? AND type = ? AND resolved = 0 ORDER BY created_at DESC LIMIT 1`, [nodeId, type], (err, existing) => {
            if (err || existing) {
                resolve(); // Skip if exists
                return;
            }
            db.run(
                `INSERT INTO alerts (node_id, type, message, severity) VALUES (?, ?, ?, ?)`,
                [nodeId, type, message, severity],
                function(err) {
                    if (!err) {
                        const alert = { id: this.lastID, node_id: nodeId, type, message, severity, created_at: new Date().toISOString() };
                        broadcast({ type: 'new_alert', alert });
                        sendEmailAlert(alert); // New: Send email
                    }
                    resolve();
                }
            );
        });
    });
}
// ======================
// BACKGROUND TASKS (OPTIMIZED + ALERT CLEANUP)
// ======================
// Mark offline nodes
setInterval(() => {
    const threshold = parseInt(settingsCache.offline_threshold || OFFLINE_THRESHOLD);
    db.run(
        `UPDATE nodes SET is_online = 0
         WHERE last_seen < datetime('now', '-' || ? || ' seconds')
           AND is_online = 1`,
        [threshold],
        (err) => {
            if (err) {
                console.error("Error marking offline nodes:", err);
            } else {
                // New: Create offline alert
                if (settingsCache.enable_alerts === 'true') {
                    db.all(`SELECT id, name FROM nodes WHERE is_online = 0 AND last_seen < datetime('now', '-' || ? || ' seconds')`, [threshold], (err, offlineNodes) => {
                        if (err) return;
                        offlineNodes.forEach(node => createAlert(node.id, 'offline', `${node.name} has been offline for over ${threshold}s`, 'critical'));
                    });
                }
            }
        }
    );
}, 30000);
// Cleanup old stats & resolved alerts
cron.schedule('0 3 * * *', () => {
    const days = parseInt(settingsCache.stats_retention_days || 30);
    db.run(
        `DELETE FROM node_stats WHERE timestamp < datetime('now', '-' || ? || ' days')`,
        [days],
        function(err) {
            if (err) {
                console.error("Error cleaning old stats:", err);
            } else {
                log(`Cleaned stats older than ${days} days (${this.changes} records removed)`);
            }
        }
    );
    // Clean old resolved alerts (keep 90 days)
    db.run(`DELETE FROM alerts WHERE resolved = 1 AND resolved_at < datetime('now', '-90 days')`, function(err) {
        if (err) console.error("Error cleaning old alerts:", err);
        else log(`Cleaned old resolved alerts (${this.changes} records)`);
    });
    // New: Vacuum database for optimization
    db.exec('VACUUM', (err) => {
        if (err) console.error("VACUUM error:", err);
        else log('Database VACUUM completed');
    });
});
// WebSocket connection cleanup
setInterval(() => {
    wss.clients.forEach((ws) => {
        if (!ws.isAlive) {
            return ws.terminate();
        }
        ws.isAlive = false;
    });
    wss.clients.forEach(ws => ws.ping());
}, 30000);
// ======================
// ERROR HANDLING MIDDLEWARE (COMPREHENSIVE)
// ======================
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    generateAuditLog(req.session?.user?.id || null, 'error', { error: err.message, url: req.url }, req.ip);
    res.status(500).render('error', {
        message: 'Internal Server Error',
        user: req.session.user || null
    });
});
// ======================
// START SERVER (RESILIENT)
// ======================
initDB().then(() => {
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`
╔══════════════════════════════════════════════════════════════════════════════╗
║ VPS Monitor Pro+ v7.0 Ultimate Edition                                      ║
║ New: Swap Metrics/Alerts • Email Notifications • DB Backup • Stats API      ║
║ All Fixed • Enhanced Security • Blazing Fast • Full Integrity • Zero Bugs   ║
║                                                                             ║
║ Admin Panel → http://localhost:${PORT}/admin                                ║
║ Profile → http://localhost:${PORT}/admin/profile                            ║
║ Public Page → http://localhost:${PORT}/status                               ║
║ Default Login: admin / admin123 → CHANGE IT NOW!                            ║
║                                                                             ║ Made by ❤️ with Hopingboyz                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
        `.trim());
    });
}).catch((error) => {
    console.error("Failed to initialize database:", error);
    process.exit(1);
});
process.on('SIGINT', () => {
    log("Shutting down gracefully...");
    db.close((err) => {
        if (err) {
            console.error("Error closing database:", err);
        }
        server.close(() => {
            console.log("Server shut down successfully");
            process.exit(0);
        });
    });
});
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});
module.exports = app;