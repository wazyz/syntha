const express = require('express');
const { createClient } = require('@libsql/client');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const fs = require('fs-extra');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

// Configuración de subida de archivos (temporal en /tmp, Railway sí tiene /tmp)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        fs.ensureDirSync('/tmp/uploads');
        cb(null, '/tmp/uploads/');
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({
    storage,
    limits: { fileSize: 500 * 1024 * 1024 } // 500MB
});

// ==================== BASE DE DATOS TURSO ====================
const db = createClient({
    url: process.env.TURSO_URL,
    authToken: process.env.TURSO_TOKEN
});

// Helper: ejecutar query y devolver rows
async function dbAll(sql, params = []) {
    const result = await db.execute({ sql, args: params });
    return result.rows;
}

async function dbGet(sql, params = []) {
    const result = await db.execute({ sql, args: params });
    return result.rows[0] || null;
}

async function dbRun(sql, params = []) {
    const result = await db.execute({ sql, args: params });
    return result;
}

// Inicializar tablas
async function initDB() {
    await dbRun(`CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        line TEXT NOT NULL,
        domain TEXT,
        email TEXT,
        source_file TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    await dbRun(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        verified INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    await dbRun(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    await dbRun(`CREATE TABLE IF NOT EXISTS upload_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        lines_added INTEGER,
        uploaded_by TEXT,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    await dbRun(`CREATE TABLE IF NOT EXISTS search_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        query TEXT,
        query_type TEXT,
        result_count INTEGER,
        searched_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabla de tokens de admin (persistente entre reinicios)
    await dbRun(`CREATE TABLE IF NOT EXISTS admin_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Crear admin por defecto si no existe
    const adminExists = await dbGet("SELECT id FROM admins WHERE username = ?", ['admin']);
    if (!adminExists) {
        const hashed = bcrypt.hashSync('Admin123!', 10);
        await dbRun("INSERT INTO admins (username, password) VALUES (?, ?)", ['admin', hashed]);
        console.log('✅ Admin creado: admin / Admin123!');
    }

    console.log('✅ Base de datos Turso inicializada');
}

// ==================== FUNCIONES AUXILIARES ====================

function extractDomain(line) {
    const urlMatch = line.match(/(https?:\/\/)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\/[^\s:]*)?/);
    if (urlMatch) return urlMatch[2];
    const domainMatch = line.match(/^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:\/]/);
    if (domainMatch) return domainMatch[1];
    return null;
}

function extractEmail(line) {
    const emailMatch = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    return emailMatch ? emailMatch[0] : null;
}

// Insertar en lotes para máxima velocidad con Turso
async function processAndSaveLines(lines, sourceFile) {
    let added = 0;
    let skipped = 0;
    const BATCH_SIZE = 100;

    const cleanLines = lines.map(l => l.trim()).filter(l => l.length > 0);

    for (let i = 0; i < cleanLines.length; i += BATCH_SIZE) {
        const batch = cleanLines.slice(i, i + BATCH_SIZE);

        // Comprobar existentes en lote
        const placeholders = batch.map(() => '?').join(',');
        const existing = await dbAll(
            `SELECT line FROM credentials WHERE line IN (${placeholders})`,
            batch
        );
        const existingSet = new Set(existing.map(r => r.line));

        // Insertar solo los nuevos
        const newLines = batch.filter(l => !existingSet.has(l));
        for (const trimmed of newLines) {
            const domain = extractDomain(trimmed);
            const email = extractEmail(trimmed);
            await dbRun(
                "INSERT INTO credentials (line, domain, email, source_file) VALUES (?, ?, ?, ?)",
                [trimmed, domain || null, email || null, sourceFile]
            );
            added++;
        }
        skipped += batch.length - newLines.length;

        // Log de progreso cada 1000 líneas
        if (i % 1000 === 0 && i > 0) {
            console.log(`   ⏳ Procesadas ${i}/${cleanLines.length} líneas...`);
        }
    }

    return { added, skipped };
}

// ==================== MIDDLEWARE DE VERIFICACIÓN ====================

async function verifyUserToken(req, res, next) {
    const token = req.headers['x-auth-token'];
    if (!token) return res.status(401).json({ error: 'No autorizado. Inicia sesión.' });

    try {
        const decoded = Buffer.from(token, 'base64').toString();
        const [userId, email, expires] = decoded.split('|');

        if (Date.now() > parseInt(expires)) {
            return res.status(401).json({ error: 'Sesión expirada. Vuelve a iniciar sesión.' });
        }

        const user = await dbGet(
            "SELECT id, username, email, verified FROM users WHERE id = ? AND email = ?",
            [userId, email]
        );
        if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
        if (user.verified !== 1) return res.status(403).json({ error: 'Cuenta no verificada.' });

        req.user = user;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// Tokens de admin en memoria (válidos 24h, se limpian al reiniciar)
const activeAdminTokens = new Map();

async function verifyAdmin(req, res, next) {
    const token = req.headers['x-admin-token'];
    if (!token) return res.status(401).json({ error: 'No autorizado' });

    try {
        // Buscar en tokens activos en memoria
        if (activeAdminTokens.has(token)) {
            const adminData = activeAdminTokens.get(token);
            if (Date.now() - adminData.createdAt < 24 * 60 * 60 * 1000) {
                req.admin = adminData.admin;
                return next();
            } else {
                activeAdminTokens.delete(token);
            }
        }

        // Fallback: decodificar token
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const colonIdx = decoded.lastIndexOf(':');
        if (colonIdx === -1) return res.status(401).json({ error: 'Token inválido' });
        const username = decoded.substring(0, colonIdx);

        const admin = await dbGet("SELECT * FROM admins WHERE username = ?", [username]);
        if (!admin) return res.status(401).json({ error: 'Token inválido. Vuelve a iniciar sesión.' });

        req.admin = admin;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ==================== API PÚBLICA ====================

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
        return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    if (password.length < 6)
        return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    try {
        const existingEmail = await dbGet("SELECT id FROM users WHERE email = ?", [email]);
        if (existingEmail) return res.status(409).json({ error: 'El email ya está registrado' });

        const existingUser = await dbGet("SELECT id FROM users WHERE username = ?", [username]);
        if (existingUser) return res.status(409).json({ error: 'El nombre de usuario ya existe' });

        const hashed = bcrypt.hashSync(password, 10);
        await dbRun(
            "INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, 0)",
            [username, email, hashed]
        );
        res.json({ success: true, message: 'Registro exitoso. Espera verificación del admin.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email y contraseña son obligatorios' });

    try {
        const user = await dbGet("SELECT * FROM users WHERE email = ?", [email]);
        if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });

        if (!bcrypt.compareSync(password, user.password))
            return res.status(401).json({ error: 'Credenciales inválidas' });

        if (user.verified !== 1)
            return res.status(403).json({ error: 'Cuenta pendiente de verificación', needsVerification: true });

        const expires = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 días
        const token = Buffer.from(`${user.id}|${user.email}|${expires}`).toString('base64');
        res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

app.post('/api/verify', verifyUserToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

app.get('/api/stats', async (req, res) => {
    try {
        const row = await dbGet("SELECT COUNT(*) as total FROM credentials");
        res.json({ total_credentials: Number(row?.total) || 0 });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ==================== BÚSQUEDAS ====================

app.get('/api/search/domain', verifyUserToken, async (req, res) => {
    const domain = req.query.q;
    if (!domain) return res.status(400).json({ error: 'Se requiere dominio' });

    const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    try {
        const rows = await dbAll(
            "SELECT id, line, source_file FROM credentials WHERE domain LIKE ? ORDER BY id LIMIT 500",
            [`%${cleanDomain}%`]
        );
        dbRun("INSERT INTO search_stats (user_id, query, query_type, result_count) VALUES (?, ?, ?, ?)",
            [req.user.id, domain, 'domain', rows.length]);
        res.json({ results: rows, count: rows.length });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/search/email', verifyUserToken, async (req, res) => {
    const email = req.query.q;
    if (!email) return res.status(400).json({ error: 'Se requiere email' });

    const cleanEmail = email.toLowerCase().trim();
    try {
        const rows = await dbAll(
            "SELECT id, line, source_file FROM credentials WHERE email LIKE ? ORDER BY id LIMIT 500",
            [`%${cleanEmail}%`]
        );
        dbRun("INSERT INTO search_stats (user_id, query, query_type, result_count) VALUES (?, ?, ?, ?)",
            [req.user.id, email, 'email', rows.length]);
        res.json({ results: rows, count: rows.length });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/search/line', verifyUserToken, async (req, res) => {
    const lineNum = parseInt(req.query.num);
    if (isNaN(lineNum) || lineNum < 1)
        return res.status(400).json({ error: 'Número de línea inválido' });

    try {
        const row = await dbGet("SELECT id, line, source_file FROM credentials WHERE id = ?", [lineNum]);
        res.json({ result: row, lineNumber: lineNum });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ==================== API ADMIN ====================

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const admin = await dbGet("SELECT * FROM admins WHERE username = ?", [username]);
        if (!admin) return res.status(401).json({ error: 'Credenciales inválidas' });

        if (bcrypt.compareSync(password, admin.password)) {
            const token = Buffer.from(`${username}:${Date.now()}:${Math.random()}`).toString('base64');
            const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 días
            // Guardar token en Turso — persiste entre reinicios de Railway
            await dbRun(
                "INSERT INTO admin_tokens (username, token, expires_at) VALUES (?, ?, ?)",
                [username, token, expiresAt]
            );
            // Limpiar tokens expirados
            await dbRun("DELETE FROM admin_tokens WHERE expires_at < ?", [Date.now()]);
            res.json({ token, username: admin.username });
        } else {
            res.status(401).json({ error: 'Credenciales inválidas' });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/admin/dashboard', verifyAdmin, async (req, res) => {
    try {
        const [totalCreds, totalUsers, pendingUsers, logs, topDomains, users] = await Promise.all([
            dbGet("SELECT COUNT(*) as total FROM credentials"),
            dbGet("SELECT COUNT(*) as total FROM users"),
            dbGet("SELECT COUNT(*) as total FROM users WHERE verified = 0"),
            dbAll("SELECT * FROM upload_logs ORDER BY uploaded_at DESC LIMIT 20"),
            dbAll("SELECT domain, COUNT(*) as count FROM credentials WHERE domain IS NOT NULL GROUP BY domain ORDER BY count DESC LIMIT 20"),
            dbAll("SELECT id, username, email, verified, created_at FROM users ORDER BY created_at DESC")
        ]);
        res.json({
            total_credentials: Number(totalCreds?.total) || 0,
            total_users: Number(totalUsers?.total) || 0,
            pending_verifications: Number(pendingUsers?.total) || 0,
            recent_uploads: logs || [],
            top_domains: topDomains || [],
            users: users || []
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/verify-user', verifyAdmin, async (req, res) => {
    const { userId, action } = req.body;
    try {
        if (action === 'approve') {
            await dbRun("UPDATE users SET verified = 1 WHERE id = ?", [userId]);
            res.json({ success: true, message: 'Usuario aprobado correctamente' });
        } else if (action === 'reject') {
            await dbRun("DELETE FROM users WHERE id = ?", [userId]);
            res.json({ success: true, message: 'Usuario rechazado y eliminado' });
        } else {
            res.status(400).json({ error: 'Acción no válida' });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/admin/upload', verifyAdmin, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo' });

    req.socket.setTimeout(10 * 60 * 1000);

    try {
        const sizeMB = (req.file.size / 1024 / 1024).toFixed(2);
        console.log(`📤 Procesando: ${req.file.originalname} (${sizeMB} MB)`);

        const fileContent = await fs.readFile(req.file.path, 'utf-8');
        const lines = fileContent.split(/\r?\n/);
        console.log(`   📝 ${lines.length} líneas encontradas`);

        const { added, skipped } = await processAndSaveLines(lines, req.file.originalname);

        await dbRun(
            "INSERT INTO upload_logs (filename, lines_added, uploaded_by) VALUES (?, ?, ?)",
            [req.file.originalname, added, req.admin.username]
        );

        await fs.remove(req.file.path);
        console.log(`   ✅ ${added} añadidas, ${skipped} duplicadas`);

        res.json({ success: true, added, skipped, total_processed: lines.length, filename: req.file.originalname });
    } catch (error) {
        console.error('Error en upload:', error);
        if (req.file?.path) { try { await fs.remove(req.file.path); } catch(e) {} }
        res.status(500).json({ error: 'Error procesando el archivo: ' + error.message });
    }
});

app.delete('/api/admin/delete/:id', verifyAdmin, async (req, res) => {
    try {
        await dbRun("DELETE FROM credentials WHERE id = ?", [req.params.id]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ==================== INICIAR ====================

app.listen(PORT, '0.0.0.0', async () => {
    console.log(`🚀 SYNTHΛ arrancando en puerto ${PORT}...`);
    try {
        await initDB();
        console.log('✅ Sistema listo');
        console.log(`🌐 Web:   http://localhost:${PORT}`);
        console.log(`🔐 Admin: http://localhost:${PORT}/admin.html`);
    } catch (e) {
        console.error('❌ Error conectando a Turso:', e.message);
        console.error('   Verifica TURSO_URL y TURSO_TOKEN en las variables de entorno de Railway');
        process.exit(1);
    }
});