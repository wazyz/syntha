const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const fs = require('fs-extra');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuración de subida de archivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, '/app/data/uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Asegurar que las carpetas existan
fs.ensureDirSync('/app/data/uploads');
fs.ensureDirSync('/app/data/data');
fs.ensureDirSync('./public');

// ==================== BASE DE DATOS ====================
const db = new sqlite3.Database(process.env.DB_PATH || '/app/data/database.sqlite');

db.serialize(() => {
    // Tabla de credenciales (búsqueda principal)
    db.run(`
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            line TEXT NOT NULL,
            domain TEXT,
            email TEXT,
            source_file TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Tabla de usuarios
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Tabla de administradores
    db.run(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);
    
    // Tabla de logs de subidas
    db.run(`
        CREATE TABLE IF NOT EXISTS upload_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            lines_added INTEGER,
            uploaded_by TEXT,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Tabla de estadísticas de búsqueda
    db.run(`
        CREATE TABLE IF NOT EXISTS search_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            query TEXT,
            query_type TEXT,
            result_count INTEGER,
            searched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// Crear admin por defecto si no existe
const DEFAULT_ADMIN = {
    username: 'admin',
    password: 'Admin123!'
};

db.get("SELECT * FROM admins WHERE username = ?", [DEFAULT_ADMIN.username], (err, row) => {
    if (!row) {
        const hashed = bcrypt.hashSync(DEFAULT_ADMIN.password, 10);
        db.run("INSERT INTO admins (username, password) VALUES (?, ?)", 
               [DEFAULT_ADMIN.username, hashed]);
        console.log('✅ Admin creado: admin / Admin123!');
    }
});

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

async function processAndSaveLines(lines, sourceFile) {
    let added = 0;
    let skipped = 0;
    
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        
        const exists = await new Promise((resolve) => {
            db.get("SELECT id FROM credentials WHERE line = ?", [trimmed], (err, row) => {
                resolve(!!row);
            });
        });
        
        if (!exists) {
            const domain = extractDomain(trimmed);
            const email = extractEmail(trimmed);
            await new Promise((resolve) => {
                db.run(
                    "INSERT INTO credentials (line, domain, email, source_file) VALUES (?, ?, ?, ?)",
                    [trimmed, domain, email, sourceFile],
                    resolve
                );
            });
            added++;
        } else {
            skipped++;
        }
    }
    
    return { added, skipped };
}

// ==================== MIDDLEWARE DE VERIFICACIÓN ====================

// Verificar token de usuario normal
function verifyUserToken(req, res, next) {
    const token = req.headers['x-auth-token'];
    if (!token) {
        return res.status(401).json({ error: 'No autorizado. Inicia sesión.' });
    }
    
    try {
        const decoded = Buffer.from(token, 'base64').toString();
        const [userId, email, expires] = decoded.split('|');
        
        if (Date.now() > parseInt(expires)) {
            return res.status(401).json({ error: 'Sesión expirada. Vuelve a iniciar sesión.' });
        }
        
        db.get("SELECT id, username, email, verified FROM users WHERE id = ? AND email = ?", 
               [userId, email], (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Usuario no encontrado' });
            }
            if (user.verified !== 1) {
                return res.status(403).json({ error: 'Cuenta no verificada. Espera la aprobación del administrador.' });
            }
            req.user = user;
            next();
        });
    } catch (e) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// Verificar token de admin
function verifyAdmin(req, res, next) {
    const token = req.headers['x-admin-token'];
    if (!token) {
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    try {
        const decoded = Buffer.from(token, 'base64').toString();
        const [username] = decoded.split(':');
        
        db.get("SELECT * FROM admins WHERE username = ?", [username], (err, admin) => {
            if (err || !admin) {
                return res.status(401).json({ error: 'Token inválido' });
            }
            req.admin = admin;
            next();
        });
    } catch (e) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ==================== API PÚBLICA ====================

// Registro de usuario
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    db.run(
        "INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, 0)",
        [username, email, hashedPassword],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Usuario o email ya existe' });
                }
                return res.status(500).json({ error: 'Error al registrar' });
            }
            
            console.log(`📝 Nuevo usuario registrado: ${username} (${email}) - Pendiente de verificación`);
            
            res.json({ 
                success: true, 
                message: 'Registro exitoso. Tu cuenta está pendiente de verificación por el administrador.' 
            });
        }
    );
});

// Login de usuario
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        
        if (user.verified !== 1) {
            return res.status(403).json({ 
                error: 'Cuenta pendiente de verificación',
                needsVerification: true,
                message: 'Tu cuenta aún no ha sido verificada. Espera la aprobación del administrador.'
            });
        }
        
        // Token válido por 30 días
        const expiresIn = 30 * 24 * 60 * 60 * 1000;
        const token = Buffer.from(`${user.id}|${user.email}|${Date.now() + expiresIn}`).toString('base64');
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    });
});

// Verificar token (mantener sesión)
app.post('/api/verify', verifyUserToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// Estadísticas públicas
app.get('/api/stats', (req, res) => {
    db.get("SELECT COUNT(*) as total FROM credentials", (err, countRow) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ total_credentials: countRow.total || 0 });
    });
});

// Búsqueda por dominio (requiere autenticación)
app.get('/api/search/domain', verifyUserToken, (req, res) => {
    const domain = req.query.q;
    if (!domain) return res.status(400).json({ error: 'Se requiere dominio' });
    
    const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    
    db.all(
        "SELECT id, line, source_file FROM credentials WHERE domain LIKE ? ORDER BY id",
        [`%${cleanDomain}%`],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            
            db.run("INSERT INTO search_stats (user_id, query, query_type, result_count) VALUES (?, ?, ?, ?)",
                   [req.user.id, domain, 'domain', rows.length]);
            
            res.json({ results: rows, count: rows.length });
        }
    );
});

// Búsqueda por email (requiere autenticación)
app.get('/api/search/email', verifyUserToken, (req, res) => {
    const email = req.query.q;
    if (!email) return res.status(400).json({ error: 'Se requiere email' });
    
    const cleanEmail = email.toLowerCase().trim();
    
    db.all(
        "SELECT id, line, source_file FROM credentials WHERE email LIKE ? ORDER BY id",
        [`%${cleanEmail}%`],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            
            db.run("INSERT INTO search_stats (user_id, query, query_type, result_count) VALUES (?, ?, ?, ?)",
                   [req.user.id, email, 'email', rows.length]);
            
            res.json({ results: rows, count: rows.length });
        }
    );
});

// Búsqueda por número de línea (requiere autenticación)
app.get('/api/search/line', verifyUserToken, (req, res) => {
    const lineNum = parseInt(req.query.num);
    if (isNaN(lineNum) || lineNum < 1) {
        return res.status(400).json({ error: 'Número de línea inválido' });
    }
    
    db.get(
        "SELECT id, line, source_file FROM credentials WHERE id = ?",
        [lineNum],
        (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ result: row, lineNumber: lineNum });
        }
    );
});

// ==================== API DE ADMINISTRADOR ====================

// Login de admin
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get("SELECT * FROM admins WHERE username = ?", [username], (err, admin) => {
        if (err || !admin) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        
        if (bcrypt.compareSync(password, admin.password)) {
            const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');
            res.json({ token, username: admin.username });
        } else {
            res.status(401).json({ error: 'Credenciales inválidas' });
        }
    });
});

// Dashboard del administrador
app.get('/api/admin/dashboard', verifyAdmin, (req, res) => {
    db.get("SELECT COUNT(*) as total FROM credentials", (err, totalCreds) => {
        db.get("SELECT COUNT(*) as total FROM users", (err2, totalUsers) => {
            db.get("SELECT COUNT(*) as total FROM users WHERE verified = 0", (err3, pendingUsers) => {
                db.all("SELECT * FROM upload_logs ORDER BY uploaded_at DESC LIMIT 20", (err4, logs) => {
                    db.all("SELECT domain, COUNT(*) as count FROM credentials WHERE domain IS NOT NULL GROUP BY domain ORDER BY count DESC LIMIT 20", (err5, topDomains) => {
                        db.all("SELECT id, username, email, verified, created_at FROM users ORDER BY created_at DESC", (err6, users) => {
                            res.json({
                                total_credentials: totalCreds?.total || 0,
                                total_users: totalUsers?.total || 0,
                                pending_verifications: pendingUsers?.total || 0,
                                recent_uploads: logs || [],
                                top_domains: topDomains || [],
                                users: users || []
                            });
                        });
                    });
                });
            });
        });
    });
});

// Aprobar o rechazar usuario
app.post('/api/admin/verify-user', verifyAdmin, (req, res) => {
    const { userId, action } = req.body;
    
    if (action === 'approve') {
        db.run("UPDATE users SET verified = 1 WHERE id = ?", [userId], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Usuario aprobado correctamente' });
        });
    } else if (action === 'reject') {
        db.run("DELETE FROM users WHERE id = ?", [userId], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Usuario rechazado y eliminado' });
        });
    } else {
        res.status(400).json({ error: 'Acción no válida' });
    }
});

// Subir archivo de credenciales
app.post('/api/admin/upload', verifyAdmin, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No se subió ningún archivo' });
    }
    
    try {
        const fileContent = await fs.readFile(req.file.path, 'utf-8');
        const lines = fileContent.split(/\r?\n/);
        const { added, skipped } = await processAndSaveLines(lines, req.file.originalname);
        
        db.run(
            "INSERT INTO upload_logs (filename, lines_added, uploaded_by) VALUES (?, ?, ?)",
            [req.file.originalname, added, req.admin.username]
        );
        
        await fs.remove(req.file.path);
        
        res.json({
            success: true,
            added,
            skipped,
            total_processed: lines.length,
            filename: req.file.originalname
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error procesando el archivo' });
    }
});

// Eliminar una credencial específica
app.delete('/api/admin/delete/:id', verifyAdmin, (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM credentials WHERE id = ?", [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deleted: this.changes });
    });
});

// ==================== CARGAR BASES DE DATOS INICIALES ====================

async function loadBaseDatabases() {
    const dataDir = '/app/data/data';
    if (await fs.pathExists(dataDir)) {
        const files = await fs.readdir(dataDir);
        for (const file of files) {
            if (file.endsWith('.txt')) {
                console.log(`📄 Cargando archivo base: ${file}`);
                try {
                    const content = await fs.readFile(path.join(dataDir, file), 'utf-8');
                    const lines = content.split(/\r?\n/);
                    const { added, skipped } = await processAndSaveLines(lines, `[base] ${file}`);
                    console.log(`   ✅ ${added} nuevas, ${skipped} duplicadas`);
                } catch (e) {
                    console.error(`   ❌ Error cargando ${file}:`, e.message);
                }
            }
        }
    } else {
        console.log('📁 Carpeta data/ no encontrada. Creando...');
        await fs.ensureDirSync('/app/data/data');
        console.log('   Coloca tus archivos .txt en la carpeta data/ y reinicia el servidor');
    }
}

// ==================== INICIAR SERVIDOR ====================

app.listen(PORT, '0.0.0.0', async () => {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║     🚀 syntha - Servidor Activo              ║
║                                                       ║
║     🌐 Web: http://localhost:${PORT}                   ║
║     🔐 Admin: http://localhost:${PORT}/admin.html      ║
║     📝 Login: http://localhost:${PORT}/login.html      ║
║                                                       ║
║     👤 Admin: admin / Admin123!                       ║
╚═══════════════════════════════════════════════════════╝
    `);
    
    await loadBaseDatabases();
    console.log('✅ Sistema listo');
});