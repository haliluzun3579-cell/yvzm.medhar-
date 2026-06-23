/**
 * MEDHAR — Klinik Karar Destek Sistemi
 * Backend Server — Express + MongoDB + JWT
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');

// ── Sabitler ──────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'MEDHAR_SECRET_KEY_2026_GENOMIK';
const JWT_EXPIRY = '24h';
const MONGO_URI  = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/medhar'; // Localhost fallback

// ══════════════════════════════════════════════════════════
// MONGODB BAĞLANTISI VE ŞEMALAR
// ══════════════════════════════════════════════════════════
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB veritabanına bağlanıldı.'))
  .catch(err => console.error('❌ MongoDB bağlantı hatası:', err));

// Kullanıcı Şeması
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role: { type: String, required: true },
  name: { type: String, required: true },
  is_active: { type: Number, default: 1 },
  last_login: { type: Date, default: null },
  created_at: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Sınıflandırma Şeması
const classificationSchema = new mongoose.Schema({
  variant_id: String,
  chromosome: String,
  gene: String,
  panel: String,
  label: String,
  confidence: Number,
  threshold: Number,
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  created_at: { type: Date, default: Date.now }
});
const Classification = mongoose.model('Classification', classificationSchema);

// Audit Log Şeması
const auditLogSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  endpoint: String,
  ip_addr: String,
  timestamp: { type: Date, default: Date.now }
});
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ── Seed: Varsayılan kullanıcılar ─────────────────────────
async function seedDatabase() {
  try {
    const userCount = await User.countDocuments();
    if (userCount > 0) return; // Zaten seed yapılmış

    const seedUsers = [
      { email:'klinisyen@medhar.tr', password:'medhar2026', role:'klinisyen', name:'Dr. Ayşe Kaya' },
      { email:'uzman@medhar.tr',     password:'medhar2026', role:'uzman',     name:'Dr. Mehmet Demir' },
      { email:'analist@medhar.tr',   password:'medhar2026', role:'analist',   name:'Zeynep Yıldız' },
      { email:'admin@medhar.tr',     password:'medhar2026', role:'admin',     name:'Sistem Admin' },
      { email:'hoca@medhar.tr',      password:'hoca2026',   role:'hoca',      name:'Öğr. Gör. Değerlendirici' },
    ];

    let klinisyenUser = null;
    for (const u of seedUsers) {
      const newUser = await User.create({
        email:         u.email,
        password_hash: bcrypt.hashSync(u.password, 10),
        role:          u.role,
        name:          u.name
      });
      if (u.role === 'klinisyen') klinisyenUser = newUser;
    }

    // Seed analizler
    const seedCls = [
      { variant_id:'VAR_004572', chromosome:'Chr17', gene:'TP53',  panel:'Herediter Kanser', label:'Patojenik', confidence:0.94, threshold:0.5 },
      { variant_id:'VAR_001979', chromosome:'Chr7',  gene:'CFTR',  panel:'CFTR Paneli',      label:'Patojenik', confidence:0.88, threshold:0.5 },
      { variant_id:'VAR_002962', chromosome:'Chr12', gene:'BMPR2', panel:'PAH Paneli',       label:'Benign',    confidence:0.12, threshold:0.5 },
      { variant_id:'VAR_006245', chromosome:'Chr1',  gene:'GNAS',  panel:'Genel (MASTER)',   label:'VUS',       confidence:0.48, threshold:0.5 },
      { variant_id:'VAR_001918', chromosome:'Chr7',  gene:'CFTR',  panel:'CFTR Paneli',      label:'Patojenik', confidence:0.91, threshold:0.5 },
    ];
    
    if (klinisyenUser) {
      for (const c of seedCls) {
        await Classification.create({ ...c, user_id: klinisyenUser._id });
      }
    }

    console.log('✅ MongoDB: Örnek veriler (Seed) başarıyla eklendi.');
  } catch(err) {
    console.error('Seed hatası:', err);
  }
}
seedDatabase();

// ── Express ───────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // HTML dosyasını sun

// ── JWT Middleware ─────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Yetkilendirme gerekli' });
  }
  try {
    const token   = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    req.user      = payload; // { id, email, role, name } (Mongoose ObjectId 'id' olarak veriliyor)
    next();
  } catch {
    return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }
    next();
  };
}

async function auditLog(userId, action, endpoint, req) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  try {
    await AuditLog.create({ user_id: userId, action, endpoint, ip_addr: ip });
  } catch(err) {
    console.error("Audit log error:", err);
  }
}

// ═══════════════════════════════════════════════════════════
// API ENDPOINTS
// ═══════════════════════════════════════════════════════════

// ── Sistem sağlığı ────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const clsCount = await Classification.countDocuments();
    res.json({
      status:          'ok',
      uptime:          Math.round(process.uptime()),
      db:              'mongodb',
      users:           userCount,
      classifications: clsCount,
      timestamp:       new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// ── LOGIN ─────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-posta ve şifre gerekli' });

  try {
    const user = await User.findOne({ email, is_active: 1 });
    if (!user) return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });

    user.last_login = new Date();
    await user.save();
    auditLog(user._id, 'LOGIN', '/api/auth/login', req);

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({ token, user: { id: user._id, email: user.email, role: user.role, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── LOGOUT ────────────────────────────────────────────────
app.post('/api/auth/logout', requireAuth, (req, res) => {
  auditLog(req.user.id, 'LOGOUT', '/api/auth/logout', req);
  res.json({ message: 'Başarıyla çıkış yapıldı' });
});

// ── Mevcut kullanıcı bilgisi ──────────────────────────────
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password_hash');
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    // ID mapping for frontend compatibility
    const userData = user.toObject();
    userData.id = userData._id;
    delete userData._id;
    res.json(userData);
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── Kullanıcı listesi (Admin) ──────────────────────────────
app.get('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password_hash');
    const mapped = users.map(u => {
      let obj = u.toObject();
      obj.id = obj._id;
      delete obj._id;
      return obj;
    });
    res.json(mapped);
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── Kullanıcı ekle (Admin) ────────────────────────────────
app.post('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { email, password, role, name } = req.body;
  const validRoles = ['klinisyen','uzman','analist','admin','hoca'];
  if (!email || !password || !role || !name) return res.status(400).json({ error: 'Tüm alanlar gerekli' });
  if (!validRoles.includes(role)) return res.status(400).json({ error: 'Geçersiz rol' });

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Bu e-posta zaten kayıtlı' });

    const newUser = await User.create({
      email, role, name,
      password_hash: bcrypt.hashSync(password, 10),
      is_active: 1
    });

    auditLog(req.user.id, 'CREATE_USER', '/api/users', req);

    const safeUser = newUser.toObject();
    delete safeUser.password_hash;
    safeUser.id = safeUser._id;
    delete safeUser._id;
    res.json(safeUser);
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── Kullanıcı güncelle (Admin) ────────────────────────────
app.patch('/api/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

    if (req.body.name !== undefined) user.name = req.body.name;
    if (req.body.role !== undefined) user.role = req.body.role;
    if (req.body.is_active !== undefined) user.is_active = req.body.is_active;
    
    await user.save();
    auditLog(req.user.id, 'UPDATE_USER', `/api/users/${req.params.id}`, req);
    res.json({ message: 'Güncellendi' });
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── Sınıflandırma geçmişi ─────────────────────────────────
app.get('/api/classifications', requireAuth, async (req, res) => {
  try {
    let query = {};
    if (!['admin','analist'].includes(req.user.role)) {
      query.user_id = req.user.id;
    }

    const cls = await Classification.find(query)
      .populate('user_id', 'name role')
      .sort({ created_at: -1 })
      .limit(50);

    const result = cls.map(c => {
      const obj = c.toObject();
      obj.id = obj._id;
      delete obj._id;
      // Map user details
      if (obj.user_id) {
        obj.user_name = obj.user_id.name;
        obj.user_role = obj.user_id.role;
        obj.user_id = obj.user_id._id;
      } else {
        obj.user_name = '—';
        obj.user_role = '—';
      }
      return obj;
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── Yeni analiz kaydet ────────────────────────────────────
app.post('/api/classifications', requireAuth, async (req, res) => {
  const { variant_id, chromosome, gene, panel, label, confidence, threshold } = req.body;
  if (!variant_id || !label || confidence === undefined) return res.status(400).json({ error: 'Eksik alan' });

  try {
    const newCls = await Classification.create({
      variant_id, chromosome, gene, panel, label,
      confidence, threshold: threshold ?? 0.5,
      user_id: req.user.id
    });

    auditLog(req.user.id, `CLASSIFY:${label}`, '/api/classifications', req);
    res.json({ id: newCls._id, message: 'Analiz kaydedildi' });
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── Dashboard istatistikleri ──────────────────────────────
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
  try {
    const total = await Classification.countDocuments();
    const patojenik = await Classification.countDocuments({ label: 'Patojenik' });
    const benign = await Classification.countDocuments({ label: 'Benign' });
    const vus = await Classification.countDocuments({ label: 'VUS' });

    res.json({ total, patojenik, benign, vus });
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── Audit log (Admin) ─────────────────────────────────────
app.get('/api/audit-logs', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const logs = await AuditLog.find()
      .populate('user_id', 'name email')
      .sort({ timestamp: -1 })
      .limit(100);

    const mapped = logs.map(l => {
      const obj = l.toObject();
      obj.id = obj._id;
      delete obj._id;
      if (obj.user_id) {
        obj.user_name = obj.user_id.name;
        obj.user_email = obj.user_id.email;
        obj.user_id = obj.user_id._id;
      } else {
        obj.user_name = '—';
        obj.user_email = '—';
      }
      return obj;
    });

    res.json(mapped);
  } catch (err) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// ── HTML dosyasını sun ────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Sunucuyu başlat ───────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║   MEDHAR Klinik Karar Destek Sistemi         ║');
  console.log('║   Sunucu çalışıyor!                          ║');
  console.log(`║   ➜  http://localhost:${PORT}                   ║`);
  console.log('║                                              ║');
  console.log('║   Varsayılan Hesaplar:                       ║');
  console.log('║   klinisyen@medhar.tr / medhar2026           ║');
  console.log('║   uzman@medhar.tr     / medhar2026           ║');
  console.log('║   admin@medhar.tr     / medhar2026           ║');
  console.log('║                                              ║');
  console.log(`║   MongoDB Aktif. (Render & Atlas Uyumlu)     ║`);
  console.log('╚══════════════════════════════════════════════╝');
  console.log('');
});
