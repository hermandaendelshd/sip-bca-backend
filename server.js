const express = require('express');
const { Pool } = require('pg'); // 1. UBAH DARI mysql2 MENJADI pg
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'kunci_rahasia_sip_bca_2026';

// 2. KONEKSI DATABASE SUPABASE POSTGRESQL
const db = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres.qhjmizuixizgwpouytjt:Wym92DWejpvwEGYM@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres',
    ssl: { rejectUnauthorized: false }
});

// Middleware Verifikasi Token JWT
function authMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Akses ditolak! Token tidak ada.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token tidak valid atau kadaluwarsa.' });
        req.user = user;
        next();
    });
}

// 3. ENDPOINT LOGIN (Diubah dari ? menjadi $1 dan [rows] jadi result.rows)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Username atau password salah!' });
        }

        const user = result.rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Username atau password salah!' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role, rt_wilayah: user.rt_wilayah },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({
            message: 'Login berhasil!',
            token: token,
            user: {
                username: user.username,
                role: user.role,
                rt_wilayah: user.rt_wilayah
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. ENDPOINT AMBIL DATA WARGA (Diubah dari ? menjadi $1)
app.get('/api/warga', authMiddleware, async (req, res) => {
    try {
        let query = 'SELECT * FROM warga';
        let queryParams = [];

        if (req.user.role === 'RT') {
            query += ' WHERE rt = $1';
            queryParams.push(req.user.rt_wilayah);
        }

        query += ' ORDER BY id DESC';

        const result = await db.query(query, queryParams);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. ENDPOINT TAMBAH WARGA BARU (Diubah dari ? menjadi $1, $2, dst.)
app.post('/api/warga', authMiddleware, async (req, res) => {
    const { nik, no_kk, nama, alamat, hubungan, jk, tgl_lahir, agama, rt, status_tinggal, status_keberadaan } = req.body;

    if (req.user.role === 'RT' && rt !== req.user.rt_wilayah) {
        return res.status(403).json({ message: 'Anda tidak diizinkan menambah data untuk RT lain!' });
    }

    try {
        const query = `
            INSERT INTO warga (nik, no_kk, nama, alamat, hubungan, jk, tgl_lahir, agama, rt, status_tinggal, status_keberadaan)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `;
        await db.query(query, [nik, no_kk, nama, alamat, hubungan, jk, tgl_lahir, agama, rt, status_tinggal, status_keberadaan || 'Aktif']);
        
        res.json({ message: 'Data warga berhasil ditambahkan!' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server berjalan di port ${PORT}`);
});