const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(session({ 
    secret: 'jkt48_secret', 
    resave: false, 
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// --- KONEKSI DATABASE ---
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'db_jkt48_service'
}).promise();

// --- MIDDLEWARE ---
const isLogin = (req, res, next) => req.session.userId ? next() : res.redirect('/login');
const isAdmin = (req, res, next) => {
    if (req.session.role === 'admin') next();
    else res.status(403).send("Akses Ditolak: Halaman ini hanya untuk Admin.");
};

// --- AUTH ROUTES ---
app.get('/', (req, res) => res.redirect('/login'));

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        const hash = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', [username, email, hash, role || 'user']);
        res.redirect('/login');
    } catch (err) { res.send("Error: Email sudah terdaftar."); }
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [req.body.email]);
    const user = rows[0];
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        req.session.userId = user.id;
        req.session.role = user.role;
        return res.redirect('/dashboard');
    }
    res.send('Email atau Password salah!');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// --- DASHBOARD USER ---
app.get('/dashboard', isLogin, async (req, res) => {
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    res.render('dashboard', { user: rows[0] });
});

app.post('/generate-key', isLogin, async (req, res) => {
    const key = 'jkt48_' + uuidv4().substring(0, 8);
    await db.query('UPDATE users SET api_key = ? WHERE id = ?', [key, req.session.userId]);
    res.redirect('/dashboard');
});

// --- ADMIN ROUTES (KELOLA DATA) ---
app.get('/admin', isLogin, isAdmin, async (req, res) => {
    const [members] = await db.query('SELECT * FROM members');
    const [users] = await db.query('SELECT * FROM users');
    const [admin] = await db.query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    res.render('admin', { members, users, user: admin[0] });
});

app.get('/admin/add', isLogin, isAdmin, (req, res) => {
    res.render('add_member');
});

app.post('/admin/add', isLogin, isAdmin, async (req, res) => {
    try {
        const { nama, panggilan, tgl_lahir, foto, instagram, tiktok } = req.body;
        
        const query = `
            INSERT INTO members (nama_lengkap, nama_panggilan, tanggal_lahir, foto_url, instagram, tiktok) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        
        await db.query(query, [nama, panggilan, tgl_lahir, foto, instagram, tiktok]);
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send("Gagal simpan data ke database.");
    }
});

app.get('/admin/delete-member/:id', isLogin, isAdmin, async (req, res) => {
    await db.query('DELETE FROM members WHERE id = ?', [req.params.id]);
    res.redirect('/admin');
});

app.get('/admin/delete-user/:id', isLogin, isAdmin, async (req, res) => {
    if(req.params.id == req.session.userId) return res.send("Jangan hapus akun sendiri!");
    await db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.redirect('/admin');
});

// --- SCRAPER GITHUB (ANTI 403) ---
app.get('/scrape', async (req, res) => {
    try {
        const { data } = await axios.get('https://raw.githubusercontent.com/f2face/jkt48-sns-data/main/members.json');
        const memberData = data.map(m => [m.full_name, m.image_url]);
        await db.query('DELETE FROM members');
        await db.query('INSERT INTO members (nama_lengkap, foto_url) VALUES ?', [memberData]);
        res.send("Berhasil sinkronisasi data! <a href='/admin'>Kembali</a>");
    } catch (e) { res.send("Gagal: " + e.message); }
});

// --- API ---
app.get('/api/members', async (req, res) => {
    const [user] = await db.query('SELECT * FROM users WHERE api_key = ?', [req.query.api_key]);
    if (!user.length) return res.status(401).json({ error: 'API Key Salah!' });
    
    const [members] = await db.query('SELECT * FROM members');
    res.json(members); // Sekarang otomatis menyertakan kolom baru tadi
});

// Halaman untuk melihat tampilan profil cantik menggunakan API
app.get('/view/members', async (req, res) => {
    const [user] = await db.query('SELECT * FROM users WHERE api_key = ?', [req.query.api_key]);
    if (!user.length) return res.status(401).send('API Key Salah!');

    const [members] = await db.query('SELECT * FROM members');
    res.render('view_members', { members }); // Merender file EJS baru
});

app.get('/view/members', isLogin, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE api_key = ?', [req.query.api_key]);
        if (!rows.length) return res.status(401).send("API Key tidak valid!");

        const [members] = await db.query('SELECT * FROM members');
        // Render file 'view_members.ejs'
        res.render('view_members', { members }); 
    } catch (err) {
        res.status(500).send("Error memuat galeri.");
    }
});

app.listen(3000, () => console.log('Server Jalan: http://localhost:3000'));