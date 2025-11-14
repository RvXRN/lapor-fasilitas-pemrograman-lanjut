# ===============================================================
# app.py - LaporIN: Sistem Pelaporan Fasilitas Publik
# Versi: 1.0 | Tanggal: 10 Nov 2025
# ===============================================================
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from sqlalchemy.exc import IntegrityError
import re
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# ===============================================================
# 1. DEKORATOR UNTUK NO-CACHE DI HALAMAN PROTECTED
# ===============================================================
def nocache(view):
    def no_cache_view(*args, **kwargs):
        resp = make_response(view(*args, **kwargs))
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    no_cache_view.__name__ = view.__name__
    return no_cache_view

# ===============================================================
# 2. INISIALISASI FLASK APP & EKSTENSI
# ===============================================================
app = Flask(__name__)
app.config.update(
    SECRET_KEY='rahasia_laporin_2025_super_aman_123!',
    SQLALCHEMY_DATABASE_URI='mysql+mysqlconnector://root:@localhost/pelaporan_fasilitas',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={'pool_pre_ping': True, 'pool_recycle': 300}
)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Silakan login terlebih dahulu.'
login_manager.login_message_category = 'warning'

# ===============================================================
# 3. MODEL USER
# ===============================================================
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    nama_lengkap = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    no_telp = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    def __repr__(self):
        return f'<User {self.username}>'

# ===============================================================
# 4. USER LOADER FLASK LOGIN
# ===============================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===============================================================
# 5. BUAT TABEL & ADMIN DEFAULT (sekali saja di awal)
# ===============================================================
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(nama_lengkap='Administrator', username='admin', email='admin@laporin.id', no_telp='081234567890', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Admin default dibuat: username=admin, password=admin123")

# ===============================================================
# 6. ROUTE: LOGIN
# ===============================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip().lower()
        password = request.form.get('password', '')
        if not identifier or not password:
            flash('Email/Username dan password wajib diisi!', 'danger')
            return render_template('login.html')
        user = User.query.filter(
            db.or_(
                db.func.lower(User.email) == identifier,
                db.func.lower(User.username) == identifier
            )
        ).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash(f'Selamat datang, {user.nama_lengkap}!', 'success')
            next_page = request.args.get('next')
            if user.role == 'admin':
                return redirect(next_page or url_for('admin_dashboard'))
            else:
                return redirect(next_page or url_for('index'))
        else:
            flash('Email/Username atau password salah!', 'danger')
    return render_template('login.html')

# ===============================================================
# 7. ROUTE: REGISTER
# ===============================================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nama_lengkap = request.form.get('nama_lengkap', '').strip()
        username = request.form.get('username', '').strip().lower()
        no_telp = request.form.get('no_telp', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not all([nama_lengkap, username, no_telp, email, password, confirm_password]):
            flash('Semua field wajib diisi!', 'danger')
            return render_template('register.html', form=request.form)
        if not re.match(r'^\d{10,13}$', no_telp):
            flash('No. telepon harus 10–13 digit angka!', 'danger')
            return render_template('register.html', form=request.form)
        if not re.match(r'^[a-z0-9_]{3,20}$', username):
            flash('Username: huruf kecil, angka, underscore (3–20 karakter).', 'danger')
            return render_template('register.html', form=request.form)
        if not re.match(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$', email):
            flash('Format email tidak valid!', 'danger')
            return render_template('register.html', form=request.form)
        if password != confirm_password:
            flash('Konfirmasi password tidak cocok!', 'danger')
            return render_template('register.html', form=request.form)
        if len(password) < 6:
            flash('Password minimal 6 karakter!', 'danger')
            return render_template('register.html', form=request.form)
        try:
            new_user = User(nama_lengkap=nama_lengkap, username=username, email=email, no_telp=no_telp)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username atau email sudah digunakan!', 'danger')
    return render_template('register.html', form=None)

# ===============================================================
# 8. ROUTE: LUPA PASSWORD & RESET
# ===============================================================
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Email wajib diisi!', 'danger')
            return render_template('forgot.html')
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='reset-password')
            reset_url = url_for('reset_password', token=token, _external=True)
            # TODO: kirim email ke user berisi reset_url
            flash(f'Link reset password telah dikirim ke {email}', 'info')
            print('Link reset password:', reset_url)
        else:
            flash('Email tidak ditemukan!', 'danger')
    return render_template('forgot.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=7200)  # token 2 jam
    except SignatureExpired:
        flash('Link reset sudah kadaluarsa.', 'danger')
        return redirect(url_for('forgot'))
    except BadSignature:
        flash('Token reset password tidak valid.', 'danger')
        return redirect(url_for('forgot'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Reset password gagal, user tidak ditemukan.', 'danger')
        return redirect(url_for('forgot'))
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        confirm_pwd = request.form.get('confirm_password', '')
        if pwd != confirm_pwd or len(pwd) < 6:
            flash('Password tidak cocok atau kurang dari 6 karakter!', 'danger')
            return render_template('reset_token.html')
        user.set_password(pwd)
        db.session.commit()
        flash('Password berhasil direset. Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html')

@app.route('/forgot_generate_link', methods=['POST'])
def forgot_generate_link():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    no_telp = data.get('no_telp', '').strip()
    user = User.query.filter_by(email=email, no_telp=no_telp).first()
    if not user:
        return jsonify({'success': False, 'message': 'Email dan No. Telepon tidak cocok atau belum terdaftar!'})
    token = serializer.dumps(email, salt='reset-password')
    reset_link = url_for('reset_password', token=token, _external=True)
    return jsonify({'success': True, 'reset_link': reset_link})

# ===============================================================
# 9. ROUTE: ADMIN DASHBOARD (role admin)
# ===============================================================
@app.route('/admin/dashboard')
@login_required
@nocache
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Akses ditolak! Hanya admin.', 'danger')
        return redirect(url_for('index'))
    total_users = User.query.count()
    total_reports = 12  # Ganti dengan query asli jika sudah ada model Laporan
    return render_template('admin_dashboard.html', user=current_user, total_users=total_users, total_reports=total_reports)

# ===============================================================
# 10. ROUTE: DASHBOARD UTAMA & LAINNYA
# ===============================================================
@app.route('/')
@login_required
@nocache
def index():
    laporan = [
        {'id': 1, 'judul': 'Jalan Berlubang di Jl. Sudirman', 'status': 'Menunggu', 'tanggal': '10 Nov 2025'},
        {'id': 2, 'judul': 'Lampu Jalan Mati', 'status': 'Selesai', 'tanggal': '9 Nov 2025'}
    ]
    return render_template('index.html', laporan=laporan, user=current_user)

@app.route('/profil')
@login_required
@nocache
def profil():
    return render_template('profil.html', user=current_user)

@app.route('/riwayat')
@login_required
@nocache
def riwayat():
    return render_template('riwayat.html', user=current_user)

@app.route('/laporan_saya')
@login_required
@nocache
def laporan_saya():
    return render_template('laporan_saya.html', user=current_user)

@app.route('/tambah_laporan')
@login_required
@nocache
def tambah_laporan():
    return render_template('tambah_laporan.html', user=current_user)

@app.route('/kelola_pengguna')
@login_required
@nocache
def kelola_pengguna():
    if current_user.role != 'admin':
        abort(403)
    return render_template('kelola_pengguna.html', user=current_user)

@app.route('/tentang')
@nocache
def tentang():
    return render_template('tentang.html')

# ===============================================================
# 11. ROUTE: LOGOUT
# ===============================================================
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

# ===============================================================
# 12. ERROR HANDLER 403 (Forbidden lebih ramah)
# ===============================================================
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# ===============================================================
# 13. JALANKAN SERVER
# ===============================================================
if __name__ == '__main__':
    print("LaporIN siap dijalankan!")
    print("Login admin: username=admin, password=admin123")
    app.run(host='127.0.0.1', port=5000, debug=True)
