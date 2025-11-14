from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from datetime import datetime


db = SQLAlchemy()
bcrypt = Bcrypt()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    nama_lengkap = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    no_telp = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, nama_lengkap, username, no_telp, email, password, role='user'):
        self.nama_lengkap = nama_lengkap.strip()
        self.username = username.strip().lower()
        self.no_telp = no_telp.strip()
        self.email = email.strip().lower()
        self.set_password(password)  # Gunakan method untuk set password
        self.role = role

    def set_password(self, password):
        """Hash dan simpan password."""
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Cek kecocokan password."""
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self):
        return f"<User id={self.id} | {self.username} | {self.email}>"
