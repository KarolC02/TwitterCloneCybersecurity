from datetime import datetime
from . import db  

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    private_key = db.Column(db.Text, nullable=True)
    public_key = db.Column(db.Text, nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)

    messages = db.relationship('Message', backref='user', lazy=True)

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class BannedIP(db.Model):
    __tablename__ = 'banned_ips'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    ban_start = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ban_end = db.Column(db.DateTime, nullable=True)
    triggers_count = db.Column(db.Integer, default=1, nullable=False)
    reason = db.Column(db.String(255), nullable=True)

    def is_active(self):
        if self.ban_end is None:
            return True 
        return datetime.utcnow() < self.ban_end

class PasswordReset(db.Model):
    """
    Table to store password reset tokens.
    Each record is valid until expires_at or used is True.
    """
    __tablename__ = 'password_reset'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token_hash = db.Column(db.String(128), nullable=False)  
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', backref='resets')
