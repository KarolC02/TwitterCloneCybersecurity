import re
import time
import pyotp
import secrets
import hashlib
from datetime import datetime, timedelta 
from passlib.hash import pbkdf2_sha256
from flask import Blueprint, request, session, redirect, url_for, flash, render_template, current_app
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from qrcode import QRCode, constants
from io import BytesIO
import base64

from odprojekt import limiter, db  
from .models import User, BannedIP, PasswordReset  

auth_bp = Blueprint('auth_bp', __name__, template_folder='templates')

USERNAME_MAX_LEN = 50
EMAIL_MAX_LEN = 100
PASSWORD_MAX_LEN = 128
USERNAME_REGEX = re.compile(r'^[A-Za-z0-9_.-]+$')
EMAIL_REGEX = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1", "123123", "admin", "letmein",
    "welcome", "monkey", "football", "iloveyou", "111111", "12345", "sunshine", "princess", "password123"
}

def validate_password_strength(pw):
    issues = []
    
    if len(pw) < 12:
        issues.append("Password must be at least 12 characters long.")
    
    if not any(c.isdigit() for c in pw):
        issues.append("Password must contain at least one digit.")
    
    if not any(c.islower() for c in pw):
        issues.append("Password must contain at least one lowercase letter.")
    
    if not any(c.isupper() for c in pw):
        issues.append("Password must contain at least one uppercase letter.")
    
    if not any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in pw):
        issues.append("Password must contain at least one special character.")
    
    if pw.lower() in COMMON_PASSWORDS:
        issues.append("Password is too common or easily guessable.")
    
    return issues

def generate_qr_code(uri):
    qr = QRCode(
        version=1,
        error_correction=constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', user=None)
    
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not email or not password:
        flash("Missing fields.", "error")
        return redirect(url_for('auth_bp.register'))
    
    if len(username) > USERNAME_MAX_LEN or not USERNAME_REGEX.match(username):
        flash("Invalid username format.", "error")
        return redirect(url_for('auth_bp.register'))
    
    if len(email) > EMAIL_MAX_LEN or not EMAIL_REGEX.match(email):
        flash("Invalid email format.", "error")
        return redirect(url_for('auth_bp.register'))
    
    if len(password) > PASSWORD_MAX_LEN:
        flash("Password too long.", "error")
        return redirect(url_for('auth_bp.register'))
    
    pw_issues = validate_password_strength(password)
    if pw_issues:
        for msg in pw_issues:
            flash(msg, "error")
        return redirect(url_for('auth_bp.register'))
    
    existing = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing:
        flash("User already exists.", "error")
        return redirect(url_for('auth_bp.register'))
    
    hashed = pbkdf2_sha256.hash(password)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Twitter Clone")
    qr_code = generate_qr_code(totp_uri)
    
    u = User(
        username=username,
        email=email,
        password_hash=hashed,
        private_key=private_pem.decode(),
        public_key=public_pem.decode(),
        totp_secret=totp_secret
    )
    db.session.add(u)
    db.session.commit()

    session['temp_user_id'] = u.id
    flash("Registered successfully. Please set up 2FA.", "info")
    return render_template('twofa_setup.html', qr_code=qr_code, totp_secret=totp_secret, user=None)

@auth_bp.route('/twofa-setup', methods=['GET', 'POST'])
def twofa_setup():
    if 'temp_user_id' not in session:
        flash("No pending 2FA setup. Please register first.", "error")
        return redirect(url_for('auth_bp.register'))
    
    if request.method == 'GET':
        user = User.query.get(session['temp_user_id'])
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('auth_bp.register'))
        
        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(name=user.username, issuer_name="Twitter Clone")
        qr_code = generate_qr_code(totp_uri)
        return render_template('twofa_setup.html', qr_code=qr_code, totp_secret=user.totp_secret, user=None)

    token = request.form.get('token', '').strip()
    user = User.query.get(session['temp_user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('auth_bp.register'))
    
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(token):
        session.pop('temp_user_id')
        session['user_id'] = user.id
        flash("2FA setup successful. You are now logged in.", "info")
        return redirect(url_for('main_bp.index'))
    else:
        flash("Invalid 2FA token. Please try again.", "error")
        return redirect(url_for('auth_bp.twofa_setup'))

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'GET':
        return render_template('login.html', user=None)
    
    username_or_email = request.form.get('username_or_email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username_or_email or not password:
        time.sleep(1)
        flash("Invalid credentials.", "error")
        return redirect(url_for('auth_bp.login'))
    
    user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
    if not user or not pbkdf2_sha256.verify(password, user.password_hash):
        time.sleep(1)
        flash("Invalid credentials.", "error")
        return redirect(url_for('auth_bp.login'))
    
    session['temp_user_id'] = user.id
    flash("Password correct. Verify 2FA now.", "info")
    return redirect(url_for('auth_bp.twofa_verify'))

@auth_bp.route('/twofa-verify', methods=['GET', 'POST'])
def twofa_verify():
    if request.method == 'GET':
        return render_template('twofa_verify.html', user=None)
    
    if 'temp_user_id' not in session:
        flash("No pending 2FA. Login first.", "error")
        return redirect(url_for('auth_bp.login'))
    
    token = request.form.get('token', '').strip()
    user = User.query.get(session['temp_user_id'])
    if not user or not user.totp_secret:
        time.sleep(1)
        flash("Invalid credentials or no TOTP set.", "error")
        return redirect(url_for('auth_bp.login'))
    
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(token):
        session.pop('temp_user_id')
        session['user_id'] = user.id
        flash("2FA success. Logged in.", "info")
        return redirect(url_for('main_bp.index'))
    else:
        time.sleep(1)
        flash("Invalid TOTP token.", "error")
        return redirect(url_for('auth_bp.twofa_verify'))

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    print("Session before logout:", session)  
    if 'user_id' in session:
        session.pop('user_id')
    if 'temp_user_id' in session:
        session.pop('temp_user_id')
    session.clear()
    print("Session after logout:", session)   
    flash("Logged out.", "info")
    return redirect(url_for('auth_bp.login'))

@auth_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash("Not authenticated. Login + 2FA first.", "error")
        return redirect(url_for('auth_bp.login'))
    
    if request.method == 'GET':
        user = User.query.get(session['user_id'])
        return render_template('change_password.html', user=user)
    
    old_password = request.form.get('old_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    token = request.form.get('totp_token', '').strip()
    
    if not old_password or not new_password or not token:
        flash("Missing fields.", "error")
        return redirect(url_for('auth_bp.change_password'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('auth_bp.login'))
    
    if not pbkdf2_sha256.verify(old_password, user.password_hash):
        time.sleep(1)
        flash("Invalid credentials.", "error")
        return redirect(url_for('auth_bp.change_password'))
    
    pw_issues = validate_password_strength(new_password)
    if pw_issues:
        for issue in pw_issues:
            flash(issue, "error")
        return redirect(url_for('auth_bp.change_password'))
    
    if not user.totp_secret:
        flash("No TOTP set.", "error")
        return redirect(url_for('auth_bp.change_password'))
    
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(token):
        time.sleep(1)
        flash("Invalid 2FA token.", "error")
        return redirect(url_for('auth_bp.change_password'))
    
    user.password_hash = pbkdf2_sha256.hash(new_password)
    db.session.commit()
    flash("Password changed.", "info")
    return redirect(url_for('main_bp.index'))

@auth_bp.route('/banned', methods=['GET'])
def banned():
    """
    Informs the user they are banned if IP is in BannedIP table.
    """
    return render_template('banned.html'), 403


##################################
# FORGOT PASSWORD + RESET PASSWORD
##################################
@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """
    Step 1: User enters email. We send them a reset link if an account exists for that email.
    """
    if request.method == 'GET':
        return render_template('forgot_password.html')

    email = request.form.get('email', '').strip()
    if not email:
        flash("Please enter an email address.", "error")
        return redirect(url_for('auth_bp.forgot_password'))

    user = User.query.filter_by(email=email).first()
    flash("If an account with that email exists, a reset link has been sent.")

    if not user:
        return redirect(url_for('auth_bp.login'))
    
    raw_token = secrets.token_urlsafe(32)  
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    expires = datetime.utcnow() + timedelta(hours=1)
    pr = PasswordReset(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires,
        used=False
    )
    db.session.add(pr)
    db.session.commit()


    reset_link = url_for('auth_bp.reset_password', token=raw_token, _external=True)

    mail = current_app.mail
    from flask_mail import Message
    msg = Message(
        subject="Password Reset",
        sender="no-reply@yourapp.com",
        recipients=[user.email]
    )
    msg.body = f"""
Hello {user.username},

Here is your password reset link (valid for 1 hour):

{reset_link}

If you didn't request this, please ignore.
"""
    mail.send(msg)

    return redirect(url_for('auth_bp.login'))


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    pr = PasswordReset.query.filter_by(token_hash=token_hash, used=False).first()
    if not pr:
        flash("Invalid or expired reset token.", "error")
        return redirect(url_for('auth_bp.login'))

    if datetime.utcnow() > pr.expires_at:
        flash("This reset link has expired.", "error")
        return redirect(url_for('auth_bp.login'))

    if request.method == 'GET':
        return render_template('reset_password.html', token=token)

    new_password = request.form.get('new_password', '').strip()

    pw_issues = validate_password_strength(new_password)
    if pw_issues:
        for issue in pw_issues:
            flash(issue, "error")
        return redirect(url_for('auth_bp.reset_password', token=token))

    user = User.query.get(pr.user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('auth_bp.login'))

    user.password_hash = pbkdf2_sha256.hash(new_password)
    db.session.commit()

    pr.used = True
    db.session.commit()

    flash("Your password has been reset! Please login.", "info")
    return redirect(url_for('auth_bp.login'))
