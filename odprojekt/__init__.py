import os
from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, flash
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from flask_mail import Mail

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address, storage_uri="redis://redis:6379")

def create_app():
    load_dotenv()  

    app = Flask(__name__)

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///odprojekt.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_TYPE'] = 'filesystem'

    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')

    db.init_app(app)
    Session(app)
    CSRFProtect(app)
    limiter.init_app(app)

    mail = Mail(app)
    app.mail = mail 

    from .filters import markdown_to_html
    @app.template_filter()
    def safe_markdown(content):
        if not content:
            return ""
        return markdown_to_html(content)

    from .models import BannedIP

    @app.before_request
    def check_ip_ban():
        """
        If this IP is banned in BannedIP table, redirect them to /banned.
        """
        if request.endpoint == 'auth_bp.banned':
            return
        ip = request.remote_addr
        if ip:
            banned_entry = BannedIP.query.filter_by(ip_address=ip).first()
            if banned_entry and banned_entry.is_active():
                flash("Your IP is banned from this service.", "error")
                return redirect(url_for('auth_bp.banned'))

    from .main_routes import main_bp
    app.register_blueprint(main_bp)

    from .auth_routes import auth_bp
    app.register_blueprint(auth_bp)

    from .message_routes import message_bp
    app.register_blueprint(message_bp)

    with app.app_context():
        db.create_all()

    return app
