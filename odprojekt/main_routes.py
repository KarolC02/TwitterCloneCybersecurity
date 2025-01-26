from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from .models import User, Message
from sqlalchemy.sql import func

main_bp = Blueprint('main_bp', __name__, template_folder='templates')

def require_login():
    if 'user_id' not in session:
        flash("You must be logged in to access this page.", "error")
        return redirect(url_for('auth_bp.login'))

@main_bp.route('/')
def index():
    if 'user_id' not in session:
        flash("Please log in to access the wall.", "error")
        return redirect(url_for('auth_bp.login'))
    
    user = User.query.get(session.get('user_id'))
    if not user:
        flash("User not found. Please log in again.", "error")
        return redirect(url_for('auth_bp.login'))
    
    messages = Message.query.order_by(Message.timestamp.desc()).limit(20).all()
    return render_template('index.html', messages=messages, user=user)

@main_bp.route('/profile/<username>')
def profile(username):
    if 'user_id' not in session:
        return require_login()
    
    profile_user = User.query.filter_by(username=username).first_or_404()
    logged_in_user = User.query.get(session.get('user_id'))
    if not logged_in_user:
        flash("Logged-in user not found. Please log in again.", "error")
        return redirect(url_for('auth_bp.login'))
    
    messages = Message.query.filter_by(user_id=profile_user.id).order_by(Message.timestamp.desc()).all()
    return render_template('profile.html', user=logged_in_user, profile_user=profile_user, messages=messages)

@main_bp.route('/search', methods=['GET'])
def search_users():
    if 'user_id' not in session:
        return require_login()

    query = request.args.get('q', '').strip()
    if not query:
        flash("Please enter a username to search.", "info")
        return redirect(url_for('main_bp.index'))
    
    user = User.query.get(session.get('user_id'))
    if not user:
        flash("User not found. Please log in again.", "error")
        return redirect(url_for('auth_bp.login'))
    
    results = User.query.filter(User.username.ilike(f"%{query}%")).all()
    return render_template('search_results.html', query=query, results=results, user=user)

@main_bp.context_processor
def inject_popular_users():
    if 'user_id' not in session:
        return {"popular_users": []} 

    user = User.query.get(session.get('user_id'))
    if not user:
        return {"popular_users": []}
    
    popular_users = (
        User.query
        .join(Message, User.id == Message.user_id)
        .group_by(User.id)
        .order_by(func.count(Message.id).desc())
        .limit(5)
        .all()
    )
    return {"popular_users": popular_users}
