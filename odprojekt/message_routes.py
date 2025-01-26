import time
import base64
import pyotp
from flask import Blueprint, request, session, redirect, url_for, flash, render_template, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .models import db, Message, User

message_bp = Blueprint('message_bp', __name__, template_folder='templates')

@message_bp.route('/post-message', methods=['POST'])
def post_message():
    if 'user_id' not in session:
        flash("Not authenticated. Login + 2FA first.", "error")
        return redirect(url_for('auth_bp.login'))

    content = request.form.get('content', '').strip()
    if not content:
        flash("Missing content.", "error")
        return redirect(url_for('main_bp.index'))

    user = User.query.get(session['user_id'])
    if not user or not user.private_key:
        flash("User or key missing.", "error")
        return redirect(url_for('auth_bp.login'))

    private_obj = serialization.load_pem_private_key(user.private_key.encode(), password=None)
    sig = private_obj.sign(content.encode(), padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.b64encode(sig).decode()

    msg = Message(user_id=user.id, content=content, signature=signature_b64)
    db.session.add(msg)
    db.session.commit()

    flash("Message posted.", "info")
    return redirect(url_for('main_bp.index'))

@message_bp.route('/user/<username>', methods=['GET'])
def view_user_messages(username):
    user = User.query.filter_by(username=username).first_or_404()
    messages_data = []
    for m in user.messages:
        messages_data.append({
            "id": m.id,
            "content": m.content,
            "signature": m.signature,
            "timestamp": m.timestamp.isoformat() if m.timestamp else None
        })
    return jsonify({"user": username, "messages": messages_data}), 200

@message_bp.route('/verify-message/<int:message_id>', methods=['GET'])
def verify_message(message_id):
    msg = Message.query.get(message_id)
    if not msg:
        return jsonify({"error": "Message not found"}), 404
    
    user = msg.user
    if not user or not user.public_key:
        return jsonify({"error": "Key missing."}), 400
    
    if not msg.signature:
        return jsonify({"error": "No signature"}), 400
    
    pub = serialization.load_pem_public_key(user.public_key.encode())
    sig_bytes = base64.b64decode(msg.signature)
    content_bytes = msg.content.encode()
    
    try:
        pub.verify(sig_bytes, content_bytes, padding.PKCS1v15(), hashes.SHA256())
        verified = True
    except:
        verified = False
    
    return jsonify({"message_id": msg.id, "content": msg.content, "verified": verified}), 200
