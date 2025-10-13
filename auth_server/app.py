import os
import sys
from datetime import datetime, timedelta
import jwt
import pyotp
import qrcode
from io import BytesIO
import base64

# --- YEH LINES ADD KAREIN ---
# This tells Python to look in the parent directory for the 'shared' folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# --- END ---

from flask import (Flask, request, render_template, redirect, make_response, 
                   session, flash, url_for)

from shared.config import Config
from shared.auth_utils import get_user_from_cookie
from models import db, User

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_user_from_cookie():
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email address already registered.', 'error')
            return redirect(url_for('register'))
        
        mfa_secret = pyotp.random_base32()
        new_user = User(email=email, mfa_secret=mfa_secret)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=email, issuer_name='SSO-Demo')
        img = qrcode.make(uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_code_data = base64.b64encode(buffered.getvalue()).decode()
        
        return render_template('register_success.html', qr_code=qr_code_data)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_user_from_cookie():
        return redirect(url_for('dashboard'))

    redirect_url = request.args.get('redirect', url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id_mfa_pending'] = user.id
            session['redirect_url'] = redirect_url
            return redirect(url_for('verify_mfa'))
        
        flash('Invalid email or password!', 'error')
    
    return render_template('login.html')

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    user_id = session.get('user_id_mfa_pending')
    if not user_id: 
        return redirect(url_for('login'))
    
    user = db.session.get(User, user_id)
    if not user: 
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code = request.form['otp_code']
        totp = pyotp.TOTP(user.mfa_secret)
        
        if totp.verify(otp_code):
            redirect_url = session.pop('redirect_url', '/')
            session.pop('user_id_mfa_pending', None)
            
            payload = {'sub': user.id, 'username': user.email.split('@')[0], 'email': user.email,
                       'exp': datetime.utcnow() + timedelta(hours=24)}
            token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
            response = make_response(redirect(redirect_url))
            response.set_cookie('sso_token', token, httponly=True, samesite="Lax", domain="localhost")
            return response
        else:
            flash('Invalid OTP code.', 'error')

    return render_template('verify_mfa.html')

@app.route('/dashboard')
def dashboard():
    user = get_user_from_cookie()
    if not user:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    redirect_url = request.args.get('redirect', url_for('login'))
    response = make_response(redirect(redirect_url))
    response.set_cookie('sso_token', '', expires=0, domain="localhost", path='/')
    session.clear()
    flash('You have been logged out.', 'success')
    return response

@app.route('/')
def home():
    if get_user_from_cookie():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@demo.com').first():
            mfa_secret = pyotp.random_base32()
            admin = User(email='admin@demo.com', mfa_secret=mfa_secret)
            admin.set_password('password123')
            db.session.add(admin)
            db.session.commit()
            print("="*50)
            print("✅ Default user ban gaya: admin@demo.com / password123")
            print("🔑 Iska MFA Secret Key hai (Authenticator app mein daalein):")
            print(f"   {mfa_secret}")
            print("="*50)
    
    print("🚀 Auth server chalu ho raha hai http://localhost:5000 par")
    app.run(debug=True, port=5000, host='localhost')