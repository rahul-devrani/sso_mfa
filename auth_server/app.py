import os
import sys
from datetime import datetime, timedelta
import jwt
import pyotp
import qrcode
from io import BytesIO
import base64

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (Flask, request, render_template, redirect, make_response, 
                   session, flash, url_for)

from shared.config import Config
from shared.auth_utils import get_user_from_cookie
from models import db, User

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

def _create_sso_cookie(user, redirect_url):
    payload = {
        'sub': user.id,
        'username': user.email.split('@')[0],
        'email': user.email,
        'role': user.role,  
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    response = make_response(redirect(redirect_url))
    response.set_cookie('sso_token', token, httponly=True, samesite="Lax", domain="localhost")
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_user_from_cookie():
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email address already registered', 'error')
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
            session['redirect_url'] = redirect_url
            
            if user.mfa_enabled:
                session['user_id_mfa_pending'] = user.id
                return redirect(url_for('verify_mfa'))
            else:
                flash('Login successful (MFA is disabled)', 'success')
                return _create_sso_cookie(user, redirect_url)
            
        flash('Invalid email or password', 'error')
    
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
            
            return _create_sso_cookie(user, redirect_url)
        else:
            flash('Invalid OTP code', 'error')

    return render_template('verify_mfa.html')

@app.route('/dashboard')
def dashboard():
    user_data = get_user_from_cookie()
    if not user_data:
        return redirect(url_for('login'))
    
    try:
        db_user = db.session.get(User, user_data['sub'])
    except Exception as e:
        return redirect(url_for('logout'))

    if not db_user:
        return redirect(url_for('logout'))

    return render_template('dashboard.html', user=user_data, db_user=db_user)

@app.route('/enable-mfa', methods=['GET', 'POST'])
def enable_mfa():
    user_data = get_user_from_cookie()
    if not user_data:
        return redirect(url_for('login'))
    
    db_user = db.session.get(User, user_data['sub'])
    if not db_user:
        return redirect(url_for('logout'))

    if request.method == 'POST':
        otp_code = request.form['otp_code']
        if not db_user.mfa_secret:
            db_user.mfa_secret = pyotp.random_base32()
            
        totp = pyotp.TOTP(db_user.mfa_secret)
        
        if totp.verify(otp_code):
            db_user.mfa_enabled = True
            db.session.commit()
            flash('MFA enabled successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP code, Try again', 'error')
    
    if not db_user.mfa_secret:
        db_user.mfa_secret = pyotp.random_base32()
        db.session.commit()
        
    uri = pyotp.totp.TOTP(db_user.mfa_secret).provisioning_uri(name=db_user.email, issuer_name='SSO-Demo')
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code_data = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('enable_mfa.html', qr_code=qr_code_data)

@app.route('/disable-mfa', methods=['GET', 'POST'])
def disable_mfa():
    user_data = get_user_from_cookie()
    if not user_data:
        return redirect(url_for('login'))
    
    db_user = db.session.get(User, user_data['sub'])
    if not db_user:
        return redirect(url_for('logout'))

    if request.method == 'POST':
        otp_code = request.form['otp_code']
        totp = pyotp.TOTP(db_user.mfa_secret)
        
        if totp.verify(otp_code):
            db_user.mfa_enabled = False
            db.session.commit()
            flash('MFA disabled successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP code, Try again.', 'error')

    return render_template('disable_mfa.html')

@app.route('/logout')
def logout():
    redirect_url = request.args.get('redirect', url_for('login'))
    response = make_response(redirect(redirect_url))
    response.set_cookie('sso_token', '', expires=0, domain="localhost", path='/')
    session.clear()
    flash('You have been logged out', 'success')
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
            
            admin = User(email='admin@demo.com', mfa_secret=mfa_secret, role='admin')
            admin.set_password('password123')
            db.session.add(admin)
            db.session.commit()
            print("="*50)
            print("Default ADMIN user created: admin@demo.com / password123")
            print(f"   Role: {admin.role}")
            print("MFA Secret Key (Add to Authenticator App):")
            print(f"   {mfa_secret}")
            print("="*50)
    
    print("Auth server starting on http://localhost:5000")
    app.run(debug=True, port=5000, host='localhost')
