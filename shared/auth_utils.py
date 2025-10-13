import jwt
from functools import wraps
from flask import request, redirect, current_app, g

def get_user_from_cookie():
    """Sirf cookie ko verify karke user data deta hai, redirect nahi karta."""
    token = request.cookies.get('sso_token')
    if not token:
        return None
    try:
        secret_key = current_app.config['JWT_SECRET_KEY']
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return {'username': payload.get('username')}
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def require_auth(f):
    """Yeh decorator user ko login page par bhejta hai agar woh logged-in nahi hai."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_user_from_cookie()
        if not user:
            login_url = f"{current_app.config['AUTH_SERVER_URL']}/login?redirect={request.url_root}"
            return redirect(login_url)
        
        g.user = user
        return f(*args, **kwargs)
    
    return decorated_function