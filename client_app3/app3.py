import os, sys
from flask import Flask, render_template, redirect, url_for

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import Config
from shared.auth_utils import get_user_from_cookie, require_auth

app = Flask(__name__, template_folder='.')
app.config.from_object(Config)

@app.route('/')
def home():
    user = get_user_from_cookie() 


    app_content = {
        "title": "Profile Settings",
        "icon": "",
        "settings": [
            {"name": "Username", "value": user.get('username') if user else "N/A"},
            {"name": "Email", "value": user.get('email') if user else "N/A"},
            {"name": "Role", "value": user.get('role').capitalize() if user else "N/A"},
            
            {"name": "Subscription", "value": "Premium Plan"},
            {"name": "Notifications", "value": "Enabled"} 
        ]
    }
    
    return render_template('app_template.html', 
                           app_name="App 3", 
                           user=user, 
                           content=app_content)

@app.route('/login')
@require_auth
def login():
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("Client App 3 (Settings) opening in http://localhost:5003 ")
    app.run(debug=True, port=5003, host='localhost')
