import os, sys
from flask import Flask, render_template, redirect, url_for, request

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import Config
from shared.auth_utils import get_user_from_cookie, require_auth

app = Flask(__name__, template_folder='.')
app.config.from_object(Config)

@app.route('/')
def home():
    user = get_user_from_cookie()
    
  
    app_content = {
        "title": "My Notes App",
        "icon": "", 
        "notes": [
            "Finalize the PBL Project Demo.",
            "Review OS concepts: Security, IPC, Concurrency.",
            "Explain the Auth Server as 'Centralized Security'.",
            "Explain Client Apps as 'Distributed Services'.",
            "Ensure JWT tokens are HttpOnly and Secure."
        ]
            }
    return render_template('app_template.html', 
                           app_name="App 1", 
                           user=user, 
                           content=app_content) 

@app.route('/login')
@require_auth
def login():
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("Client App 1 (Notes) opening on http://localhost:5001 par")
    app.run(debug=True, port=5001, host='localhost')
