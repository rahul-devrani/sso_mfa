import os, sys
from flask import Flask, render_template, redirect, url_for, abort 

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import Config
from shared.auth_utils import get_user_from_cookie, require_auth

app = Flask(__name__, template_folder='.')
app.config.from_object(Config)

@app.route('/')
def home():
    user = get_user_from_cookie() 

    if user and user.get('role') != 'admin':
        return render_template('unauthorized.html', user=user), 403 
    elif not user:
        app_content = {
            "title": "Admin To-Do List",
            "icon": "->",
        }
        return render_template('app_template.html', 
                               app_name="App 2", 
                               user=user, 
                               content=app_content)

    app_content = {
        "title": "ADMIN To-Do List",
        "icon": "->",
        "tasks": [
            {"name": "User database check ", "done": True},
            {"name": "New features deploy ", "done": False},
            {"name": "Security audit complete ", "done": False}
        ]
    }
    
    return render_template('app_template.html', 
                           app_name="App 2", 
                           user=user, 
                           content=app_content)

@app.route('/login')
@require_auth
def login():
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("Client App 2 (To-Do) opening in http://localhost:5002 ")
    app.run(debug=True, port=5002, host='localhost')
