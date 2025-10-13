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
    return render_template('app_template.html', app_name="App 2", user=user)

@app.route('/login')
@require_auth
def login():
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("🚀 Client App 2 chalu ho raha hai http://localhost:5002 par")
    app.run(debug=True, port=5002, host='localhost')