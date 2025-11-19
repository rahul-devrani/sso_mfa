import os
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

class Config:
    
    SECRET_KEY = 'secret-key'
    JWT_SECRET_KEY = 'jwt-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'sso.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    AUTH_SERVER_URL = 'http://localhost:5000'
