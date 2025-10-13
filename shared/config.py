class Config:
    SECRET_KEY = 'a-super-secret-key'
    JWT_SECRET_KEY = 'a-different-jwt-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///sso.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    AUTH_SERVER_URL = 'http://localhost:5000'