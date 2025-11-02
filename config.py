import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')
    DATABASE = 'expense_guard.db'
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}
    
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    
    FERNET_KEY_FILE = 'key.key'
    AUDIT_LOG = 'audit_log.txt'
    
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)
    
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'Admin@123!'
    ADMIN_EMAIL = 'admin@expenseguard.com'
