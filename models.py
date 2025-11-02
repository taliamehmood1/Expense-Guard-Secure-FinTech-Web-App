import sqlite3
from datetime import datetime
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DATABASE, 
                         detect_types=sqlite3.PARSE_DECLTYPES,
                         isolation_level=None)
    conn.execute('PRAGMA encoding = "UTF-8"')
    conn.row_factory = sqlite3.Row
    # Enable foreign key support
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_database():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            role TEXT DEFAULT 'user',
            is_2fa_enabled INTEGER DEFAULT 0,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked_until TIMESTAMP,
            profile_picture TEXT,
            theme_preference TEXT DEFAULT 'light',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            icon TEXT,
            color TEXT,
            user_id INTEGER,
            is_default INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category_id INTEGER,
            amount_encrypted TEXT NOT NULL,
            description TEXT,
            transaction_type TEXT DEFAULT 'expense',
            tags TEXT,
            receipt_file TEXT,
            is_recurring INTEGER DEFAULT 0,
            recurring_frequency TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (category_id) REFERENCES categories (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category_id INTEGER,
            amount_encrypted TEXT NOT NULL,
            period TEXT DEFAULT 'monthly',
            start_date TIMESTAMP,
            end_date TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (category_id) REFERENCES categories (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS twofa_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT,
            details TEXT,
            ip_address TEXT
        )
    ''')
    
    default_categories = [
        ('Food & Dining', '🍔', '#FF6B6B', 1),
        ('Transportation', '🚗', '#4ECDC4', 1),
        ('Shopping', '🛍️', '#95E1D3', 1),
        ('Entertainment', '🎮', '#FFE66D', 1),
        ('Bills & Utilities', '💡', '#FF8B94', 1),
        ('Healthcare', '🏥', '#A8E6CF', 1),
        ('Education', '📚', '#FFD3B6', 1),
        ('Travel', '✈️', '#FFAAA5', 1),
        ('Savings', '💰', '#B4E7CE', 1),
        ('Other', '📦', '#C7CEEA', 1)
    ]
    
    cursor.execute('SELECT COUNT(*) FROM categories WHERE is_default = 1')
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            'INSERT INTO categories (name, icon, color, is_default) VALUES (?, ?, ?, ?)',
            default_categories
        )
    
    conn.commit()
    conn.close()
