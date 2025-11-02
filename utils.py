import os
import re
import secrets
import bcrypt
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from config import Config
from models import get_db

def get_or_create_fernet_key():
    if os.path.exists(Config.FERNET_KEY_FILE):
        with open(Config.FERNET_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(Config.FERNET_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

cipher = Fernet(get_or_create_fernet_key())

def encrypt_amount(amount):
    return cipher.encrypt(str(amount).encode()).decode()

def decrypt_amount(encrypted_amount):
    try:
        return float(cipher.decrypt(encrypted_amount.encode()).decode())
    except:
        return 0.0

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain a digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain special character"
    return True, "Strong password"

def sanitize_input(text):
    """
    Sanitize user input to prevent XSS and SQL injection while fully supporting Unicode/emojis.
    This function allows all valid UTF-8 characters including emojis, international characters, etc.
    """
    if text is None:
        return ''
        
    # Convert to string and strip whitespace
    text = str(text).strip()
    if not text:
        return text
    
    # Only block actual script injection attempts - allow emojis and Unicode
    # We check for dangerous HTML/JavaScript patterns but allow normal punctuation
    dangerous_patterns = [
        '<script',
        '</script',
        'javascript:',
        'onload=',
        'onerror=',
        'onclick=',
        'onmouseover=',
        'onfocus=',
        '<iframe',
        '</iframe',
        'eval(',
        'expression(',
    ]
    
    text_lower = text.lower()
    
    # Check for dangerous patterns
    for pattern in dangerous_patterns:
        if pattern in text_lower:
            # Remove the dangerous pattern but keep the rest of the text
            text = re.sub(re.escape(pattern), '', text, flags=re.IGNORECASE)
    
    # Block SQL comment syntax only when combined with SQL keywords (not standalone semicolons)
    # This prevents SQL injection but allows normal punctuation
    sql_injection_pattern = r'(--|/\*|\*/)\s*(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|EXECUTE)'
    text = re.sub(sql_injection_pattern, '', text, flags=re.IGNORECASE)
    
    return text

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def audit_log(username, action, details='', ip_address='127.0.0.1'):
    """Audit logging with full Unicode/emoji support"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Use UTF-8 encoding for file writing to support emojis and international characters
    with open(Config.AUDIT_LOG, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {username} | {action} | {details} | IP: {ip_address}\n")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO audit_logs (username, action, details, ip_address) VALUES (?, ?, ?, ?)',
        (username, action, details, ip_address)
    )
    conn.commit()
    conn.close()

def generate_2fa_code():
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def generate_reset_token(user_id):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    return serializer.dumps(user_id, salt='password-reset-salt')

def verify_reset_token(token, max_age=3600):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    try:
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
        return user_id
    except:
        return None

def is_account_locked(user):
    if user['account_locked_until']:
        locked_until = datetime.fromisoformat(user['account_locked_until'])
        if datetime.now() < locked_until:
            return True, locked_until
    return False, None

def record_failed_login(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if user:
        attempts = user['failed_login_attempts'] + 1
        if attempts >= Config.MAX_LOGIN_ATTEMPTS:
            locked_until = datetime.now() + Config.ACCOUNT_LOCKOUT_DURATION
            cursor.execute(
                'UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE username = ?',
                (attempts, locked_until.isoformat(), username)
            )
        else:
            cursor.execute(
                'UPDATE users SET failed_login_attempts = ? WHERE username = ?',
                (attempts, username)
            )
        conn.commit()
    conn.close()

def reset_failed_login(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE username = ?',
        (username,)
    )
    conn.commit()
    conn.close()

def get_spending_summary(user_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT c.name, c.icon, c.color, t.amount_encrypted
        FROM transactions t
        JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ? AND t.transaction_type = 'expense'
    ''', (user_id,))
    
    transactions = cursor.fetchall()
    conn.close()
    
    summary = {}
    total = 0
    for tx in transactions:
        category = tx['name']
        amount = decrypt_amount(tx['amount_encrypted'])
        total += amount
        if category not in summary:
            summary[category] = {'amount': 0, 'icon': tx['icon'], 'color': tx['color']}
        summary[category]['amount'] += amount
    
    return summary, total

def get_budget_status(user_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT b.id, b.amount_encrypted, c.name, c.icon, c.color, b.category_id
        FROM budgets b
        JOIN categories c ON b.category_id = c.id
        WHERE b.user_id = ? AND b.period = 'monthly'
    ''', (user_id,))
    
    budgets = cursor.fetchall()
    
    budget_status = []
    for budget in budgets:
        budget_amount = decrypt_amount(budget['amount_encrypted'])
        
        cursor.execute('''
            SELECT amount_encrypted FROM transactions
            WHERE user_id = ? AND category_id = ? AND transaction_type = 'expense'
            AND strftime('%Y-%m', date) = strftime('%Y-%m', 'now')
        ''', (user_id, budget['category_id']))
        
        spent_txs = cursor.fetchall()
        spent = sum([decrypt_amount(tx['amount_encrypted']) for tx in spent_txs])
        
        percentage = (spent / budget_amount * 100) if budget_amount > 0 else 0
        
        budget_status.append({
            'category': budget['name'],
            'icon': budget['icon'],
            'color': budget['color'],
            'budget': budget_amount,
            'spent': spent,
            'remaining': budget_amount - spent,
            'percentage': min(percentage, 100)
        })
    
    conn.close()
    return budget_status
