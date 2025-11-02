import os
import io
import csv
import pandas as pd
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from config import Config
from models import init_database, get_db
from utils import (
    hash_password, check_password, validate_password, sanitize_input,
    allowed_file, audit_log, encrypt_amount, decrypt_amount,
    generate_2fa_code, generate_reset_token, verify_reset_token,
    is_account_locked, record_failed_login, reset_failed_login,
    get_spending_summary, get_budget_status
)

app = Flask(__name__)
app.config.from_object(Config)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > Config.PERMANENT_SESSION_LIFETIME:
                session.clear()
                flash('Session expired due to inactivity', 'warning')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in', 'error')
            return redirect(url_for('login'))
        
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def create_admin_user():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (Config.ADMIN_USERNAME,))
    if not cursor.fetchone():
        password_hash = hash_password(Config.ADMIN_PASSWORD)
        cursor.execute(
            'INSERT INTO users (username, email, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)',
            (Config.ADMIN_USERNAME, Config.ADMIN_EMAIL, password_hash, 'Administrator', 'admin')
        )
        conn.commit()
        audit_log('system', 'Admin user created', 'Initial setup')
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    conn = None
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Debug logging
            print(f"Registration attempt - Username: {username}, Email: {email}")
            
            # Input validation
            if not username or not email or not password:
                flash('All fields are required', 'error')
                return render_template('register.html')
            
            # Simple length check only
            if len(username) < 3 or len(username) > 30:
                flash('Username must be between 3 and 30 characters', 'error')
                return render_template('register.html')
                
            # Only block specific dangerous characters, allow everything else
            if any(char in username for char in ['<', '>', '&', '"', '\'', ';', '--']):
                flash('Username contains invalid characters', 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('register.html')
            
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
                return render_template('register')
            
            conn = get_db()
            cursor = conn.cursor()
            
            # Check if username exists
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                flash('Username already exists', 'error')
                conn.close()
                return render_template('register.html')
                
            # Check if email exists
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                flash('Email already registered', 'error')
                conn.close()
                return render_template('register.html')
                
            # Hash password and create user
            password_hash = hash_password(password)
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, username)
            )
            conn.commit()
            user_id = cursor.lastrowid
            
            # Log successful registration
            audit_log(username, 'User registered successfully')
            
            # Commit and close connection
            conn.commit()
            conn.close()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            # Log the error
            error_msg = f"Registration error: {str(e)}"
            print(error_msg)
            if 'conn' in locals() and conn:
                conn.rollback()
                conn.close()
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')
    
    # GET request - show registration form
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        twofa_code = request.form.get('twofa_code', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            flash('Invalid credentials', 'error')
            audit_log(username, 'Failed login attempt', 'User not found')
            conn.close()
            return render_template('login.html')
        
        locked, locked_until = is_account_locked(user)
        if locked:
            flash(f'Account locked until {locked_until.strftime("%H:%M:%S")}', 'error')
            conn.close()
            return render_template('login.html')
        
        if not check_password(password, user['password_hash']):
            record_failed_login(username)
            flash('Invalid credentials', 'error')
            audit_log(username, 'Failed login attempt', 'Wrong password')
            conn.close()
            return render_template('login.html')
        
        if user['is_2fa_enabled']:
            if not twofa_code:
                code = generate_2fa_code()
                expires_at = (datetime.now() + timedelta(minutes=2)).isoformat()
                cursor.execute(
                    'INSERT INTO twofa_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
                    (user['id'], code, expires_at)
                )
                conn.commit()
                conn.close()
                session['pending_2fa_user_id'] = user['id']
                flash(f'2FA Code: {code} (expires in 2 minutes)', 'info')
                return render_template('login.html', show_2fa=True)
            else:
                cursor.execute(
                    'SELECT * FROM twofa_codes WHERE user_id = ? AND code = ? AND used = 0 AND expires_at > ?',
                    (user['id'], twofa_code, datetime.now().isoformat())
                )
                code_record = cursor.fetchone()
                if not code_record:
                    flash('Invalid or expired 2FA code', 'error')
                    conn.close()
                    return render_template('login.html', show_2fa=True)
                
                cursor.execute('UPDATE twofa_codes SET used = 1 WHERE id = ?', (code_record['id'],))
                conn.commit()
        
        conn.close()
        reset_failed_login(username)
        
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['last_activity'] = datetime.now().isoformat()
        
        audit_log(username, 'Successful login', 'User authenticated')
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Unknown')
    audit_log(username, 'User logged out')
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT t.*, c.name as category_name, c.icon, c.color
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ?
        ORDER BY t.date DESC
        LIMIT 10
    ''', (session['user_id'],))
    recent_txs = cursor.fetchall()
    
    transactions = []
    for tx in recent_txs:
        transactions.append({
            'id': tx['id'],
            'category': tx['category_name'] or 'Uncategorized',
            'icon': tx['icon'] or '📦',
            'color': tx['color'] or '#999',
            'amount': decrypt_amount(tx['amount_encrypted']),
            'description': tx['description'],
            'type': tx['transaction_type'],
            'date': tx['date'],
            'receipt': tx['receipt_file']
        })
    
    summary, total_spent = get_spending_summary(session['user_id'])
    budget_status = get_budget_status(session['user_id'])
    
    cursor.execute(
        'SELECT COUNT(*) as count FROM transactions WHERE user_id = ?',
        (session['user_id'],)
    )
    total_transactions = cursor.fetchone()['count']
    
    conn.close()
    
    return render_template('dashboard.html',
        transactions=transactions,
        summary=summary,
        total_spent=total_spent,
        budget_status=budget_status,
        total_transactions=total_transactions
    )

@app.route('/transactions')
@login_required
def transactions():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT t.*, c.name as category_name, c.icon, c.color
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ?
        ORDER BY t.date DESC
    ''', (session['user_id'],))
    
    all_txs = cursor.fetchall()
    transactions = []
    for tx in all_txs:
        transactions.append({
            'id': tx['id'],
            'category': tx['category_name'] or 'Uncategorized',
            'icon': tx['icon'] or '📦',
            'amount': decrypt_amount(tx['amount_encrypted']),
            'description': tx['description'],
            'type': tx['transaction_type'],
            'tags': tx['tags'],
            'date': tx['date'],
            'receipt': tx['receipt_file']
        })
    
    cursor.execute('SELECT * FROM categories WHERE is_default = 1 OR user_id = ?', (session['user_id'],))
    categories = cursor.fetchall()
    
    conn.close()
    
    return render_template('transactions.html', transactions=transactions, categories=categories)

@app.route('/transaction/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    if request.method == 'POST':
        category_id = request.form.get('category_id')
        amount = request.form.get('amount')
        description = sanitize_input(request.form.get('description'))
        tx_type = request.form.get('type', 'expense')
        tags = sanitize_input(request.form.get('tags', ''))
        
        if not category_id or not amount:
            flash('Category and amount are required', 'error')
            return redirect(url_for('transactions'))
        
        try:
            amount_float = float(amount)
            if amount_float <= 0:
                raise ValueError
        except ValueError:
            flash('Invalid amount', 'error')
            return redirect(url_for('transactions'))
        
        amount_encrypted = encrypt_amount(amount_float)
        
        receipt_file = None
        if 'receipt' in request.files:
            file = request.files['receipt']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"{session['user_id']}_{datetime.now().timestamp()}_{file.filename}")
                os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
                file.save(os.path.join(Config.UPLOAD_FOLDER, filename))
                receipt_file = filename
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO transactions (user_id, category_id, amount_encrypted, description, transaction_type, tags, receipt_file)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], category_id, amount_encrypted, description, tx_type, tags, receipt_file))
        conn.commit()
        conn.close()
        
        audit_log(session['username'], f'Added {tx_type}', f'Amount: ${amount_float}, Category ID: {category_id}')
        flash(f'{tx_type.capitalize()} added successfully!', 'success')
        return redirect(url_for('transactions'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM categories WHERE is_default = 1 OR user_id = ?', (session['user_id'],))
    categories = cursor.fetchall()
    conn.close()
    
    return render_template('add_edit_transaction.html', categories=categories, transaction=None)

@app.route('/transaction/edit/<int:tx_id>', methods=['GET', 'POST'])
@login_required
def edit_transaction(tx_id):
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        category_id = request.form.get('category_id')
        amount = request.form.get('amount')
        description = sanitize_input(request.form.get('description'))
        
        try:
            amount_float = float(amount)
            if amount_float <= 0:
                raise ValueError
        except ValueError:
            flash('Invalid amount', 'error')
            conn.close()
            return redirect(url_for('transactions'))
        
        amount_encrypted = encrypt_amount(amount_float)
        
        cursor.execute('''
            UPDATE transactions
            SET category_id = ?, amount_encrypted = ?, description = ?
            WHERE id = ? AND user_id = ?
        ''', (category_id, amount_encrypted, description, tx_id, session['user_id']))
        conn.commit()
        conn.close()
        
        audit_log(session['username'], 'Edited transaction', f'TX ID: {tx_id}')
        flash('Transaction updated successfully!', 'success')
        return redirect(url_for('transactions'))
    
    cursor.execute('SELECT * FROM transactions WHERE id = ? AND user_id = ?', (tx_id, session['user_id']))
    tx = cursor.fetchone()
    
    if not tx:
        flash('Transaction not found', 'error')
        conn.close()
        return redirect(url_for('transactions'))
    
    transaction = {
        'id': tx['id'],
        'category_id': tx['category_id'],
        'amount': decrypt_amount(tx['amount_encrypted']),
        'description': tx['description'],
        'type': tx['transaction_type']
    }
    
    cursor.execute('SELECT * FROM categories WHERE is_default = 1 OR user_id = ?', (session['user_id'],))
    categories = cursor.fetchall()
    conn.close()
    
    return render_template('add_edit_transaction.html', categories=categories, transaction=transaction)

@app.route('/transaction/delete/<int:tx_id>', methods=['POST'])
@login_required
def delete_transaction(tx_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM transactions WHERE id = ? AND user_id = ?', (tx_id, session['user_id']))
    conn.commit()
    conn.close()
    
    audit_log(session['username'], 'Deleted transaction', f'TX ID: {tx_id}')
    flash('Transaction deleted successfully!', 'success')
    return redirect(url_for('transactions'))

@app.route('/budgets')
@login_required
def budgets():
    budget_status = get_budget_status(session['user_id'])
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM categories WHERE is_default = 1 OR user_id = ?', (session['user_id'],))
    categories = cursor.fetchall()
    conn.close()
    
    return render_template('budgets.html', budgets=budget_status, categories=categories)

@app.route('/budget/add', methods=['POST'])
@login_required
def add_budget():
    category_id = request.form.get('category_id')
    amount = request.form.get('amount')
    
    try:
        amount_float = float(amount)
        if amount_float <= 0:
            raise ValueError
    except ValueError:
        flash('Invalid budget amount', 'error')
        return redirect(url_for('budgets'))
    
    amount_encrypted = encrypt_amount(amount_float)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO budgets (user_id, category_id, amount_encrypted, period)
        VALUES (?, ?, ?, 'monthly')
    ''', (session['user_id'], category_id, amount_encrypted))
    conn.commit()
    conn.close()
    
    audit_log(session['username'], 'Added budget', f'Category ID: {category_id}, Amount: ${amount_float}')
    flash('Budget created successfully!', 'success')
    return redirect(url_for('budgets'))

@app.route('/import_export')
@login_required
def import_export():
    return render_template('import_export.html')

@app.route('/import/csv', methods=['POST'])
@login_required
def import_csv():
    if 'csv_file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('import_export'))
    
    file = request.files['csv_file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('import_export'))
    
    if not file.filename.endswith('.csv'):
        flash('Invalid file type. Please upload a CSV file', 'error')
        return redirect(url_for('import_export'))
    
    try:
        df = pd.read_csv(file)
        required_columns = ['category', 'amount', 'description', 'type']
        if not all(col in df.columns for col in required_columns):
            flash('CSV must have columns: category, amount, description, type', 'error')
            return redirect(url_for('import_export'))
        
        conn = get_db()
        cursor = conn.cursor()
        
        success_count = 0
        failed_rows = []
        
        for idx, row in df.iterrows():
            try:
                cursor.execute('SELECT id FROM categories WHERE name = ?', (row['category'],))
                category = cursor.fetchone()
                if not category:
                    failed_rows.append(f"Row {idx+2}: Category '{row['category']}' not found")
                    continue
                
                amount = float(row['amount'])
                if amount <= 0:
                    failed_rows.append(f"Row {idx+2}: Invalid amount")
                    continue
                
                amount_encrypted = encrypt_amount(amount)
                cursor.execute('''
                    INSERT INTO transactions (user_id, category_id, amount_encrypted, description, transaction_type)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session['user_id'], category['id'], amount_encrypted, row['description'], row['type']))
                success_count += 1
            except Exception as e:
                failed_rows.append(f"Row {idx+2}: {str(e)}")
        
        conn.commit()
        conn.close()
        
        audit_log(session['username'], 'CSV import', f'Imported {success_count} transactions')
        
        if failed_rows:
            flash(f'Imported {success_count} transactions. Failures: {"; ".join(failed_rows[:5])}', 'warning')
        else:
            flash(f'Successfully imported {success_count} transactions!', 'success')
        
    except Exception as e:
        flash(f'Import failed: {str(e)}', 'error')
    
    return redirect(url_for('import_export'))

@app.route('/export/csv')
@login_required
def export_csv():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT t.*, c.name as category
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ?
        ORDER BY t.date DESC
    ''', (session['user_id'],))
    
    transactions = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Category', 'Amount', 'Description', 'Type', 'Tags'])
    
    for tx in transactions:
        amount = decrypt_amount(tx['amount_encrypted'])
        writer.writerow([tx['date'], tx['category'], f'{amount:.2f}', tx['description'], tx['transaction_type'], tx['tags']])
    
    output.seek(0)
    audit_log(session['username'], 'CSV export', f'Exported {len(transactions)} transactions')
    
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'transactions_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email'))
        display_name = sanitize_input(request.form.get('display_name'))
        enable_2fa = request.form.get('enable_2fa') == 'on'
        
        cursor.execute('''
            UPDATE users SET email = ?, display_name = ?, is_2fa_enabled = ?
            WHERE id = ?
        ''', (email, display_name, 1 if enable_2fa else 0, session['user_id']))
        conn.commit()
        
        audit_log(session['username'], 'Updated profile')
        flash('Profile updated successfully!', 'success')
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100')
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('admin_logs.html', logs=logs)

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email'))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            token = generate_reset_token(user['id'])
            expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
            cursor.execute('''
                INSERT INTO password_reset_tokens (user_id, token, expires_at)
                VALUES (?, ?, ?)
            ''', (user['id'], token, expires_at))
            conn.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            flash(f'Password reset link (valid for 1 hour): {reset_url}', 'info')
            audit_log(user['username'], 'Password reset requested')
        else:
            flash('If the email exists, a reset link has been sent', 'info')
        
        conn.close()
        return redirect(url_for('login'))
    
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user_id = verify_reset_token(token)
    if not user_id:
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_password.html', token=token)
        
        password_hash = hash_password(password)
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
        cursor.execute('UPDATE password_reset_tokens SET used = 1 WHERE token = ?', (token,))
        conn.commit()
        
        cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        username = cursor.fetchone()['username']
        conn.close()
        
        audit_log(username, 'Password reset completed')
        flash('Password reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/api/chart/spending')
@login_required
def api_chart_spending():
    summary, total = get_spending_summary(session['user_id'])
    
    labels = list(summary.keys())
    data = [summary[cat]['amount'] for cat in labels]
    colors = [summary[cat]['color'] for cat in labels]
    
    return jsonify({
        'labels': labels,
        'data': data,
        'colors': colors
    })

@app.route('/api/decrypt_balance')
@login_required
def api_decrypt_balance():
    _, total = get_spending_summary(session['user_id'])
    audit_log(session['username'], 'Decrypted balance', f'Amount: ${total:.2f}')
    return jsonify({'balance': f'{total:.2f}'})

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message='Page Not Found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, error_message='Internal Server Error'), 500

if __name__ == '__main__':
    # Enable debug mode for detailed error messages
    app.debug = True
    
    # Configure to show detailed error messages in browser
    app.config['DEBUG'] = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    
    # Create necessary directories
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Initialize database
    init_database()
    create_admin_user()
    
    # Run the application with debug mode enabled
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True)
