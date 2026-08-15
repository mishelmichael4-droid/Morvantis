import os
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

CAIRO_TZ = timezone(timedelta(hours=3))

def format_time(ts):
    """Convert raw DB UTC timestamp to Cairo time (UTC+3)."""
    try:
        if isinstance(ts, datetime):
            dt = ts
        else:
            ts_str = str(ts).split('.')[0]  # Remove microsecond formatting
            dt = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
        dt = dt.replace(tzinfo=timezone.utc).astimezone(CAIRO_TZ)
        return dt.strftime('%d %b %Y  |  %I:%M %p')
    except Exception:
        return str(ts)

app = Flask(__name__)
app.secret_key = 'super_secret_mina_key_2026'

# Secure Cookies & Session configurations
app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get('VERCEL') == '1',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# CSRF Protection for state-changing requests
@app.before_request
def csrf_protect():
    if request.method in ["POST", "PUT", "DELETE"]:
        referer = request.headers.get("Referer")
        if not referer:
            return jsonify({'error': 'CSRF Protection: Referer header missing.'}), 403
            
        from urllib.parse import urlparse
        ref_host = urlparse(referer).netloc
        req_host = request.host
        if ref_host != req_host:
            return jsonify({'error': 'CSRF Protection: Cross-origin request blocked.'}), 403

# Clickjacking and MIME sniffing protections
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Setup Limiter (Anti-Spam)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Custom Database Helper to support SQLite locally and PostgreSQL on Vercel
import urllib.parse
from contextlib import contextmanager

class DB:
    @staticmethod
    @contextmanager
    def get_cursor():
        db_url = os.environ.get('DATABASE_URL')
        is_pg = db_url is not None
        
        if is_pg:
            import psycopg2
            from psycopg2.extras import DictCursor
            # Standardize postgres protocol for psycopg2
            url = db_url.replace('postgres://', 'postgresql://')
            conn = psycopg2.connect(url)
            c = conn.cursor(cursor_factory=DictCursor)
        else:
            import sqlite3
            conn = sqlite3.connect('database.db')
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
        try:
            yield c, is_pg
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            c.close()
            conn.close()

    @staticmethod
    def fix_query(query, is_pg):
        if is_pg:
            # Convert parameter placeholders from ? to %s
            query = query.replace('?', '%s')
            # Convert SQLite AUTOINCREMENT to Postgres SERIAL
            query = query.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
            query = query.replace('"admin"', "'admin'")
        return query

def init_db():
    try:
        with DB.get_cursor() as (c, is_pg):
            c.execute(DB.fix_query('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT,
                    message TEXT NOT NULL,
                    status TEXT DEFAULT 'new',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''', is_pg))
            
            # Add status column if upgrading from old DB (SQLite only)
            if not is_pg:
                try:
                    c.execute('ALTER TABLE messages ADD COLUMN status TEXT DEFAULT \'new\'')
                except Exception:
                    pass

            c.execute(DB.fix_query('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''', is_pg))

            c.execute(DB.fix_query('''
                CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash TEXT
                )
            ''', is_pg))
            
            c.execute(DB.fix_query('''
                CREATE TABLE IF NOT EXISTS page_views (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''', is_pg))

            # Default admin user
            c.execute(DB.fix_query('SELECT * FROM admin WHERE username = ?', is_pg), ('admin',))
            if not c.fetchone():
                hashed = generate_password_hash('mina')
                c.execute(DB.fix_query('INSERT INTO admin (username, password_hash) VALUES (?, ?)', is_pg), ('admin', hashed))
    except Exception as e:
        print(f"Failed to initialize database: {e}")

init_db()

@app.errorhandler(429)
def ratelimit_handler(e):
    ip = get_remote_address()
    try:
        with DB.get_cursor() as (c, is_pg):
            c.execute(DB.fix_query('INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)', is_pg), (ip, 'هجوم آلي أو استخدام برامج (Bot/Hacker Detected)'))
    except Exception:
        pass # Already blocked or database error
    return jsonify({'error': 'You have been temporarily blocked for sending too many messages. Please try again later.'}), 429

@app.route('/')
def index():
    try:
        ip = get_remote_address()
        ua = request.headers.get('User-Agent', '')
        with DB.get_cursor() as (c, is_pg):
            c.execute(DB.fix_query('INSERT INTO page_views (ip_address, user_agent) VALUES (?, ?)', is_pg), (ip, ua))
    except Exception as e:
        print(f"Error logging page view: {e}")
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
@limiter.limit("5 per hour")
def submit():
    try:
        ip = get_remote_address()
        
        with DB.get_cursor() as (c, is_pg):
            # Check if IP is permanently blocked
            c.execute(DB.fix_query('SELECT * FROM blocked_ips WHERE ip_address = ?', is_pg), (ip,))
            if c.fetchone():
                return jsonify({'error': 'Your IP address has been blocked from sending messages due to spam.'}), 403

            data = request.get_json()
            name = data.get('name')
            email = data.get('email')
            phone = data.get('phone')
            message = data.get('message')

            if not all([name, email, message]):
                return jsonify({'error': 'Name, email, and message are required.'}), 400

            c.execute(DB.fix_query('''
                INSERT INTO messages (name, email, phone, message)
                VALUES (?, ?, ?, ?)
            ''', is_pg), (name, email, phone, message))

        return jsonify({'message': 'Success'}), 200
    except Exception as e:
        print(f"Error saving message: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        with DB.get_cursor() as (c, is_pg):
            c.execute(DB.fix_query('SELECT password_hash FROM admin WHERE username = "admin"', is_pg))
            row = c.fetchone()
        
        if row and check_password_hash(row[0], password):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid password!")
    
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    total_views = 0
    unique_visitors = 0
    with DB.get_cursor() as (c, is_pg):
        c.execute(DB.fix_query('SELECT * FROM messages ORDER BY timestamp DESC', is_pg))
        raw_msgs = c.fetchall()
        
        c.execute(DB.fix_query('SELECT * FROM blocked_ips ORDER BY timestamp DESC', is_pg))
        raw_blocked = c.fetchall()
        
        try:
            c.execute(DB.fix_query('SELECT COUNT(*) FROM page_views', is_pg))
            row = c.fetchone()
            total_views = row[0] if row else 0
            
            c.execute(DB.fix_query('SELECT COUNT(DISTINCT ip_address) FROM page_views', is_pg))
            row_unique = c.fetchone()
            unique_visitors = row_unique[0] if row_unique else 0
        except Exception as e:
            print(f"Error loading page views stats: {e}")

    # Format timestamps
    messages = []
    for m in raw_msgs:
        m = dict(m)
        m['timestamp'] = format_time(m['timestamp'])
        messages.append(m)

    blocked_ips = []
    for b in raw_blocked:
        b = dict(b)
        b['timestamp'] = format_time(b['timestamp'])
        blocked_ips.append(b)
    
    return render_template('dashboard.html', messages=messages, blocked_ips=blocked_ips, total_views=total_views, unique_visitors=unique_visitors)

@app.route('/done/<int:msg_id>', methods=['POST'])
def mark_done(msg_id):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    with DB.get_cursor() as (c, is_pg):
        c.execute(DB.fix_query('UPDATE messages SET status = ? WHERE id = ?', is_pg), ('done', msg_id))
    return redirect(url_for('dashboard'))

@app.route('/undone/<int:msg_id>', methods=['POST'])
def mark_undone(msg_id):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    with DB.get_cursor() as (c, is_pg):
        c.execute(DB.fix_query('UPDATE messages SET status = ? WHERE id = ?', is_pg), ('new', msg_id))
    return redirect(url_for('dashboard'))

@app.route('/unblock/<ip>', methods=['POST'])
def unblock(ip):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    with DB.get_cursor() as (c, is_pg):
        c.execute(DB.fix_query('DELETE FROM blocked_ips WHERE ip_address = ?', is_pg), (ip,))
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:msg_id>', methods=['POST'])
def delete_message(msg_id):
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    with DB.get_cursor() as (c, is_pg):
        c.execute(DB.fix_query('DELETE FROM messages WHERE id = ?', is_pg), (msg_id,))
    return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    with DB.get_cursor() as (c, is_pg):
        c.execute(DB.fix_query('SELECT password_hash FROM admin WHERE username = "admin"', is_pg))
        row = c.fetchone()
        
        if not row or not check_password_hash(row[0], current_password):
            flash('كلمة المرور الحالية غير صحيحة.', 'error')
            return redirect(url_for('dashboard'))
            
        new_hash = generate_password_hash(new_password)
        c.execute(DB.fix_query('UPDATE admin SET password_hash = ? WHERE username = "admin"', is_pg), (new_hash,))
        
    flash('تم تغيير كلمة المرور بنجاح!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
