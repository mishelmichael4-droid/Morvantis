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
        
        # Add status column if upgrading from old DB
        try:
            c.execute(DB.fix_query('ALTER TABLE messages ADD COLUMN status TEXT DEFAULT \'new\'', is_pg))
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
        
        # Default admin user
        c.execute(DB.fix_query('SELECT * FROM admin WHERE username = ?', is_pg), ('admin',))
        if not c.fetchone():
            hashed = generate_password_hash('mina')
            c.execute(DB.fix_query('INSERT INTO admin (username, password_hash) VALUES (?, ?)', is_pg), ('admin', hashed))

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
        return jsonify({'error': 'Internal server error'}), 500

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

    with DB.get_cursor() as (c, is_pg):
        c.execute(DB.fix_query('SELECT * FROM messages ORDER BY timestamp DESC', is_pg))
        raw_msgs = c.fetchall()
        
        c.execute(DB.fix_query('SELECT * FROM blocked_ips ORDER BY timestamp DESC', is_pg))
        raw_blocked = c.fetchall()

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
    
    return render_template('dashboard.html', messages=messages, blocked_ips=blocked_ips)

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
