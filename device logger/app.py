from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import os

app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(__file__), 'inventory.db')

# Initialize database if not exists
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE,
        count INTEGER
    )''')
    # Insert default items if not present
        import hashlib
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT
        )''')
        # Insert default items if not present
        for item in ['Laptops', 'Laptop Chargers', 'Headphones']:
            c.execute('INSERT OR IGNORE INTO items (name, count) VALUES (?, ?)', (item, 0))
        # Insert default admin user if not present
        admin_username = 'admin'
        admin_password = 'admin123'  # Change this after first login
        password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        c.execute('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)', (admin_username, password_hash))
        conn.commit()
        conn.close()
from flask import Flask, render_template, request, redirect, url_for, session, flash
app.secret_key = 'supersecretkey'  # Change this in production

init_db()

# Helper to get all items
def get_items():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT name, count FROM items')
    items = c.fetchall()
    conn.close()
    return items

# Helper to update item count
def update_item(name, count):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('UPDATE items SET count = ? WHERE name = ?', (count, name))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    items = get_items()
    return render_template('index.html', items=items)

@app.route('/refresh')
def refresh():
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
def check_login():
    return session.get('logged_in', False)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not check_login():
        return redirect(url_for('login'))
    items = get_items()
    if request.method == 'POST':
        for name, _ in items:
            new_count = request.form.get(name)
            if new_count is not None and new_count.isdigit():
                update_item(name, int(new_count))
        return redirect(url_for('admin'))
    return render_template('admin.html', items=items)

@app.route('/login', methods=['GET', 'POST'])
def login():
    import hashlib
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username=? AND password_hash=?', (username, password_hash))
        user = c.fetchone()
        conn.close()
        if user:
            session['logged_in'] = True
            return redirect(url_for('admin'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
