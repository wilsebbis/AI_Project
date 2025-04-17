import os
import bcrypt  # Import bcrypt for password hashing
from flask import Flask, render_template, request, redirect, url_for, session
from cryptography.fernet import Fernet
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Default rate limits for all routes
)

# Use an environment variable for the secret key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))  # Fallback to a random key if not set

# Retrieve the hashed master password from an environment variable
#HASHED_MASTER_PASSWORD = os.environ.get('HASHED_MASTER_PASSWORD')

HASHED_MASTER_PASSWORD="$2b$12$0g0KMuqFV6tTIPcBFp6gLOEZ4RWB1BDaiasy9HJxvp6nC/rCQ4Wte"

# Generate a key for encryption (store this securely in production)
if not os.path.exists('secret.key'):
    with open('secret.key', 'wb') as key_file:
        key_file.write(Fernet.generate_key())

with open('secret.key', 'rb') as key_file:
    encryption_key = key_file.read()

cipher = Fernet(encryption_key)

# Database setup
DATABASE = 'password_manager.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts to 5 per minute
def login():
    if request.method == 'POST':
        master_password = request.form['master_password']
        
        # Check if HASHED_MASTER_PASSWORD is set and valid
        if not HASHED_MASTER_PASSWORD or not HASHED_MASTER_PASSWORD.strip():
            return "Server error: Master password is not configured.", 500

        # Verify the master password using bcrypt
        try:
            if bcrypt.checkpw(master_password.encode(), HASHED_MASTER_PASSWORD.encode()):
                session['master_password'] = master_password
                return redirect(url_for('index'))
            else:
                return render_template('invalid_password.html', back_url=url_for('login'))
        except ValueError as e:
            return f"Configuration error: {str(e)}", 500
        except Exception as e:
            return f"An error occurred: {str(e)}", 500

    return render_template('login.html')

# Routes
@app.route('/')
def index():
    if 'master_password' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, website, username FROM passwords')
        passwords = cursor.fetchall()
    return render_template('index.html', passwords=passwords)

@app.errorhandler(429)
def ratelimit_error(e):
    return "Too many requests. Please try again later.", 429

@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'master_password' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']

        if len(password) > 1000:
            return "Password exceeds the maximum allowed length of 1000 characters", 400

        encrypted_password = cipher.encrypt(password.encode()).decode()
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)',
                           (website, username, encrypted_password))
            conn.commit()
        return redirect(url_for('index'))
    return render_template('add_password.html')

@app.route('/view_password/<int:password_id>', methods=['GET', 'POST'])
def view_password(password_id):
    if 'master_password' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        master_password = request.form['master_password']
        # Verify the master password
        if master_password == 'your_master_password':  # Replace with a hashed password check
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, website, username, password FROM passwords WHERE id = ?', (password_id,))
                password_entry = cursor.fetchone()
            if password_entry:
                try:
                    # Ensure the password is properly encoded and decoded
                    decrypted_password = cipher.decrypt(password_entry[3].encode()).decode()
                except Exception as e:
                    return f"Decryption error: {str(e)}", 500
                return render_template('view_password.html', entry=password_entry, password=decrypted_password)
            return "Password not found", 404
        else:
            return render_template('invalid_password.html', back_url=url_for('view_password', password_id=password_id))

    # Render the reauthentication form
    return render_template('reauthenticate.html', password_id=password_id)

@app.route('/delete_password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    if 'master_password' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        conn.commit()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('master_password', None)
    return redirect(url_for('login'))

@app.route('/test_encryption')
def test_encryption():
    try:
        test_password = "test123"
        encrypted = cipher.encrypt(test_password.encode()).decode()
        decrypted = cipher.decrypt(encrypted.encode()).decode()
        return f"Encryption and decryption successful: {decrypted}"
    except Exception as e:
        return f"Encryption/Decryption error: {str(e)}"
    
@app.route('/update_password/<int:password_id>', methods=['GET', 'POST'])
def update_password(password_id):
    if 'master_password' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']

        if len(new_password) > 1000:
            return "Password exceeds the maximum allowed length of 1000 characters", 400

        encrypted_password = cipher.encrypt(new_password.encode()).decode()
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE passwords SET password = ? WHERE id = ?', (encrypted_password, password_id))
            conn.commit()
        return redirect(url_for('index'))
    
    # Render the update password form
    return render_template('update_password.html', password_id=password_id)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)