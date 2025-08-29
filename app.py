from flask import Flask, render_template_string, request, jsonify, g, session, redirect, url_for
import sqlite3
import datetime
import os
import json
from authlib.integrations.flask_client import OAuth
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix

#test comment
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_prefix=1, x_host=1, x_proto=1)
app.config['APPLICATION_ROOT'] = '/contacts'
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Load Google OAuth configuration from client_secret.json
def load_google_config():
    try:
        with open('client_secret.json', 'r') as f:
            config = json.load(f)
            return config['web']
    except FileNotFoundError:
        return None
    except (KeyError, json.JSONDecodeError):
        return None

google_config = load_google_config()

# Google OAuth configuration
oauth = OAuth(app)
if google_config:
    google = oauth.register(
        name='google',
        client_id=google_config['client_id'],
        client_secret=google_config['client_secret'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
else:
    google = None

DATABASE = 'communication_tracker.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.teardown_appcontext
def close_db_teardown(error):
    close_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    with app.app_context():
        db = get_db()
        
        # Users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                google_id TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Check if contacts table exists and get its columns
        try:
            cursor = db.execute("PRAGMA table_info(contacts)")
            existing_columns = [column[1] for column in cursor.fetchall()]
        except:
            existing_columns = []
        
        # Create contacts table if it doesn't exist
        if not existing_columns:
            db.execute('''
                CREATE TABLE contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    last_sent DATETIME,
                    last_received DATETIME,
                    last_sent_method TEXT,
                    last_received_method TEXT,
                    needs_response INTEGER DEFAULT 0,
                    text_response_hours INTEGER DEFAULT 12,
                    email_response_hours INTEGER DEFAULT 48,
                    max_days_since_contact INTEGER DEFAULT 30,
                    snoozed_until DATETIME,
                    muted INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    UNIQUE(user_id, name)
                )
            ''')
        else:
            # Add missing columns to existing table
            try:
                if 'user_id' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN user_id INTEGER DEFAULT 1')
                    print("Added user_id column to contacts table")
                if 'last_sent_method' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN last_sent_method TEXT')
                if 'last_received_method' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN last_received_method TEXT')
                if 'text_response_hours' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN text_response_hours INTEGER DEFAULT 12')
                if 'email_response_hours' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN email_response_hours INTEGER DEFAULT 48')
                if 'max_days_since_contact' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN max_days_since_contact INTEGER DEFAULT 30')
                if 'snoozed_until' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN snoozed_until DATETIME')
                if 'muted' not in existing_columns:
                    db.execute('ALTER TABLE contacts ADD COLUMN muted INTEGER DEFAULT 0')
            except Exception as e:
                print(f"Error adding columns: {e}")
        
        # Communication log with user_id
        try:
            cursor = db.execute("PRAGMA table_info(communication_log)")
            log_columns = [column[1] for column in cursor.fetchall()]
        except:
            log_columns = []
        
        if not log_columns:
            db.execute('''
                CREATE TABLE communication_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    contact_id INTEGER,
                    action TEXT NOT NULL,
                    method TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (contact_id) REFERENCES contacts (id)
                )
            ''')
        else:
            try:
                if 'user_id' not in log_columns:
                    db.execute('ALTER TABLE communication_log ADD COLUMN user_id INTEGER DEFAULT 1')
            except Exception as e:
                print(f"Error adding user_id to communication_log: {e}")
        
        db.commit()
        print("Database initialization complete")

def force_migration():
    """Force database migration - call this if automatic migration fails"""
    with app.app_context():
        db = get_db()
        
        print("Starting forced database migration...")
        
        # Backup existing data
        try:
            contacts = db.execute('SELECT * FROM contacts').fetchall()
            print(f"Found {len(contacts)} existing contacts")
        except:
            contacts = []
        
        # Drop and recreate contacts table with all columns
        try:
            db.execute('DROP TABLE IF EXISTS contacts_backup')
            db.execute('CREATE TABLE contacts_backup AS SELECT * FROM contacts')
            print("Created backup of contacts table")
        except Exception as e:
            print(f"Backup failed (table might not exist): {e}")
        
        try:
            db.execute('DROP TABLE IF EXISTS contacts')
            db.execute('''
                CREATE TABLE contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL DEFAULT 1,
                    name TEXT NOT NULL,
                    last_sent DATETIME,
                    last_received DATETIME,
                    last_sent_method TEXT,
                    last_received_method TEXT,
                    needs_response INTEGER DEFAULT 0,
                    text_response_hours INTEGER DEFAULT 12,
                    email_response_hours INTEGER DEFAULT 48,
                    max_days_since_contact INTEGER DEFAULT 30,
                    snoozed_until DATETIME,
                    muted INTEGER DEFAULT 0
                )
            ''')
            print("Created new contacts table")
            
            # Restore data if we had any
            if contacts:
                for contact in contacts:
                    try:
                        db.execute('''
                            INSERT INTO contacts (id, name, last_sent, last_received, needs_response, user_id)
                            VALUES (?, ?, ?, ?, ?, 1)
                        ''', (contact[0], contact[1], contact.get('last_sent'), contact.get('last_received'), contact.get('needs_response', 0)))
                    except:
                        # Fallback - just insert name and id
                        db.execute('INSERT INTO contacts (id, name, user_id) VALUES (?, ?, 1)', (contact[0], contact[1]))
                print(f"Restored {len(contacts)} contacts")
            
        except Exception as e:
            print(f"Error recreating contacts table: {e}")
        
        db.commit()
        print("Forced migration complete!")

@app.route('/')
@login_required
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/login')
def login():
    if 'user' in session:
        return redirect(url_for('index'))
    
    if not google_config:
        return '''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px;">
            <h2>⚠️ Google OAuth Not Configured</h2>
            <p>To enable Google authentication, you need to create a <code>client_secret.json</code> file in the same directory as your app.</p>
            
            <h3>Setup Steps:</h3>
            <ol>
                <li>Go to <a href="https://console.developers.google.com/" target="_blank">Google Cloud Console</a></li>
                <li>Create a project or select an existing one</li>
                <li>Enable the Google+ API</li>
                <li>Create OAuth 2.0 credentials</li>
                <li>Set authorized redirect URI to: <code>http://localhost:5001/auth/callback</code></li>
                <li>Download the JSON file and save it as <code>client_secret.json</code></li>
            </ol>
            
            <h3>Expected file format:</h3>
            <pre style="background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto;">
{
  "web": {
    "client_id": "your_client_id",
    "project_id": "your_project_id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "your_client_secret",
    "redirect_uris": ["http://localhost:5001/auth/callback"]
  }
}</pre>
            
            <p>After creating the file, restart the application.</p>
            <p><strong>For development:</strong> You can skip this and use the demo mode by visiting <a href="/demo">/demo</a></p>
        </div>
        '''
    
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    
    if user_info:
        db = get_db()
        
        # Check if user exists
        user = db.execute('SELECT * FROM users WHERE google_id = ?', (user_info['sub'],)).fetchone()
        
        if not user:
            # Create new user
            db.execute(
                'INSERT INTO users (google_id, email, name) VALUES (?, ?, ?)',
                (user_info['sub'], user_info['email'], user_info['name'])
            )
            db.commit()
            user = db.execute('SELECT * FROM users WHERE google_id = ?', (user_info['sub'],)).fetchone()
        
        # Store user in session
        session['user'] = {
            'id': user['id'],
            'email': user['email'],
            'name': user['name']
        }
        
        return redirect(url_for('index'))
    
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/migrate')
def migrate_db():
    """Manual database migration endpoint"""
    try:
        force_migration()
        return '''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 5px;">
            <h2>✅ Database Migration Complete!</h2>
            <p>Your database has been successfully migrated to support multi-user authentication.</p>
            <p>All existing contacts have been preserved and assigned to user ID 1.</p>
            <p><a href="/demo">Click here to access your contacts in demo mode</a></p>
        </div>
        '''
    except Exception as e:
        return f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px;">
            <h2>❌ Migration Failed</h2>
            <p>Error: {str(e)}</p>
            <p>Please check the console output for more details.</p>
        </div>
        '''

@app.route('/demo')
def demo():
    # Demo mode for development/testing
    session['user'] = {
        'id': 1,
        'email': 'demo@example.com',
        'name': 'Demo User'
    }
    
    # Create demo user if not exists
    db = get_db()
    demo_user = db.execute('SELECT * FROM users WHERE id = 1').fetchone()
    if not demo_user:
        db.execute(
            'INSERT OR REPLACE INTO users (id, google_id, email, name) VALUES (?, ?, ?, ?)',
            (1, 'demo', 'demo@example.com', 'Demo User')
        )
        db.commit()
    
    return redirect(url_for('index'))

@app.route('/api/contacts', methods=['GET'])
@login_required
def get_contacts():
    user_id = session['user']['id']
    db = get_db()
    contacts = db.execute('SELECT * FROM contacts WHERE user_id = ? ORDER BY name', (user_id,)).fetchall()
    
    result = []
    now = datetime.datetime.now()
    
    for contact in contacts:
        contact_dict = dict(contact)
        
        # Calculate time since last communication
        last_sent = datetime.datetime.fromisoformat(contact['last_sent']) if contact['last_sent'] else None
        last_received = datetime.datetime.fromisoformat(contact['last_received']) if contact['last_received'] else None
        
        # Find the most recent communication
        last_comm = None
        last_method = None
        last_was_received = False
        
        if last_sent and last_received:
            if last_sent >= last_received:
                last_comm = last_sent
                try:
                    last_method = contact['last_sent_method']
                except (KeyError, IndexError):
                    last_method = None
                last_was_received = False
            else:
                last_comm = last_received
                try:
                    last_method = contact['last_received_method']
                except (KeyError, IndexError):
                    last_method = None
                last_was_received = True
        elif last_sent:
            last_comm = last_sent
            try:
                last_method = contact['last_sent_method']
            except (KeyError, IndexError):
                last_method = None
            last_was_received = False
        elif last_received:
            last_comm = last_received
            try:
                last_method = contact['last_received_method']
            except (KeyError, IndexError):
                last_method = None
            last_was_received = True
        
        contact_dict['overdue'] = False
        contact_dict['needs_communication'] = False
        contact_dict['snoozed'] = False
        
        # Handle missing columns gracefully for existing contacts
        try:
            contact_dict['muted'] = bool(contact['muted'])
        except (KeyError, IndexError):
            contact_dict['muted'] = False
        
        # Get max days since contact setting
        try:
            max_days_since_contact = contact['max_days_since_contact'] or 30
        except (KeyError, IndexError):
            max_days_since_contact = 30
        
        # Check if contact is snoozed
        try:
            snoozed_until = contact['snoozed_until']
            if snoozed_until:
                snooze_until = datetime.datetime.fromisoformat(snoozed_until)
                if now < snooze_until:
                    contact_dict['snoozed'] = True
                    time_until_unsnooze = snooze_until - now
                    days = time_until_unsnooze.days
                    hours = time_until_unsnooze.seconds // 3600
                    contact_dict['snooze_time_left'] = f"{days}d {hours}h" if days > 0 else f"{hours}h"
        except (KeyError, IndexError):
            pass  # Column doesn't exist yet
        
        if last_comm:
            time_diff = now - last_comm
            days = time_diff.days
            hours = time_diff.seconds // 3600
            total_hours = days * 24 + hours
            method_text = f" ({last_method})" if last_method else ""
            contact_dict['time_since'] = f"{days}d {hours}h{method_text}"
            
            # Check if response is overdue (only if last communication was received, needs response, not snoozed, and not muted)
            if last_was_received and contact['needs_response'] and not contact_dict['snoozed'] and not contact_dict['muted']:
                try:
                    text_hours = contact['text_response_hours'] or 12
                    email_hours = contact['email_response_hours'] or 48
                except (KeyError, IndexError):
                    text_hours = 12
                    email_hours = 48
                
                expected_response_hours = text_hours if last_method == 'text' else email_hours
                if total_hours > expected_response_hours:
                    contact_dict['overdue'] = True
            
            # Check if it's been too long since any contact (regardless of who initiated)
            if days >= max_days_since_contact and not contact_dict['snoozed'] and not contact_dict['muted']:
                contact_dict['needs_communication'] = True
        else:
            contact_dict['time_since'] = "Never"
            # If never contacted, mark as needing communication unless snoozed/muted
            if not contact_dict['snoozed'] and not contact_dict['muted']:
                contact_dict['needs_communication'] = True
        
        result.append(contact_dict)
    
    return jsonify(result)

@app.route('/api/contacts', methods=['POST'])
@login_required
def add_contact():
    user_id = session['user']['id']
    data = request.get_json()
    name = data.get('name', '').strip()
    
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    
    db = get_db()
    try:
        db.execute('INSERT INTO contacts (user_id, name) VALUES (?, ?)', (user_id, name))
        db.commit()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Contact already exists'}), 400

@app.route('/api/contacts/<int:contact_id>/sent', methods=['POST'])
@login_required
def mark_sent(contact_id):
    user_id = session['user']['id']
    data = request.get_json()
    method = data.get('method', 'text')
    
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    now = datetime.datetime.now().isoformat()
    
    # Update contact
    db.execute('UPDATE contacts SET last_sent = ?, last_sent_method = ?, needs_response = 0 WHERE id = ?', 
               (now, method, contact_id))
    
    # Log the communication
    db.execute('INSERT INTO communication_log (user_id, contact_id, action, method, timestamp) VALUES (?, ?, ?, ?, ?)',
               (user_id, contact_id, 'sent', method, now))
    
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/received', methods=['POST'])
@login_required
def mark_received(contact_id):
    user_id = session['user']['id']
    data = request.get_json()
    method = data.get('method', 'text')
    
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    now = datetime.datetime.now().isoformat()
    
    # Update contact
    db.execute('UPDATE contacts SET last_received = ?, last_received_method = ?, needs_response = 1 WHERE id = ?', 
               (now, method, contact_id))
    
    # Log the communication
    db.execute('INSERT INTO communication_log (user_id, contact_id, action, method, timestamp) VALUES (?, ?, ?, ?, ?)',
               (user_id, contact_id, 'received', method, now))
    
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/phone', methods=['POST'])
@login_required
def mark_phone_call(contact_id):
    user_id = session['user']['id']
    
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    now = datetime.datetime.now().isoformat()
    
    # Update both last_sent and last_received since phone calls are bidirectional
    # Don't set needs_response since phone calls are immediate two-way communication
    db.execute('UPDATE contacts SET last_sent = ?, last_received = ?, last_sent_method = ?, last_received_method = ?, needs_response = 0 WHERE id = ?', 
               (now, now, 'phone', 'phone', contact_id))
    
    # Log the communication
    db.execute('INSERT INTO communication_log (user_id, contact_id, action, method, timestamp) VALUES (?, ?, ?, ?, ?)',
               (user_id, contact_id, 'phone_call', 'phone', now))
    
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/responded', methods=['POST'])
@login_required
def mark_responded(contact_id):
    user_id = session['user']['id']
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    now = datetime.datetime.now().isoformat()
    
    # Update contact
    db.execute('UPDATE contacts SET needs_response = 0 WHERE id = ?', (contact_id,))
    
    # Log the response
    db.execute('INSERT INTO communication_log (user_id, contact_id, action, method, timestamp) VALUES (?, ?, ?, ?, ?)',
               (user_id, contact_id, 'responded', 'manual', now))
    
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/settings', methods=['POST'])
@login_required
def update_settings(contact_id):
    user_id = session['user']['id']
    data = request.get_json()
    text_hours = data.get('text_response_hours', 12)
    email_hours = data.get('email_response_hours', 48)
    max_days = data.get('max_days_since_contact', 30)
    
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    db.execute('UPDATE contacts SET text_response_hours = ?, email_response_hours = ?, max_days_since_contact = ? WHERE id = ?',
               (text_hours, email_hours, max_days, contact_id))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/snooze', methods=['POST'])
@login_required
def snooze_contact(contact_id):
    user_id = session['user']['id']
    data = request.get_json()
    snooze_hours = data.get('hours', 24)
    
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    snooze_until = (datetime.datetime.now() + datetime.timedelta(hours=snooze_hours)).isoformat()
    db.execute('UPDATE contacts SET snoozed_until = ? WHERE id = ?', (snooze_until, contact_id))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/unsnooze', methods=['POST'])
@login_required
def unsnooze_contact(contact_id):
    user_id = session['user']['id']
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    db.execute('UPDATE contacts SET snoozed_until = NULL WHERE id = ?', (contact_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/mute', methods=['POST'])
@login_required
def mute_contact(contact_id):
    user_id = session['user']['id']
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    db.execute('UPDATE contacts SET muted = 1 WHERE id = ?', (contact_id,))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/contacts/<int:contact_id>/unmute', methods=['POST'])
@login_required
def unmute_contact(contact_id):
    user_id = session['user']['id']
    db = get_db()
    
    # Verify contact belongs to user
    contact = db.execute('SELECT * FROM contacts WHERE id = ? AND user_id = ?', (contact_id, user_id)).fetchone()
    if not contact:
        return jsonify({'error': 'Contact not found'}), 404
    
    db.execute('UPDATE contacts SET muted = 0 WHERE id = ?', (contact_id,))
    db.commit()
    return jsonify({'success': True})

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Communication Tracker</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .contacts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .contacts-section {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .section-header {
            background: #f8f9fa;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 16px;
            border-bottom: 1px solid #dee2e6;
        }
        .communication-needed-header {
            background: #ffe6e6;
            color: #dc3545;
        }
        .section-content {
            /* Remove max-height and overflow to let content expand naturally */
        }
        .add-contact {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .add-contact input {
            flex: 1;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 16px;
        }
        .add-contact button {
            padding: 10px 20px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        .add-contact button:hover {
            background: #0056b3;
        }
        .contact {
            background: white;
            padding: 15px 20px;
            border-bottom: 1px solid #f0f0f0;
            border-left: 4px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2px;
        }
        .contact:last-child {
            border-bottom: none;
        }
        .contact.needs-communication {
            background-color: #fff5f5;
            border-left-color: #fd7e14;
        }
        .contact-info {
            flex: 1;
        }
        .contact-name {
            font-weight: bold;
            font-size: 18px;
            margin-bottom: 5px;
            line-height: 1.3;
        }
        .contact-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 4px;
        }
        .contact-time {
            color: #666;
            font-size: 14px;
        }
        .contact-actions {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
            align-items: center;
        }
        .phone-call-section {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-right: 15px;
        }
        .phone-call-label {
            font-size: 10px;
            color: #666;
            text-align: center;
            margin-bottom: 2px;
        }
        .phone-call-btn {
            background: #20c997;
            color: white;
            padding: 8px 12px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            white-space: nowrap;
        }
        .phone-call-btn:hover {
            background: #17a085;
        }
        .btn-group {
            display: flex;
            flex-direction: column;
            gap: 2px;
            margin-right: 10px;
        }
        .btn-group-label {
            font-size: 10px;
            color: #666;
            text-align: center;
            margin-bottom: 2px;
        }
        .btn {
            padding: 5px 10px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            white-space: nowrap;
        }
        .btn-sent {
            background: #28a745;
            color: white;
        }
        .btn-received {
            background: #ffc107;
            color: black;
        }
        .btn-responded {
            background: #17a2b8;
            color: white;
        }
        .btn:hover {
            opacity: 0.8;
        }
        .needs-response-badge {
            background: #ff6b6b;
            color: white;
            padding: 2px 6px;
            border-radius: 8px;
            font-size: 10px;
            white-space: nowrap;
        }
        .overdue-badge {
            background: #dc3545;
            color: white;
            padding: 2px 6px;
            border-radius: 8px;
            font-size: 10px;
            animation: pulse 2s infinite;
            white-space: nowrap;
        }
        .communication-needed-badge {
            background: #fd7e14;
            color: white;
            padding: 2px 6px;
            border-radius: 8px;
            font-size: 10px;
            white-space: nowrap;
        }
        .snoozed-badge {
            background: #6f42c1;
            color: white;
            padding: 2px 6px;
            border-radius: 8px;
            font-size: 10px;
            white-space: nowrap;
        }
        .contact.snoozed {
            opacity: 0.7;
        }
        .muted-badge {
            background: #6c757d;
            color: white;
            padding: 2px 6px;
            border-radius: 8px;
            font-size: 10px;
            white-space: nowrap;
        }
        .contact.muted {
            opacity: 0.6;
            filter: grayscale(30%);
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .settings-btn {
            background: #6c757d;
            color: white;
            font-size: 10px;
            padding: 3px 6px;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 20px;
            border-radius: 10px;
            width: 300px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .setting-group {
            margin-bottom: 15px;
        }
        .setting-label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .setting-input {
            width: 100%;
            padding: 8px;
            border: 2px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        .modal-buttons {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
            margin-top: 20px;
        }
        .modal-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .modal-btn-save {
            background: #28a745;
            color: white;
        }
        .modal-btn-cancel {
            background: #6c757d;
            color: white;
        }
        .snooze-section {
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
        }
        .snooze-buttons {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
            margin-top: 10px;
        }
        .snooze-btn {
            padding: 5px 10px;
            border: 1px solid #6f42c1;
            background: white;
            color: #6f42c1;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
        }
        .snooze-btn:hover {
            background: #6f42c1;
            color: white;
        }
        .unsnooze-btn {
            background: #6f42c1;
            color: white;
            padding: 5px 10px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
        }
        .unsnooze-btn:hover {
            background: #5a2d91;
        }
        .mute-section {
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
        }
        .mute-btn {
            padding: 8px 16px;
            border: 1px solid #6c757d;
            background: white;
            color: #6c757d;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            width: 100%;
        }
        .mute-btn:hover {
            background: #6c757d;
            color: white;
        }
        .unmute-btn {
            background: #6c757d;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            width: 100%;
        }
        .unmute-btn:hover {
            background: #5a6268;
        }
        .warning-text {
            font-size: 11px;
            color: #666;
            margin-top: 5px;
            font-style: italic;
        }
        .empty-section {
            padding: 40px 20px;
            text-align: center;
            color: #666;
            font-style: italic;
        }
        @media (max-width: 768px) {
            .contacts-grid {
                grid-template-columns: 1fr;
            }
            .contact {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
                padding: 20px;
                margin-bottom: 8px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .contact-info {
                width: 100%;
                padding-bottom: 8px;
                border-bottom: 1px solid #eee;
            }
            .contact-name {
                font-size: 16px;
                margin-bottom: 8px;
            }
            .contact-badges {
                margin-bottom: 4px;
            }
            .contact-actions {
                width: 100%;
                justify-content: flex-start;
                gap: 8px;
                padding-top: 4px;
            }
            .phone-call-section {
                margin-right: 12px;
            }
            .phone-call-btn {
                padding: 8px 12px;
                font-size: 13px;
                min-height: 36px;
            }
            .btn-group {
                margin-right: 12px;
            }
            .btn {
                padding: 8px 12px;
                font-size: 13px;
                min-width: 50px;
                min-height: 36px;
            }
            .settings-btn {
                padding: 8px 12px;
                font-size: 16px;
                min-width: 40px;
                min-height: 36px;
            }
            .btn-responded {
                padding: 8px 12px;
                font-size: 13px;
                min-height: 36px;
            }
            .modal-content {
                width: 90%;
                margin: 5% auto;
                max-height: 85vh;
                overflow-y: auto;
            }
            .add-contact {
                flex-direction: column;
                gap: 10px;
            }
            .add-contact input {
                width: 100%;
                box-sizing: border-box;
                padding: 12px;
                font-size: 16px;
            }
            .add-contact button {
                padding: 12px 20px;
                font-size: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="contacts-grid">
        <div class="contacts-section">
            <div class="section-header communication-needed-header">
                Communication Needed (<span id="communicationNeededCount">0</span>)
            </div>
            <div class="section-content" id="communicationNeededList">
                <div class="empty-section">No communication needed</div>
            </div>
        </div>
        
        <div class="contacts-section">
            <div class="section-header">
                All Contacts (<span id="allCount">0</span>)
            </div>
            <div class="section-content" id="allContactsList">
                <div class="empty-section">No contacts yet. Add someone to start tracking!</div>
            </div>
        </div>
    </div>
    
    <!-- Settings Modal -->
    <div id="settingsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">Response Time Settings</div>
            <div class="setting-group">
                <label class="setting-label" for="textHours">Text Response Time (hours):</label>
                <input type="number" id="textHours" class="setting-input" min="1" max="168">
            </div>
            <div class="setting-group">
                <label class="setting-label" for="emailHours">Email Response Time (hours):</label>
                <input type="number" id="emailHours" class="setting-input" min="1" max="720">
            </div>
            <div class="setting-group">
                <label class="setting-label" for="maxDays">Max days since contact:</label>
                <input type="number" id="maxDays" class="setting-input" min="1" max="365">
                <div class="warning-text">Contact will appear in "Communication Needed" if no contact for this many days</div>
            </div>
            <div class="snooze-section" id="snoozeSection">
                <div class="setting-label">Snooze Options:</div>
                <div id="currentSnoozeStatus"></div>
                <div class="snooze-buttons" id="snoozeButtons">
                    <button class="snooze-btn" onclick="snoozeContact(1)">1 hour</button>
                    <button class="snooze-btn" onclick="snoozeContact(4)">4 hours</button>
                    <button class="snooze-btn" onclick="snoozeContact(24)">1 day</button>
                    <button class="snooze-btn" onclick="snoozeContact(72)">3 days</button>
                    <button class="snooze-btn" onclick="snoozeContact(168)">1 week</button>
                </div>
            </div>
            <div class="mute-section">
                <div class="setting-label">Mute Contact:</div>
                <div id="currentMuteStatus"></div>
                <div id="muteButton"></div>
            </div>
            <div class="modal-buttons">
                <button class="modal-btn modal-btn-cancel" onclick="closeSettingsModal()">Cancel</button>
                <button class="modal-btn modal-btn-save" onclick="saveSettings()">Save</button>
            </div>
        </div>
    </div>
    
    <div class="add-contact">
        <input type="text" id="nameInput" placeholder="Enter person's name" onkeypress="handleKeyPress(event)">
        <button onclick="addContact()">Add Contact</button>
    </div>

    <script>
        let contacts = [];
        let currentContactId = null;
        
        function handleKeyPress(event) {
            if (event.key === 'Enter') {
                addContact();
            }
        }
        
        async function addContact() {
            const nameInput = document.getElementById('nameInput');
            const name = nameInput.value.trim();
            
            if (!name) {
                alert('Please enter a name');
                return;
            }
            
            try {
                const response = await fetch('/contacts/api/contacts', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ name: name })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    nameInput.value = '';
                    loadContacts();
                } else {
                    alert(result.error || 'Error adding contact');
                }
            } catch (error) {
                alert('Error adding contact');
            }
        }
        
        async function markPhoneCall(contactId) {
            await fetch(`/contacts/api/contacts/${contactId}/phone`, { method: 'POST' });
            loadContacts();
        }
        
        async function markSent(contactId, method) {
            await fetch(`/contacts/api/contacts/${contactId}/sent`, { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ method: method })
            });
            loadContacts();
        }
        
        async function markReceived(contactId, method) {
            await fetch(`/contacts/api/contacts/${contactId}/received`, { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ method: method })
            });
            loadContacts();
        }
        
        async function markResponded(contactId) {
            await fetch(`/contacts/api/contacts/${contactId}/responded`, { method: 'POST' });
            loadContacts();
        }
        
        function openSettingsModal(contactId) {
            const contact = contacts.find(c => c.id === contactId);
            if (contact) {
                currentContactId = contactId;
                document.getElementById('textHours').value = contact.text_response_hours || 12;
                document.getElementById('emailHours').value = contact.email_response_hours || 48;
                document.getElementById('maxDays').value = contact.max_days_since_contact || 30;
                
                // Update snooze status
                const snoozeStatus = document.getElementById('currentSnoozeStatus');
                const snoozeButtons = document.getElementById('snoozeButtons');
                
                if (contact.snoozed) {
                    snoozeStatus.innerHTML = `<div style="color: #6f42c1; margin-bottom: 10px;">Currently snoozed for ${contact.snooze_time_left}</div>`;
                    snoozeButtons.innerHTML = '<button class="unsnooze-btn" onclick="unsnoozeContact()">Remove Snooze</button>';
                } else {
                    snoozeStatus.innerHTML = '<div style="color: #666; margin-bottom: 10px;">Not snoozed</div>';
                    snoozeButtons.innerHTML = `
                        <button class="snooze-btn" onclick="snoozeContact(1)">1 hour</button>
                        <button class="snooze-btn" onclick="snoozeContact(4)">4 hours</button>
                        <button class="snooze-btn" onclick="snoozeContact(24)">1 day</button>
                        <button class="snooze-btn" onclick="snoozeContact(72)">3 days</button>
                        <button class="snooze-btn" onclick="snoozeContact(168)">1 week</button>
                    `;
                }
                
                // Update mute status
                const muteStatus = document.getElementById('currentMuteStatus');
                const muteButton = document.getElementById('muteButton');
                
                if (contact.muted) {
                    muteStatus.innerHTML = '<div style="color: #6c757d; margin-bottom: 10px;">This contact is muted and will never appear in communication needed section</div>';
                    muteButton.innerHTML = '<button class="unmute-btn" onclick="unmuteContact()">Unmute Contact</button>';
                } else {
                    muteStatus.innerHTML = '<div style="color: #666; margin-bottom: 10px;">Contact will appear in communication needed section when thresholds are exceeded</div>';
                    muteButton.innerHTML = `
                        <button class="mute-btn" onclick="muteContact()">Mute Contact</button>
                        <div class="warning-text">Muted contacts never appear in communication needed</div>
                    `;
                }
                
                document.getElementById('settingsModal').style.display = 'block';
            }
        }
        
        function closeSettingsModal() {
            document.getElementById('settingsModal').style.display = 'none';
            currentContactId = null;
        }
        
        async function saveSettings() {
            if (!currentContactId) return;
            
            const textHours = parseInt(document.getElementById('textHours').value);
            const emailHours = parseInt(document.getElementById('emailHours').value);
            const maxDays = parseInt(document.getElementById('maxDays').value);
            
            try {
                await fetch(`/contacts/api/contacts/${currentContactId}/settings`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ 
                        text_response_hours: textHours,
                        email_response_hours: emailHours,
                        max_days_since_contact: maxDays
                    })
                });
                closeSettingsModal();
                loadContacts();
            } catch (error) {
                alert('Error saving settings');
            }
        }
        
        async function snoozeContact(hours) {
            if (!currentContactId) return;
            
            try {
                await fetch(`/contacts/api/contacts/${currentContactId}/snooze`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ hours: hours })
                });
                closeSettingsModal();
                loadContacts();
            } catch (error) {
                alert('Error snoozing contact');
            }
        }
        
        async function unsnoozeContact() {
            if (!currentContactId) return;
            
            try {
                await fetch(`/contacts/api/contacts/${currentContactId}/unsnooze`, {
                    method: 'POST'
                });
                closeSettingsModal();
                loadContacts();
            } catch (error) {
                alert('Error removing snooze');
            }
        }
        
        async function muteContact() {
            if (!currentContactId) return;
            
            if (confirm('Are you sure you want to mute this contact? They will never appear in the communication needed section.')) {
                try {
                    await fetch(`/contacts/api/contacts/${currentContactId}/mute`, {
                        method: 'POST'
                    });
                    closeSettingsModal();
                    loadContacts();
                } catch (error) {
                    alert('Error muting contact');
                }
            }
        }
        
        async function unmuteContact() {
            if (!currentContactId) return;
            
            try {
                await fetch(`/contacts/api/contacts/${currentContactId}/unmute`, {
                    method: 'POST'
                });
                closeSettingsModal();
                loadContacts();
            } catch (error) {
                alert('Error unmuting contact');
            }
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('settingsModal');
            if (event.target === modal) {
                closeSettingsModal();
            }
        }
        
        async function loadContacts() {
            try {
                const response = await fetch('/contacts/api/contacts');
                contacts = await response.json();
                
                // Sort contacts by name
                contacts.sort((a, b) => a.name.localeCompare(b.name));
                
                renderContacts();
            } catch (error) {
                console.error('Error loading contacts:', error);
            }
        }
        
        function renderContactCard(contact) {
            return `
                <div class="contact ${contact.needs_communication ? 'needs-communication' : ''} ${contact.snoozed ? 'snoozed' : ''} ${contact.muted ? 'muted' : ''}">
                    <div class="contact-info">
                        <div class="contact-name">
                            ${contact.name}
                        </div>
                        <div class="contact-badges">
                            ${contact.needs_response ? '<span class="needs-response-badge">Needs Response</span>' : ''}
                            ${contact.overdue ? '<span class="overdue-badge">OVERDUE</span>' : ''}
                            ${contact.needs_communication ? '<span class="communication-needed-badge">Contact Needed</span>' : ''}
                            ${contact.snoozed ? `<span class="snoozed-badge">Snoozed ${contact.snooze_time_left}</span>` : ''}
                            ${contact.muted ? '<span class="muted-badge">MUTED</span>' : ''}
                        </div>
                        <div class="contact-time">Last contact: ${contact.time_since}</div>
                    </div>
                    <div class="contact-actions">
                        <div class="phone-call-section">
                            <div class="phone-call-label">Phone Call</div>
                            <button class="phone-call-btn" onclick="markPhoneCall(${contact.id})">Talked</button>
                        </div>
                        <div class="btn-group">
                            <div class="btn-group-label">Sent</div>
                            <div>
                                <button class="btn btn-sent" onclick="markSent(${contact.id}, 'text')">Text</button>
                                <button class="btn btn-sent" onclick="markSent(${contact.id}, 'email')">Email</button>
                            </div>
                        </div>
                        <div class="btn-group">
                            <div class="btn-group-label">Received</div>
                            <div>
                                <button class="btn btn-received" onclick="markReceived(${contact.id}, 'text')">Text</button>
                                <button class="btn btn-received" onclick="markReceived(${contact.id}, 'email')">Email</button>
                            </div>
                        </div>
                        ${contact.needs_response ? `<button class="btn btn-responded" onclick="markResponded(${contact.id})">Responded</button>` : ''}
                        <button class="btn settings-btn" onclick="openSettingsModal(${contact.id})">Settings</button>
                    </div>
                </div>
            `;
        }
        
        function renderContacts() {
            const communicationNeededContainer = document.getElementById('communicationNeededList');
            const allContainer = document.getElementById('allContactsList');
            const communicationNeededCountEl = document.getElementById('communicationNeededCount');
            const allCountEl = document.getElementById('allCount');
            
            // Separate contacts that need communication from all contacts
            const communicationNeededContacts = contacts.filter(contact => 
                (contact.overdue && contact.needs_response) || contact.needs_communication
            );
            const allContacts = contacts;
            
            // Update counts
            communicationNeededCountEl.textContent = communicationNeededContacts.length;
            allCountEl.textContent = allContacts.length;
            
            // Render communication needed contacts
            if (communicationNeededContacts.length === 0) {
                communicationNeededContainer.innerHTML = '<div class="empty-section">No communication needed</div>';
            } else {
                communicationNeededContainer.innerHTML = communicationNeededContacts.map(renderContactCard).join('');
            }
            
            // Render all contacts
            if (allContacts.length === 0) {
                allContainer.innerHTML = '<div class="empty-section">No contacts yet. Add someone to start tracking!</div>';
            } else {
                allContainer.innerHTML = allContacts.map(renderContactCard).join('');
            }
        }
        
        // Load contacts when page loads
        loadContacts();
        
        // Auto-refresh every minute to update timers
        setInterval(loadContacts, 60000);
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)