from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import pyotp
import qrcode  # Import the qrcode library
from io import BytesIO
import base64
import re
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask)

DATABASE = 'members.db'
SESSION_TIMEOUT = 30  # 30seconds

# Simple user store for staff and members (no security library)
USERS = {
    "staff": {"password": "staffpass", "role": "staff"},
    "member": {"password": "memberpass", "role": "member"},
    "pakkarim": {"password": "karim", "role": "staff"}
}

# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request

def check_session_timeout():
    create_tables()  # Ensure tables exist
    
    session.permanent = True  # Mark session as permanent to use the lifetime setting
    
    if 'user' in session:
        last_activity = session.get('last_activity')
        current_time = time.time()
        
        if last_activity and (current_time - last_activity > SESSION_TIMEOUT):
            # Clear session data on timeout
            session.clear()
            return render_template(
                'timeout.html',
                message="Sorry bro, sila login balik ah."
            )
        # Update last activity time
        session['last_activity'] = current_time

        
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                membership_status TEXT NOT NULL
                                    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY,
                class_name TEXT NOT NULL,
                class_time TEXT NOT NULL
                                    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                member_id INTEGER,
                class_id INTEGER,
                FOREIGN KEY (member_id) REFERENCES members (id),
                FOREIGN KEY (class_id) REFERENCES classes (id)
                                    )''')
    db.commit()

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in USERS and USERS[username]['password'] == password:
            session['user'] = username
            session['role'] = USERS[username]['role']
            # Redirect to OTP generation for extra security
            return redirect(url_for('generate_otp'))
        else:
            return "Login Failed!"
    return render_template('login.html')

def get_user_secret(username):
    return 'JBSWY3DPEHPK3PXP'

# Function to retrieve user's OTP secret (replace with your own logic)
def get_user_secret(username):
    # Simulating a secret for a user (In real use, retrieve from your database)
    return 'JBSWY3DPEHPK3PXP'  # Replace with a way to fetch the secret for the user

# Generate OTP
@app.route('/generate_otp', methods=['GET'])
def generate_otp():
    user_id = session.get('user')  # Retrieve the logged-in user
    if user_id is None:
        return redirect(url_for('login'))  # Redirect if user is not logged in

    secret = get_user_secret(user_id)  # Retrieve OTP secret for user
    if secret is None:
        return "Error: OTP secret not found", 400

    # Generate the QR Code for the authenticator app
    qr = qrcode.make(f'otpauth://totp/{user_id}?secret={secret}&issuer=GymManagement')
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')  # Encode QR code to base64 for rendering

    return render_template('otp_display.html', qr_code=qr_code)  # Remove otp=otp here

# Verify OTP
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_id = session.get('user')  # Retrieve the logged-in user
    if user_id is None:
        return redirect(url_for('login'))  # Redirect if user is not logged in

    secret = get_user_secret(user_id)  # Retrieve OTP secret for user
    if secret is None:
        return "Error: OTP secret not found", 400

    entered_otp = request.form['otp']  # Get the OTP entered by the user
    totp = pyotp.TOTP(secret)

    if totp.verify(entered_otp):
        return redirect(url_for('dashboard'))  # Redirect to dashboard on successful verification
    else:
        return "Invalid OTP. Please try again.", 400

# Input validation functions
def is_valid_name(name):
    """ Validate that name only contains alphabets and spaces. """
    return bool(re.match("^[A-Za-z ]+$", name))

def is_valid_status(status):
    """ Validate that membership status is either 'active' or 'inactive'. """
    return status.lower() in ['active', 'inactive']

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']

        # Input validation
        if not name or not is_valid_name(name):
            return "Invalid name. Only letters and spaces are allowed.", 400
        
        if not status or not is_valid_status(status):
            return "Invalid status. Use 'active' or 'inactive'.", 400
        
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    return render_template('add_member.html')

# View specific member class
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']

        # Ensure valid class_id (numeric and exists in the database)
        if not class_id.isdigit() or not query_db("SELECT * FROM classes WHERE id = ?", [class_id], one=True):
            return "Invalid class selection.", 400
        
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

# View users
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# New Route for Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Delete member from the database
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    
    # Also delete any classes associated with the member in the member_classes table
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    
    db.commit()
    
    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
