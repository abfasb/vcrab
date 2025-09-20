from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from math import ceil
from flask import flash
from flask import make_response
from flask_mysqldb import MySQL
from flask_cors import CORS
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from decimal import Decimal
import io
import csv
import mysql.connector
import eventlet
import pandas as pd
import joblib
import pdfkit
import numpy as np
import os
import pymysql
import requests
import random
import string
import json
import openpyxl
import pytz
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows


app = Flask(__name__)
app.secret_key = "vcrab_secret_key"
socketio = SocketIO(app, cors_allowed_origins="*")

db_config = {
    "host": "hopper.proxy.rlwy.net",  
    "user": "root",
    "password": "ESwDjBGnHlTcYOEYFHkvzWVidzEFZZCO",
    "database": "railway",
    "port": 18476                      
}


email_config = {
    "email": "icallakate0285@gmail.com",
    "password": "yasrayvyssjpuitl",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587
}

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as e:
        print("Database connection error:", e)
        return None

def send_email(to, subject, text, html=None):
    try:
        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = email_config["email"]
        msg['To'] = to
        
        # Attach both plain text and HTML versions
        part1 = MIMEText(text, 'plain')
        msg.attach(part1)
        
        if html:
            part2 = MIMEText(html, 'html')
            msg.attach(part2)
        
        # Create secure connection with server and send email
        with smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"]) as server:
            server.ehlo()  # Can be omitted
            server.starttls()  # Secure the connection
            server.ehlo()  # Can be omitted
            server.login(email_config["email"], email_config["password"])
            server.send_message(msg)
        
        print(f"Email successfully sent to {to}")
        return True
    except Exception as e:
        print(f"Failed to send email to {to}. Error: {str(e)}")
        return False

# Custom JSON encoder for Decimal types
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, obj)

app.json_encoder = DecimalEncoder
# ==================== ROUTES ====================
@app.route("/")
def index():
    """Serve the enhanced landing page"""
    return render_template("index.html")

@app.route("/home")
def home():
    """Redirect home to login for authenticated users"""
    return redirect(url_for("login"))

@app.route('/verify-reset-code', methods=['GET', 'POST'])
def verify_reset_code():
    if request.method == 'POST':
        reset_code = request.form.get('reset_code')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if the reset code exists and has not expired
        cursor.execute("SELECT * FROM password_reset_codes WHERE reset_code = %s AND expires_at > %s", (reset_code, datetime.now()))
        reset_entry = cursor.fetchone()

        if not reset_entry:
            flash('Invalid or expired reset code', 'error')
            return redirect(url_for('forgot_password'))

        # Redirect to the reset password page with the code as a URL parameter
        return redirect(url_for('reset_password', reset_code=reset_code))

    return render_template('verify_reset_code.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        reset_code = request.args.get('reset_code')  
        if not reset_code:
            flash('Invalid or expired reset code', 'error')
            return redirect(url_for('forgot_password'))
        return render_template('reset_password.html', reset_code=reset_code)
    
    elif request.method == 'POST':
        reset_code = request.form.get('reset_code') 
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not reset_code:
            flash('Invalid or expired reset code', 'error')
            return redirect(url_for('forgot_password'))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', reset_code=reset_code))

        hashed_password = generate_password_hash(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE users
                SET password = %s
                WHERE id = (SELECT user_id FROM password_reset_codes WHERE reset_code = %s)
            """, (hashed_password, reset_code))
            conn.commit()

            cursor.execute("DELETE FROM password_reset_codes WHERE reset_code = %s", (reset_code,))
            conn.commit()
            
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error resetting password: {str(e)}")
            flash('An error occurred while resetting your password. Please try again.', 'error')
            return redirect(url_for('reset_password', reset_code=reset_code))
        finally:
            conn.close()

app.config['SECURITY_PASSWORD_SALT'] = 'vcrab_salt'  

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        terms = request.form.get("terms")

        # Validate form data
        if not all([username, email, password, confirm_password, terms]):
            flash("All fields are required", "error")
            return redirect(url_for("register"))
            
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        # Password strength validation
        if len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        if conn is None:
            flash("Database connection error. Please try again later.", "error")
            return redirect(url_for("register"))

        try:
            cursor = conn.cursor(dictionary=True)  # Use dictionary cursor
            
            # Check if username or email already exists
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                flash("Username or email already exists", "error")
                return redirect(url_for("register"))

            # Insert new user
            cursor.execute("""
                INSERT INTO users (username, email, password, status, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, email, hashed_password, 'pending', 'user'))  # Changed role to 'user'
            
            conn.commit()

            # Notify admin about new registration
            cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
            admins = cursor.fetchall()
            for admin in admins:
                try:
                    send_email(
                        admin['email'],
                        "New User Registration",
                        f"A new user {username} ({email}) has registered and is awaiting approval."
                    )
                except Exception as e:
                    print(f"Failed to send email to admin: {e}")

            flash("Registration successful! Please wait for admin approval.", "success")
            return redirect(url_for("login"))

        except mysql.connector.Error as e:
            flash(f"Registration failed: {e}", "error")
            return redirect(url_for("register"))
            
        finally:
            if 'cursor' in locals():
                cursor.close()
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        if conn is None:
            return "Database connection error."
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["status"] != "approved":
                return "⛔ Your account is still pending admin approval."
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            return "Invalid credentials. Try again."

    return render_template("login.html")

@app.route("/admin/users")
def manage_users():
    if session.get("role") != "admin":
        return "Unauthorized access"

    page = int(request.args.get("page", 1))
    limit = 5
    offset = (page - 1) * limit

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total FROM users WHERE status = 'pending'")
    total_users = cursor.fetchone()['total']
    total_pages = (total_users + limit - 1) // limit

    cursor.execute("""
        SELECT id, username, email, status 
        FROM users 
        WHERE status = 'pending' 
        ORDER BY id DESC 
        LIMIT %s OFFSET %s
    """, (limit, offset))
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin_users.html", users=users, page=page, total_pages=total_pages)

@app.route('/admin/export_users')
def export_pending_users():
    if session.get('role') != 'admin':
        return "Unauthorized"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT username, email, status FROM users WHERE status = 'pending'")
    users = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Username', 'Email', 'Status'])
    writer.writerows(users)

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype="text/csv",
        as_attachment=True,
        download_name="pending_users.csv"
    )

@app.route("/admin/approve/<int:user_id>")
def approve_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email, username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    cursor.execute("UPDATE users SET status = 'approved' WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    if user:
        subject = "Your VCRAB Account Has Been Approved"
        message = f"""Hello {user['username']},
        
Your account for the VCRAB system has been approved by the administrator. 
You can now log in using your credentials.

Thank you,
VCRAB Team"""
        send_email(user['email'], subject, message)

    return redirect(url_for("manage_users"))

@app.route("/admin/reject/<int:user_id>")
def reject_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT email, username FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    cursor.execute("UPDATE users SET status = 'rejected' WHERE id = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    if user:
        subject = "Your VCRAB Account Application"
        message = f"""Hello {user['username']},
        
We regret to inform you that your account application for the VCRAB system 
has been rejected by the administrator.

Thank you for your interest,
VCRAB Team"""
        send_email(user['email'], subject, message)

    return redirect(url_for("manage_users"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = %s", (session["username"],))
    user = cursor.fetchone()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_email = request.form["email"]
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]

        hash_format_valid = user["password"].startswith("pbkdf2:sha256:")
        try:
            password_correct = check_password_hash(user["password"], current_password)
        except Exception as e:
            password_correct = False
            print("❌ Error checking password hash:", str(e))

        if not hash_format_valid or not password_correct:
            flash("Incorrect current password or invalid stored password format.", "danger")
        else:
            if new_email and new_email != user["email"]:
                cursor.execute("UPDATE users SET email = %s WHERE username = %s", (new_email, session["username"]))
            if new_password:
                hashed_pw = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, session["username"]))
            conn.commit()
            flash("Profile updated successfully.", "success")

            subject = "Your VCRAB Account Has Been Updated"
            message = f"""Hello {user['username']},
            
Your VCRAB account profile has been successfully updated. 
If you didn't make these changes, please contact the administrator immediately.

Thank you,
VCRAB Team"""
            send_email(user['email'] if 'email' in user else new_email, subject, message)

        cursor.execute("SELECT username, email, role, status FROM users WHERE username = %s", (session["username"],))
        user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("profile.html", user=user)

@app.route("/create_admin_user")
def create_admin_user():
    conn = get_db_connection()
    cursor = conn.cursor()

    username = "newadmin"
    email = "admin@example.com"
    password = generate_password_hash("admin", method="pbkdf2:sha256")
    status = "approved"
    role = "admin"

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing = cursor.fetchone()
    if existing:
        return "❗User already exists."

    try:
        cursor.execute("""
            INSERT INTO users (username, email, password, status, role)
            VALUES (%s, %s, %s, %s, %s)
        """, (username, email, password, status, role))
        conn.commit()
        
        # Send welcome email to new admin
        subject = "Your VCRAB Admin Account"
        message = f"""Hello {username},
        
Your VCRAB admin account has been created successfully.
Username: {username}
Password: admin

Please change your password immediately after logging in.

Thank you,
VCRAB Team"""
        send_email(email, subject, message)
        
        return "✅ Admin user created! Username: newadmin | Password: admin"
    except Exception as e:
        return f"❌ Failed to insert admin: {e}"
    finally:
        cursor.close()
        conn.close()

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email address', 'error')
            return redirect(url_for('forgot_password'))

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('forgot_password'))

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, email, username FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user:
                flash('Email address not found', 'error')
                return redirect(url_for('forgot_password'))

            # Generate a 6-digit reset code (numeric only)
            reset_code = ''.join(random.choices('0123456789', k=6))  # Numeric code only
            expires_at = datetime.now() + timedelta(hours=1)  # Set expiration time to 1 hour
            
            # Store the reset code in the database
            cursor.execute("""
                INSERT INTO password_reset_codes (user_id, reset_code, expires_at)
                VALUES (%s, %s, %s)
            """, (user['id'], reset_code, expires_at))
            conn.commit()

            # Send the reset code to the user's email
            subject = "Password Reset Code"
            message = f"""Hello {user['username']},

Here is your password reset code: {reset_code}.
It will expire in 1 hour.

If you did not request this, please ignore this email.

Thank you, Vcrab Team."""
            send_email(user['email'], subject, message)

            flash('A reset code has been sent to your email', 'success')
            return redirect(url_for('verify_reset_code'))  # Redirect to a page to input the reset code

        except Exception as e:
            flash(f'An error occurred. Please try again. {str(e)}', 'error')
            return redirect(url_for('forgot_password'))
        finally:
            if 'cursor' in locals():
                cursor.close()
            if conn:
                conn.close()

    return render_template('forgot_password.html')

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/controls") 
def controls():
    return render_template("control.html", username=session["username"])

@app.route("/monitoring")
def monitoring():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("monitoring.html", username=session.get("username"))

@app.route('/growth-monitoring')
def growth_monitoring():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template('growth_monitoring.html', username=session.get("username"))

@app.route("/reports")
def reports():
    return render_template("reports.html", username=session["username"])

@app.route("/notification")
def notification():
    return render_template("notification.html", username=session["username"])

@app.route('/analytics')
def analytics():
    return render_template("analytics.html", username=session.get("username"))

@app.route('/inventory')
def inventory():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template('inventory.html', username=session.get("username"))

@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    
    # Send logout notification
    if username:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT email FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and user.get('email'):
                send_email(
                    user['email'],
                    "You Have Logged Out",
                    f"Hello {username},\n\nYou have successfully logged out of the VCRAB system."
                )
    
    return redirect(url_for("login"))

# ==================== UPDATED SENSOR DATA ENDPOINTS ====================

@app.route('/upload', methods=['POST'])
def upload_sensor_data():
    try:
        # Get the data from the request
        data = request.get_json()
        print("Received Data:", data)  # Log the incoming data to verify
        device_id = data.get("device_id", "unknown")
        temperature = data.get("temperature", 0)  # Default to 0 if None
        ph_level = data.get("ph_level", 0)  # Default to 0 if None
        tds_value = data.get("tds_value", 0)  # Default to 0 if None
        turbidity = data.get("turbidity", 0)  # Default to 0 if None

        # Validate device_id
        if device_id not in ["ESP32_1", "ESP32_2"]:
            return jsonify({"error": "Invalid device ID"}), 400

        # Establish DB connection
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB connection error"}), 500

        cursor = conn.cursor()

        # Insert data into respective tables based on device_id
        if device_id == "ESP32_1":
            cursor.execute("""
                INSERT INTO esp32_1_sensor_readings (device_id, temperature, ph_level)
                VALUES (%s, %s, %s)
            """, (device_id, temperature, ph_level))
            
            # Check for alerts and notify immediately
            check_and_send_alerts("temperature", temperature)
            check_and_send_alerts("ph_level", ph_level)
            
        elif device_id == "ESP32_2":
            cursor.execute("""
                INSERT INTO esp32_2_sensor_readings (device_id, tds_value, turbidity)
                VALUES (%s, %s, %s)
            """, (device_id, tds_value, turbidity))
            
            # Check for alerts and notify immediately
            check_and_send_alerts("tds_value", tds_value)
            check_and_send_alerts("turbidity", turbidity)

        # Commit the transaction and close the cursor and connection
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Data inserted and checked successfully"}), 200

    except KeyError as ke:
        return jsonify({"error": f"Missing required parameter: {str(ke)}"}), 400
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

def check_and_send_alerts(parameter, value):
    """Check sensor values and send immediate alerts if thresholds are exceeded"""
    try:
        conn = get_db_connection()
        if not conn:
            return
            
        cursor = conn.cursor(dictionary=True)
        
        # Get current thresholds
        cursor.execute("SELECT * FROM sensor_thresholds WHERE id = 1")
        thresholds = cursor.fetchone()
        
        if not thresholds:
            cursor.close()
            conn.close()
            return
        
        status = "Safe"
        advice = f"{parameter.replace('_', ' ').capitalize()} is within normal range"
        
        # Check thresholds for each parameter
        if parameter == "temperature":
            if value < thresholds["temp_min"] - 2 or value > thresholds["temp_max"] + 2:
                status = "Critical"
                advice = "Temperature is at critical levels! Immediate action required."
            elif value < thresholds["temp_min"] or value > thresholds["temp_max"]:
                status = "Warning"
                advice = "Temperature is outside optimal range. Monitor closely."
                
        elif parameter == "ph_level":
            if value < thresholds["ph_min"] - 0.5 or value > thresholds["ph_max"] + 0.5:
                status = "Critical"
                advice = "pH level is at critical levels! Check water chemistry immediately."
            elif value < thresholds["ph_min"] or value > thresholds["ph_max"]:
                status = "Warning"
                advice = "pH level is outside optimal range. Consider water treatment."
                
        elif parameter == "tds_value":
            if value > thresholds["tds_max"] + 100:
                status = "Critical"
                advice = "TDS levels are critically high! Check filtration system."
            elif value > thresholds["tds_max"]:
                status = "Warning"
                advice = "TDS levels are elevated. Monitor water quality."
                
        elif parameter == "turbidity":
            if value > thresholds["turbidity_max"] + 5:
                status = "Critical"
                advice = "Turbidity is critically high! Check filtration and water clarity."
            elif value > thresholds["turbidity_max"]:
                status = "Warning"
                advice = "Turbidity levels are elevated. Monitor water clarity."
        
        # Insert notification if not Safe
        if status != "Safe":
            cursor.execute("""
                INSERT INTO crab_notifications (parameter, value, status, advice, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (parameter, value, status, advice, datetime.now()))
            conn.commit()
            
            # Emit real-time notification via SocketIO
            socketio.emit('new_notification', {
                'parameter': parameter,
                'value': value,
                'status': status,
                'advice': advice,
                'timestamp': datetime.now().isoformat()
            })
            
            # Send email alerts for critical conditions
            if status == "Critical":
                cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
                admins = cursor.fetchall()
                for admin in admins:
                    try:
                        send_email(
                            admin['email'],
                            f"CRITICAL ALERT: {parameter.replace('_', ' ').title()}",
                            f"""CRITICAL CONDITION DETECTED!

Parameter: {parameter.replace('_', ' ').title()}
Current Value: {value}
Status: {status}
Recommendation: {advice}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please take immediate action to address this issue.

V-CRAB Monitoring System"""
                        )
                    except Exception as e:
                        print(f"Failed to send critical alert email: {e}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error in check_and_send_alerts: {e}")

@app.route('/fetch_data', methods=['GET'])
def fetch_sensor_data():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB error"}), 500

        cursor = conn.cursor(dictionary=True)

        # Fetch the most recent sensor values for ESP32_1
        cursor.execute("SELECT temperature, ph_level, timestamp FROM esp32_1_sensor_readings ORDER BY timestamp DESC LIMIT 1")
        esp32_1_data = cursor.fetchone()

        # Fetch the most recent sensor values for ESP32_2
        cursor.execute("SELECT tds_value, turbidity, timestamp FROM esp32_2_sensor_readings ORDER BY timestamp DESC LIMIT 1")
        esp32_2_data = cursor.fetchone()

        cursor.close()
        conn.close()

        # Prepare combined response data
        response_data = {
            "temperature": esp32_1_data["temperature"] if esp32_1_data else 0,
            "ph_level": esp32_1_data["ph_level"] if esp32_1_data else 0,
            "tds_value": esp32_2_data["tds_value"] if esp32_2_data else 0,
            "turbidity": esp32_2_data["turbidity"] if esp32_2_data else 0,
            "timestamp": max(
                esp32_1_data["timestamp"] if esp32_1_data else datetime.min,
                esp32_2_data["timestamp"] if esp32_2_data else datetime.min
            ).isoformat() if (esp32_1_data or esp32_2_data) else datetime.now().isoformat()
        }

        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fetch_esp32_1_data")
def fetch_esp32_1_data():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM esp32_1_sensor_readings ORDER BY timestamp DESC LIMIT 10")
    result = cursor.fetchall()
    conn.close()
    return jsonify(result)

@app.route("/fetch_esp32_2_data")
def fetch_esp32_2_data():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM esp32_2_sensor_readings ORDER BY timestamp DESC LIMIT 10")
    result = cursor.fetchall()
    conn.close()
    return jsonify(result)

@app.route("/notify", methods=["POST"])
def notify():
    try:
        data = request.get_json()
        device_id = data.get("device_id", "unknown")
        message = data.get("message")
        if not message:
            return jsonify({"error": "No message provided"}), 400

        insert_notification(device_id, message)
        return jsonify({"status": "Notification saved"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def insert_notification(device_id, message):
    conn = get_db_connection()
    if conn is None:
        print("Database connection error when inserting notification!")
        return
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notifications (device_id, message)
        VALUES (%s, %s)
    """, (device_id, message))
    conn.commit()
    cursor.close()
    conn.close()
    print(f"🔔 Notification inserted from {device_id}: {message}")

@app.route("/fetch_logs")
def fetch_logs():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"})
    cursor = conn.cursor(dictionary=True)
    
    # Fetch logs from both ESP32 tables
    cursor.execute("""
        (SELECT timestamp, 'ESP32_1' as device FROM esp32_1_sensor_readings ORDER BY timestamp DESC LIMIT 5)
        UNION ALL
        (SELECT timestamp, 'ESP32_2' as device FROM esp32_2_sensor_readings ORDER BY timestamp DESC LIMIT 5)
        ORDER BY timestamp DESC LIMIT 10
    """)
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(logs)

@app.route('/fetch_reports', methods=['GET'])
def fetch_reports():
    print("Fetch reports endpoint hit")  # Debugging
    start_date = request.args.get('start', '')
    end_date = request.args.get('end', '')
    print(f"Received parameters - start: {start_date}, end: {end_date}")  # Debugging

    try:
        conn = get_db_connection()
        if conn is None:
            print("Database connection failed!")  # Debugging
            return jsonify({"error": "Database connection failed!"}), 500

        cursor = conn.cursor(dictionary=True)

        # First try a simple query to verify connection works
        test_query = "SELECT 1 as test"
        cursor.execute(test_query)
        test_result = cursor.fetchone()
        print(f"Test query result: {test_result}")  # Debugging

        # Build the main query
        query = """
        SELECT 
            timestamp,
            COALESCE(temperature, 0) as temperature,
            COALESCE(ph_level, 0) as ph_level,
            COALESCE(tds_value, 0) as tds_value,
            COALESCE(turbidity, 0) as turbidity
        FROM (
            SELECT 
                e1.timestamp,
                e1.temperature,
                e1.ph_level,
                NULL as tds_value,
                NULL as turbidity
            FROM esp32_1_sensor_readings e1
            UNION ALL
            SELECT 
                e2.timestamp,
                NULL as temperature,
                NULL as ph_level,
                e2.tds_value,
                e2.turbidity
            FROM esp32_2_sensor_readings e2
        ) as combined_data
        """
        
        params = []
        if start_date and end_date:
            query += " WHERE DATE(timestamp) BETWEEN %s AND %s"
            params.extend([start_date, end_date])
        
        query += " ORDER BY timestamp DESC"
        
        if not (start_date and end_date):
            query += " LIMIT 100"

        print(f"Executing query: {query}")  # Debugging
        print(f"With params: {params}")  # Debugging
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        print(f"Fetched {len(rows)} rows")  # Debugging
        
        cursor.close()
        conn.close()
        
        return jsonify(rows)

    except mysql.connector.Error as e:
        print(f"MySQL Error: {e}")  # Debugging
        error_msg = f"Database error: {str(e)}"
        if 'conn' in locals() and conn:
            conn.close()
        return jsonify({"error": error_msg}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")  # Debugging
        error_msg = f"Unexpected error: {str(e)}"
        if 'conn' in locals() and conn:
            conn.close()
        return jsonify({"error": error_msg}), 500


@app.route('/fetch_average_data')
def fetch_average_data():
    print("Fetch average data endpoint hit")  # Debugging
    period = request.args.get('period', 'daily')
    print(f"Period requested: {period}")  # Debugging
    
    try:
        conn = get_db_connection()
        if conn is None:
            print("Database connection failed!")  # Debugging
            return jsonify({"error": "Database connection failed!"}), 500

        cursor = conn.cursor(dictionary=True)

        # Verify connection with test query
        test_query = "SELECT 1 as test"
        cursor.execute(test_query)
        test_result = cursor.fetchone()
        print(f"Test query result: {test_result}")  # Debugging

        interval_map = {
            'daily': '1 DAY',
            'weekly': '7 DAY',
            'monthly': '30 DAY'
        }
        interval = interval_map.get(period, '1 DAY')

        # Get table structures to verify columns exist
        cursor.execute("DESCRIBE esp32_1_sensor_readings")
        table1_columns = [col['Field'] for col in cursor.fetchall()]
        print(f"esp32_1 columns: {table1_columns}")  # Debugging

        cursor.execute("DESCRIBE esp32_2_sensor_readings")
        table2_columns = [col['Field'] for col in cursor.fetchall()]
        print(f"esp32_2 columns: {table2_columns}")  # Debugging

        # Build queries with verified column names
        query1 = f"""
            SELECT 
                AVG(temperature) as avg_temp, 
                MIN(temperature) as min_temp, 
                MAX(temperature) as max_temp,
                AVG(ph_level) as avg_ph, 
                MIN(ph_level) as min_ph, 
                MAX(ph_level) as max_ph
            FROM esp32_1_sensor_readings 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL {interval})
        """
        
        query2 = f"""
            SELECT 
                AVG(tds_value) as avg_tds, 
                MIN(tds_value) as min_tds, 
                MAX(tds_value) as max_tds,
                AVG(turbidity) as avg_turbidity, 
                MIN(turbidity) as min_turbidity, 
                MAX(turbidity) as max_turbidity
            FROM esp32_2_sensor_readings 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL {interval})
        """
        
        print(f"Executing query1: {query1}")  # Debugging
        cursor.execute(query1)
        esp32_1_data = cursor.fetchone() or {}
        print(f"Query1 result: {esp32_1_data}")  # Debugging
        
        print(f"Executing query2: {query2}")  # Debugging
        cursor.execute(query2)
        esp32_2_data = cursor.fetchone() or {}
        print(f"Query2 result: {esp32_2_data}")  # Debugging
        
        result = {
            'temperature': {
                'avg': float(esp32_1_data.get('avg_temp', 0)),
                'min': float(esp32_1_data.get('min_temp', 0)),
                'max': float(esp32_1_data.get('max_temp', 0))
            },
            'ph_level': {
                'avg': float(esp32_1_data.get('avg_ph', 0)),
                'min': float(esp32_1_data.get('min_ph', 0)),
                'max': float(esp32_1_data.get('max_ph', 0))
            },
            'tds_value': {
                'avg': float(esp32_2_data.get('avg_tds', 0)),
                'min': float(esp32_2_data.get('min_tds', 0)),
                'max': float(esp32_2_data.get('max_tds', 0))
            },
            'turbidity': {
                'avg': float(esp32_2_data.get('avg_turbidity', 0)),
                'min': float(esp32_2_data.get('min_turbidity', 0)),
                'max': float(esp32_2_data.get('max_turbidity', 0))
            }
        }
        
        cursor.close()
        conn.close()
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in fetch_average_data: {str(e)}", exc_info=True)  # Debugging
        if 'conn' in locals() and conn:
            conn.close()
        return jsonify({"error": str(e)}), 500

def load_ml_models():
    """Load trained ML models for prediction"""
    try:
        model = joblib.load('models/water_quality_model.pkl')
        scaler = joblib.load('models/water_quality_scaler.pkl')
        features = joblib.load('models/feature_names.pkl')
        metadata = joblib.load('models/model_metadata.pkl')
        return model, scaler, features, metadata
    except FileNotFoundError:
        print("⚠️ ML models not found. Please run training script first.")
        return None, None, None, None

# Global ML model variables
ML_MODEL, ML_SCALER, ML_FEATURES, ML_METADATA = load_ml_models()


@app.route('/api/predict')
def predict():
    """Enhanced prediction endpoint with ML model and SMTP notifications"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get latest data from both ESP32 tables
    cursor.execute("SELECT temperature, ph_level, timestamp FROM esp32_1_sensor_readings ORDER BY timestamp DESC LIMIT 1")
    esp32_1_latest = cursor.fetchone()
    
    cursor.execute("SELECT tds_value, turbidity, timestamp FROM esp32_2_sensor_readings ORDER BY timestamp DESC LIMIT 1")
    esp32_2_latest = cursor.fetchone()

    if not esp32_1_latest and not esp32_2_latest:
        conn.close()
        return jsonify({"error": "No data available"}), 404

    # Combine latest data
    latest = {
        'temperature': float(esp32_1_latest['temperature']) if esp32_1_latest else 27.5,
        'ph_level': float(esp32_1_latest['ph_level']) if esp32_1_latest else 7.5,
        'tds_value': float(esp32_2_latest['tds_value']) if esp32_2_latest else 525,
        'turbidity': float(esp32_2_latest['turbidity']) if esp32_2_latest else 20,
        'timestamp': max(
            esp32_1_latest['timestamp'] if esp32_1_latest else datetime.min,
            esp32_2_latest['timestamp'] if esp32_2_latest else datetime.min
        )
    }

    # Get thresholds
    cursor.execute("SELECT * FROM sensor_thresholds ORDER BY id DESC LIMIT 1")
    thresholds = cursor.fetchone()
    
    if not thresholds:
        # Use default thresholds based on your sensor parameters
        thresholds = {
            "temp_min": 25, "temp_max": 30,
            "ph_min": 6.5, "ph_max": 8.5,
            "tds_min": 50, "tds_max": 1000,
            "turbidity_min": 10, "turbidity_max": 30
        }

    # ML Prediction
    ml_prediction = None
    ml_confidence = 0
    if ML_MODEL and ML_SCALER and ML_FEATURES:
        try:
            # Prepare data for ML model
            feature_data = np.array([[
                latest['temperature'],
                latest['ph_level'],
                latest['tds_value'],
                latest['turbidity']
            ]])
            
            # Scale features
            feature_data_scaled = ML_SCALER.transform(feature_data)
            
            # Make prediction
            ml_prediction = ML_MODEL.predict(feature_data_scaled)[0]
            ml_probabilities = ML_MODEL.predict_proba(feature_data_scaled)[0]
            ml_confidence = max(ml_probabilities) * 100
            
        except Exception as e:
            print(f"ML Prediction error: {e}")
            ml_prediction = None


    crab_ranges = {
        "ph_level": {
            "safe": (thresholds["ph_min"], thresholds["ph_max"]),
            "warning_low": (max(0, thresholds["ph_min"] - 0.3), thresholds["ph_min"]),
            "warning_high": (thresholds["ph_max"], thresholds["ph_max"] + 0.3),
            "critical_low": (0, max(0, thresholds["ph_min"] - 0.3)),
            "critical_high": (thresholds["ph_max"] + 0.3, 14)
        },
        "tds_value": {
            "safe": (thresholds["tds_min"], thresholds["tds_max"]),
            "warning_low": (max(0, thresholds["tds_min"] - 50), thresholds["tds_min"]),
            "warning_high": (thresholds["tds_max"], thresholds["tds_max"] + 200),
            "critical_low": (0, max(0, thresholds["tds_min"] - 50)),
            "critical_high": (thresholds["tds_max"] + 200, 100000)
        },
        "turbidity": {
            "safe": (thresholds["turbidity_min"], thresholds["turbidity_max"]),
            "warning": (thresholds["turbidity_max"], thresholds["turbidity_max"] + 10),
            "critical": (thresholds["turbidity_max"] + 10, 1000)
        },
        "temperature": {
            "safe": (thresholds["temp_min"], thresholds["temp_max"]),
            "warning_low": (max(0, thresholds["temp_min"] - 2), thresholds["temp_min"]),
            "warning_high": (thresholds["temp_max"], thresholds["temp_max"] + 2),
            "critical_low": (0, max(0, thresholds["temp_min"] - 2)),
            "critical_high": (thresholds["temp_max"] + 2, 50)
        }
    }

    prediction = {}
    critical_count = 0
    warning_count = 0
    safe_count = 0
    advice = []

    for param, ranges in crab_ranges.items():
        val = latest[param]
        status = "Safe"
        advice_msg = f"{param.replace('_', ' ').capitalize()} is optimal for crabs"

        if param == "ph_level":
            if val < ranges["critical_low"][1]:
                status = "Critical"
                advice_msg = "Dangerously low pH! Can cause crab respiratory distress"
            elif val > ranges["critical_high"][0]:
                status = "Critical"
                advice_msg = "Dangerously high pH! Disrupts crab shell formation"
            elif ranges["warning_low"][0] <= val <= ranges["warning_low"][1]:
                status = "Warning"
                advice_msg = "Low pH may affect crab molting process"
            elif ranges["warning_high"][0] <= val <= ranges["warning_high"][1]:
                status = "Warning"
                advice_msg = "High pH may reduce crab feeding efficiency"

        elif param == "tds_value":
            if val < ranges["critical_low"][1]:
                status = "Critical"
                advice_msg = "Dangerously low salinity! Causes osmotic stress in crabs"
            elif val > ranges["critical_high"][0]:
                status = "Critical"
                advice_msg = "Dangerously high salinity! Leads to crab dehydration"
            elif ranges["warning_low"][0] <= val <= ranges["warning_low"][1]:
                status = "Warning"
                advice_msg = "Low salinity may reduce crab growth rate"
            elif ranges["warning_high"][0] <= val <= ranges["warning_high"][1]:
                status = "Warning"
                advice_msg = "High salinity may affect crab reproduction"

        elif param == "turbidity":
            if val > ranges["critical"][0]:
                status = "Critical"
                advice_msg = "Extreme turbidity! Risk of gill damage in crabs"
            elif ranges["warning"][0] <= val <= ranges["warning"][1]:
                status = "Warning"
                advice_msg = "High turbidity reduces crab feeding efficiency"

        elif param == "temperature":
            if val < ranges["critical_low"][1]:
                status = "Critical"
                advice_msg = "Dangerously cold! Crabs may become lethargic"
            elif val > ranges["critical_high"][0]:
                status = "Critical"
                advice_msg = "Dangerously hot! Risk of crab mortality"
            elif ranges["warning_low"][0] <= val <= ranges["warning_low"][1]:
                status = "Warning"
                advice_msg = "Cool temperatures may reduce crab metabolism"
            elif ranges["warning_high"][0] <= val <= ranges["warning_high"][1]:
                status = "Warning"
                advice_msg = "Warm temperatures may increase crab stress"

        if status == "Safe":
            safe_count += 1
        elif status == "Critical":
            critical_count += 1
        elif status == "Warning":
            warning_count += 1

        prediction[param] = {
            "value": val,
            "status": status,
            "advice": advice_msg
        }
        advice.append(advice_msg)

        if status in ["Warning", "Critical"]:
            cursor.execute("""
                INSERT INTO crab_notifications (parameter, value, status, advice, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (param, val, status, advice_msg, latest["timestamp"]))

    # Determine overall status
    if critical_count > 0:
        overall_status = "Critical"
    elif warning_count > 0:
        overall_status = "Warning"
    else:
        overall_status = "Safe"

    # Use ML prediction if available and confident
    if ml_prediction and ml_confidence > 70:
        overall_status = ml_prediction

    total_params = len(crab_ranges) or 1
    overall_score = (safe_count * 100 + warning_count * 50) / total_params
    overall_score = round(overall_score, 1)

    # Generate future predictions (next 24 hours)
    future_predictions = generate_future_predictions(latest, ML_MODEL, ML_SCALER)

    prediction["timestamp"] = latest["timestamp"]
    prediction["overall_status"] = overall_status
    prediction["overall_score"] = overall_score  
    prediction["summary"] = advice
    prediction["ml_prediction"] = ml_prediction
    prediction["ml_confidence"] = round(ml_confidence, 1)
    prediction["model_accuracy"] = ML_METADATA['accuracy'] * 100 if ML_METADATA else 94.2
    prediction["future_predictions"] = future_predictions

    # SMTP Email Notification Logic (Same as your existing approach)
    if critical_count > 0:
        overall_status = "Critical"
        subject = "🚨 CRITICAL ALERT: V-CRAB Water Quality Emergency"
        message = f"""CRITICAL conditions detected in crab habitat at {latest["timestamp"]}:

- Overall Status: {overall_status}
- Health Score: {overall_score}/100
- ML Prediction: {ml_prediction or 'N/A'} (Confidence: {ml_confidence:.1f}%)
- Model Accuracy: {prediction["model_accuracy"]:.1f}%

CRITICAL PARAMETERS:
"""
        for param, data in prediction.items():
            if isinstance(data, dict) and data.get("status") == "Critical":
                message += f"- {param.replace('_', ' ').title()}: {data['value']} ({data['advice']})\n"

        message += f"""
IMMEDIATE ACTIONS REQUIRED:
- STOP feeding operations immediately
- Increase water circulation and aeration
- Contact aquaculture specialist
- Monitor crab behavior closely

This alert was generated by the V-CRAB Predictive Analytics monitoring system.
"""
        
        # Send to all admins
        cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
        admins = cursor.fetchall()
        for admin in admins:
            send_email(admin['email'], subject, message)
            print(f"🚨 Critical alert sent to {admin['email']}")

    elif warning_count > 0:
        overall_status = "Warning"
        subject = "⚠️ WARNING: V-CRAB Water Quality Alert"
        message = f"""WARNING conditions detected in crab habitat at {latest["timestamp"]}:

- Overall Status: {overall_status}
- Health Score: {overall_score}/100
- ML Prediction: {ml_prediction or 'N/A'} (Confidence: {ml_confidence:.1f}%)

WARNING PARAMETERS:
"""
        for param, data in prediction.items():
            if isinstance(data, dict) and data.get("status") in ["Warning", "Critical"]:
                message += f"- {param.replace('_', ' ').title()}: {data['value']} ({data['advice']})\n"

        message += f"""
RECOMMENDED ACTIONS:
- Monitor conditions closely over next 2-4 hours
- Prepare contingency measures
- Consider adjusting feeding schedule
- Check filtration systems

This alert was generated by the V-CRAB Predictive Analytics monitoring system.
"""
        
        # Send to all admins
        cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
        admins = cursor.fetchall()
        for admin in admins:
            send_email(admin['email'], subject, message)
            print(f"⚠️ Warning alert sent to {admin['email']}")

    # Store prediction in database
    cursor.execute("SELECT COUNT(*) AS count FROM predictive_analytics WHERE timestamp = %s", (latest["timestamp"],))
    if cursor.fetchone()["count"] == 0:
        insert_query = """
            INSERT INTO predictive_analytics (pH, tds, turbidity, temperature, overall_status, ml_prediction, confidence_score, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            latest["ph_level"],
            latest["tds_value"],
            latest["turbidity"],
            latest["temperature"],
            overall_status,
            ml_prediction,
            ml_confidence,
            latest["timestamp"]
        ))

    conn.commit()
    conn.close()

    return jsonify(prediction)

def generate_future_predictions(current_data, model, scaler):
    """Generate predictions for the next 24 hours"""
    if not model or not scaler:
        return []
    
    future_predictions = []
    
    try:
        # Generate predictions for next 24 hours (every 4 hours)
        for hours_ahead in [4, 8, 12, 16, 20, 24]:
            # Simulate slight variations in sensor readings
            temp_variation = np.random.normal(0, 0.5)
            ph_variation = np.random.normal(0, 0.1)
            tds_variation = np.random.normal(0, 20)
            turbidity_variation = np.random.normal(0, 2)
            
            future_data = np.array([[
                current_data['temperature'] + temp_variation,
                current_data['ph_level'] + ph_variation,
                current_data['tds_value'] + tds_variation,
                current_data['turbidity'] + turbidity_variation
            ]])
            
            future_data_scaled = scaler.transform(future_data)
            prediction = model.predict(future_data_scaled)[0]
            probabilities = model.predict_proba(future_data_scaled)[0]
            confidence = max(probabilities) * 100
            
            future_time = current_data['timestamp'] + timedelta(hours=hours_ahead)
            
            future_predictions.append({
                'time': future_time.strftime('%H:%M'),
                'prediction': prediction,
                'confidence': round(confidence, 1),
                'hours_ahead': hours_ahead
            })
    
    except Exception as e:
        print(f"Future prediction error: {e}")
    
    return future_predictions

@app.route('/api/training-data')
def get_training_data():
    """Get ML training data for display"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT temperature, ph_level, tds_value, turbidity, quality_status, created_at
        FROM ml_training_data 
        ORDER BY created_at DESC 
        LIMIT 100
    """)
    
    training_data = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return jsonify(training_data)

@app.route('/api/model-performance')
def get_model_performance():
    """Get ML model performance metrics"""
    if not ML_METADATA:
        return jsonify({"error": "Model metadata not available"}), 404
    
    return jsonify({
        "model_type": ML_METADATA.get('model_type', 'Unknown'),
        "accuracy": round(ML_METADATA.get('accuracy', 0) * 100, 2),
        "training_date": ML_METADATA.get('training_date', 'Unknown'),
        "training_samples": ML_METADATA.get('training_samples', 0),
        "features": ML_METADATA.get('features', [])
    })

@app.route('/api/notifications')
def get_crab_notifications():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, parameter, value, status, advice, timestamp, is_read 
        FROM crab_notifications 
        ORDER BY timestamp DESC 
        LIMIT 100
    """)
    notifications = cursor.fetchall()
    conn.close()
    return jsonify(notifications)

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
def mark_notification_as_read(notification_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE crab_notifications 
        SET is_read = TRUE 
        WHERE id = %s
    """, (notification_id,))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/api/notifications/mark-all-read', methods=['POST'])
def mark_all_notifications_as_read():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE crab_notifications SET is_read = TRUE")
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/api/notifications', methods=['DELETE'])
def delete_all_notifications():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM crab_notifications")
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/get_thresholds', methods=["GET"])
def get_thresholds():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sensor_thresholds WHERE id = 1")
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(row)

@app.route('/set_thresholds', methods=["POST"])
def set_thresholds():
    data = request.get_json()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sensor_thresholds SET
            temp_min = %s, temp_max = %s,
            ph_min = %s, ph_max = %s,
            tds_min = %s, tds_max = %s,
            turbidity_min = %s, turbidity_max = %s
        WHERE id = 1
    """, (
        data['temp_min'], data['temp_max'],
        data['ph_min'], data['ph_max'],
        data['tds_min'], data['tds_max'],
        data['turbidity_min'], data['turbidity_max']
    ))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Thresholds updated successfully"})

@app.route('/download_csv', methods=['GET'])
def download_csv():
    start_date = request.args.get('start', '')
    end_date = request.args.get('end', '')

    if not start_date or not end_date:
        return jsonify({"error": "Both start and end dates are required"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed!"}), 500

    cursor = conn.cursor(dictionary=True)

    try:
        # Updated query to fetch from both ESP32 tables
        query = """
        SELECT 
            COALESCE(e1.timestamp, e2.timestamp) as timestamp,
            COALESCE(e1.temperature, 0) as temperature,
            COALESCE(e1.ph_level, 0) as ph_level,
            COALESCE(e2.tds_value, 0) as tds_value,
            COALESCE(e2.turbidity, 0) as turbidity
        FROM esp32_1_sensor_readings e1
        FULL OUTER JOIN esp32_2_sensor_readings e2 
            ON DATE(e1.timestamp) = DATE(e2.timestamp) 
            AND HOUR(e1.timestamp) = HOUR(e2.timestamp)
            AND MINUTE(e1.timestamp) = MINUTE(e2.timestamp)
        WHERE (DATE(e1.timestamp) BETWEEN %s AND %s) 
           OR (DATE(e2.timestamp) BETWEEN %s AND %s)
        ORDER BY timestamp DESC
        """
        cursor.execute(query, (start_date, end_date, start_date, end_date))
        rows = cursor.fetchall()

        if not rows:
            return jsonify({"error": "No data found for selected dates"}), 404

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Temperature (°C)', 'pH Level', 'TDS (ppm)', 'Turbidity (NTU)'])
        
        for row in rows:
            writer.writerow([
                row['timestamp'],
                row['temperature'],
                row['ph_level'],
                row['tds_value'],
                row['turbidity']
            ])
        
        output.seek(0)
        
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=sensor_data_{start_date}_to_{end_date}.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    except mysql.connector.Error as e:
        print("Database Error:", e)
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/fetch_history', methods=['GET'])
def fetch_history():
    time_range = request.args.get('range')

    if time_range == 'weekly':
        data = get_data_for_last_week()  
    elif time_range == 'monthly':
        data = get_data_for_last_month()  
    elif time_range == 'yearly':
        data = get_data_for_last_year() 
    else:
        data = []

    if not data:
        return jsonify({"message": "No data available for the selected time range."}), 404

    return jsonify(data)

def get_data_for_last_week():
    conn = get_db_connection()
    if conn is None:
        return []
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT DATE(COALESCE(e1.timestamp, e2.timestamp)) as date, 
               AVG(COALESCE(e1.temperature, 0)) as avg_temp,
               AVG(COALESCE(e1.ph_level, 0)) as avg_ph,
               AVG(COALESCE(e2.tds_value, 0)) as avg_tds,
               AVG(COALESCE(e2.turbidity, 0)) as avg_turbidity
        FROM esp32_1_sensor_readings e1
        FULL OUTER JOIN esp32_2_sensor_readings e2 
            ON DATE(e1.timestamp) = DATE(e2.timestamp)
        WHERE (e1.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)) 
           OR (e2.timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY))
        GROUP BY DATE(COALESCE(e1.timestamp, e2.timestamp))
        ORDER BY date
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return data

def get_data_for_last_month():
    conn = get_db_connection()
    if conn is None:
        return []
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT DATE(COALESCE(e1.timestamp, e2.timestamp)) as date, 
               AVG(COALESCE(e1.temperature, 0)) as avg_temp,
               AVG(COALESCE(e1.ph_level, 0)) as avg_ph,
               AVG(COALESCE(e2.tds_value, 0)) as avg_tds,
               AVG(COALESCE(e2.turbidity, 0)) as avg_turbidity
        FROM esp32_1_sensor_readings e1
        FULL OUTER JOIN esp32_2_sensor_readings e2 
            ON DATE(e1.timestamp) = DATE(e2.timestamp)
        WHERE (e1.timestamp >= DATE_SUB(NOW(), INTERVAL 1 MONTH)) 
           OR (e2.timestamp >= DATE_SUB(NOW(), INTERVAL 1 MONTH))
        GROUP BY DATE(COALESCE(e1.timestamp, e2.timestamp))
        ORDER BY date
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return data

def get_data_for_last_year():
    conn = get_db_connection()
    if conn is None:
        return []
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT MONTH(COALESCE(e1.timestamp, e2.timestamp)) as month, 
               AVG(COALESCE(e1.temperature, 0)) as avg_temp,
               AVG(COALESCE(e1.ph_level, 0)) as avg_ph,
               AVG(COALESCE(e2.tds_value, 0)) as avg_tds,
               AVG(COALESCE(e2.turbidity, 0)) as avg_turbidity
        FROM esp32_1_sensor_readings e1
        FULL OUTER JOIN esp32_2_sensor_readings e2 
            ON MONTH(e1.timestamp) = MONTH(e2.timestamp)
        WHERE (e1.timestamp >= DATE_SUB(NOW(), INTERVAL 1 YEAR)) 
           OR (e2.timestamp >= DATE_SUB(NOW(), INTERVAL 1 YEAR))
        GROUP BY MONTH(COALESCE(e1.timestamp, e2.timestamp))
        ORDER BY month
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return data

# ==================== INVENTORY API ENDPOINTS ====================

@app.route('/api/inventory', methods=['GET'])
def get_inventory():
    """Get all inventory batches with pagination and filtering"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        search = request.args.get('search', '')
        status_filter = request.args.get('status', 'all')
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        where_conditions = []
        params = []
        
        if search:
            where_conditions.append("(batch_id LIKE %s OR notes LIKE %s OR crab_gender LIKE %s)")
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        
        if status_filter != 'all':
            where_conditions.append("status = %s")
            params.append(status_filter.capitalize())
        
        where_clause = " WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        # Get total count
        count_query = f"SELECT COUNT(*) as total FROM crab_inventory{where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']
        
        # Get paginated data
        offset = (page - 1) * per_page
        data_query = f"""
            SELECT id, batch_id, crab_gender, crab_count, initial_count, average_weight, 
                   status, date_planted, date_harvested, dead_count,
                   harvest_weight, notes, created_at
            FROM crab_inventory{where_clause}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        cursor.execute(data_query, params + [per_page, offset])
        batches = cursor.fetchall()
        
        # Convert date objects to strings for JSON serialization
        for batch in batches:
            if batch['date_planted']:
                batch['date_planted'] = batch['date_planted'].strftime('%Y-%m-%d')
            if batch['date_harvested']:
                batch['date_harvested'] = batch['date_harvested'].strftime('%Y-%m-%d')
            if batch['created_at']:
                batch['created_at'] = batch['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            if batch['dead_count'] is None:
                batch['dead_count'] = 0
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "batches": batches,
            "total": total_count,
            "page": page,
            "per_page": per_page,
            "total_pages": (total_count + per_page - 1) // per_page
        })
        
    except Exception as e:
        print(f"Error in get_inventory: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/inventory/batches', methods=['POST'])
def add_batch():
    """Add a new inventory batch"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['batchId', 'gender', 'count', 'datePlanted']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"success": False, "error": f"Missing required field: {field}"}), 400
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if batch ID already exists
        cursor.execute("SELECT id FROM crab_inventory WHERE batch_id = %s", (data['batchId'],))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "Batch ID already exists"}), 400
        
        # Insert new batch
        insert_query = """
            INSERT INTO crab_inventory (
                batch_id, crab_gender, crab_count, initial_count, average_weight,
                status, date_planted, date_harvested, dead_count, notes, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            data['batchId'],
            data['gender'],
            int(data['count']),
            int(data['count']),  # initial_count same as count
            float(data.get('averageWeight', 0)),
            data.get('status', 'Growing'),
            data['datePlanted'],
            data.get('dateHarvested') if data.get('dateHarvested') else None,
            int(data.get('deadCount', 0)),  # Added dead_count field
            data.get('notes', ''),
            session.get('user_id')
        )
        
        cursor.execute(insert_query, values)
        batch_id = cursor.lastrowid
        conn.commit()
        
        cursor.close()
        conn.close()
        
        # Send notification email to admins (optional)
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT email FROM users WHERE role = 'admin' AND status = 'approved'")
                admins = cursor.fetchall()
                
                for admin in admins:
                    send_email(
                        admin['email'],
                        "New Inventory Batch Added",
                        f"""New inventory batch has been added:

Batch ID: {data['batchId']}
Gender: {data['gender']}
Count: {data['count']}
Dead Count: {data.get('deadCount', 0)}
Date Planted: {data['datePlanted']}
Status: {data.get('status', 'Growing')}

Added by: {session.get('username', 'Unknown')}"""
                    )
                cursor.close()
                conn.close()
        except Exception as e:
            print(f"Failed to send notification email: {e}")
        
        return jsonify({"success": True, "message": "Batch added successfully", "id": batch_id}), 201
        
    except Exception as e:
        print(f"Error in add_batch: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/inventory/batches/<int:batch_id>', methods=['PUT'])
def update_batch(batch_id):
    """Update an existing inventory batch"""
    try:
        data = request.get_json()
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if batch exists
        cursor.execute("SELECT id FROM crab_inventory WHERE id = %s", (batch_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "Batch not found"}), 404
        
        # Update batch
        update_query = """
            UPDATE crab_inventory SET
                batch_id = %s, crab_gender = %s, crab_count = %s, average_weight = %s,
                status = %s, date_planted = %s, date_harvested = %s, dead_count = %s,
                notes = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """
        
        values = (
            data['batchId'],
            data['gender'],
            int(data['count']),
            float(data.get('averageWeight', 0)),
            data.get('status', 'Growing'),
            data['datePlanted'],
            data.get('dateHarvested') if data.get('dateHarvested') else None,
            int(data.get('deadCount', 0)),  # Added dead_count field
            data.get('notes', ''),
            batch_id
        )
        
        cursor.execute(update_query, values)
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Batch updated successfully"}), 200
        
    except Exception as e:
        print(f"Error in update_batch: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/inventory/statistics', methods=['GET'])
def get_inventory_statistics():
    """Get inventory statistics"""
    try:
        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get statistics
        cursor.execute("""
            SELECT 
                SUM(crab_count) as total_crabs,
                SUM(dead_count) as total_dead_crabs,
                COUNT(CASE WHEN status = 'Growing' THEN 1 END) as active_batches,
                COUNT(CASE WHEN status = 'Harvested' THEN 1 END) as harvested_batches,
                COUNT(*) as total_batches
            FROM crab_inventory
        """)
        
        stats = cursor.fetchone()
        
        total_crabs = stats['total_crabs'] or 0
        total_dead = stats['total_dead_crabs'] or 0
        alive_crabs = total_crabs - total_dead
        mortality_rate = (total_dead / total_crabs * 100) if total_crabs > 0 else 0
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "statistics": {
                "totalCrabs": total_crabs,
                "aliveCrabs": alive_crabs,
                "totalDeadCrabs": total_dead,
                "mortalityRate": round(mortality_rate, 2),
                "activeBatches": stats['active_batches'] or 0,
                "harvestedBatches": stats['harvested_batches'] or 0,
                "totalBatches": stats['total_batches'] or 0
            }
        })
        
    except Exception as e:
        print(f"Error in get_inventory_statistics: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/inventory/batches/<int:batch_id>/dead-count', methods=['PUT'])
def update_dead_count(batch_id):
    """Update dead count for a specific batch"""
    try:
        data = request.get_json()
        dead_count = int(data.get('deadCount', 0))
        
        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if batch exists and get current count
        cursor.execute("SELECT crab_count FROM crab_inventory WHERE id = %s", (batch_id,))
        batch = cursor.fetchone()
        if not batch:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "Batch not found"}), 404
        
        total_count = batch[0]
        if dead_count > total_count:
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "Dead count cannot exceed total count"}), 400
        
        # Update dead count
        cursor.execute("""
            UPDATE crab_inventory SET 
                dead_count = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (dead_count, batch_id))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Dead count updated successfully"}), 200
        
    except Exception as e:
        print(f"Error in update_dead_count: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


def get_crab_db_connection():
    try:
        crab_db_config = {
            "host": "localhost",
            "user": "root",
            "password": "",
            "database": "vcrab_db_individual"
        }
        return mysql.connector.connect(**crab_db_config)
    except mysql.connector.Error as e:
        print("Crab Database connection error:", e)
        return None

# Add these routes to your main Flask application

# API Endpoints for Individual Crab Management

@app.route('/api/individual-crabs', methods=['GET'])
def get_individual_crabs():
    """Get all individual crabs with their latest growth data"""
    try:
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get all crabs with their latest growth records
        cursor.execute("""
            SELECT 
                ic.*,
                lgr.latest_weight,
                lgr.latest_length,
                lgr.latest_width,
                lgr.latest_record_date,
                CASE 
                    WHEN ic.status = 'alive' AND lgr.latest_weight >= ic.target_weight THEN 'ready_for_harvest'
                    WHEN ic.status = 'alive' THEN 'growing'
                    ELSE ic.status
                END as harvest_status
            FROM individual_crabs ic
            LEFT JOIN (
                SELECT 
                    box_number,
                    weight as latest_weight,
                    length as latest_length,
                    width as latest_width,
                    record_date as latest_record_date,
                    ROW_NUMBER() OVER (PARTITION BY box_number ORDER BY record_date DESC) as rn
                FROM crab_growth_records
            ) lgr ON ic.box_number = lgr.box_number AND lgr.rn = 1
            ORDER BY ic.box_number
        """)
        
        crabs = cursor.fetchall()
        
        # Convert datetime objects to strings
        for crab in crabs:
            if crab['date_added']:
                crab['date_added'] = crab['date_added'].strftime('%Y-%m-%d')
            if crab['date_of_death']:
                crab['date_of_death'] = crab['date_of_death'].strftime('%Y-%m-%d')
            if crab['latest_record_date']:
                crab['latest_record_date'] = crab['latest_record_date'].strftime('%Y-%m-%d')
            if crab['created_at']:
                crab['created_at'] = crab['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            if crab['updated_at']:
                crab['updated_at'] = crab['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "crabs": crabs
        })
        
    except Exception as e:
        print(f"Error in get_individual_crabs: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/individual-crabs', methods=['POST'])
def add_individual_crab():
    """Add a new crab to a specific box"""
    try:
        data = request.get_json()
        
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO individual_crabs 
            (box_number, crab_id, status, date_added, target_weight, initial_weight, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            data['box_number'],
            data['crab_id'],
            data.get('status', 'alive'),
            data['date_added'],
            data.get('target_weight', 150.0),
            data.get('initial_weight'),
            data.get('notes', '')
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Crab added successfully"})
        
    except Exception as e:
        print(f"Error in add_individual_crab: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/individual-crabs/<int:box_number>', methods=['PUT'])
def update_individual_crab(box_number):
    """Update crab information"""
    try:
        data = request.get_json()
        
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Handle status change to dead
        if data.get('status') == 'dead' and data.get('date_of_death'):
            # Insert mortality record
            cursor.execute("""
                INSERT INTO mortality_records 
                (box_number, crab_id, death_date, cause_of_death, notes)
                SELECT box_number, crab_id, %s, %s, %s
                FROM individual_crabs WHERE box_number = %s
            """, (
                data['date_of_death'],
                data.get('cause_of_death', 'Unknown'),
                data.get('notes', ''),
                box_number
            ))
        
        cursor.execute("""
            UPDATE individual_crabs 
            SET crab_id = %s, status = %s, date_of_death = %s, 
                target_weight = %s, notes = %s, updated_at = CURRENT_TIMESTAMP
            WHERE box_number = %s
        """, (
            data['crab_id'],
            data['status'],
            data.get('date_of_death'),
            data.get('target_weight'),
            data.get('notes', ''),
            box_number
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Crab updated successfully"})
        
    except Exception as e:
        print(f"Error in update_individual_crab: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/growth-records/<int:box_number>', methods=['GET'])
def get_crab_growth_records(box_number):
    """Get growth records for a specific crab"""
    try:
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT * FROM crab_growth_records 
            WHERE box_number = %s 
            ORDER BY record_date DESC
        """, (box_number,))
        
        records = cursor.fetchall()
        
        # Convert datetime objects to strings
        for record in records:
            if record['record_date']:
                record['record_date'] = record['record_date'].strftime('%Y-%m-%d')
            if record['created_at']:
                record['created_at'] = record['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "records": records
        })
        
    except Exception as e:
        print(f"Error in get_crab_growth_records: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/growth-records', methods=['POST'])
def add_growth_record():
    """Add a new growth record"""
    try:
        data = request.get_json()
        
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Calculate growth rate from previous record
        cursor.execute("""
            SELECT weight, record_date FROM crab_growth_records 
            WHERE box_number = %s 
            ORDER BY record_date DESC LIMIT 1
        """, (data['box_number'],))
        
        previous_record = cursor.fetchone()
        growth_rate = None
        
        if previous_record:
            prev_weight, prev_date = previous_record
            current_date = datetime.strptime(data['record_date'], '%Y-%m-%d').date()
            days_diff = (current_date - prev_date).days
            
            if days_diff > 0:
                weight_diff = data['weight'] - prev_weight
                growth_rate = (weight_diff / prev_weight) * 100 if prev_weight > 0 else 0
        
        cursor.execute("""
            INSERT INTO crab_growth_records 
            (box_number, record_date, weight, length, width, growth_rate, notes, recorded_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['box_number'],
            data['record_date'],
            data['weight'],
            data['length'],
            data['width'],
            growth_rate,
            data.get('notes', ''),
            data.get('recorded_by', 'System')
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Growth record added successfully"})
        
    except Exception as e:
        print(f"Error in add_growth_record: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/feeding-schedules-individual', methods=['GET'])
def get_individual_feeding_schedules():
    """Get feeding schedules for individual crab system"""
    try:
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT * FROM feeding_schedules 
            WHERE is_active = TRUE 
            ORDER BY feeding_time
        """)
        
        schedules = cursor.fetchall()
        
        # Convert datetime objects to strings
        for schedule in schedules:
            if schedule['feeding_time']:
                schedule['feeding_time'] = str(schedule['feeding_time'])
            if schedule['start_date']:
                schedule['start_date'] = schedule['start_date'].strftime('%Y-%m-%d')
            if schedule['end_date']:
                schedule['end_date'] = schedule['end_date'].strftime('%Y-%m-%d')
            if schedule['created_at']:
                schedule['created_at'] = schedule['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            if schedule['updated_at']:
                schedule['updated_at'] = schedule['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "schedules": schedules
        })
        
    except Exception as e:
        print(f"Error in get_individual_feeding_schedules: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/feeding-schedules-individual', methods=['POST'])
def add_individual_feeding_schedule():
    """Add feeding schedule for individual crab system"""
    try:
        data = request.get_json()
        
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO feeding_schedules 
            (schedule_name, box_numbers, feed_type, amount_per_crab, frequency, 
             feeding_time, start_date, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data.get('schedule_name', f"Schedule {datetime.now().strftime('%Y%m%d_%H%M%S')}"),
            data['box_numbers'],
            data['feed_type'],
            data['amount_per_crab'],
            data['frequency'],
            data['feeding_time'],
            data.get('start_date', datetime.now().date()),
            data.get('notes', '')
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Feeding schedule added successfully"})
        
    except Exception as e:
        print(f"Error in add_individual_feeding_schedule: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/farm-statistics', methods=['GET'])
def get_farm_statistics():
    """Get comprehensive farm statistics"""
    try:
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get basic counts
        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN status = 'alive' THEN 1 END) as alive_count,
                COUNT(CASE WHEN status = 'dead' THEN 1 END) as dead_count,
                COUNT(CASE WHEN status = 'empty' THEN 1 END) as empty_count,
                (80 - COUNT(*)) as available_boxes
            FROM individual_crabs
        """)
        
        basic_stats = cursor.fetchone()
        
        # Get average weight and growth rates
        cursor.execute("""
            SELECT 
                AVG(lgr.latest_weight) as avg_weight,
                COUNT(CASE WHEN lgr.latest_weight >= ic.target_weight THEN 1 END) as harvest_ready
            FROM individual_crabs ic
            LEFT JOIN (
                SELECT 
                    box_number,
                    weight as latest_weight,
                    ROW_NUMBER() OVER (PARTITION BY box_number ORDER BY record_date DESC) as rn
                FROM crab_growth_records
            ) lgr ON ic.box_number = lgr.box_number AND lgr.rn = 1
            WHERE ic.status = 'alive'
        """)
        
        growth_stats = cursor.fetchone()
        
        # Calculate mortality rate
        total_crabs = basic_stats['alive_count'] + basic_stats['dead_count']
        mortality_rate = (basic_stats['dead_count'] / total_crabs * 100) if total_crabs > 0 else 0
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "statistics": {
                "alive_count": basic_stats['alive_count'],
                "dead_count": basic_stats['dead_count'],
                "empty_count": basic_stats['empty_count'] + basic_stats['available_boxes'],
                "harvest_ready": growth_stats['harvest_ready'] or 0,
                "avg_weight": round(growth_stats['avg_weight'] or 0, 1),
                "mortality_rate": round(mortality_rate, 2),
                "total_capacity": 80,
                "occupancy_rate": round((basic_stats['alive_count'] + basic_stats['dead_count']) / 80 * 100, 1)
            }
        })
        
    except Exception as e:
        print(f"Error in get_farm_statistics: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/top-performers', methods=['GET'])
def get_top_performers():
    """Get top performing crabs by growth rate"""
    try:
        limit = int(request.args.get('limit', 10))
        
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                ic.box_number,
                ic.crab_id,
                lgr.latest_weight,
                ic.initial_weight,
                DATEDIFF(CURDATE(), ic.date_added) as days_in_farm,
                ROUND((lgr.latest_weight - ic.initial_weight) / DATEDIFF(lgr.latest_record_date, ic.date_added), 2) as avg_daily_growth
            FROM individual_crabs ic
            JOIN (
                SELECT 
                    box_number,
                    weight as latest_weight,
                    record_date as latest_record_date,
                    ROW_NUMBER() OVER (PARTITION BY box_number ORDER BY record_date DESC) as rn
                FROM crab_growth_records
            ) lgr ON ic.box_number = lgr.box_number AND lgr.rn = 1
            WHERE ic.status = 'alive' AND ic.initial_weight IS NOT NULL
            ORDER BY avg_daily_growth DESC
            LIMIT %s
        """, (limit,))
        
        performers = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "performers": performers
        })
        
    except Exception as e:
        print(f"Error in get_top_performers: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/harvest-ready', methods=['GET'])
def get_harvest_ready():
    """Get crabs ready for harvest"""
    try:
        conn = get_crab_db_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                ic.box_number,
                ic.crab_id,
                ic.target_weight,
                lgr.latest_weight,
                lgr.latest_record_date,
                DATEDIFF(CURDATE(), ic.date_added) as days_in_farm
            FROM individual_crabs ic
            JOIN (
                SELECT 
                    box_number,
                    weight as latest_weight,
                    record_date as latest_record_date,
                    ROW_NUMBER() OVER (PARTITION BY box_number ORDER BY record_date DESC) as rn
                FROM crab_growth_records
            ) lgr ON ic.box_number = lgr.box_number AND lgr.rn = 1
            WHERE ic.status = 'alive' AND lgr.latest_weight >= ic.target_weight
            ORDER BY lgr.latest_weight DESC
        """)
        
        harvest_ready = cursor.fetchall()
        
        # Convert dates to strings
        for crab in harvest_ready:
            if crab['latest_record_date']:
                crab['latest_record_date'] = crab['latest_record_date'].strftime('%Y-%m-%d')
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "harvest_ready": harvest_ready
        })
        
    except Exception as e:
        print(f"Error in get_harvest_ready: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
