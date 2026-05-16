import os
import psycopg2
from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = "supersecretkey"

# =========================
# LOAD ENV + DATABASE
# =========================
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
print("DEBUG DB URL:", DATABASE_URL)

def get_db_connection():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL is not loaded from .env")
    return psycopg2.connect(DATABASE_URL)

# =========================
# LOGGING FUNCTION
# =========================
def add_log(name, role, activity, active=True):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO logs (name, role, activity, active)
        VALUES (%s, %s, %s, %s)
        """,
        (name, role, activity, active)
    )

    conn.commit()
    cur.close()
    conn.close()

# =========================
# ROUTES
# =========================

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM user_data WHERE LOWER(username) = LOWER(%s) AND password = %s",
            (username, password)
        )

        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:
            session['user'] = username

            # ✅ LOG LOGIN
            add_log(username, "user", "Logged in", True)

            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    # ✅ LOG DASHBOARD ACCESS
    add_log(session['user'], "user", "Opened dashboard", True)

    return render_template('dashboard.html')


@app.route('/activity')
def activity():
    if 'user' not in session:
        return redirect(url_for('login'))

    # ✅ LOG ACTIVITY PAGE
    add_log(session['user'], "user", "Opened activity page", True)

    return render_template('activity.html')


@app.route('/settings')
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))

    # ✅ LOG SETTINGS PAGE
    add_log(session['user'], "user", "Opened settings page", True)

    return render_template('settings.html')


@app.route('/logout')
def logout():
    if 'user' in session:
        # ✅ LOG LOGOUT
        add_log(session['user'], "user", "Logged out", False)

    session.clear()
    return redirect(url_for('login'))


# =========================
# OPTIONAL: CLICK LOGGING API
# =========================
@app.route('/log', methods=['POST'])
def log():
    if 'user' not in session:
        return jsonify({"error": "not logged in"}), 403

    data = request.get_json()
    activity = data.get("activity")

    add_log(session['user'], "user", activity, True)

    return jsonify({"success": True})



# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    app.run(debug=True)