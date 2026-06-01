import os
import cv2
import time
import threading
import numpy as np
from flask import Flask, render_template, redirect, url_for, session, request, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from functools import wraps
from datetime import datetime
from pytz import timezone
from user_agents import parse  # robust UA parsing
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database connection
db_url = os.environ.get("DATABASE_URL")
if not db_url:
    raise RuntimeError("DATABASE_URL is not set!")

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ── CCTV Camera Configuration ──────────────────────────────────────────
CAMERA_RTSP_URL = os.environ.get(
    "CAMERA_RTSP_URL",
    "rtsp://admin:123456@192.168.100.85:554/profile1"
)

class CameraStream:
    """Thread-safe RTSP camera reader. Continuously grabs the latest frame
    in a background thread so the main Flask threads never block on I/O."""

    def __init__(self, src):
        self.src = src
        self.frame = None
        self.running = False
        self.lock = threading.Lock()
        self.cap = None

    def start(self):
        self.running = True
        t = threading.Thread(target=self._reader, daemon=True)
        t.start()
        return self

    def _reader(self):
        # Suppress noisy FFmpeg RTSP errors in console
        os.environ["OPENCV_LOG_LEVEL"] = "SILENT"
        os.environ["OPENCV_FFMPEG_LOGLEVEL"] = "-8"
        while self.running:
            try:
                if self.cap is None or not self.cap.isOpened():
                    self.cap = cv2.VideoCapture(self.src, cv2.CAP_FFMPEG)
                    # Reduce OpenCV buffer to always get the newest frame
                    self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                    time.sleep(1)
                    continue
                grabbed, frame = self.cap.read()
                if grabbed:
                    with self.lock:
                        self.frame = frame
                else:
                    # Connection lost — reset
                    self.cap.release()
                    self.cap = None
                    time.sleep(2)
            except Exception:
                time.sleep(2)

    def read(self):
        with self.lock:
            return self.frame.copy() if self.frame is not None else None

    def is_alive(self):
        return self.frame is not None

    def stop(self):
        self.running = False
        if self.cap:
            self.cap.release()

# Create the camera stream reader but do not start it yet (lazy start)
camera = CameraStream(CAMERA_RTSP_URL)

def _offline_frame():
    """Return a dark placeholder image when the camera is offline."""
    img = np.zeros((480, 640, 3), dtype=np.uint8)
    img[:] = (24, 24, 24)
    text = "CAMERA OFFLINE"
    font = cv2.FONT_HERSHEY_SIMPLEX
    scale, thickness = 1.0, 2
    (tw, th), _ = cv2.getTextSize(text, font, scale, thickness)
    cx, cy = (640 - tw) // 2, (480 + th) // 2
    cv2.putText(img, text, (cx, cy), font, scale, (80, 80, 80), thickness, cv2.LINE_AA)
    return img

def generate_frames():
    """Yield MJPEG frames for the /video_feed route."""
    if not camera.running:
        camera.start()
    while True:
        frame = camera.read()
        if frame is None:
            frame = _offline_frame()
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
        if not ret:
            continue
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
        time.sleep(0.05)  # ~20 fps cap

# Models
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(20), nullable=False)   # "login" or "logout"
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone("Asia/Manila")))
    ip_address = db.Column(db.String(45))
    user_agent_raw = db.Column(db.String(300))
    browser = db.Column(db.String(50))
    device_info = db.Column(db.String(200))

# Helpers using user_agents
def parse_browser(ua_string):
    if not ua_string:
        return "Unknown"
    ua = parse(ua_string)
    return ua.browser.family  # e.g. "Opera", "Chrome", "Firefox"

def parse_device_info(ua_string):
    if not ua_string:
        return "Unknown device"
    ua = parse(ua_string)
    if ua.is_mobile:
        return "Mobile"
    if ua.is_tablet:
        return "Tablet"
    if ua.is_pc:
        return "PC/Desktop"
    if ua.is_bot:
        return "Bot"
    return "Other/Unknown Device"

# Session protection
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session or 'username' not in session:
            session.clear()
            session['state'] = 'login'
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# State enforcement (blocks manual typing)
def enforce_state(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_state = session.get('state', 'login')
        referer = request.headers.get("Referer", "")
        # If no referer (manual typing), force back to current state
        if not referer and request.endpoint != current_state:
            return redirect(url_for(current_state))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    session['state'] = 'login'
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@enforce_state
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['username'] = admin.username
            session['state'] = 'dashboard'
            ua_string = request.headers.get('User-Agent')
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            log = ActivityLog(
                username=admin.username,
                action="login",
                ip_address=ip,
                user_agent_raw=ua_string,
                browser=parse_browser(ua_string),
                device_info=parse_device_info(ua_string)
            )
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard')
@login_required
@enforce_state
def dashboard():
    session['state'] = 'dashboard'
    return render_template('dashboard.html')

@app.route('/video_feed')
@login_required
def video_feed():
    """MJPEG stream endpoint — browser loads this as an <img> src."""
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/camera_status')
@login_required
def camera_status():
    """JSON endpoint for the frontend to poll camera health."""
    if not camera.running:
        camera.start()
    return jsonify({"online": camera.is_alive()})

@app.route('/activity')
@login_required
@enforce_state
def activity():
    session['state'] = 'activity'
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('activity.html', logs=logs)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
@enforce_state
def logout():
    username = session.get('username')
    if username:
        ua_string = request.headers.get('User-Agent')
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        log = ActivityLog(
            username=username,
            action="logout",
            ip_address=ip,
            user_agent_raw=ua_string,
            browser=parse_browser(ua_string),
            device_info=parse_device_info(ua_string)
        )
        db.session.add(log)
        db.session.commit()
    session.clear()
    session['state'] = 'login'
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
