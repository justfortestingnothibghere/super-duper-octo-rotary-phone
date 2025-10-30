import eventlet
eventlet.monkey_patch()  # ✅ must be first!

import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO
from dotenv import load_dotenv

# Load environment
load_dotenv()

# ----- Setup -----
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
PROFILE_FOLDER = os.path.join(UPLOAD_FOLDER, 'profile')
DOC_FOLDER = os.path.join(UPLOAD_FOLDER, 'docs')
for p in (UPLOAD_FOLDER, PROFILE_FOLDER, DOC_FOLDER):
    os.makedirs(p, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'data.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'

# ✅ Enable SocketIO with Eventlet
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# ===================== MODELS =====================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    profile_photo = db.Column(db.String(300), nullable=True)
    password = db.Column(db.String(200), nullable=False)  # NOTE: plain text (demo)
    is_admin = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, default=False)

class VerificationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    email = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    pan_number = db.Column(db.String(80), nullable=True)
    document_path = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SharedText(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ===================== LOGIN HANDLER =====================
@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# ===================== HELPERS =====================
ALLOWED_PHOTO = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_DOC = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename, allowed):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed

# ===================== ROUTES =====================
@app.route('/')
def index():
    texts = SharedText.query.order_by(SharedText.created_at.desc()).limit(50).all()
    return render_template('index.html', texts=texts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        phone = request.form.get('phone')
        password = request.form['password']
        bio = request.form.get('bio')

        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash('Username or email already taken')
            return redirect(url_for('register'))

        photo = request.files.get('profile_photo')
        photo_path = None
        if photo and allowed_file(photo.filename, ALLOWED_PHOTO):
            fname = secure_filename(f"{username}_{int(datetime.utcnow().timestamp())}_{photo.filename}")
            photo.save(os.path.join(PROFILE_FOLDER, fname))
            photo_path = os.path.join('uploads', 'profile', fname)

        user = User(username=username, name=name, email=email, phone=phone, bio=bio or '', profile_photo=photo_path, password=password)

        if User.query.count() == 0:  # first user is admin
            user.is_admin = True

        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Registered successfully!')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        loginid = request.form['loginid']
        password = request.form['password']
        user = User.query.filter((User.username==loginid)|(User.email==loginid)).first()
        if not user or user.password != password:
            flash('Invalid credentials')
            return redirect(url_for('login'))
        login_user(user)
        flash('Logged in successfully!')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out')
    return redirect(url_for('index'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    texts = SharedText.query.filter_by(user_id=user.id).order_by(SharedText.created_at.desc()).all()
    return render_template('profile.html', user=user, texts=texts)

@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# Request Verification
@app.route('/request-verification', methods=['GET', 'POST'])
@login_required
def request_verification():
    if request.method == 'POST':
        description = request.form.get('description')
        pan = request.form.get('pan_number')
        doc = request.files.get('document')
        doc_path = None
        if doc and allowed_file(doc.filename, ALLOWED_DOC):
            fname = secure_filename(f"{current_user.username}_doc_{int(datetime.utcnow().timestamp())}_{doc.filename}")
            doc.save(os.path.join(DOC_FOLDER, fname))
            doc_path = os.path.join('uploads', 'docs', fname)

        req = VerificationRequest(
            user_id=current_user.id, username=current_user.username,
            name=current_user.name, phone=current_user.phone, email=current_user.email,
            description=description, pan_number=pan, document_path=doc_path
        )
        db.session.add(req)
        db.session.commit()
        flash('Verification request submitted')
        return redirect(url_for('index'))
    return render_template('request_verification.html')

# Admin Panel
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Admin only')
        return redirect(url_for('index'))
    requests = VerificationRequest.query.order_by(VerificationRequest.created_at.desc()).all()
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin.html', requests=requests, users=users)

@app.route('/admin/handle/<int:req_id>/<action>')
@login_required
def handle_request(req_id, action):
    if not current_user.is_admin:
        flash('Admin only')
        return redirect(url_for('index'))
    req = VerificationRequest.query.get_or_404(req_id)
    if action == 'approve':
        req.status = 'approved'
        user = User.query.get(req.user_id)
        if user:
            user.verified = True
    elif action == 'reject':
        req.status = 'rejected'
    db.session.commit()
    flash('Request updated')
    return redirect(url_for('admin'))

# Text sharing
@app.route('/share', methods=['POST'])
@login_required
def share():
    content = request.form.get('content', '').strip()
    if not content:
        flash('Cannot share empty text')
        return redirect(url_for('index'))
    st = SharedText(user_id=current_user.id, content=content)
    db.session.add(st)
    db.session.commit()

    socketio.emit('new_text', {
        'id': st.id,
        'user': current_user.username,
        'content': st.content,
        'created_at': st.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }, broadcast=True)

    flash('Shared successfully!')
    return redirect(url_for('index'))

# Socket events
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# ===================== MAIN =====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
